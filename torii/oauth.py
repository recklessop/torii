"""OAuth 2.1 authorization server (PRD FR2).

What a claude.ai custom connector needs, and where it is:

* RFC 8414 authorization-server metadata — `/.well-known/oauth-authorization-server`
* RFC 9728 protected-resource metadata — `/.well-known/oauth-protected-resource`
* RFC 7591 dynamic client registration — `POST /oauth/register`
* authorization code + PKCE (S256 only) — `GET /authorize`, `POST /oauth/token`
* refresh with rotation, RFC 7009 revocation — `POST /oauth/token`, `/oauth/revoke`

On Authlib: the PRD asks for library primitives over hand-rolled flows, and
the crypto-adjacent primitive here is the PKCE challenge, which comes from
`authlib.oauth2.rfc7636`. The flow itself is deliberately explicit rather
than routed through Authlib's framework integration — Authlib's server
plumbing targets Flask/Django request objects, and adapting it to Starlette
would add an indirection layer between this file and the exact bytes on the
wire, which is the opposite of what the riskiest code in the repo needs.

Torii is the authorization server toward Claude in every case. Even once an
IdP is federated (P3+), the IdP answers who the user is; torii mints its own
tokens and decides access from grants alone.
"""

import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass
from urllib.parse import urlencode, urlparse

from authlib.oauth2.rfc7636 import create_s256_code_challenge

from . import audit, cache, config, credentials

log = logging.getLogger(__name__)

# Authorization requests in flight, and issued codes, live in valkey: both are
# single-use and expire in minutes, so Postgres would only accumulate garbage.
PENDING_PREFIX = "torii:authreq:"
CODE_PREFIX = "torii:authcode:"
# A marker that an auth code was successfully spent, kept for the code's own
# lifetime so a replay within that window is caught and revokes the family (#68).
SPENT_CODE_PREFIX = "torii:spentcode:"

SUPPORTED_SCOPES = ("mcp",)


class OAuthError(Exception):
    """An error with an OAuth-shaped response body."""

    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status

    def as_dict(self) -> dict:
        body = {"error": self.error}
        if self.description:
            body["error_description"] = self.description
        return body


@dataclass
class PendingAuthorization:
    """A validated `/authorize` request waiting for the human to log in."""

    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    state: str | None = None
    scope: str | None = None
    resource: str | None = None
    created_at: float = 0.0
    # Binds the flow to the browser session that created it (Q26 / the audit's
    # "C1a"): the same value is stored in that session, and completing the flow
    # requires the two to match — so a request_id handed to another session
    # cannot be finished by it.
    nonce: str = ""


# --- metadata documents ----------------------------------------------------


def issuer() -> str:
    return config.PUBLIC_BASE_URL


def authorization_server_metadata() -> dict:
    """RFC 8414. `issuer` must match byte-for-byte what the client used."""
    base = issuer()
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        # S256 only: OAuth 2.1 forbids `plain`, and a downgrade here would
        # make PKCE decorative.
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": list(SUPPORTED_SCOPES),
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "service_documentation": f"{base}/ui",
    }


def protected_resource_metadata(server: str | None = None) -> dict:
    """RFC 9728: tells a client which authorization server guards an endpoint.

    `server` names a per-server endpoint (`/<server>/mcp`), so each connector
    gets metadata whose `resource` matches the URL the client actually calls.
    """
    base = issuer()
    resource = f"{base}/{server}/mcp" if server else f"{base}/mcp"
    return {
        "resource": resource,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": list(SUPPORTED_SCOPES),
        "resource_documentation": f"{base}/ui",
    }


def www_authenticate_header(server: str | None = None) -> str:
    """RFC 9728 discovery hint on a 401, so a client that hasn't registered
    yet can find the metadata without being told out of band."""
    path = "/.well-known/oauth-protected-resource"
    if server:
        path = f"{path}/{server}/mcp"
    return f'Bearer resource_metadata="{issuer()}{path}"'


# --- dynamic client registration (RFC 7591) -------------------------------


def _validate_redirect_uris(uris) -> list[str]:
    if not uris or not isinstance(uris, list):
        raise OAuthError("invalid_redirect_uri", "redirect_uris is required")
    validated = []
    for uri in uris:
        if not isinstance(uri, str):
            raise OAuthError("invalid_redirect_uri", "redirect_uris must be strings")
        parsed = urlparse(uri)
        if parsed.fragment:
            raise OAuthError("invalid_redirect_uri", "fragments are not allowed")
        if parsed.scheme in ("http", "https"):
            if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
                # Plain HTTP off-localhost would leak the code in transit.
                raise OAuthError("invalid_redirect_uri", "http is localhost-only")
        elif not parsed.scheme:
            raise OAuthError("invalid_redirect_uri", "absolute URIs only")
        # A private-use scheme (claude://...) is how native apps come back.
        validated.append(uri)
    return validated


async def register_client(conn, request_body: dict, ip: str | None = None) -> dict:
    """Open registration, per RFC 7591.

    Registration deliberately grants nothing: the client has no principal and
    therefore no grants until a human completes an authorization with it
    (FR2). An unauthorized registration is a row and nothing more.
    """
    redirect_uris = _validate_redirect_uris(request_body.get("redirect_uris"))
    client_name = (request_body.get("client_name") or "unnamed client")[:200]
    grant_types = request_body.get("grant_types") or ["authorization_code", "refresh_token"]
    response_types = request_body.get("response_types") or ["code"]
    auth_method = request_body.get("token_endpoint_auth_method") or "none"

    for grant_type in grant_types:
        if grant_type not in ("authorization_code", "refresh_token"):
            raise OAuthError("invalid_client_metadata", f"unsupported grant type {grant_type}")
    if response_types != ["code"]:
        raise OAuthError("invalid_client_metadata", "only response_type=code is supported")
    if auth_method not in ("none", "client_secret_post", "client_secret_basic"):
        raise OAuthError("invalid_client_metadata", f"unsupported auth method {auth_method}")

    client_id = "tor_cl_" + secrets.token_urlsafe(16)
    client_secret = None
    secret_hash = None
    if auth_method != "none":
        client_secret = secrets.token_urlsafe(32)
        secret_hash = credentials.hash_secret(client_secret)

    await conn.execute(
        """INSERT INTO oauth_clients
               (client_id, client_secret_hash, client_name, redirect_uris,
                grant_types, response_types, scope, token_endpoint_auth_method,
                registered_via)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'dcr')""",
        client_id,
        secret_hash,
        client_name,
        redirect_uris,
        grant_types,
        response_types,
        request_body.get("scope"),
        auth_method,
    )
    await audit.record_auth_event(
        conn,
        event=audit.DCR_REGISTERED,
        client_id=client_id,
        ip=ip,
        detail={"client_name": client_name, "redirect_uris": redirect_uris},
    )

    registration = {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": auth_method,
        "client_id_issued_at": int(time.time()),
    }
    if client_secret:
        registration["client_secret"] = client_secret
    return registration


# --- authorization requests ------------------------------------------------


async def _load_client(conn, client_id: str):
    if not client_id:
        raise OAuthError("invalid_client", "client_id is required", status=401)
    row = await conn.fetchrow(
        """SELECT client_id, client_secret_hash, client_name, redirect_uris,
                  token_endpoint_auth_method, principal_id, disabled_at
             FROM oauth_clients WHERE client_id = $1""",
        client_id,
    )
    if row is None or row["disabled_at"] is not None:
        raise OAuthError("invalid_client", "unknown or disabled client", status=401)
    return row


async def begin_authorization(conn, params: dict) -> tuple[str, PendingAuthorization]:
    """Validate an `/authorize` request and park it until login completes.

    Errors here are rendered as pages rather than redirected: an unvalidated
    redirect_uri is not a safe place to send an error.
    """
    client = await _load_client(conn, params.get("client_id", ""))

    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri not in (client["redirect_uris"] or []):
        # Exact match only. Prefix matching is how open redirectors happen.
        raise OAuthError("invalid_request", "redirect_uri does not match registration")

    if params.get("response_type") != "code":
        raise OAuthError("unsupported_response_type", "only response_type=code is supported")

    challenge = params.get("code_challenge", "")
    method = params.get("code_challenge_method", "")
    if not challenge:
        raise OAuthError("invalid_request", "PKCE is required")
    if method != "S256":
        raise OAuthError("invalid_request", "code_challenge_method must be S256")

    pending = PendingAuthorization(
        client_id=client["client_id"],
        redirect_uri=redirect_uri,
        code_challenge=challenge,
        code_challenge_method=method,
        state=params.get("state"),
        scope=params.get("scope"),
        resource=params.get("resource"),
        created_at=time.time(),
    )
    request_id = secrets.token_urlsafe(24)
    await cache.client().setex(
        PENDING_PREFIX + request_id, config.AUTH_CODE_TTL, json.dumps(asdict(pending))
    )
    return request_id, pending


async def load_pending(request_id: str) -> PendingAuthorization | None:
    raw = await cache.client().get(PENDING_PREFIX + (request_id or ""))
    if not raw:
        return None
    return PendingAuthorization(**json.loads(raw))


async def bind_pending_nonce(request_id: str, nonce: str) -> None:
    """Stamp the flow nonce onto the stored pending, preserving its TTL (Q26)."""
    pending = await load_pending(request_id)
    if pending is None:
        return
    pending.nonce = nonce
    ttl = await cache.client().ttl(PENDING_PREFIX + request_id)
    await cache.client().setex(
        PENDING_PREFIX + request_id,
        ttl if isinstance(ttl, int) and ttl > 0 else config.AUTH_CODE_TTL,
        json.dumps(asdict(pending)),
    )


async def client_bound_to(conn, client_id: str, principal_id) -> bool:
    """True when this client is already authorized by (bound to) this principal.

    That binding is torii's record that the human has approved this client
    before, so consent (Q26) is shown only when this returns False — a returning
    connector passes straight through, a fresh/unbound one hits the screen.
    """
    bound = await conn.fetchval(
        "SELECT principal_id FROM oauth_clients WHERE client_id = $1", client_id
    )
    return bound is not None and str(bound) == str(principal_id)


def denied_location(pending: PendingAuthorization) -> str:
    """Redirect back to the client with `error=access_denied` (RFC 6749 §4.1.2.1)."""
    params = {"error": "access_denied"}
    if pending.state:
        params["state"] = pending.state
    sep = "&" if "?" in pending.redirect_uri else "?"
    return f"{pending.redirect_uri}{sep}{urlencode(params)}"


async def complete_authorization(
    conn,
    request_id: str,
    principal_id: str,
    user_agent: str | None = None,
    ip: str | None = None,
) -> str:
    """Mint a single-use code and bind the client to the human who authorized
    it. Returns the redirect URL for the browser."""
    pending = await load_pending(request_id)
    if pending is None:
        raise OAuthError("invalid_request", "authorization request expired")
    await cache.client().delete(PENDING_PREFIX + request_id)

    code = secrets.token_urlsafe(32)
    payload = asdict(pending) | {"principal_id": str(principal_id)}
    await cache.client().setex(
        CODE_PREFIX + credentials.hash_secret(code),
        config.AUTH_CODE_TTL,
        json.dumps(payload),
    )

    # Tokens are bound to the human who authorized the client (PRD section 4).
    # Re-binding on every authorization means a client handed to a different
    # human follows the human, not the registration.
    #
    # access_mode is set from the principal's preference at FIRST bind (Q14):
    # someone who wants every new connector to start limited gets that even
    # though DCR mints a brand-new client_id each time a connector is re-added.
    # Only applied when the client is unbound, so re-authorizing an existing
    # connector never silently re-widens or re-narrows it.
    await conn.execute(
        """UPDATE oauth_clients c
              SET principal_id = $2,
                  access_mode = CASE
                      WHEN c.principal_id IS NULL AND p.narrow_new_clients
                          THEN 'narrowed' ELSE c.access_mode END,
                  -- Recorded once, at first authorization: it's what tells a
                  -- phone apart from a desktop when both self-register as
                  -- "claude.ai" (Q16). COALESCE so re-authorizing elsewhere
                  -- doesn't rewrite where the connector was set up.
                  first_seen_user_agent = COALESCE(c.first_seen_user_agent, $3),
                  first_seen_ip = COALESCE(c.first_seen_ip, $4::inet),
                  last_seen_at = now(),
                  updated_at = now()
             FROM principals p
            WHERE c.client_id = $1 AND p.id = $2""",
        pending.client_id,
        principal_id,
        user_agent,
        ip,
    )
    await audit.record_auth_event(
        conn,
        event=audit.CLIENT_AUTHORIZED,
        principal_id=principal_id,
        client_id=pending.client_id,
        detail={"scope": pending.scope, "resource": pending.resource},
    )

    query = {"code": code}
    if pending.state:
        query["state"] = pending.state
    separator = "&" if "?" in pending.redirect_uri else "?"
    return f"{pending.redirect_uri}{separator}{urlencode(query)}"


def error_redirect(pending: PendingAuthorization, error: str, description: str = "") -> str:
    query = {"error": error}
    if description:
        query["error_description"] = description
    if pending.state:
        query["state"] = pending.state
    separator = "&" if "?" in pending.redirect_uri else "?"
    return f"{pending.redirect_uri}{separator}{urlencode(query)}"


# --- token endpoint --------------------------------------------------------


async def _authenticate_client(conn, form: dict):
    """Confidential clients must prove it; public clients are identified by
    client_id plus PKCE, which is what OAuth 2.1 expects of them."""
    client = await _load_client(conn, form.get("client_id", ""))
    if client["token_endpoint_auth_method"] != "none":
        presented = form.get("client_secret", "")
        if not presented or credentials.hash_secret(presented) != client["client_secret_hash"]:
            raise OAuthError("invalid_client", "client authentication failed", status=401)
    return client


async def _audit_grant_failure(conn, client_id, reason: str) -> None:
    """Token-endpoint failures were silent — code theft left no trace, unlike
    the refresh path (#68). Every refusal writes one row now."""
    await audit.record_auth_event(
        conn,
        event=audit.TOKEN_GRANT_FAILURE,
        outcome="failure",
        client_id=client_id,
        detail={"grant_type": "authorization_code", "reason": reason},
    )


async def exchange_code(conn, form: dict) -> dict:
    try:
        client = await _authenticate_client(conn, form)
    except OAuthError as exc:
        await _audit_grant_failure(conn, form.get("client_id"), f"client_auth:{exc.error}")
        raise

    code = form.get("code", "")
    code_hash = credentials.hash_secret(code)
    key = CODE_PREFIX + code_hash
    spent_key = SPENT_CODE_PREFIX + code_hash

    # Single use, atomically: GETDEL means two simultaneous exchanges can't both
    # read the pending payload, so only one ever issues tokens.
    raw = await cache.client().getdel(key)
    if not raw:
        # No live code. If we remember spending it, this is a replay — OAuth 2.1
        # treats that as proof of compromise, so revoke the tokens it minted
        # (as the refresh path does for its family). Otherwise it's expired.
        spent = await cache.client().get(spent_key)
        if spent:
            info = json.loads(spent)
            await credentials.revoke_client_tokens(
                conn, info["client_id"], reason="code_replay"
            )
            await audit.record_auth_event(
                conn,
                event=audit.TOKEN_REPLAY,
                outcome="failure",
                principal_id=info.get("principal_id"),
                client_id=info["client_id"],
                detail={"action": "revoked_token_family", "grant_type": "authorization_code"},
            )
            raise OAuthError("invalid_grant", "authorization code reuse detected")
        await _audit_grant_failure(conn, client["client_id"], "unknown_or_expired_code")
        raise OAuthError("invalid_grant", "code is invalid or expired")
    payload = json.loads(raw)

    if payload["client_id"] != client["client_id"]:
        await _audit_grant_failure(conn, client["client_id"], "client_mismatch")
        raise OAuthError("invalid_grant", "code was issued to another client")
    if form.get("redirect_uri") and form["redirect_uri"] != payload["redirect_uri"]:
        await _audit_grant_failure(conn, client["client_id"], "redirect_uri_mismatch")
        raise OAuthError("invalid_grant", "redirect_uri mismatch")

    verifier = form.get("code_verifier", "")
    if not verifier:
        await _audit_grant_failure(conn, client["client_id"], "missing_code_verifier")
        raise OAuthError("invalid_request", "code_verifier is required")
    if create_s256_code_challenge(verifier) != payload["code_challenge"]:
        await _audit_grant_failure(conn, client["client_id"], "pkce_mismatch")
        raise OAuthError("invalid_grant", "PKCE verification failed")

    pair = await credentials.issue_token_pair(
        conn,
        payload["principal_id"],
        client["client_id"],
        scope=payload.get("scope"),
        resource=payload.get("resource"),
    )
    # Remember the code was spent so a replay within its lifetime is caught above.
    await cache.client().setex(
        spent_key,
        config.AUTH_CODE_TTL,
        json.dumps({"client_id": client["client_id"], "principal_id": payload["principal_id"]}),
    )
    await audit.record_auth_event(
        conn,
        event=audit.TOKEN_ISSUED,
        principal_id=payload["principal_id"],
        client_id=client["client_id"],
        detail={"grant_type": "authorization_code"},
    )
    return pair.as_response(payload.get("scope"))


async def refresh(conn, form: dict) -> dict:
    client = await _authenticate_client(conn, form)
    presented = form.get("refresh_token", "")
    if not presented:
        raise OAuthError("invalid_request", "refresh_token is required")

    try:
        pair = await credentials.rotate_refresh_token(conn, presented, client["client_id"])
    except credentials.TokenReplayDetected:
        await audit.record_auth_event(
            conn,
            event=audit.TOKEN_REPLAY,
            outcome="failure",
            client_id=client["client_id"],
            detail={"action": "revoked_token_family"},
        )
        raise OAuthError("invalid_grant", "refresh token reuse detected") from None
    except credentials.CredentialError:
        raise OAuthError("invalid_grant", "refresh token is invalid or expired") from None

    await audit.record_auth_event(
        conn,
        event=audit.TOKEN_REFRESHED,
        client_id=client["client_id"],
        detail={"grant_type": "refresh_token"},
    )
    return pair.as_response()


async def token(conn, form: dict) -> dict:
    grant_type = form.get("grant_type", "")
    if grant_type == "authorization_code":
        return await exchange_code(conn, form)
    if grant_type == "refresh_token":
        return await refresh(conn, form)
    raise OAuthError("unsupported_grant_type", f"unsupported grant type {grant_type!r}")


async def revoke(conn, form: dict) -> None:
    """RFC 7009. Always answers 200: a client must not learn from this
    endpoint whether a token it doesn't hold exists."""
    presented = form.get("token", "")
    if not presented:
        return
    client_id = form.get("client_id")
    if client_id:
        try:
            await _authenticate_client(conn, form)
        except OAuthError:
            return
    revoked = await credentials.revoke_token(conn, presented, reason="client_revoked")
    if revoked:
        await audit.record_auth_event(
            conn, event=audit.TOKEN_REVOKED, client_id=client_id, detail={"via": "rfc7009"}
        )

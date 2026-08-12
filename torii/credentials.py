"""Credential minting and verification: passwords, TOTP, static keys, tokens.

Hashing choices, since they differ on purpose:

* **Passwords use bcrypt.** They are low-entropy and human-chosen, so the
  cost factor is the defence.
* **Keys and tokens use SHA-256.** They are 256 bits of `secrets` output, so
  there is nothing to brute-force and a slow KDF would only add latency to
  every single MCP call. What matters is that the plaintext is never stored,
  and a lookup by hash is exact and indexable.

Every function here takes a connection rather than opening one, so callers
control transactions and tests can roll back.
"""

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass

import asyncpg
import bcrypt
import pyotp

from . import cache, config
from .rbac import Caller

log = logging.getLogger(__name__)

# --- constants -------------------------------------------------------------

KEY_PREFIX = config.API_KEY_PREFIX          # "tor_"
KEY_BYTES = 32
DISPLAY_PREFIX_LENGTH = len(KEY_PREFIX) + 8  # "tor_" + 8 chars, non-secret
BCRYPT_MAX_BYTES = 72                        # bcrypt truncates beyond this
TOTP_VALID_WINDOW = 1                        # ±30s for clock drift
TOTP_INTERVAL_SECONDS = 30                   # pyotp default step
# A code stays valid across step-1..step+1, i.e. up to (2·window+1) steps, so a
# used-code marker has to outlive that whole span to actually stop reuse (#74).
TOTP_REPLAY_TTL_SECONDS = TOTP_INTERVAL_SECONDS * (2 * TOTP_VALID_WINDOW + 1)
TOTP_USED_PREFIX = "torii:totp_used:"


class CredentialError(Exception):
    """Base for credential problems that are the caller's fault."""


class PasswordTooLong(CredentialError):
    pass


class TokenReplayDetected(CredentialError):
    """A refresh token that was already rotated was presented again.

    Treated as compromise: the whole rotation family is revoked (RFC 9700's
    guidance) rather than just refusing this one request.
    """


# --- passwords -------------------------------------------------------------


def hash_password(password: str) -> str:
    if len(password.encode()) > BCRYPT_MAX_BYTES:
        # Silently truncating would mean two different passwords authenticate
        # the same account.
        raise PasswordTooLong(f"password exceeds {BCRYPT_MAX_BYTES} bytes")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode()[:BCRYPT_MAX_BYTES], password_hash.encode())
    except ValueError:
        # Malformed hash in the database — refuse rather than raise into a
        # login handler.
        return False


def generate_temp_password() -> str:
    """A temp password for onboarding. Read aloud once, then forced changed."""
    return secrets.token_urlsafe(12)


# --- TOTP ------------------------------------------------------------------


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str, issuer: str = "torii") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def totp_qr_svg(secret: str, username: str, issuer: str = "torii") -> str:
    """Inline SVG QR for the provisioning URI.

    Inline rather than an <img src> to an endpoint or a third-party chart
    API: the secret must never leave this process, and the enrollment page
    has to work with no external requests at all.
    """
    import io

    import segno

    uri = totp_provisioning_uri(secret, username, issuer)
    buffer = io.BytesIO()
    segno.make(uri, error="m").save(
        buffer,
        kind="svg",
        scale=5,
        dark="#000000",      # replaced with currentColor below
        light=None,          # transparent, so it works in light and dark
        omitsize=True,       # size comes from CSS
        svgclass=None,
        lineclass=None,
        xmldecl=False,
    )
    # segno validates colours against real CSS colour values, so the
    # theme-following `currentColor` has to be substituted afterwards. That
    # is what lets one piece of markup render in both light and dark. segno
    # shortens #000000 to #000, so match on what it actually emits.
    svg = buffer.getvalue().decode()
    return re.sub(r'stroke="#0{3,6}"', 'stroke="currentColor"', svg)


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=TOTP_VALID_WINDOW)


async def verify_totp_unused(secret: str, code: str, subject: str) -> bool:
    """`verify_totp` plus a single-use guard (RFC 6238 §5.2, issue #74).

    `valid_window=1` keeps a code good for ~90s, so a shoulder-surfed or
    LAN-sniffed code could otherwise authenticate several times. Once a code is
    accepted for a `subject` (the principal id) we record it in valkey and
    refuse any second use for as long as it could still verify. `subject` scopes
    the guard so two identities may legitimately hold the same 6-digit code.

    A wrong code returns False without recording anything. On a valkey outage
    the guard fails CLOSED: the whole login flow already needs valkey for its
    session, so refusing the code is safe and keeps the guard from becoming a
    replay bypass.
    """
    if not verify_totp(secret, code):
        return False
    normalized = code.strip().replace(" ", "")
    key = TOTP_USED_PREFIX + subject + ":" + hash_secret(normalized)
    try:
        first_use = await cache.client().set(
            key, "1", nx=True, ex=TOTP_REPLAY_TTL_SECONDS
        )
    except Exception:  # noqa: BLE001 — a guard that can't check must not admit
        log.warning("TOTP replay guard unavailable (valkey); refusing the code")
        return False
    return bool(first_use)


# --- secret hashing --------------------------------------------------------


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _new_secret(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(KEY_BYTES)


# --- static API keys (PRD FR2; tor_ prefix, shown once) --------------------


@dataclass(frozen=True)
class MintedKey:
    id: str
    principal_id: str
    name: str
    key_prefix: str
    # Full plaintext. Returned exactly once, never stored, never logged.
    secret: str


async def mint_api_key(
    conn: asyncpg.Connection,
    principal_id,
    name: str,
    created_by=None,
    rotated_from=None,
    narrowed: bool = False,
) -> MintedKey:
    """Mint a `tor_` key.

    `narrowed` (Q15) bounds the key to its own grants, so a user with access to
    several servers can issue a key that reaches exactly one. Note that handing
    someone a per-server URL is NOT a substitute: `/<slug>/mcp` and `/mcp` are
    served by the same resolver, so an inheriting key reaches everything
    whichever URL it's pointed at.
    """
    secret = _new_secret(KEY_PREFIX)
    row = await conn.fetchrow(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash,
                                 created_by, rotated_from, access_mode)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, principal_id, name, key_prefix""",
        principal_id,
        name,
        secret[:DISPLAY_PREFIX_LENGTH],
        hash_secret(secret),
        created_by,
        rotated_from,
        "narrowed" if narrowed else "inherit",
    )
    return MintedKey(
        id=str(row["id"]),
        principal_id=str(row["principal_id"]),
        name=row["name"],
        key_prefix=row["key_prefix"],
        secret=secret,
    )


async def rotate_api_key(conn: asyncpg.Connection, key_id, actor_id=None) -> MintedKey:
    """Revoke a key and issue its replacement, keeping the audit chain."""
    old = await conn.fetchrow(
        "SELECT id, principal_id, name, access_mode FROM api_keys WHERE id = $1", key_id
    )
    if old is None:
        raise CredentialError("no such key")
    await conn.execute(
        """UPDATE api_keys SET revoked_at = now(), revoked_reason = 'rotated'
            WHERE id = $1 AND revoked_at IS NULL""",
        key_id,
    )
    replacement = await mint_api_key(
        conn,
        old["principal_id"],
        old["name"],
        created_by=actor_id,
        rotated_from=old["id"],
        # Carry the scope across, or rotating a limited key would silently
        # hand back a key with the principal's full baseline.
        narrowed=old["access_mode"] == "narrowed",
    )
    await conn.execute(
        """INSERT INTO grants (subject_type, api_key_id, upstream_id, tool_scope,
                               tools, created_by, note)
           SELECT 'key', $2::uuid, upstream_id, tool_scope, tools, created_by, note
             FROM grants WHERE subject_type = 'key' AND api_key_id = $1""",
        key_id,
        replacement.id,
    )
    return replacement


async def revoke_api_key(conn: asyncpg.Connection, key_id, reason: str = "revoked") -> bool:
    result = await conn.execute(
        """UPDATE api_keys SET revoked_at = now(), revoked_reason = $2
            WHERE id = $1 AND revoked_at IS NULL""",
        key_id,
        reason,
    )
    return result.endswith(" 1")


async def authenticate_api_key(conn: asyncpg.Connection, presented: str) -> Caller | None:
    """Resolve a `tor_...` bearer value to a caller, or None.

    Authorization is NOT decided here — that's `rbac.check`. This only
    answers "whose key is this, and is it still live".
    """
    if not presented or not presented.startswith(KEY_PREFIX):
        return None
    row = await conn.fetchrow(
        """SELECT k.id, k.principal_id, p.username, p.kind, p.disabled_at
             FROM api_keys k
             JOIN principals p ON p.id = k.principal_id
            WHERE k.key_hash = $1 AND k.revoked_at IS NULL""",
        hash_secret(presented),
    )
    if row is None or row["disabled_at"] is not None:
        return None
    await conn.execute("UPDATE api_keys SET last_used_at = now() WHERE id = $1", row["id"])
    return Caller(
        principal_id=str(row["principal_id"]),
        username=row["username"],
        kind=row["kind"],
        api_key_id=str(row["id"]),
    )


# --- OAuth tokens ----------------------------------------------------------


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"

    def as_response(self, scope: str | None = None) -> dict:
        body = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
        }
        if scope:
            body["scope"] = scope
        return body


async def issue_token_pair(
    conn: asyncpg.Connection,
    principal_id,
    client_id: str,
    scope: str | None = None,
    resource: str | None = None,
    rotated_from=None,
) -> TokenPair:
    access = _new_secret()
    refresh = _new_secret()
    await conn.execute(
        """INSERT INTO tokens (kind, token_hash, principal_id, client_id, scope,
                               resource, expires_at)
           VALUES ('access', $1, $2, $3, $4, $5, now() + ($6 || ' seconds')::interval)""",
        hash_secret(access),
        principal_id,
        client_id,
        scope,
        resource,
        str(config.ACCESS_TOKEN_TTL),
    )
    await conn.execute(
        """INSERT INTO tokens (kind, token_hash, principal_id, client_id, scope,
                               resource, expires_at, rotated_from)
           VALUES ('refresh', $1, $2, $3, $4, $5,
                   now() + ($6 || ' seconds')::interval, $7)""",
        hash_secret(refresh),
        principal_id,
        client_id,
        scope,
        resource,
        str(config.REFRESH_TOKEN_TTL),
        rotated_from,
    )
    return TokenPair(
        access_token=access, refresh_token=refresh, expires_in=config.ACCESS_TOKEN_TTL
    )


async def authenticate_access_token(
    conn: asyncpg.Connection, presented: str
) -> Caller | None:
    if not presented:
        return None
    row = await conn.fetchrow(
        """SELECT t.id, t.principal_id, t.client_id, p.username, p.kind, p.disabled_at
             FROM tokens t
             JOIN principals p ON p.id = t.principal_id
            WHERE t.token_hash = $1
              AND t.kind = 'access'
              AND t.revoked_at IS NULL
              AND t.expires_at > now()""",
        hash_secret(presented),
    )
    if row is None or row["disabled_at"] is not None:
        return None
    await conn.execute("UPDATE tokens SET last_used_at = now() WHERE id = $1", row["id"])
    return Caller(
        principal_id=str(row["principal_id"]),
        username=row["username"],
        kind=row["kind"],
        client_id=row["client_id"],
    )


async def rotate_refresh_token(
    conn: asyncpg.Connection, presented: str, client_id: str
) -> TokenPair:
    """Exchange a refresh token for a new pair, revoking the old one.

    A replayed (already-rotated) token revokes the entire family: if the same
    refresh token reaches us twice, one of the two holders is not the
    legitimate client and we cannot tell which.
    """
    row = await conn.fetchrow(
        """SELECT id, principal_id, client_id, scope, resource, revoked_at, expires_at
             FROM tokens WHERE token_hash = $1 AND kind = 'refresh'""",
        hash_secret(presented),
    )
    if row is None:
        raise CredentialError("invalid_grant")
    if row["client_id"] != client_id:
        # Refresh tokens are bound to the client they were issued to.
        raise CredentialError("invalid_grant")
    if row["revoked_at"] is not None:
        await _revoke_family(conn, row["id"])
        raise TokenReplayDetected("refresh token reuse")
    if row["expires_at"] is not None and await conn.fetchval(
        "SELECT $1::timestamptz <= now()", row["expires_at"]
    ):
        raise CredentialError("invalid_grant")

    await conn.execute(
        """UPDATE tokens SET revoked_at = now(), revoked_reason = 'rotated'
            WHERE id = $1""",
        row["id"],
    )
    # The access token issued alongside it dies with it: a rotation is a new
    # session for the client, and leaving the old access token live would
    # widen the window a stolen refresh token buys.
    await conn.execute(
        """UPDATE tokens SET revoked_at = now(), revoked_reason = 'superseded'
            WHERE kind = 'access' AND client_id = $1 AND principal_id = $2
              AND revoked_at IS NULL""",
        row["client_id"],
        row["principal_id"],
    )
    return await issue_token_pair(
        conn,
        row["principal_id"],
        row["client_id"],
        row["scope"],
        row["resource"],
        rotated_from=row["id"],
    )


async def _revoke_family(conn: asyncpg.Connection, token_id) -> None:
    """Revoke every token reachable through the rotation chain from here."""
    await conn.execute(
        """WITH RECURSIVE family AS (
               SELECT id FROM tokens WHERE id = $1
               UNION
               SELECT t.id FROM tokens t JOIN family f ON t.rotated_from = f.id
           )
           UPDATE tokens SET revoked_at = now(), revoked_reason = 'replay_detected'
            WHERE id IN (SELECT id FROM family) AND revoked_at IS NULL""",
        token_id,
    )
    # The chain only links refresh tokens; kill the access tokens of the same
    # client/principal too, since we now assume compromise.
    await conn.execute(
        """UPDATE tokens SET revoked_at = now(), revoked_reason = 'replay_detected'
            WHERE revoked_at IS NULL
              AND (client_id, principal_id) IN (
                    SELECT client_id, principal_id FROM tokens WHERE id = $1)""",
        token_id,
    )


async def revoke_token(conn: asyncpg.Connection, presented: str, reason: str = "revoked") -> bool:
    result = await conn.execute(
        """UPDATE tokens SET revoked_at = now(), revoked_reason = $2
            WHERE token_hash = $1 AND revoked_at IS NULL""",
        hash_secret(presented),
        reason,
    )
    return result.endswith(" 1")


async def revoke_client_tokens(
    conn: asyncpg.Connection, client_id: str, reason: str = "client_revoked"
) -> int:
    result = await conn.execute(
        """UPDATE tokens SET revoked_at = now(), revoked_reason = $2
            WHERE client_id = $1 AND revoked_at IS NULL""",
        client_id,
        reason,
    )
    return int(result.split()[-1])


async def revoke_principal_tokens(
    conn: asyncpg.Connection, principal_id, reason: str = "principal_disabled"
) -> int:
    result = await conn.execute(
        """UPDATE tokens SET revoked_at = now(), revoked_reason = $2
            WHERE principal_id = $1 AND revoked_at IS NULL""",
        principal_id,
        reason,
    )
    return int(result.split()[-1])


# --- provisioned OAuth clients (PRD Q14) -----------------------------------


@dataclass(frozen=True)
class MintedClient:
    client_id: str
    client_secret: str          # returned once, stored hashed
    client_name: str
    label: str | None
    access_mode: str


async def mint_oauth_client(
    conn: asyncpg.Connection,
    principal_id,
    client_name: str,
    redirect_uris: list[str],
    label: str | None = None,
    narrowed: bool = False,
) -> MintedClient:
    """Create a confidential client up front, bound to a principal.

    Why this exists: DCR mints a fresh client_id on every registration, so a
    connector that is removed and re-added is a NEW client and loses any
    narrowing attached to the old id (Q14). A client provisioned here has a
    stable id and secret, so its grants survive re-adding it in Claude — and
    the secret means a stolen refresh token can't be redeemed without it.

    Bound to the principal immediately: unlike DCR, the caller is already
    authenticated, so there's no reason to leave it unbound.
    """
    client_id = "tor_cl_" + secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    await conn.execute(
        """INSERT INTO oauth_clients
               (client_id, client_secret_hash, client_name, redirect_uris,
                grant_types, response_types, token_endpoint_auth_method,
                registered_via, principal_id, label, access_mode)
           VALUES ($1, $2, $3, $4,
                   '{authorization_code,refresh_token}', '{code}',
                   'client_secret_post', 'manual', $5, NULLIF($6, ''), $7)""",
        client_id,
        hash_secret(client_secret),
        client_name,
        redirect_uris,
        principal_id,
        label or "",
        "narrowed" if narrowed else "inherit",
    )
    return MintedClient(
        client_id=client_id,
        client_secret=client_secret,
        client_name=client_name,
        label=label,
        access_mode="narrowed" if narrowed else "inherit",
    )


# --- WebAuthn passkeys (PRD Q25) -------------------------------------------
#
# A passkey is a second credential type on the LOCAL identity, not a new auth
# backend: the backend seam is about who vouches for an identity (local vs an
# IdP), and a passkey is just a stronger way of proving the same local one.
# Ceremony state (the challenge) is the caller's problem, exactly like the
# TOTP enrollment secret — these functions take bytes in and give verdicts
# out, and never touch valkey.
#
# The gate flags on a passkey outcome are computed IDENTICALLY to the
# password path. needs_totp_enrollment can be true here even though
# registration required a full session: an admin can flip totp_required on
# later, or reset a lost authenticator (nulling the secret). In both cases
# the account's policy says "must hold TOTP", and a passkey login must not
# become the way around it — web.session_principal does the gating either
# way.

import urllib.parse
import uuid as _uuid

import webauthn as _webauthn
from webauthn.helpers import (
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# Stable outcome reasons — they land in audit detail, like auth_backends'.
PASSKEY_OK = "ok"
UNKNOWN_CREDENTIAL = "unknown_credential"
BAD_PASSKEY = "bad_passkey"        # signature/origin/rp/uv failure — one bucket, on purpose
PASSKEY_DISABLED = "disabled"


def webauthn_rp_id() -> str:
    """The Relying Party ID passkeys are bound to.

    Hostname of PUBLIC_BASE_URL, read at call time so tests can monkeypatch;
    an explicit WEBAUTHN_RP_ID overrides for edge cases.
    """
    if config.WEBAUTHN_RP_ID:
        return config.WEBAUTHN_RP_ID
    return urllib.parse.urlsplit(config.PUBLIC_BASE_URL).hostname or "localhost"


def webauthn_origin() -> str:
    """What the browser will put in clientDataJSON.origin: scheme://host[:port]."""
    parts = urllib.parse.urlsplit(config.PUBLIC_BASE_URL)
    return f"{parts.scheme}://{parts.netloc}"


@dataclass(frozen=True)
class PasskeyChallenge:
    options_json: str    # feed straight to the browser
    challenge: bytes     # store (valkey), hand back to the verify step


async def start_passkey_registration(
    conn: asyncpg.Connection, principal_id, username: str
) -> PasskeyChallenge:
    """Options for navigator.credentials.create().

    Discoverable credential, user verification required — the whole point is
    that the one gesture carries both factors. Existing credentials are
    excluded so re-registering the same authenticator is a clean refusal
    rather than a confusing duplicate.
    """
    existing = await conn.fetch(
        "SELECT credential_id FROM webauthn_credentials WHERE principal_id = $1",
        principal_id,
    )
    options = _webauthn.generate_registration_options(
        rp_id=webauthn_rp_id(),
        rp_name=config.WEBAUTHN_RP_NAME,
        user_id=str(principal_id).encode(),
        user_name=username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=r["credential_id"]) for r in existing
        ],
    )
    return PasskeyChallenge(
        options_json=_webauthn.options_to_json(options), challenge=options.challenge
    )


async def register_passkey(
    conn: asyncpg.Connection, principal_id, name: str,
    credential_json: str, challenge: bytes,
) -> dict:
    """Verify an attestation and store the credential. Raises CredentialError."""
    try:
        verified = _webauthn.verify_registration_response(
            credential=credential_json,
            expected_challenge=challenge,
            expected_rp_id=webauthn_rp_id(),
            expected_origin=webauthn_origin(),
            require_user_verification=True,
        )
    except (InvalidRegistrationResponse, InvalidJSONStructure) as exc:
        raise CredentialError(f"registration refused: {exc}") from None

    aaguid = None
    if verified.aaguid:
        try:
            aaguid = _uuid.UUID(verified.aaguid)
        except ValueError:
            aaguid = None
    # Transports come from the browser's response, not the verified object.
    try:
        parsed = parse_registration_credential_json(credential_json)
        transports = [t.value for t in (parsed.response.transports or [])]
    except Exception:  # noqa: BLE001 — display metadata, never worth failing over
        transports = []
    try:
        row = await conn.fetchrow(
            """INSERT INTO webauthn_credentials
                   (principal_id, credential_id, public_key, sign_count,
                    transports, aaguid, backup_eligible, backed_up, name)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               RETURNING id, name, created_at""",
            principal_id,
            verified.credential_id,
            verified.credential_public_key,
            verified.sign_count,
            transports,
            aaguid,
            verified.credential_device_type == CredentialDeviceType.MULTI_DEVICE,
            verified.credential_backed_up,
            name.strip(),
        )
    except asyncpg.UniqueViolationError:
        raise CredentialError("that authenticator is already registered") from None
    except asyncpg.CheckViolationError:
        raise CredentialError("a passkey needs a name") from None
    return {"id": str(row["id"]), "name": row["name"], "created_at": row["created_at"]}


def start_passkey_login() -> PasskeyChallenge:
    """Options for navigator.credentials.get(), usernameless.

    The empty allow-list is the discoverable-credential flow: the
    authenticator itself offers the account chooser. Pure function — there is
    no principal to look anything up for yet.
    """
    options = _webauthn.generate_authentication_options(
        rp_id=webauthn_rp_id(),
        user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[],
    )
    return PasskeyChallenge(
        options_json=_webauthn.options_to_json(options), challenge=options.challenge
    )


@dataclass(frozen=True)
class PasskeyOutcome:
    """AuthOutcome-equivalent for a passkey login.

    A separate class because auth_backends imports this module — importing
    back would be a cycle. Field names match, so session minting reads
    identically at both call sites.
    """
    ok: bool
    reason: str
    principal_id: str | None = None
    username: str | None = None
    is_admin: bool = False
    must_change_password: bool = False
    needs_totp_enrollment: bool = False
    credential_name: str | None = None   # for audit detail


async def authenticate_passkey(
    conn: asyncpg.Connection, credential_json: str, challenge: bytes
) -> PasskeyOutcome:
    """Verify an assertion and resolve who signed it.

    The disabled check happens BEFORE any signature work, mirroring
    authenticate_api_key. unknown_credential and bad_passkey are distinct in
    the audit trail but must read identically to the client — the login page
    is an enumeration surface.
    """
    try:
        parsed = parse_authentication_credential_json(credential_json)
    except Exception:  # noqa: BLE001 — malformed input is a refusal, not a 500
        return PasskeyOutcome(ok=False, reason=BAD_PASSKEY)

    row = await conn.fetchrow(
        """SELECT w.id, w.name, w.public_key, w.sign_count,
                  w.principal_id, p.username, p.is_admin, p.disabled_at,
                  p.totp_required, i.password_is_temp, i.totp_secret
             FROM webauthn_credentials w
             JOIN principals p ON p.id = w.principal_id
             LEFT JOIN auth_identities i
                    ON i.principal_id = p.id AND i.backend = 'local'
            WHERE w.credential_id = $1""",
        parsed.raw_id,
    )
    if row is None:
        return PasskeyOutcome(ok=False, reason=UNKNOWN_CREDENTIAL)
    if row["disabled_at"] is not None:
        return PasskeyOutcome(ok=False, reason=PASSKEY_DISABLED)

    try:
        verified = _webauthn.verify_authentication_response(
            credential=credential_json,
            expected_challenge=challenge,
            expected_rp_id=webauthn_rp_id(),
            expected_origin=webauthn_origin(),
            credential_public_key=row["public_key"],
            credential_current_sign_count=row["sign_count"],
            require_user_verification=True,
        )
    except (InvalidAuthenticationResponse, InvalidJSONStructure):
        return PasskeyOutcome(
            ok=False, reason=BAD_PASSKEY, credential_name=row["name"]
        )

    await conn.execute(
        """UPDATE webauthn_credentials
              SET sign_count = $2, last_used_at = now()
            WHERE id = $1""",
        row["id"], verified.new_sign_count,
    )
    # Deliberately no touch of auth_identities.failed_attempts/locked_until:
    # a passkey login must not unlock a password identity under attack.
    return PasskeyOutcome(
        ok=True,
        reason=PASSKEY_OK,
        principal_id=str(row["principal_id"]),
        username=row["username"],
        is_admin=row["is_admin"],
        must_change_password=bool(row["password_is_temp"]),
        needs_totp_enrollment=bool(row["totp_required"]) and row["totp_secret"] is None,
        credential_name=row["name"],
    )

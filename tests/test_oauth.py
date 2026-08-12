"""The OAuth 2.1 authorization server, driven over HTTP.

These go through the real ASGI app: metadata, DCR, the authorize page, the
login gates, code exchange with PKCE, rotation, and revocation. The parts that
must fail — PKCE downgrade, code replay, cross-client code use, redirect_uri
tampering — get more attention than the happy path.
"""

import hashlib
import base64
import json
import os

import asyncpg
import httpx
import pyotp
import pytest

from conftest import make_upstream
from torii import app as app_module
from torii import cache, config, credentials, db, oauth

USERNAME = "alice"
PASSWORD = "a-real-password-1"

# A separate database, so TRUNCATE here can't disturb the schema/rbac tests
# that share the primary test database and depend on rollback isolation.
OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit(
        "/", 1
    )[0]
    + "/torii_oauth",
)


def pkce_pair(verifier="verifier-that-is-long-enough-to-be-valid-0123456789"):
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
async def client(oauth_database, monkeypatch):
    """An HTTP client against the app, sharing the OAuth test database.

    asyncpg pools and the redis client are bound to the event loop they were
    created in; pytest-asyncio gives each test its own loop, so a pool from
    an earlier test can't be reused (and can't be safely closed from the
    wrong loop either). Reset the module-level references so the next call
    into db/cache constructs fresh clients in this test's loop.
    """
    monkeypatch.setattr(config, "DATABASE_URL", oauth_database)
    db._pool = None
    cache._client = None

    pool = await db.pool()
    async with pool.acquire() as conn:
        await _reset(conn)

    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://torii.test", follow_redirects=False
    ) as http:
        yield http

    await db.close()
    await cache.close()


async def _reset(conn):
    """These tests exercise the whole app, so they can't hide in a rolled-back
    transaction. Clear what they create instead."""
    await conn.execute(
        """TRUNCATE audit_calls, audit_auth_events, tokens, grants, api_keys,
                    auth_identities, oauth_clients, upstreams, principals
                    RESTART IDENTITY CASCADE"""
    )
    keys = [k async for k in cache.client().scan_iter("torii:*")]
    if keys:
        await cache.client().delete(*keys)


async def _human(totp=True, temp=False):
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            """INSERT INTO principals (kind, username, totp_required)
               VALUES ('human', $1, TRUE) RETURNING id""",
            USERNAME,
        )
        secret = credentials.generate_totp_secret() if totp else None
        await conn.execute(
            """INSERT INTO auth_identities
                   (principal_id, backend, password_hash, password_is_temp, totp_secret)
               VALUES ($1, 'local', $2, $3, $4::text)""",
            principal_id,
            credentials.hash_password(PASSWORD),
            temp,
            secret,
        )
    return str(principal_id), secret


async def _register(http, redirect_uri="https://claude.ai/api/mcp/auth_callback"):
    response = await http.post(
        "/oauth/register",
        json={"client_name": "claude.ai", "redirect_uris": [redirect_uri]},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _authorize_and_login(http, client_id, redirect_uri, challenge, totp_secret,
                               state="xyz-state"):
    page = await http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": "mcp",
        },
    )
    assert page.status_code == 200
    request_id = _extract_request_id(page.text)

    login = await http.post(
        "/authorize",
        data={
            "request_id": request_id,
            "username": USERNAME,
            "password": PASSWORD,
            "totp_code": pyotp.TOTP(totp_secret).now() if totp_secret else "",
        },
    )
    return await _through_consent(http, login)


async def _through_consent(http, response, *, headers=None):
    """Follow a login/gate hand-off through the Q26 consent step and approve.

    A response that hands off to consent (302 -> /authorize/consent) is followed:
    a new (unbound) client renders the screen, which we approve; a client already
    bound to the principal auto-completes and the consent GET is itself the client
    redirect. Anything that isn't a consent hand-off (a gate page, an error) is
    returned unchanged, so gate tests still see their gate. `headers` ride the
    consent request(s), which is where the connector's first-seen browser/IP is
    now captured.
    """
    loc = response.headers.get("location", "") if response.status_code in (301, 302, 303) else ""
    if not loc.startswith("/authorize/consent"):
        return response
    page = await http.get(loc, headers=headers)
    if page.status_code != 200:
        return page  # bound client: the consent GET already redirected with the code
    return await http.post(
        "/authorize/consent",
        data={
            "request_id": _extract_request_id(page.text),
            "csrf": _extract_field(page.text, "csrf"),
            "decision": "approve",
        },
        headers=headers,
    )


def _extract_field(html: str, name: str) -> str:
    marker = f'name="{name}" value="'
    start = html.index(marker) + len(marker)
    return html[start : html.index('"', start)]


def _extract_request_id(html: str) -> str:
    return _extract_field(html, "request_id")


def _code_from(response) -> str:
    location = response.headers["location"]
    query = dict(part.split("=", 1) for part in location.split("?", 1)[1].split("&"))
    return query["code"]


# --- metadata --------------------------------------------------------------


async def test_authorization_server_metadata(client):
    response = await client.get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    body = response.json()

    assert body["issuer"] == config.PUBLIC_BASE_URL
    assert body["authorization_endpoint"].endswith("/authorize")
    assert body["token_endpoint"].endswith("/oauth/token")
    assert body["registration_endpoint"].endswith("/oauth/register")
    assert body["grant_types_supported"] == ["authorization_code", "refresh_token"]
    # OAuth 2.1 forbids `plain`; advertising it would make PKCE decorative.
    assert body["code_challenge_methods_supported"] == ["S256"]


async def test_protected_resource_metadata(client):
    for path in (
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ):
        response = await client.get(path)
        assert response.status_code == 200
        body = response.json()
        assert body["resource"].endswith("/mcp")
        assert body["authorization_servers"] == [config.PUBLIC_BASE_URL]


async def test_metadata_is_public_and_uncookied(client):
    response = await client.get("/.well-known/oauth-authorization-server")
    assert "set-cookie" not in response.headers


# --- dynamic client registration -------------------------------------------


async def test_registration_returns_a_client_id(client):
    registration = await _register(client)
    assert registration["client_id"].startswith("tor_cl_")
    assert registration["token_endpoint_auth_method"] == "none"
    # A public client gets no secret; PKCE is what protects it.
    assert "client_secret" not in registration


async def test_registration_grants_nothing(client):
    """FR2: DCR without a completed authorization grants nothing. The client
    has no principal, so it can hold no grants at all."""
    registration = await _register(client)
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT principal_id FROM oauth_clients WHERE client_id = $1",
            registration["client_id"],
        )
        assert row["principal_id"] is None
        assert await conn.fetchval("SELECT count(*) FROM grants") == 0


async def test_registration_is_audited(client):
    registration = await _register(client)
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT event, client_id FROM audit_auth_events WHERE event = 'dcr_registered'"
        )
    assert row["client_id"] == registration["client_id"]


async def test_confidential_client_gets_a_secret_once(client):
    response = await client.post(
        "/oauth/register",
        json={
            "client_name": "office-add-in",
            "redirect_uris": ["https://example.org/cb"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert response.status_code == 201
    secret = response.json()["client_secret"]

    pool = await db.pool()
    async with pool.acquire() as conn:
        stored = await conn.fetchval(
            "SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1",
            response.json()["client_id"],
        )
    assert stored == credentials.hash_secret(secret)


@pytest.mark.parametrize(
    "body",
    [
        {"client_name": "no uris"},
        {"client_name": "x", "redirect_uris": []},
        {"client_name": "x", "redirect_uris": ["https://x/cb#frag"]},
        {"client_name": "x", "redirect_uris": ["http://evil.example/cb"]},
        {"client_name": "x", "redirect_uris": ["/relative"]},
        {"client_name": "x", "redirect_uris": ["https://x/cb"], "response_types": ["token"]},
        {"client_name": "x", "redirect_uris": ["https://x/cb"], "grant_types": ["implicit"]},
    ],
)
async def test_bad_registrations_are_refused(client, body):
    response = await client.post("/oauth/register", json=body)
    assert response.status_code == 400
    assert "error" in response.json()


async def test_localhost_http_redirect_is_allowed(client):
    """Claude Code and other native clients come back on a loopback port."""
    response = await client.post(
        "/oauth/register",
        json={"client_name": "cli", "redirect_uris": ["http://127.0.0.1:41999/cb"]},
    )
    assert response.status_code == 201


# --- authorize: validation before anything is shown ------------------------


async def test_authorize_requires_pkce(client):
    registration = await _register(client)
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
        },
    )
    assert response.status_code == 400
    assert "PKCE" in response.text


async def test_authorize_rejects_plain_pkce(client):
    registration = await _register(client)
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_challenge": "whatever",
            "code_challenge_method": "plain",
        },
    )
    assert response.status_code == 400


async def test_authorize_rejects_unregistered_redirect_uri(client):
    """Exact match only — prefix matching is how open redirectors happen."""
    registration = await _register(client)
    _, challenge = pkce_pair()
    for tampered in (
        "https://claude.ai/api/mcp/auth_callback/../evil",
        "https://claude.ai/api/mcp/auth_callback?x=1",
        "https://evil.example/cb",
    ):
        response = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": registration["client_id"],
                "redirect_uri": tampered,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert response.status_code == 400, tampered
        # The error is rendered, never redirected to an unvalidated URI.
        assert "location" not in response.headers


async def test_authorize_rejects_unknown_client(client):
    _, challenge = pkce_pair()
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "tor_cl_nope",
            "redirect_uri": "https://claude.ai/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 401


async def test_authorize_shows_a_login_page(client):
    await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 200
    assert "claude.ai" in response.text or "Sign in" in response.text
    assert 'name="request_id"' in response.text


# --- the full flow ---------------------------------------------------------


async def test_full_authorization_code_flow(client):
    principal_id, secret = await _human()
    registration = await _register(client)
    verifier, challenge = pkce_pair()

    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    assert redirected.status_code == 302
    location = redirected.headers["location"]
    assert location.startswith(registration["redirect_uris"][0])
    assert "state=xyz-state" in location

    tokens = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code_from(redirected),
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_verifier": verifier,
        },
    )
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == config.ACCESS_TOKEN_TTL
    assert body["refresh_token"]
    assert tokens.headers["cache-control"] == "no-store"

    pool = await db.pool()
    async with pool.acquire() as conn:
        caller = await credentials.authenticate_access_token(conn, body["access_token"])
        assert caller.principal_id == principal_id
        assert caller.client_id == registration["client_id"]
        # Authorizing binds the client to the human who authorized it.
        assert str(await conn.fetchval(
            "SELECT principal_id FROM oauth_clients WHERE client_id = $1",
            registration["client_id"],
        )) == principal_id


async def test_wrong_password_does_not_issue_a_code(client):
    await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()
    page = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    response = await client.post(
        "/authorize",
        data={
            "request_id": _extract_request_id(page.text),
            "username": USERNAME,
            "password": "wrong",
            "totp_code": "000000",
        },
    )
    assert response.status_code == 401
    assert "location" not in response.headers

    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'login_failure'"
        ) == 1


async def test_missing_totp_is_refused_not_bypassed(client):
    await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()
    page = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    response = await client.post(
        "/authorize",
        data={
            "request_id": _extract_request_id(page.text),
            "username": USERNAME,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 401
    assert "authenticator" in response.text.lower()


async def test_totp_enrollment_gate_blocks_the_code(client):
    """A human with no authenticator yet must enroll before any client gets a
    code — the gate can't be walked past."""
    await _human(totp=False)
    registration = await _register(client)
    _, challenge = pkce_pair()

    response = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, None
    )
    assert response.status_code == 200
    assert "Set up two-factor" in response.text
    assert "location" not in response.headers

    # The enrollment page carries the secret; confirming it completes the flow.
    secret = response.text.split('<div class="secret">')[1].split("</div>")[0].strip()
    request_id = _extract_request_id(response.text)
    completed = await _through_consent(client, await client.post(
        "/authorize/totp",
        data={"request_id": request_id, "totp_code": pyotp.TOTP(secret).now()},
    ))
    assert completed.status_code == 302
    assert completed.headers["location"].startswith(registration["redirect_uris"][0])

    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT totp_secret FROM auth_identities") == secret


async def test_temp_password_gate_blocks_the_code(client):
    await _human(temp=True)
    registration = await _register(client)
    _, challenge = pkce_pair()
    secret = None
    pool = await db.pool()
    async with pool.acquire() as conn:
        secret = await conn.fetchval("SELECT totp_secret FROM auth_identities")

    response = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    assert response.status_code == 200
    assert "Choose a password" in response.text

    completed = await _through_consent(client, await client.post(
        "/authorize/password",
        data={
            "request_id": _extract_request_id(response.text),
            "password": "a-new-long-password",
            "confirm": "a-new-long-password",
        },
    ))
    assert completed.status_code == 302

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT password_hash, password_is_temp FROM auth_identities"
        )
    assert row["password_is_temp"] is False
    assert credentials.verify_password("a-new-long-password", row["password_hash"])


# --- token endpoint negatives ---------------------------------------------


async def test_code_is_single_use(client):
    _, secret = await _human()
    registration = await _register(client)
    verifier, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    code = _code_from(redirected)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": registration["client_id"],
        "redirect_uri": registration["redirect_uris"][0],
        "code_verifier": verifier,
    }

    assert (await client.post("/oauth/token", data=form)).status_code == 200
    replayed = await client.post("/oauth/token", data=form)
    assert replayed.status_code == 400
    assert replayed.json()["error"] == "invalid_grant"


async def test_code_replay_revokes_the_issued_tokens_and_audits(client):
    """#68: OAuth 2.1 treats a code replay as proof of compromise. The tokens
    minted from the first (legitimate) exchange are killed, and the replay is
    recorded — code theft used to leave no trace and live tokens behind."""
    _, secret = await _human()
    registration = await _register(client)
    verifier, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    form = {
        "grant_type": "authorization_code",
        "code": _code_from(redirected),
        "client_id": registration["client_id"],
        "redirect_uri": registration["redirect_uris"][0],
        "code_verifier": verifier,
    }
    issued = await client.post("/oauth/token", data=form)
    assert issued.status_code == 200
    access = issued.json()["access_token"]

    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await credentials.authenticate_access_token(conn, access) is not None

    replayed = await client.post("/oauth/token", data=form)
    assert replayed.status_code == 400
    assert replayed.json()["error"] == "invalid_grant"

    async with pool.acquire() as conn:
        # The access token issued from the replayed code is dead.
        assert await credentials.authenticate_access_token(conn, access) is None
        assert await conn.fetchval(
            """SELECT count(*) FROM audit_auth_events
                WHERE event = 'token_replay' AND outcome = 'failure'"""
        ) == 1


async def test_token_endpoint_failures_are_audited(client):
    """#68: every token-endpoint refusal writes an audit row, so stolen-code
    attempts are visible in the viewer like refresh-token abuse already is."""
    _, secret = await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    bad = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code_from(redirected),
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_verifier": "not-the-verifier-that-made-the-challenge",
        },
    )
    assert bad.status_code == 400

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT detail FROM audit_auth_events
                WHERE event = 'token_grant_failure' AND outcome = 'failure'"""
        )
    assert row is not None
    import json
    assert json.loads(row["detail"])["reason"] == "pkce_mismatch"


async def test_wrong_code_verifier_is_refused(client):
    _, secret = await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code_from(redirected),
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_verifier": "not-the-verifier-that-made-the-challenge",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_missing_code_verifier_is_refused(client):
    _, secret = await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code_from(redirected),
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
        },
    )
    assert response.status_code == 400


async def test_another_client_cannot_redeem_the_code(client):
    _, secret = await _human()
    mine = await _register(client)
    theirs = await _register(client, "https://claude.ai/other_callback")
    verifier, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, mine["client_id"], mine["redirect_uris"][0], challenge, secret
    )
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code_from(redirected),
            "client_id": theirs["client_id"],
            "redirect_uri": theirs["redirect_uris"][0],
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_redirect_uri_must_match_at_the_token_endpoint(client):
    _, secret = await _human()
    registration = await _register(client)
    verifier, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code_from(redirected),
            "client_id": registration["client_id"],
            "redirect_uri": "https://evil.example/cb",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400


async def test_unsupported_grant_type(client):
    registration = await _register(client)
    response = await client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": registration["client_id"]},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


async def test_confidential_client_must_authenticate(client):
    registration = await client.post(
        "/oauth/register",
        json={
            "client_name": "add-in",
            "redirect_uris": ["https://example.org/cb"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    client_id = registration.json()["client_id"]
    response = await client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": "x"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


# --- refresh and revocation ------------------------------------------------


async def _tokens_for(client):
    _, secret = await _human()
    registration = await _register(client)
    verifier, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": _code_from(redirected),
            "client_id": registration["client_id"],
            "redirect_uri": registration["redirect_uris"][0],
            "code_verifier": verifier,
        },
    )
    return registration, response.json()


async def test_refresh_rotates(client):
    registration, tokens = await _tokens_for(client)
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": registration["client_id"],
        },
    )
    assert response.status_code == 200
    rotated = response.json()
    assert rotated["refresh_token"] != tokens["refresh_token"]

    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await credentials.authenticate_access_token(conn, rotated["access_token"])
        assert await credentials.authenticate_access_token(conn, tokens["access_token"]) is None


async def test_replayed_refresh_token_kills_the_session(client):
    registration, tokens = await _tokens_for(client)
    first = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": registration["client_id"],
        },
    )
    assert first.status_code == 200

    replay = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": registration["client_id"],
        },
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    pool = await db.pool()
    async with pool.acquire() as conn:
        # Everything that client held is now dead, and the replay is on record.
        assert await conn.fetchval(
            "SELECT count(*) FROM tokens WHERE revoked_at IS NULL"
        ) == 0
        assert await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'token_replay'"
        ) == 1


async def test_revocation_endpoint_revokes_and_stays_quiet(client):
    registration, tokens = await _tokens_for(client)
    response = await client.post(
        "/oauth/revoke",
        data={"token": tokens["access_token"], "client_id": registration["client_id"]},
    )
    assert response.status_code == 200

    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await credentials.authenticate_access_token(conn, tokens["access_token"]) is None

    # RFC 7009: an unknown token also gets a 200, so this can't probe for tokens.
    assert (await client.post("/oauth/revoke", data={"token": "made-up"})).status_code == 200


# --- discovery hint --------------------------------------------------------


def test_www_authenticate_points_at_the_metadata():
    header = oauth.www_authenticate_header()
    assert header.startswith("Bearer ")
    assert "/.well-known/oauth-protected-resource" in header


async def test_newly_bound_client_starts_narrowed_when_the_principal_asks(client):
    """Q14 end to end: with narrow_new_clients on, a self-registering connector
    that completes authorization is limited from the moment it binds — so a
    re-added connector can't come back with the principal's full baseline."""
    principal_id, secret = await _human()
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE principals SET narrow_new_clients = TRUE WHERE id = $1::uuid",
            principal_id,
        )
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:9/mcp")
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1::uuid, $2, 'all')""",
            principal_id, upstream_id,
        )

    registration = await _register(client)
    _, challenge = pkce_pair()
    redirected = await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    assert redirected.status_code == 302

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = $1",
            registration["client_id"],
        ) == "narrowed"


async def test_re_authorizing_an_existing_client_does_not_change_its_mode(client):
    """Only the FIRST bind sets the mode. Re-authorizing a connector the user
    has deliberately unlimited must not silently re-narrow it (or vice versa)."""
    principal_id, secret = await _human()
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE principals SET narrow_new_clients = TRUE WHERE id = $1::uuid", principal_id
        )

    registration = await _register(client)
    _, challenge = pkce_pair()
    await _authorize_and_login(
        client, registration["client_id"], registration["redirect_uris"][0], challenge, secret
    )
    # Owner decides it should inherit after all.
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE oauth_clients SET access_mode = 'inherit' WHERE client_id = $1",
            registration["client_id"],
        )

    # Second authorization: the browser session is still valid, so /authorize
    # completes straight to a redirect without re-rendering the login page.
    _, challenge2 = pkce_pair("second-verifier-long-enough-abcdefghijklmnop-0123")
    again = await client.get("/authorize", params={
        "response_type": "code",
        "client_id": registration["client_id"],
        "redirect_uri": registration["redirect_uris"][0],
        "code_challenge": challenge2,
        "code_challenge_method": "S256",
        "state": "second",
    })
    assert again.status_code == 302, again.text[:200]
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = $1",
            registration["client_id"],
        ) == "inherit"


async def test_authorizing_records_what_the_connector_was_set_up_from(client, monkeypatch):
    """Q16: every claude.ai surface registers as "claude.ai", so torii records
    the browser and address at FIRST authorization to tell them apart."""
    # CF-Connecting-IP is only trusted from a configured proxy now (#65); in the
    # real deployment that's the Cloudflare tunnel peer. Trust it here so the
    # forwarded address is honoured the way it is in production.
    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", True)
    _, secret = await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()

    iphone = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1")
    page = await client.get("/authorize", params={
        "response_type": "code", "client_id": registration["client_id"],
        "redirect_uri": registration["redirect_uris"][0],
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    request_id = _extract_request_id(page.text)
    browser = {"User-Agent": iphone, "CF-Connecting-IP": "203.0.113.9"}
    login = await client.post(
        "/authorize",
        data={"request_id": request_id, "username": USERNAME, "password": PASSWORD,
              "totp_code": pyotp.TOTP(secret).now()},
        headers=browser,
    )
    # first_seen is captured where the client is bound — the consent approval.
    await _through_consent(client, login, headers=browser)

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT first_seen_user_agent, first_seen_ip FROM oauth_clients
                WHERE client_id = $1""",
            registration["client_id"],
        )
    assert "iPhone" in row["first_seen_user_agent"]
    assert str(row["first_seen_ip"]) == "203.0.113.9"

    from torii import useragent
    assert useragent.describe(row["first_seen_user_agent"]) == "Safari on iPhone"


async def test_re_authorizing_elsewhere_does_not_rewrite_where_it_was_set_up(client):
    """It describes where the connector was ADDED. Otherwise the field would
    just track wherever it was last used, which the audit log already does."""
    _, secret = await _human()
    registration = await _register(client)
    _, challenge = pkce_pair()

    page = await client.get("/authorize", params={
        "response_type": "code", "client_id": registration["client_id"],
        "redirect_uri": registration["redirect_uris"][0],
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    mac = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/126.0 Safari/537.36"}
    login = await client.post(
        "/authorize",
        data={"request_id": _extract_request_id(page.text), "username": USERNAME,
              "password": PASSWORD, "totp_code": pyotp.TOTP(secret).now()},
        headers=mac,
    )
    await _through_consent(client, login, headers=mac)  # first auth: sets first_seen = Mac

    # Same connector, authorized again from a phone — now a bound client, so the
    # consent step auto-completes; first_seen must NOT be rewritten.
    _, challenge2 = pkce_pair("another-verifier-long-enough-0123456789-abcdef")
    reauth = await client.get("/authorize", params={
        "response_type": "code", "client_id": registration["client_id"],
        "redirect_uri": registration["redirect_uris"][0],
        "code_challenge": challenge2, "code_challenge_method": "S256",
    }, headers={"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1"})
    await _through_consent(client, reauth, headers={"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1"})

    pool = await db.pool()
    async with pool.acquire() as conn:
        agent = await conn.fetchval(
            "SELECT first_seen_user_agent FROM oauth_clients WHERE client_id = $1",
            registration["client_id"],
        )
    assert "Macintosh" in agent


# --- Q26: authorize consent (the #58 critical) -----------------------------


async def _login_ui(http, secret):
    """Establish a logged-in /ui session on the given client."""
    r = await http.post(
        "/ui/login",
        data={"username": USERNAME, "password": PASSWORD,
              "totp_code": pyotp.TOTP(secret).now() if secret else ""},
    )
    assert r.status_code in (302, 303), r.text
    return r


async def _authorize_get(http, registration, challenge, **extra):
    params = {
        "response_type": "code", "client_id": registration["client_id"],
        "redirect_uri": registration["redirect_uris"][0],
        "code_challenge": challenge, "code_challenge_method": "S256",
        "state": "s", "scope": "mcp",
    }
    params.update(extra)
    return await http.get("/authorize", params=params)


def _no_code_to(resp, redirect_uri) -> bool:
    """True if the response did NOT hand a code to the client — the invariant
    every negative consent test asserts."""
    loc = resp.headers.get("location", "")
    return not (loc.startswith(redirect_uri) and "code=" in loc)


async def test_new_client_gets_consent_not_a_silent_code(client):
    """THE fix (#58/Q26): a logged-in session hitting /authorize for a client it
    has not approved gets the consent screen, never a silent code."""
    _, secret = await _human()
    await _login_ui(client, secret)
    reg = await _register(client)
    _, challenge = pkce_pair()

    r = await _authorize_get(client, reg, challenge)
    assert r.status_code == 302
    assert r.headers["location"].startswith("/authorize/consent")  # not the client
    assert _no_code_to(r, reg["redirect_uris"][0])

    page = await client.get(r.headers["location"])
    assert page.status_code == 200
    assert "Approve" in page.text and "Deny" in page.text
    assert "claude.ai" in page.text  # redirect host shown so an attacker's stands out


async def test_consent_approve_issues_the_code(client):
    _, secret = await _human()
    await _login_ui(client, secret)
    reg = await _register(client)
    _, challenge = pkce_pair()
    page = await client.get((await _authorize_get(client, reg, challenge)).headers["location"])
    approved = await client.post("/authorize/consent", data={
        "request_id": _extract_request_id(page.text),
        "csrf": _extract_field(page.text, "csrf"),
        "decision": "approve",
    })
    assert approved.status_code == 302
    assert approved.headers["location"].startswith(reg["redirect_uris"][0])
    assert "code=" in approved.headers["location"]


async def test_consent_without_the_session_token_is_refused(client):
    """The cross-site forge: an Approve POST that doesn't carry the flow's
    session-bound token issues no code."""
    _, secret = await _human()
    await _login_ui(client, secret)
    reg = await _register(client)
    _, challenge = pkce_pair()
    page = await client.get((await _authorize_get(client, reg, challenge)).headers["location"])
    refused = await client.post("/authorize/consent", data={
        "request_id": _extract_request_id(page.text),
        "csrf": "forged-token",
        "decision": "approve",
    })
    assert _no_code_to(refused, reg["redirect_uris"][0])


async def test_already_approved_client_skips_consent(client):
    """A returning connector (bound to you) authorizes with no prompt."""
    _, secret = await _human()
    reg = await _register(client)
    _, challenge = pkce_pair()
    first = await _authorize_and_login(
        client, reg["client_id"], reg["redirect_uris"][0], challenge, secret
    )
    assert first.headers["location"].startswith(reg["redirect_uris"][0])  # bound now

    _, challenge2 = pkce_pair("second-verifier-abcdefghijklmnopqrstuvwxyz-012345")
    r = await _authorize_get(client, reg, challenge2)
    assert r.status_code == 302 and r.headers["location"].startswith("/authorize/consent")
    consent = await client.get(r.headers["location"])
    # Bound: the consent GET itself completes with a code — no screen shown.
    assert consent.status_code == 302
    assert consent.headers["location"].startswith(reg["redirect_uris"][0])
    assert "code=" in consent.headers["location"]


async def test_deny_returns_access_denied_and_no_code(client):
    _, secret = await _human()
    await _login_ui(client, secret)
    reg = await _register(client)
    _, challenge = pkce_pair()
    page = await client.get((await _authorize_get(client, reg, challenge)).headers["location"])
    denied = await client.post("/authorize/consent", data={
        "request_id": _extract_request_id(page.text),
        "csrf": _extract_field(page.text, "csrf"),
        "decision": "deny",
    })
    assert denied.status_code == 302
    loc = denied.headers["location"]
    assert loc.startswith(reg["redirect_uris"][0])
    assert "error=access_denied" in loc and "code=" not in loc


async def test_a_request_id_cannot_be_completed_by_another_session(client):
    """C1a: a flow started in one browser cannot be finished in another — the
    per-flow nonce lives only in the creating session's cookie."""
    _, secret = await _human()
    reg = await _register(client)
    _, challenge = pkce_pair()

    attacker = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_module.app),
        base_url="https://torii.test", follow_redirects=False,
    )
    try:
        page = await attacker.get("/authorize", params={
            "response_type": "code", "client_id": reg["client_id"],
            "redirect_uri": reg["redirect_uris"][0],
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        request_id = _extract_request_id(page.text)
    finally:
        await attacker.aclose()

    # The victim (logged in, different session) tries to complete the attacker's
    # request_id — their cookie holds no nonce for it.
    await _login_ui(client, secret)
    refused_get = await client.get(f"/authorize/consent?request_id={request_id}")
    assert _no_code_to(refused_get, reg["redirect_uris"][0])
    forced = await client.post("/authorize/consent", data={
        "request_id": request_id, "csrf": "anything", "decision": "approve",
    })
    assert _no_code_to(forced, reg["redirect_uris"][0])

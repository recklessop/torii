"""Passkey login through the whole ASGI app (PRD Q25).

The contract under test: a passkey login mints the SAME session as the
password path — including the gates. If any of these go green while a gate
test goes red, the passkey path has become a bypass.
"""

import base64
import hashlib
import json

import httpx
import pytest
import pytest_asyncio

from torii import app as app_module
from torii import cache, config, credentials, db

from webauthn_device import FakeAuthenticator

USERNAME = "alice"
PASSWORD = "correct-horse-battery"
ORIGIN = "https://torii.test"
RP_ID = "torii.test"


@pytest.fixture
async def client(oauth_database, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL", oauth_database)
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", ORIGIN)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "")
    db._pool = None
    cache._client = None

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """TRUNCATE audit_calls, audit_auth_events, tokens, grants, api_keys,
                        auth_identities, oauth_clients, upstreams, group_members,
                        groups, principals
                        RESTART IDENTITY CASCADE"""
        )
        keys = [k async for k in cache.client().scan_iter("torii:*")]
        if keys:
            await cache.client().delete(*keys)

    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as http:
        yield http

    await db.close()
    await cache.close()


async def _seed_human(*, temp=False, totp_required=False, totp_secret=None):
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            """INSERT INTO principals (kind, username, totp_required)
               VALUES ('human', $1, $2) RETURNING id""",
            USERNAME, totp_required,
        )
        await conn.execute(
            """INSERT INTO auth_identities
                   (principal_id, backend, password_hash, password_is_temp, totp_secret)
               VALUES ($1, 'local', $2, $3, $4)""",
            principal_id, credentials.hash_password(PASSWORD), temp, totp_secret,
        )
    return str(principal_id)


async def _enroll_directly(principal_id, name="MacBook"):
    """Enroll a passkey straight at the database — most flow tests need a
    registered credential, not the registration ceremony."""
    device = FakeAuthenticator(rp_id=RP_ID)
    pool = await db.pool()
    async with pool.acquire() as conn:
        challenge = await credentials.start_passkey_registration(
            conn, principal_id, USERNAME
        )
        await credentials.register_passkey(
            conn, principal_id, name,
            json.dumps(device.create(challenge.options_json, ORIGIN)),
            challenge.challenge,
        )
    return device


async def _passkey_login(client, device, request_id=None, **get_kwargs):
    start = await client.post("/ui/webauthn/login/options.json")
    assert start.status_code == 200, start.text
    payload = start.json()
    assertion = device.get(json.dumps(payload["options"]), ORIGIN, **get_kwargs)
    body = {"ref": payload["ref"], "credential": assertion}
    if request_id:
        body["request_id"] = request_id
    return await client.post("/ui/webauthn/login/verify.json", json=body)


# --- login -----------------------------------------------------------------


async def test_passkey_login_mints_a_working_session(client):
    principal_id = await _seed_human()
    device = await _enroll_directly(principal_id)
    response = await _passkey_login(client, device)
    assert response.status_code == 200, response.text
    assert response.json()["redirect"] == "/ui"
    page = await client.get("/ui", follow_redirects=False)
    assert page.status_code == 200
    assert USERNAME in page.text


async def test_a_wrong_signature_is_a_401_with_no_session(client):
    principal_id = await _seed_human()
    await _enroll_directly(principal_id)
    stranger = FakeAuthenticator(rp_id=RP_ID)
    response = await _passkey_login(client, stranger)
    assert response.status_code == 401
    page = await client.get("/ui", follow_redirects=False)
    assert page.status_code == 302


async def test_a_challenge_ref_is_single_use(client):
    principal_id = await _seed_human()
    device = await _enroll_directly(principal_id)
    start = await client.post("/ui/webauthn/login/options.json")
    payload = start.json()
    assertion = device.get(json.dumps(payload["options"]), ORIGIN)
    body = {"ref": payload["ref"], "credential": assertion}
    first = await client.post("/ui/webauthn/login/verify.json", json=body)
    assert first.status_code == 200
    replay = await client.post("/ui/webauthn/login/verify.json", json=body)
    assert replay.status_code == 401


async def test_a_disabled_account_reads_differently_but_mints_nothing(client):
    principal_id = await _seed_human()
    device = await _enroll_directly(principal_id)
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE principals SET disabled_at = now() WHERE id = $1::uuid", principal_id
        )
    response = await _passkey_login(client, device)
    assert response.status_code == 401
    assert "disabled" in response.json()["error"]


async def test_malformed_body_is_a_400(client):
    response = await client.post(
        "/ui/webauthn/login/verify.json", json={"ref": "x"}
    )
    assert response.status_code == 400


# --- the gates cannot be bypassed ------------------------------------------


async def test_passkey_login_cannot_skip_the_password_change_gate(client):
    principal_id = await _seed_human(temp=True)
    device = await _enroll_directly(principal_id)
    response = await _passkey_login(client, device)
    assert response.status_code == 200
    assert response.json()["redirect"] == "/ui/change_password"
    # The session is mid-gate: NOT logged in.
    page = await client.get("/ui", follow_redirects=False)
    assert page.status_code == 302
    assert page.headers["location"] == "/ui/change_password"


async def test_passkey_login_honours_the_totp_enrollment_gate(client):
    # The lost-authenticator scenario: policy says TOTP, secret is gone.
    principal_id = await _seed_human(totp_required=True, totp_secret=None)
    device = await _enroll_directly(principal_id)
    response = await _passkey_login(client, device)
    assert response.status_code == 200
    assert response.json()["redirect"] == "/ui/enroll_totp"
    page = await client.get("/ui", follow_redirects=False)
    assert page.status_code == 302
    assert page.headers["location"] == "/ui/enroll_totp"


async def test_enrollment_requires_a_full_session(client):
    response = await client.post("/ui/webauthn/register/options.json")
    assert response.status_code == 401


async def test_a_mid_gate_session_cannot_enroll_a_passkey(client):
    principal_id = await _seed_human(temp=True)
    device = await _enroll_directly(principal_id)
    login = await _passkey_login(client, device)
    assert login.json()["redirect"] == "/ui/change_password"
    response = await client.post("/ui/webauthn/register/options.json")
    assert response.status_code == 401


# --- OAuth continuity ------------------------------------------------------


async def test_a_pending_oauth_authorize_completes_via_passkey(client):
    principal_id = await _seed_human()
    device = await _enroll_directly(principal_id)

    redirect_uri = "https://claude.ai/api/mcp/auth_callback"
    registered = await client.post(
        "/oauth/register",
        json={"client_name": "claude.ai", "redirect_uris": [redirect_uri]},
    )
    client_id = registered.json()["client_id"]
    verifier = "v" * 64
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    page = await client.get(
        "/authorize",
        params={
            "response_type": "code", "client_id": client_id,
            "redirect_uri": redirect_uri, "code_challenge": code_challenge,
            "code_challenge_method": "S256", "state": "s", "scope": "mcp",
        },
    )
    assert page.status_code == 200
    marker = 'name="request_id" value="'
    start = page.text.index(marker) + len(marker)
    request_id = page.text[start:page.text.index('"', start)]
    # The login page offers the passkey button on the authorize surface too.
    assert 'id="passkey-signin"' in page.text

    response = await _passkey_login(client, device, request_id=request_id)
    assert response.status_code == 200, response.text
    consent_url = response.json()["redirect"]
    # A passkey login lands on the Q26 consent step, not straight on a code.
    assert consent_url.startswith("/authorize/consent")

    consent = await client.get(consent_url)
    assert consent.status_code == 200

    def _field(name):
        marker = f'name="{name}" value="'
        s = consent.text.index(marker) + len(marker)
        return consent.text[s:consent.text.index('"', s)]

    approved = await client.post(
        "/authorize/consent",
        data={"request_id": _field("request_id"), "csrf": _field("csrf"), "decision": "approve"},
    )
    assert approved.status_code == 302
    location = approved.headers["location"]
    assert location.startswith(redirect_uri)

    code = dict(
        part.split("=", 1) for part in location.split("?", 1)[1].split("&")
    )["code"]
    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": redirect_uri, "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    assert token.json()["access_token"]


# --- audit -----------------------------------------------------------------


async def test_login_success_and_failure_are_audited(client):
    principal_id = await _seed_human()
    device = await _enroll_directly(principal_id)
    await _passkey_login(client, device)
    await _passkey_login(client, FakeAuthenticator(rp_id=RP_ID))

    pool = await db.pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT event, outcome, detail FROM audit_auth_events
                WHERE detail->>'method' = 'passkey' ORDER BY ts"""
        )
    assert [r["event"] for r in rows] == ["login_success", "login_failure"]
    assert json.loads(rows[1]["detail"])["reason"] == "unknown_credential"


# --- lifecycle -------------------------------------------------------------


async def _password_sign_in(client):
    return await client.post(
        "/ui/login",
        data={"username": USERNAME, "password": PASSWORD, "totp_code": ""},
        follow_redirects=False,
    )


async def test_enroll_name_remove_lifecycle(client):
    principal_id = await _seed_human()
    await _password_sign_in(client)

    # Enroll through the real ceremony endpoints.
    device = FakeAuthenticator(rp_id=RP_ID)
    start = await client.post("/ui/webauthn/register/options.json")
    assert start.status_code == 200, start.text
    options = start.json()["options"]
    credential = device.create(json.dumps(options), ORIGIN)
    verify = await client.post(
        "/ui/webauthn/register/verify.json",
        json={"name": "MacBook Touch ID", "credential": credential},
    )
    assert verify.status_code == 200, verify.text
    assert verify.json()["name"] == "MacBook Touch ID"

    account = await client.get("/ui/account")
    assert "MacBook Touch ID" in account.text

    # A second verify with the same (consumed) challenge is refused.
    replay = await client.post(
        "/ui/webauthn/register/verify.json",
        json={"name": "again", "credential": credential},
    )
    assert replay.status_code == 401

    pool = await db.pool()
    async with pool.acquire() as conn:
        cred_id = await conn.fetchval(
            "SELECT id FROM webauthn_credentials WHERE principal_id = $1::uuid",
            principal_id,
        )
        events = await conn.fetch(
            "SELECT event FROM audit_auth_events WHERE event = 'passkey_enrolled'"
        )
    assert len(events) == 1

    removed = await client.post(
        f"/ui/account/webauthn/{cred_id}/delete", follow_redirects=False
    )
    assert removed.status_code == 303

    # The passkey no longer signs in.
    login = await _passkey_login(client, device)
    assert login.status_code == 401
    async with pool.acquire() as conn:
        revoked = await conn.fetch(
            "SELECT detail FROM audit_auth_events WHERE event = 'passkey_revoked'"
        )
    assert len(revoked) == 1
    assert json.loads(revoked[0]["detail"])["via"] == "self"


async def test_a_user_cannot_delete_someone_elses_passkey(client):
    alice = await _seed_human()
    device = await _enroll_directly(alice)
    pool = await db.pool()
    async with pool.acquire() as conn:
        cred_id = await conn.fetchval(
            "SELECT id FROM webauthn_credentials WHERE principal_id = $1::uuid", alice
        )
        await conn.execute(
            """INSERT INTO principals (kind, username) VALUES ('human', 'mallory')"""
        )
        await conn.execute(
            """INSERT INTO auth_identities (principal_id, backend, password_hash)
               SELECT id, 'local', $1 FROM principals WHERE username = 'mallory'""",
            credentials.hash_password(PASSWORD),
        )
    await client.post(
        "/ui/login",
        data={"username": "mallory", "password": PASSWORD, "totp_code": ""},
        follow_redirects=False,
    )
    response = await client.post(
        f"/ui/account/webauthn/{cred_id}/delete", follow_redirects=False
    )
    assert response.status_code == 403
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM webauthn_credentials WHERE id = $1", cred_id
        ) == 1


async def test_admin_revokes_and_non_admin_cannot(client):
    import pyotp

    alice = await _seed_human()
    await _enroll_directly(alice)
    pool = await db.pool()
    async with pool.acquire() as conn:
        cred_id = await conn.fetchval(
            "SELECT id FROM webauthn_credentials WHERE principal_id = $1::uuid", alice
        )

    # alice is not an admin: the admin route refuses her.
    await _password_sign_in(client)
    refused = await client.post(
        f"/ui/admin/principals/{alice}/webauthn/{cred_id}/revoke",
        follow_redirects=False,
    )
    assert refused.status_code in (302, 403)
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM webauthn_credentials WHERE id = $1", cred_id
        ) == 1

    # A real admin (TOTP enrolled, as the schema demands) can.
    secret = credentials.generate_totp_secret()
    async with pool.acquire() as conn:
        admin_id = await conn.fetchval(
            """INSERT INTO principals (kind, username, is_admin, totp_required)
               VALUES ('human', 'boss', TRUE, TRUE) RETURNING id"""
        )
        await conn.execute(
            """INSERT INTO auth_identities
                   (principal_id, backend, password_hash, totp_secret, totp_enrolled_at)
               VALUES ($1, 'local', $2, $3, now())""",
            admin_id, credentials.hash_password(PASSWORD), secret,
        )
    await client.post(
        "/ui/login",
        data={"username": "boss", "password": PASSWORD,
              "totp_code": pyotp.TOTP(secret).now()},
        follow_redirects=False,
    )
    revoked = await client.post(
        f"/ui/admin/principals/{alice}/webauthn/{cred_id}/revoke",
        follow_redirects=False,
    )
    assert revoked.status_code == 303
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM webauthn_credentials WHERE id = $1", cred_id
        ) == 0
        detail = await conn.fetchval(
            "SELECT detail FROM audit_auth_events WHERE event = 'passkey_revoked'"
        )
    assert json.loads(detail)["via"] == "admin"


async def test_the_account_page_lists_passkeys_and_offers_enrollment(client):
    principal_id = await _seed_human()
    await _enroll_directly(principal_id, name="my key")
    await _password_sign_in(client)
    page = await client.get("/ui/account")
    assert page.status_code == 200
    assert "my key" in page.text
    assert 'id="passkey-enroll"' in page.text


async def test_the_login_page_offers_the_passkey_button(client):
    page = await client.get("/ui/login")
    assert 'id="passkey-signin"' in page.text
    assert "isSecureContext" in page.text
    assert "navigator.credentials" in page.text

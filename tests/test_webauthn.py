"""Passkey helpers and ceremonies (PRD Q25). Negative cases outnumber
positive ones on purpose — this is a login path."""

import json

import asyncpg
import pytest

from torii import config, credentials

from webauthn_device import FakeAuthenticator

ORIGIN = "https://torii.test"
RP_ID = "torii.test"


@pytest.fixture(autouse=True)
def _test_origin(monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", ORIGIN)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "")


# --- pure helpers ----------------------------------------------------------


def test_rp_id_derives_from_public_base_url(monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://torii.example.com:8443")
    assert credentials.webauthn_rp_id() == "torii.example.com"


def test_rp_id_override_wins(monkeypatch):
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "example.com")
    assert credentials.webauthn_rp_id() == "example.com"


def test_origin_keeps_scheme_and_port(monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://torii.example.com:8443")
    assert credentials.webauthn_origin() == "https://torii.example.com:8443"


def test_login_options_are_usernameless_and_require_uv():
    challenge = credentials.start_passkey_login()
    options = json.loads(challenge.options_json)
    assert options["userVerification"] == "required"
    assert options.get("allowCredentials", []) == []
    assert challenge.challenge


# --- seeding ---------------------------------------------------------------


async def _human(conn, username="alice", *, kind="human", totp_required=False,
                 totp_secret=None, password_is_temp=False, disabled=False):
    principal_id = await conn.fetchval(
        """INSERT INTO principals (kind, username, totp_required, disabled_at)
           VALUES ($1, $2, $3, CASE WHEN $4 THEN now() END) RETURNING id""",
        kind, username, totp_required, disabled,
    )
    if kind == "human":
        await conn.execute(
            """INSERT INTO auth_identities
                   (principal_id, backend, password_hash, password_is_temp, totp_secret)
               VALUES ($1, 'local', $2, $3, $4)""",
            principal_id, credentials.hash_password("a-long-enough-password"),
            password_is_temp, totp_secret,
        )
    return principal_id


async def _enroll(conn, principal_id, username="alice", device=None, name="test key"):
    device = device or FakeAuthenticator(rp_id=RP_ID)
    challenge = await credentials.start_passkey_registration(conn, principal_id, username)
    created = await credentials.register_passkey(
        conn, principal_id, name,
        json.dumps(device.create(challenge.options_json, ORIGIN)),
        challenge.challenge,
    )
    return device, created


async def _login(conn, device, **get_kwargs):
    challenge = credentials.start_passkey_login()
    assertion = device.get(challenge.options_json, ORIGIN, **get_kwargs)
    return await credentials.authenticate_passkey(
        conn, json.dumps(assertion), challenge.challenge
    )


# --- registration ----------------------------------------------------------


async def test_register_then_authenticate_round_trip(conn):
    principal_id = await _human(conn)
    device, created = await _enroll(conn, principal_id)
    assert created["name"] == "test key"

    row = await conn.fetchrow(
        "SELECT credential_id, public_key FROM webauthn_credentials WHERE principal_id = $1",
        principal_id,
    )
    assert row["credential_id"] == device.credential_id

    outcome = await _login(conn, device)
    assert outcome.ok and outcome.reason == credentials.PASSKEY_OK
    assert outcome.principal_id == str(principal_id)
    assert outcome.username == "alice"


async def test_registration_options_require_uv_and_resident_key(conn):
    principal_id = await _human(conn)
    challenge = await credentials.start_passkey_registration(conn, principal_id, "alice")
    options = json.loads(challenge.options_json)
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["authenticatorSelection"]["residentKey"] == "required"


async def test_registration_excludes_existing_credentials(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    challenge = await credentials.start_passkey_registration(conn, principal_id, "alice")
    options = json.loads(challenge.options_json)
    from webauthn.helpers import base64url_to_bytes
    excluded = [base64url_to_bytes(c["id"]) for c in options.get("excludeCredentials", [])]
    assert device.credential_id in excluded


async def test_registration_with_wrong_origin_is_refused(conn):
    principal_id = await _human(conn)
    device = FakeAuthenticator(rp_id=RP_ID)
    challenge = await credentials.start_passkey_registration(conn, principal_id, "alice")
    credential = device.create(challenge.options_json, "https://evil.test")
    with pytest.raises(credentials.CredentialError):
        await credentials.register_passkey(
            conn, principal_id, "x", json.dumps(credential), challenge.challenge
        )


async def test_registration_with_wrong_rp_id_is_refused(conn):
    principal_id = await _human(conn)
    device = FakeAuthenticator(rp_id=RP_ID)
    challenge = await credentials.start_passkey_registration(conn, principal_id, "alice")
    credential = device.create(challenge.options_json, ORIGIN, rp_id="evil.test")
    with pytest.raises(credentials.CredentialError):
        await credentials.register_passkey(
            conn, principal_id, "x", json.dumps(credential), challenge.challenge
        )


async def test_registration_without_uv_is_refused(conn):
    principal_id = await _human(conn)
    device = FakeAuthenticator(rp_id=RP_ID)
    challenge = await credentials.start_passkey_registration(conn, principal_id, "alice")
    credential = device.create(challenge.options_json, ORIGIN, uv=False)
    with pytest.raises(credentials.CredentialError):
        await credentials.register_passkey(
            conn, principal_id, "x", json.dumps(credential), challenge.challenge
        )


async def test_registration_with_stale_challenge_is_refused(conn):
    principal_id = await _human(conn)
    device = FakeAuthenticator(rp_id=RP_ID)
    challenge = await credentials.start_passkey_registration(conn, principal_id, "alice")
    credential = device.create(challenge.options_json, ORIGIN)
    with pytest.raises(credentials.CredentialError):
        await credentials.register_passkey(
            conn, principal_id, "x", json.dumps(credential), b"not-that-challenge"
        )


# --- assertion -------------------------------------------------------------


async def test_sign_count_zero_apple_style_logs_in_repeatedly(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    for _ in range(3):
        outcome = await _login(conn, device, sign_count=0)
        assert outcome.ok


async def test_sign_count_advances_and_is_stored(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    assert (await _login(conn, device, sign_count=7)).ok
    stored = await conn.fetchval(
        "SELECT sign_count FROM webauthn_credentials WHERE principal_id = $1", principal_id
    )
    assert stored == 7


async def test_sign_count_regression_is_refused(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    assert (await _login(conn, device, sign_count=10)).ok
    outcome = await _login(conn, device, sign_count=5)
    assert not outcome.ok and outcome.reason == credentials.BAD_PASSKEY


async def test_assertion_with_wrong_challenge_is_refused(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    challenge = credentials.start_passkey_login()
    from webauthn.helpers import bytes_to_base64url
    assertion = device.get(
        challenge.options_json, ORIGIN,
        challenge=bytes_to_base64url(b"a-challenge-nobody-issued"),
    )
    outcome = await credentials.authenticate_passkey(
        conn, json.dumps(assertion), challenge.challenge
    )
    assert not outcome.ok and outcome.reason == credentials.BAD_PASSKEY


async def test_assertion_with_wrong_origin_is_refused(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    outcome = await _login(conn, device)  # sanity
    assert outcome.ok
    challenge = credentials.start_passkey_login()
    assertion = device.get(challenge.options_json, "https://evil.test")
    outcome = await credentials.authenticate_passkey(
        conn, json.dumps(assertion), challenge.challenge
    )
    assert not outcome.ok and outcome.reason == credentials.BAD_PASSKEY


async def test_assertion_without_uv_is_refused(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    outcome = await _login(conn, device, uv=False)
    assert not outcome.ok and outcome.reason == credentials.BAD_PASSKEY


async def test_unknown_credential_is_refused(conn):
    device = FakeAuthenticator(rp_id=RP_ID)  # never registered
    outcome = await _login(conn, device)
    assert not outcome.ok and outcome.reason == credentials.UNKNOWN_CREDENTIAL


async def test_malformed_credential_json_is_refused(conn):
    outcome = await credentials.authenticate_passkey(conn, "{not json", b"whatever")
    assert not outcome.ok and outcome.reason == credentials.BAD_PASSKEY


async def test_disabled_principal_is_refused_at_assertion_time(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    await conn.execute("UPDATE principals SET disabled_at = now() WHERE id = $1", principal_id)
    outcome = await _login(conn, device)
    assert not outcome.ok and outcome.reason == credentials.PASSKEY_DISABLED
    assert await conn.fetchval(
        "SELECT last_used_at FROM webauthn_credentials WHERE principal_id = $1", principal_id
    ) is None


async def test_cross_user_signature_is_refused(conn):
    alice = await _human(conn, "alice")
    bob = await _human(conn, "bob")
    alice_device, _ = await _enroll(conn, alice, "alice")
    bob_device, _ = await _enroll(conn, bob, "bob")
    # Present alice's credential id, signed with bob's key.
    challenge = credentials.start_passkey_login()
    assertion = alice_device.get(challenge.options_json, ORIGIN, signer=bob_device)
    outcome = await credentials.authenticate_passkey(
        conn, json.dumps(assertion), challenge.challenge
    )
    assert not outcome.ok and outcome.reason == credentials.BAD_PASSKEY


async def test_failed_assertion_does_not_touch_password_lockout(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    await conn.execute(
        "UPDATE auth_identities SET failed_attempts = 3 WHERE principal_id = $1",
        principal_id,
    )
    await _login(conn, device, uv=False)
    assert await conn.fetchval(
        "SELECT failed_attempts FROM auth_identities WHERE principal_id = $1", principal_id
    ) == 3


# --- gate flags ------------------------------------------------------------


async def test_temp_password_surfaces_must_change_password(conn):
    principal_id = await _human(conn, password_is_temp=True)
    device, _ = await _enroll(conn, principal_id)
    outcome = await _login(conn, device)
    assert outcome.ok and outcome.must_change_password


async def test_totp_required_but_unenrolled_surfaces_needs_totp_enrollment(conn):
    # The admin-resets-a-lost-authenticator scenario: policy says TOTP, the
    # secret is gone, and the passkey must not become the way around it.
    principal_id = await _human(conn, totp_required=True, totp_secret=None)
    device, _ = await _enroll(conn, principal_id)
    outcome = await _login(conn, device)
    assert outcome.ok and outcome.needs_totp_enrollment


async def test_totp_enrolled_user_gets_no_gate(conn):
    principal_id = await _human(conn, totp_required=True, totp_secret="ABCDEFGHIJKLMNOP")
    device, _ = await _enroll(conn, principal_id)
    outcome = await _login(conn, device)
    assert outcome.ok and not outcome.needs_totp_enrollment


# --- schema ----------------------------------------------------------------


async def test_a_service_principal_cannot_own_a_passkey(conn):
    service_id = await _human(conn, "bot", kind="service")
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with conn.transaction():
            await conn.execute(
                """INSERT INTO webauthn_credentials
                       (principal_id, credential_id, public_key, name)
                   VALUES ($1, $2, $3, 'x')""",
                service_id, b"cred", b"key",
            )


async def test_duplicate_credential_id_is_refused(conn):
    principal_id = await _human(conn)
    device, _ = await _enroll(conn, principal_id)
    challenge = await credentials.start_passkey_registration(conn, principal_id, "alice")
    with pytest.raises(credentials.CredentialError):
        await credentials.register_passkey(
            conn, principal_id, "again",
            json.dumps(device.create(challenge.options_json, ORIGIN)),
            challenge.challenge,
        )


async def test_a_blank_name_is_refused_by_schema(conn):
    principal_id = await _human(conn)
    with pytest.raises(asyncpg.CheckViolationError):
        async with conn.transaction():
            await conn.execute(
                """INSERT INTO webauthn_credentials
                       (principal_id, credential_id, public_key, name)
                   VALUES ($1, $2, $3, '   ')""",
                principal_id, b"cred", b"key",
            )


async def test_deleting_the_principal_deletes_their_passkeys(conn):
    principal_id = await _human(conn)
    await _enroll(conn, principal_id)
    await conn.execute("DELETE FROM principals WHERE id = $1", principal_id)
    assert await conn.fetchval(
        "SELECT count(*) FROM webauthn_credentials WHERE principal_id = $1", principal_id
    ) == 0

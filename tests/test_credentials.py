"""Credential minting, verification, rotation, and revocation."""

import pytest

from torii import config, credentials, rbac


async def _principal(conn, username="alice", kind="human"):
    return await conn.fetchval(
        "INSERT INTO principals (kind, username) VALUES ($1, $2) RETURNING id",
        kind,
        username,
    )


async def _client(conn, principal_id, client_id="cl_phone"):
    return await conn.fetchval(
        """INSERT INTO oauth_clients (client_id, client_name, principal_id)
           VALUES ($1, 'claude.ai', $2) RETURNING client_id""",
        client_id,
        principal_id,
    )


# --- passwords -------------------------------------------------------------


def test_password_roundtrip():
    hashed = credentials.hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert credentials.verify_password("correct horse battery staple", hashed)
    assert not credentials.verify_password("wrong", hashed)


def test_password_hashes_are_salted():
    assert credentials.hash_password("same") != credentials.hash_password("same")


def test_overlong_password_is_refused_not_truncated():
    """bcrypt ignores bytes past 72. Truncating silently would let two
    different passwords open the same account."""
    with pytest.raises(credentials.PasswordTooLong):
        credentials.hash_password("x" * 73)


def test_verify_is_safe_against_junk():
    assert not credentials.verify_password("", "")
    assert not credentials.verify_password("x", "not-a-bcrypt-hash")


def test_temp_passwords_are_unpredictable():
    passwords = {credentials.generate_temp_password() for _ in range(50)}
    assert len(passwords) == 50
    assert all(len(p) >= 12 for p in passwords)


# --- TOTP ------------------------------------------------------------------


def test_totp_verifies_current_code():
    import pyotp

    secret = credentials.generate_totp_secret()
    assert credentials.verify_totp(secret, pyotp.TOTP(secret).now())
    assert not credentials.verify_totp(secret, "000000")
    assert not credentials.verify_totp(secret, "")


def test_totp_accepts_a_code_with_spaces():
    import pyotp

    secret = credentials.generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert credentials.verify_totp(secret, f"{code[:3]} {code[3:]}")


def test_totp_provisioning_uri_is_scannable():
    uri = credentials.totp_provisioning_uri("JBSWY3DPEHPK3PXP", "alice")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=torii" in uri


# --- static keys -----------------------------------------------------------


async def test_minted_key_is_prefixed_hashed_and_returned_once(conn):
    principal_id = await _principal(conn)
    key = await credentials.mint_api_key(conn, principal_id, "laptop")

    assert key.secret.startswith("tor_")
    assert key.key_prefix == key.secret[: credentials.DISPLAY_PREFIX_LENGTH]

    stored = await conn.fetchrow("SELECT key_hash FROM api_keys WHERE id = $1", key.id)
    assert stored["key_hash"] == credentials.hash_secret(key.secret)
    assert key.secret not in stored["key_hash"]


async def test_key_authenticates_its_principal(conn):
    principal_id = await _principal(conn, "acme-prod", kind="service")
    key = await credentials.mint_api_key(conn, principal_id, "acme")

    caller = await credentials.authenticate_api_key(conn, key.secret)
    assert isinstance(caller, rbac.Caller)
    assert caller.principal_id == str(principal_id)
    assert caller.kind == "service"
    assert caller.api_key_id == key.id
    # A key carries no OAuth client, so it can never be client-narrowed.
    assert caller.client_id is None


async def test_key_use_is_recorded(conn):
    principal_id = await _principal(conn)
    key = await credentials.mint_api_key(conn, principal_id, "laptop")
    assert await conn.fetchval("SELECT last_used_at FROM api_keys WHERE id = $1", key.id) is None
    await credentials.authenticate_api_key(conn, key.secret)
    assert await conn.fetchval("SELECT last_used_at FROM api_keys WHERE id = $1", key.id)


@pytest.mark.parametrize(
    "presented", ["", "nope", "xyz_someotherservicekey", "tor_wrong", None]
)
async def test_bad_keys_authenticate_nothing(conn, presented):
    await _principal(conn)
    assert await credentials.authenticate_api_key(conn, presented) is None


async def test_revoked_key_stops_working(conn):
    principal_id = await _principal(conn)
    key = await credentials.mint_api_key(conn, principal_id, "laptop")
    assert await credentials.authenticate_api_key(conn, key.secret)

    assert await credentials.revoke_api_key(conn, key.id) is True
    assert await credentials.authenticate_api_key(conn, key.secret) is None
    # Revoking twice is not an error, but reports nothing changed.
    assert await credentials.revoke_api_key(conn, key.id) is False


async def test_key_of_a_disabled_principal_stops_working(conn):
    principal_id = await _principal(conn)
    key = await credentials.mint_api_key(conn, principal_id, "laptop")
    await conn.execute("UPDATE principals SET disabled_at = now() WHERE id = $1", principal_id)
    assert await credentials.authenticate_api_key(conn, key.secret) is None


async def test_rotation_replaces_the_secret_and_keeps_the_chain(conn):
    principal_id = await _principal(conn)
    old = await credentials.mint_api_key(conn, principal_id, "laptop")
    new = await credentials.rotate_api_key(conn, old.id)

    assert new.secret != old.secret
    assert new.name == old.name
    assert await credentials.authenticate_api_key(conn, old.secret) is None
    assert await credentials.authenticate_api_key(conn, new.secret)
    assert str(await conn.fetchval(
        "SELECT rotated_from FROM api_keys WHERE id = $1", new.id
    )) == old.id
    assert await conn.fetchval(
        "SELECT revoked_reason FROM api_keys WHERE id = $1", old.id
    ) == "rotated"


# --- OAuth tokens ----------------------------------------------------------


async def test_issued_pair_authenticates_and_carries_the_client(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    pair = await credentials.issue_token_pair(conn, principal_id, client_id, scope="mcp")

    caller = await credentials.authenticate_access_token(conn, pair.access_token)
    assert caller.principal_id == str(principal_id)
    assert caller.client_id == client_id
    assert pair.expires_in == config.ACCESS_TOKEN_TTL
    assert pair.as_response("mcp")["token_type"] == "Bearer"


async def test_tokens_are_stored_hashed(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    pair = await credentials.issue_token_pair(conn, principal_id, client_id)

    hashes = [r["token_hash"] for r in await conn.fetch("SELECT token_hash FROM tokens")]
    assert pair.access_token not in hashes
    assert pair.refresh_token not in hashes
    assert credentials.hash_secret(pair.access_token) in hashes


async def test_a_refresh_token_is_not_an_access_token(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    pair = await credentials.issue_token_pair(conn, principal_id, client_id)
    assert await credentials.authenticate_access_token(conn, pair.refresh_token) is None


async def test_expired_access_token_is_rejected(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    pair = await credentials.issue_token_pair(conn, principal_id, client_id)
    await conn.execute(
        """UPDATE tokens SET expires_at = now() - interval '1 second'
            WHERE kind = 'access'"""
    )
    assert await credentials.authenticate_access_token(conn, pair.access_token) is None


async def test_rotation_issues_a_new_pair_and_kills_the_old(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    first = await credentials.issue_token_pair(conn, principal_id, client_id)

    second = await credentials.rotate_refresh_token(conn, first.refresh_token, client_id)

    assert second.refresh_token != first.refresh_token
    assert await credentials.authenticate_access_token(conn, second.access_token)
    # Old access token dies with the rotation, narrowing the window a stolen
    # refresh token buys.
    assert await credentials.authenticate_access_token(conn, first.access_token) is None


async def test_replaying_a_rotated_refresh_token_revokes_the_family(conn):
    """If the same refresh token arrives twice, one holder isn't legitimate
    and we can't tell which — so everything in the chain dies."""
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    first = await credentials.issue_token_pair(conn, principal_id, client_id)
    second = await credentials.rotate_refresh_token(conn, first.refresh_token, client_id)

    with pytest.raises(credentials.TokenReplayDetected):
        await credentials.rotate_refresh_token(conn, first.refresh_token, client_id)

    assert await credentials.authenticate_access_token(conn, second.access_token) is None
    live = await conn.fetchval("SELECT count(*) FROM tokens WHERE revoked_at IS NULL")
    assert live == 0


async def test_refresh_token_is_bound_to_its_client(conn):
    principal_id = await _principal(conn)
    mine = await _client(conn, principal_id, "cl_mine")
    other = await _client(conn, principal_id, "cl_other")
    pair = await credentials.issue_token_pair(conn, principal_id, mine)

    with pytest.raises(credentials.CredentialError):
        await credentials.rotate_refresh_token(conn, pair.refresh_token, other)


async def test_unknown_refresh_token_is_invalid_grant(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    with pytest.raises(credentials.CredentialError):
        await credentials.rotate_refresh_token(conn, "not-a-token", client_id)


async def test_expired_refresh_token_cannot_rotate(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    pair = await credentials.issue_token_pair(conn, principal_id, client_id)
    await conn.execute(
        """UPDATE tokens SET expires_at = now() - interval '1 second'
            WHERE kind = 'refresh'"""
    )
    with pytest.raises(credentials.CredentialError):
        await credentials.rotate_refresh_token(conn, pair.refresh_token, client_id)


async def test_revoking_one_token(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    pair = await credentials.issue_token_pair(conn, principal_id, client_id)

    assert await credentials.revoke_token(conn, pair.access_token) is True
    assert await credentials.authenticate_access_token(conn, pair.access_token) is None


async def test_revoking_a_client_kills_every_token_it_holds(conn):
    """Per-client revocation must be immediate and total (FR2)."""
    principal_id = await _principal(conn)
    phone = await _client(conn, principal_id, "cl_phone")
    desktop = await _client(conn, principal_id, "cl_desktop")
    on_phone = await credentials.issue_token_pair(conn, principal_id, phone)
    on_desktop = await credentials.issue_token_pair(conn, principal_id, desktop)

    assert await credentials.revoke_client_tokens(conn, phone) == 2
    assert await credentials.authenticate_access_token(conn, on_phone.access_token) is None
    # The other client is untouched.
    assert await credentials.authenticate_access_token(conn, on_desktop.access_token)


async def test_disabling_a_principal_can_kill_every_token(conn):
    principal_id = await _principal(conn)
    phone = await _client(conn, principal_id, "cl_phone")
    desktop = await _client(conn, principal_id, "cl_desktop")
    await credentials.issue_token_pair(conn, principal_id, phone)
    await credentials.issue_token_pair(conn, principal_id, desktop)

    assert await credentials.revoke_principal_tokens(conn, principal_id) == 4
    assert await conn.fetchval("SELECT count(*) FROM tokens WHERE revoked_at IS NULL") == 0

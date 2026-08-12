"""TOTP policy (PRD Q11): mandatory for admins, optional for everyone else.

The rule that matters most is the one that can't be turned off: an admin row
cannot exist without the requirement. That's a schema CHECK rather than a
code path, so no future handler can forget it.
"""

import asyncpg
import pyotp
import pytest
import pytest_asyncio

from torii import auth_backends, cache, credentials

LOCAL = auth_backends.LOCAL
PASSWORD = "a-real-long-password"


@pytest_asyncio.fixture(autouse=True)
async def _fresh_cache():
    """The TOTP replay guard (#74) lives in valkey, and the redis client is
    bound to the loop it was built in; pytest-asyncio gives each test its own.
    Reset the module reference so this test builds its own, and close it here."""
    cache._client = None
    yield
    await cache.close()


async def _human(conn, username, *, is_admin=False, totp_required=False, totp=False):
    principal_id = await conn.fetchval(
        """INSERT INTO principals (kind, username, is_admin, totp_required)
           VALUES ('human', $1, $2, $3) RETURNING id""",
        username,
        is_admin,
        totp_required or is_admin,
    )
    secret = credentials.generate_totp_secret() if totp else None
    await conn.execute(
        """INSERT INTO auth_identities
               (principal_id, backend, password_hash, totp_secret, totp_enrolled_at)
           VALUES ($1, 'local', $2, $3::text,
                   CASE WHEN $3::text IS NULL THEN NULL ELSE now() END)""",
        principal_id,
        credentials.hash_password(PASSWORD),
        secret,
    )
    return principal_id, secret


# --- the schema-level invariant -------------------------------------------


async def test_an_admin_cannot_exist_without_the_requirement(conn):
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO principals (kind, username, is_admin, totp_required)
               VALUES ('human', 'sneaky-admin', TRUE, FALSE)"""
        )


async def test_an_admin_cannot_have_the_requirement_removed(conn):
    principal_id, _ = await _human(conn, "boss", is_admin=True)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            "UPDATE principals SET totp_required = FALSE WHERE id = $1", principal_id
        )


async def test_promoting_a_user_to_admin_requires_raising_totp(conn):
    """Making someone an admin while leaving 2FA off must fail, not silently
    create an admin without an authenticator."""
    principal_id, _ = await _human(conn, "normal", totp_required=False)
    # Savepoint, so the rejected UPDATE doesn't abort the test transaction.
    with pytest.raises(asyncpg.CheckViolationError):
        async with conn.transaction():
            await conn.execute(
                "UPDATE principals SET is_admin = TRUE WHERE id = $1", principal_id
            )
    # Doing both at once is fine.
    await conn.execute(
        "UPDATE principals SET is_admin = TRUE, totp_required = TRUE WHERE id = $1",
        principal_id,
    )
    assert await conn.fetchval(
        "SELECT totp_required FROM principals WHERE id = $1", principal_id
    ) is True


async def test_normal_users_default_to_no_requirement(conn):
    principal_id = await conn.fetchval(
        "INSERT INTO principals (kind, username) VALUES ('human', 'casual') RETURNING id"
    )
    assert await conn.fetchval(
        "SELECT totp_required FROM principals WHERE id = $1", principal_id
    ) is False


# --- login behaviour -------------------------------------------------------


async def test_normal_user_without_requirement_signs_in_on_password_alone(conn):
    await _human(conn, "wife", totp_required=False)
    outcome = await LOCAL.authenticate(conn, "wife", password=PASSWORD)
    assert outcome.ok
    assert outcome.needs_totp_enrollment is False


async def test_normal_user_with_requirement_is_sent_to_enrollment(conn):
    await _human(conn, "kid", totp_required=True)
    outcome = await LOCAL.authenticate(conn, "kid", password=PASSWORD)
    assert outcome.ok
    assert outcome.needs_totp_enrollment is True


async def test_admin_is_always_sent_to_enrollment(conn):
    await _human(conn, "alice", is_admin=True)
    outcome = await LOCAL.authenticate(conn, "alice", password=PASSWORD)
    assert outcome.ok
    assert outcome.needs_totp_enrollment is True


async def test_an_enrolled_user_is_still_asked_for_a_code(conn):
    """Dropping the requirement must not silently downgrade someone who has
    a working authenticator."""
    principal_id, secret = await _human(conn, "enrolled", totp_required=True, totp=True)
    await conn.execute(
        "UPDATE principals SET totp_required = FALSE WHERE id = $1", principal_id
    )

    without_code = await LOCAL.authenticate(conn, "enrolled", password=PASSWORD)
    assert not without_code.ok
    assert without_code.reason == auth_backends.TOTP_REQUIRED

    with_code = await LOCAL.authenticate(
        conn, "enrolled", password=PASSWORD, totp_code=pyotp.TOTP(secret).now()
    )
    assert with_code.ok


async def test_a_totp_code_cannot_be_replayed_within_the_window(conn):
    """#74: a code that authenticated once is refused on immediate reuse, even
    though pyotp's ±window would otherwise still accept it for ~90s."""
    _, secret = await _human(conn, "replayer", totp_required=True, totp=True)
    code = pyotp.TOTP(secret).now()

    first = await LOCAL.authenticate(conn, "replayer", password=PASSWORD, totp_code=code)
    assert first.ok

    second = await LOCAL.authenticate(conn, "replayer", password=PASSWORD, totp_code=code)
    assert not second.ok
    assert second.reason == auth_backends.BAD_TOTP

    # A fresh code (the next step, still inside the ±window) works — the guard
    # is per-code, not a lock on the account.
    import time

    later = pyotp.TOTP(secret).at(time.time() + 30)
    if later != code:
        ok = await LOCAL.authenticate(conn, "replayer", password=PASSWORD, totp_code=later)
        assert ok.ok


async def test_verify_totp_unused_is_single_use_and_subject_scoped(conn):
    """The guard itself: one acceptance per (subject, code); a wrong code
    records nothing; a different subject holding the same code is independent."""
    secret = credentials.generate_totp_secret()
    code = pyotp.TOTP(secret).now()

    assert await credentials.verify_totp_unused(secret, code, "subject-a")
    assert not await credentials.verify_totp_unused(secret, code, "subject-a")
    assert await credentials.verify_totp_unused(secret, code, "subject-b")
    assert not await credentials.verify_totp_unused(secret, "000000", "subject-a")


async def test_a_wrong_code_still_fails_for_an_unrequired_but_enrolled_user(conn):
    principal_id, _ = await _human(conn, "enrolled2", totp_required=True, totp=True)
    await conn.execute(
        "UPDATE principals SET totp_required = FALSE WHERE id = $1", principal_id
    )
    outcome = await LOCAL.authenticate(
        conn, "enrolled2", password=PASSWORD, totp_code="000000"
    )
    assert not outcome.ok
    assert outcome.reason == auth_backends.BAD_TOTP


async def test_resetting_the_authenticator_clears_the_secret(conn):
    """The lost-phone path: clearing the secret sends a still-required user
    back to enrollment, and lets an unrequired user in on password alone."""
    principal_id, _ = await _human(conn, "lostphone", totp_required=True, totp=True)
    await conn.execute(
        """UPDATE auth_identities SET totp_secret = NULL, totp_enrolled_at = NULL
            WHERE principal_id = $1 AND backend = 'local'""",
        principal_id,
    )

    outcome = await LOCAL.authenticate(conn, "lostphone", password=PASSWORD)
    assert outcome.ok
    assert outcome.needs_totp_enrollment is True

    await conn.execute(
        "UPDATE principals SET totp_required = FALSE WHERE id = $1", principal_id
    )
    outcome = await LOCAL.authenticate(conn, "lostphone", password=PASSWORD)
    assert outcome.ok
    assert outcome.needs_totp_enrollment is False

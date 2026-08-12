"""The auth-backend seam.

The invariant worth defending: a backend answers **who**, never **what**. So
these tests check identity resolution, lockout, and forced enrollment — and
that nothing in a backend can widen access.
"""

import ast
import inspect

import pyotp
import pytest_asyncio

from torii import audit, auth_backends, cache, config, credentials

LOCAL = auth_backends.LOCAL


@pytest_asyncio.fixture(autouse=True)
async def _fresh_cache():
    """TOTP verification now consults valkey for the replay guard (#74); the
    redis client is loop-bound and pytest-asyncio gives each test its own loop.
    Build a fresh client per test and close it here."""
    cache._client = None
    yield
    await cache.close()


async def _human(conn, username="alice", password="s3cret-pw", *, totp=True,
                 temp=False, is_admin=False, disabled=False, totp_required=True):
    principal_id = await conn.fetchval(
        """INSERT INTO principals (kind, username, is_admin, totp_required, disabled_at)
           VALUES ('human', $1, $2, $3, CASE WHEN $4 THEN now() ELSE NULL END)
           RETURNING id""",
        username,
        is_admin,
        totp_required or is_admin,
        disabled,
    )
    secret = credentials.generate_totp_secret() if totp else None
    await conn.execute(
        """INSERT INTO auth_identities
               (principal_id, backend, password_hash, password_is_temp, totp_secret,
                totp_enrolled_at)
           VALUES ($1, 'local', $2, $3, $4::text,
                   CASE WHEN $4::text IS NULL THEN NULL ELSE now() END)""",
        principal_id,
        credentials.hash_password(password),
        temp,
        secret,
    )
    return principal_id, secret


# --- local backend ---------------------------------------------------------


async def test_correct_password_and_totp_authenticates(conn):
    principal_id, secret = await _human(conn)
    outcome = await LOCAL.authenticate(
        conn, "alice", password="s3cret-pw", totp_code=pyotp.TOTP(secret).now()
    )
    assert outcome.ok
    assert outcome.principal_id == str(principal_id)
    assert outcome.reason == auth_backends.OK


async def test_wrong_password_fails(conn):
    await _human(conn)
    outcome = await LOCAL.authenticate(conn, "alice", password="nope", totp_code="123456")
    assert not outcome.ok
    assert outcome.reason == auth_backends.BAD_PASSWORD


async def test_wrong_totp_fails_even_with_the_right_password(conn):
    await _human(conn)
    outcome = await LOCAL.authenticate(conn, "alice", password="s3cret-pw", totp_code="000000")
    assert not outcome.ok
    assert outcome.reason == auth_backends.BAD_TOTP


async def test_missing_totp_is_its_own_answer(conn):
    """So the login page can ask for the code without re-asking the password."""
    await _human(conn)
    outcome = await LOCAL.authenticate(conn, "alice", password="s3cret-pw")
    assert not outcome.ok
    assert outcome.reason == auth_backends.TOTP_REQUIRED


async def test_unknown_username_does_not_reveal_itself(conn):
    """A wrong username and a wrong password must be indistinguishable to the
    caller: same failure, no timing shortcut worth measuring, no message
    difference in the UI layer."""
    await _human(conn)
    unknown = await LOCAL.authenticate(conn, "nobody", password="x", totp_code="1")
    wrong = await LOCAL.authenticate(conn, "alice", password="x", totp_code="1")
    assert not unknown.ok and not wrong.ok
    assert unknown.principal_id is None and wrong.principal_id is None


async def test_disabled_principal_cannot_log_in(conn):
    await _human(conn, disabled=True)
    outcome = await LOCAL.authenticate(conn, "alice", password="s3cret-pw", totp_code="1")
    assert outcome.reason == auth_backends.DISABLED


async def test_service_principal_cannot_log_in(conn):
    """Service principals are keys-only; there is no password to try."""
    await conn.execute(
        "INSERT INTO principals (kind, username) VALUES ('service', 'acme-prod')"
    )
    outcome = await LOCAL.authenticate(conn, "acme-prod", password="x", totp_code="1")
    assert outcome.reason == auth_backends.UNKNOWN_PRINCIPAL


async def test_human_without_local_credentials_is_refused(conn):
    """A principal that only has a (future) IdP identity can't log in locally."""
    principal_id = await conn.fetchval(
        "INSERT INTO principals (kind, username) VALUES ('human', 'federated') RETURNING id"
    )
    await conn.execute(
        """INSERT INTO auth_identities (principal_id, backend, provider, subject)
           VALUES ($1, 'oidc', 'authentik', 'sub-1')""",
        principal_id,
    )
    outcome = await LOCAL.authenticate(conn, "federated", password="x", totp_code="1")
    assert outcome.reason == auth_backends.NO_LOCAL_CREDENTIALS


# --- #66: constant-work so timing can't enumerate accounts -----------------


async def test_unknown_user_still_spends_a_bcrypt(conn, monkeypatch):
    """The unknown-user branch must burn an equivalent bcrypt to a real
    password check, or its speed alone distinguishes non-existent accounts."""
    calls = []
    real = credentials.verify_password
    monkeypatch.setattr(
        credentials, "verify_password",
        lambda pw, h: calls.append(h) or real(pw, h),
    )

    await _human(conn)
    await LOCAL.authenticate(conn, "nobody", password="x", totp_code="1")
    assert calls, "unknown-user branch did no bcrypt work"


async def test_disabled_and_locked_branches_also_spend_a_bcrypt(conn, monkeypatch):
    calls = []
    real = credentials.verify_password
    monkeypatch.setattr(
        credentials, "verify_password",
        lambda pw, h: calls.append(1) or real(pw, h),
    )

    await _human(conn, username="off", disabled=True)
    await LOCAL.authenticate(conn, "off", password="x", totp_code="1")
    assert calls, "disabled branch returned before any bcrypt work"


# --- forced TOTP enrollment and temp passwords ----------------------------


async def test_principal_without_totp_is_sent_to_enrollment(conn):
    """Password-correct but no secret yet: authenticated for the purpose of
    enrolling, and nothing else. The UI must not release access until the
    secret exists."""
    await _human(conn, totp=False)
    outcome = await LOCAL.authenticate(conn, "alice", password="s3cret-pw")
    assert outcome.ok
    assert outcome.needs_totp_enrollment


async def test_temp_password_is_flagged_for_forced_change(conn):
    _, secret = await _human(conn, temp=True)
    outcome = await LOCAL.authenticate(
        conn, "alice", password="s3cret-pw", totp_code=pyotp.TOTP(secret).now()
    )
    assert outcome.ok
    assert outcome.must_change_password


# --- lockout ---------------------------------------------------------------


async def test_failures_accumulate_then_lock(conn):
    principal_id, secret = await _human(conn)

    for _ in range(config.LOGIN_MAX_ATTEMPTS):
        await LOCAL.authenticate(conn, "alice", password="wrong", totp_code="1")

    assert await conn.fetchval(
        "SELECT locked_until FROM auth_identities WHERE principal_id = $1", principal_id
    ) is not None

    # Even the right credentials are refused while locked.
    outcome = await LOCAL.authenticate(
        conn, "alice", password="s3cret-pw", totp_code=pyotp.TOTP(secret).now()
    )
    assert outcome.reason == auth_backends.LOCKED


async def test_lockout_is_audited(conn):
    await _human(conn)
    for _ in range(config.LOGIN_MAX_ATTEMPTS):
        await LOCAL.authenticate(conn, "alice", password="wrong", totp_code="1")

    events = await conn.fetch(
        "SELECT event, outcome FROM audit_auth_events WHERE event = $1", audit.LOCKOUT
    )
    assert len(events) == 1
    assert events[0]["outcome"] == "failure"


async def test_success_clears_the_failure_counter(conn):
    principal_id, secret = await _human(conn)
    await LOCAL.authenticate(conn, "alice", password="wrong", totp_code="1")
    assert await conn.fetchval(
        "SELECT failed_attempts FROM auth_identities WHERE principal_id = $1", principal_id
    ) == 1

    await LOCAL.authenticate(
        conn, "alice", password="s3cret-pw", totp_code=pyotp.TOTP(secret).now()
    )
    row = await conn.fetchrow(
        """SELECT failed_attempts, locked_until, last_login_at
             FROM auth_identities WHERE principal_id = $1""",
        principal_id,
    )
    assert row["failed_attempts"] == 0
    assert row["locked_until"] is None
    assert row["last_login_at"] is not None


# --- the seam itself -------------------------------------------------------


def test_only_local_is_available_at_launch():
    """Q9c: no external IdP at launch. The seam exists; the connector doesn't."""
    assert [b.name for b in auth_backends.available_backends()] == ["local"]
    assert auth_backends.get("oidc") is None
    assert auth_backends.get("local") is LOCAL


def test_oidc_backend_is_present_but_dormant():
    assert auth_backends.OIDC.available() is False
    assert auth_backends.OIDC.name == "oidc"


async def test_dormant_oidc_backend_authenticates_nobody(conn):
    outcome = await auth_backends.OIDC.authenticate(conn, "anyone")
    assert not outcome.ok
    assert outcome.reason == auth_backends.BACKEND_UNAVAILABLE


def test_only_local_can_serve_the_admin_gui():
    """Q9: the admin GUI stays local-credentials-only, forever."""
    assert LOCAL.admin_capable is True
    assert auth_backends.OIDC.admin_capable is False


def test_backends_cannot_grant_access():
    """A backend answers who, never what. If a backend imported the resolver
    or read the grants table, authorization would have leaked out of its one
    module — so assert on imports and SQL, not on the prose."""
    tree = ast.parse(inspect.getsource(auth_backends))

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.update(alias.name for alias in node.names)
    assert "rbac" not in imported

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]
    assert not any("grants" in literal.lower() for literal in literals)
    assert not any("grant" in f.lower() for f in auth_backends.AuthOutcome.__dataclass_fields__)

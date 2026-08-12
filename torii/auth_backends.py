"""The auth-backend seam (PRD Q9/Q9b/Q9c).

At launch every human uses local credentials. The seam exists now so the
Authentik connector can be added later without touching the login flow, the
token issuance path, or authorization: a backend's only job is to answer
**who this is**. What they may reach is always decided by `torii.rbac` from
the resolved principal, so the auth method can never change authorization.

Backends never see grants, and the admin GUI accepts `local` only — forever
(Q9). That constraint lives in the UI layer; here it's just a flag on the
backend: `admin_capable`.
"""

import logging
from dataclasses import dataclass
from typing import Protocol

import asyncpg

from . import audit, config, credentials

log = logging.getLogger(__name__)

# Outcome reasons. Stable — they land in audit detail.
OK = "ok"
UNKNOWN_PRINCIPAL = "unknown_principal"
NO_LOCAL_CREDENTIALS = "no_local_credentials"
BAD_PASSWORD = "bad_password"
BAD_TOTP = "bad_totp"
TOTP_REQUIRED = "totp_required"
LOCKED = "locked"
DISABLED = "disabled"
BACKEND_UNAVAILABLE = "backend_unavailable"

# A throwaway bcrypt hash at the same cost factor as a real password, used to
# spend an equivalent amount of work on the login branches that return BEFORE
# the real password check (unknown user, disabled, locked, no local
# credentials). Without it those branches answer far faster than a genuine
# bcrypt comparison, and the timing distinguishes existing accounts from
# non-existent ones regardless of the (now generic) error message (#66).
_DUMMY_PASSWORD_HASH = credentials.hash_password(credentials.generate_temp_password())


def _constant_work(password: str) -> None:
    """Burn one bcrypt comparison so an early return can't be timed apart from
    a real password verification. The result is deliberately discarded."""
    credentials.verify_password(password or " ", _DUMMY_PASSWORD_HASH)


@dataclass(frozen=True)
class AuthOutcome:
    ok: bool
    reason: str
    principal_id: str | None = None
    username: str | None = None
    is_admin: bool = False
    # The caller must change their password before doing anything else.
    must_change_password: bool = False
    # No TOTP secret yet: enrollment is forced before access is granted.
    needs_totp_enrollment: bool = False

    def __bool__(self) -> bool:
        return self.ok


class AuthBackend(Protocol):
    name: str
    admin_capable: bool

    def available(self) -> bool: ...

    async def authenticate(
        self, conn: asyncpg.Connection, username: str, **credentials_presented
    ) -> AuthOutcome: ...


class LocalBackend:
    """bcrypt + TOTP, with lockout. The break-glass path, and the only
    backend the admin GUI accepts."""

    name = "local"
    admin_capable = True

    def available(self) -> bool:
        return True

    async def authenticate(
        self,
        conn: asyncpg.Connection,
        username: str,
        password: str = "",
        totp_code: str = "",
        **_ignored,
    ) -> AuthOutcome:
        row = await conn.fetchrow(
            """SELECT p.id, p.username, p.is_admin, p.totp_required, p.disabled_at,
                      i.id AS identity_id, i.password_hash, i.password_is_temp,
                      i.totp_secret, i.failed_attempts, i.locked_until
                 FROM principals p
                 LEFT JOIN auth_identities i
                        ON i.principal_id = p.id AND i.backend = 'local'
                WHERE p.username = $1 AND p.kind = 'human'""",
            username,
        )
        if row is None:
            # Same shape of answer as a wrong password: a login form must not
            # tell an attacker which usernames exist. Spend a bcrypt's worth of
            # work so the timing matches a real verification too (#66).
            _constant_work(password)
            return AuthOutcome(False, UNKNOWN_PRINCIPAL, username=username)
        if row["disabled_at"] is not None:
            _constant_work(password)
            return AuthOutcome(False, DISABLED, username=username)
        if row["identity_id"] is None:
            _constant_work(password)
            return AuthOutcome(False, NO_LOCAL_CREDENTIALS, username=username)

        if row["locked_until"] is not None and await conn.fetchval(
            "SELECT $1::timestamptz > now()", row["locked_until"]
        ):
            _constant_work(password)
            return AuthOutcome(False, LOCKED, username=username)

        if not credentials.verify_password(password, row["password_hash"]):
            await self._register_failure(conn, row)
            return AuthOutcome(False, BAD_PASSWORD, username=username)

        # Password is right. Whether TOTP is next depends on policy (Q11):
        # admins always need it (schema-enforced), everyone else only if an
        # operator required it. A principal who has already enrolled is always
        # asked for a code — dropping the requirement must not silently
        # downgrade an account that already has a working authenticator.
        if not row["totp_secret"]:
            await self._register_success(conn, row["identity_id"])
            return AuthOutcome(
                True,
                OK,
                principal_id=str(row["id"]),
                username=row["username"],
                is_admin=row["is_admin"],
                must_change_password=row["password_is_temp"],
                needs_totp_enrollment=bool(row["totp_required"]),
            )

        if not totp_code:
            return AuthOutcome(False, TOTP_REQUIRED, username=username)
        # Single-use within the validity window (#74): a code accepted once is
        # rejected on reuse, so a captured code can't authenticate twice.
        if not await credentials.verify_totp_unused(
            row["totp_secret"], totp_code, str(row["id"])
        ):
            await self._register_failure(conn, row)
            return AuthOutcome(False, BAD_TOTP, username=username)

        await self._register_success(conn, row["identity_id"])
        return AuthOutcome(
            True,
            OK,
            principal_id=str(row["id"]),
            username=row["username"],
            is_admin=row["is_admin"],
            must_change_password=row["password_is_temp"],
        )

    async def _register_failure(self, conn: asyncpg.Connection, row) -> None:
        attempts = (row["failed_attempts"] or 0) + 1
        lock = attempts >= config.LOGIN_MAX_ATTEMPTS
        await conn.execute(
            """UPDATE auth_identities
                  SET failed_attempts = $2,
                      locked_until = CASE WHEN $3
                          THEN now() + ($4 || ' seconds')::interval
                          ELSE locked_until END,
                      updated_at = now()
                WHERE id = $1""",
            row["identity_id"],
            attempts,
            lock,
            str(config.LOGIN_LOCKOUT_SECONDS),
        )
        if lock:
            await audit.record_auth_event(
                conn,
                event=audit.LOCKOUT,
                outcome="failure",
                principal_id=row["id"],
                principal_label=row["username"],
                backend=self.name,
                detail={"attempts": attempts, "seconds": config.LOGIN_LOCKOUT_SECONDS},
            )

    async def _register_success(self, conn: asyncpg.Connection, identity_id) -> None:
        await conn.execute(
            """UPDATE auth_identities
                  SET failed_attempts = 0, locked_until = NULL,
                      last_login_at = now(), updated_at = now()
                WHERE id = $1""",
            identity_id,
        )


class OIDCBackend:
    """Upstream OIDC federation (Authentik).

    Deferred to P3+ by Q9c: no external IdP exists at launch, so this is the
    seam's second implementation and nothing more. It stays unavailable until
    a connector is configured, and it can never serve the admin GUI (Q9).
    """

    name = "oidc"
    admin_capable = False

    def available(self) -> bool:
        return config.OIDC_ENABLED

    async def authenticate(self, conn, username: str, **_ignored) -> AuthOutcome:
        # Federated login is a redirect flow, not a username/password call.
        # When the connector lands it will consume an OIDC callback, map
        # (provider, subject) to a principal via auth_identities, and
        # JIT-create a principal with ZERO grants when there's no match.
        return AuthOutcome(False, BACKEND_UNAVAILABLE, username=username)


LOCAL = LocalBackend()
OIDC = OIDCBackend()


def all_backends() -> tuple[AuthBackend, ...]:
    return (LOCAL, OIDC)


def available_backends() -> tuple[AuthBackend, ...]:
    """What the login page should offer."""
    return tuple(b for b in all_backends() if b.available())


def get(name: str) -> AuthBackend | None:
    for backend in all_backends():
        if backend.name == name and backend.available():
            return backend
    return None

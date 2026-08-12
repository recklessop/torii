"""Bearer-auth middleware for `/mcp`.

Resolves the caller from the Authorization header (OAuth access token or a
`tor_` static key) and attaches a `Caller` to `request.state`. Wrong or
missing credentials leave state empty — the route decides what to do (`/mcp`
returns 401 with a discovery hint). This module deliberately never denies:
authorization is `torii.rbac`'s job, not this one.
"""

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from . import audit, cache, credentials, db, oauth, web

log = logging.getLogger(__name__)

# Defence-in-depth for the whole app (#59). The directory is unauthenticated,
# crawlable, and same-origin with /ui/admin/*, so a script that ever escaped an
# output context could drive admin mutations under the admin's cookie. A CSP is
# the backstop behind correct escaping, not a substitute for it.
#
# The templates use inline <script> blocks, inline `onsubmit=` handlers, and
# inline styles today, so 'unsafe-inline' is required for script-src/style-src
# to keep the app working; there are NO external scripts, styles, fonts, or
# images, so every other source is locked to 'self'. `frame-ancestors 'none'`
# plus X-Frame-Options: DENY forbids framing (clickjacking), and `form-action
# 'self'` keeps a form from posting credentials cross-origin.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Stamp the security headers on every response, app-wide."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response


class SessionRevalidationMiddleware(BaseHTTPMiddleware):
    """Re-check the live principal behind a logged-in UI cookie (#61, #67).

    The /ui gates read is_admin/principal_id straight from the signed cookie, so
    a disabled or demoted admin kept access until it expired, and a password
    change revoked nothing. This runs inside SessionMiddleware (so request.session
    is populated) on every request that carries a logged-in session and:

      - scrubs the session if the principal is gone, disabled, or the cookie was
        minted at/before sessions_valid_after (disable / password change) — the
        existing _require_login gate then redirects it to the login form;
      - refreshes is_admin from the DB so a demotion takes effect next request.

    One indexed row on pages that already run several queries. Fails OPEN on a DB
    error: the same outage breaks every page anyway, and mass-logging-out the
    operator on a blip is worse than a brief reliance on the cookie.
    """

    async def dispatch(self, request: Request, call_next):
        session = request.session.get(web.SESSION_KEY) if "session" in request.scope else None
        principal_id = (session or {}).get("principal_id")
        if principal_id:
            row = await self._live_principal(principal_id)
            if row is not False:  # False == DB error, leave the session alone
                if row is None or row["disabled"] or self._stale(session, row):
                    request.session.pop(web.SESSION_KEY, None)
                elif bool(session.get("is_admin")) != row["is_admin"]:
                    session["is_admin"] = row["is_admin"]
                    request.session[web.SESSION_KEY] = session
        return await call_next(request)

    @staticmethod
    def _stale(session: dict, row) -> bool:
        valid_after = row["valid_after"]
        if valid_after is None:
            return False
        issued_at = session.get("issued_at")
        # A session predating the issued_at stamp can't prove it's fresh, so once
        # a cutoff exists it fails safe as stale.
        return issued_at is None or issued_at < valid_after

    @staticmethod
    async def _live_principal(principal_id):
        try:
            pool = await db.pool()
            async with pool.acquire() as conn:
                return await conn.fetchrow(
                    """SELECT disabled_at IS NOT NULL          AS disabled,
                              is_admin,
                              -- float8 so it matches the float issued_at stamped
                              -- into the cookie exactly (a Decimal vs float compare
                              -- rounds and can false-expire the re-issued session).
                              EXTRACT(EPOCH FROM sessions_valid_after)::float8 AS valid_after
                         FROM principals WHERE id = $1::uuid""",
                    principal_id,
                )
        except Exception:  # noqa: BLE001 — see the fail-open note above
            log.exception("session revalidation query failed")
            return False


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Attach a Caller to /mcp requests when one can be resolved."""

    async def dispatch(self, request: Request, call_next):
        if _is_mcp_path(request.url.path):
            authorization = request.headers.get("authorization", "")
            token = _bearer_value(authorization)
            if token:
                pool = await db.pool()
                async with pool.acquire() as conn:
                    caller = None
                    if token.startswith(credentials.KEY_PREFIX):
                        caller = await credentials.authenticate_api_key(conn, token)
                    else:
                        caller = await credentials.authenticate_access_token(conn, token)
                    if caller is None:
                        await audit.record_auth_event(
                            conn,
                            event=audit.AUTH_FAILURE,
                            outcome="failure",
                            backend="bearer",
                            ip=web.client_ip(request),
                            user_agent=web.user_agent(request),
                            detail={"reason": "invalid_or_expired_token"},
                        )
                    else:
                        request.state.caller = caller
        return await call_next(request)


def _is_mcp_path(path: str) -> bool:
    """`/mcp` (aggregate) or `/<server>/mcp` (per-server, PRD Q13).

    Matched by shape rather than by looking up the server name: this runs on
    every request, and an unknown name must still reach the route so it can
    answer with an empty tool list instead of leaking existence through a
    401-vs-200 difference.
    """
    if path == "/mcp":
        return True
    return path.count("/") == 2 and path.endswith("/mcp")


def _bearer_value(header: str) -> str | None:
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value:
        return value.strip()
    return None

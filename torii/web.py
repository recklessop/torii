"""Shared web plumbing: templates, sessions, client IP, rate limiting."""

import ipaddress
import pathlib
import time

from fastapi import Request
from fastapi.templating import Jinja2Templates

from . import cache, config

TEMPLATES_DIR = pathlib.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SESSION_KEY = "torii_session"


def render(request: Request, template: str, context: dict | None = None, status_code: int = 200):
    payload = {"base_url": config.PUBLIC_BASE_URL, "session": get_session(request)}
    payload.update(context or {})
    return templates.TemplateResponse(
        request=request, name=template, context=payload, status_code=status_code
    )


# --- sessions --------------------------------------------------------------


def set_session(request: Request, **fields) -> None:
    # Anchor `issued_at` at the first authenticated write and preserve it across
    # later mutations (a caller that passes it through **get_session() keeps the
    # original; a fresh login dict gets stamped now). SessionRevalidationMiddleware
    # compares it against principals.sessions_valid_after to expire cookies minted
    # before a disable or password change (#61, #67).
    fields.setdefault("issued_at", time.time())
    request.session[SESSION_KEY] = fields


def get_session(request: Request) -> dict:
    return request.session.get(SESSION_KEY) or {}


def clear_session(request: Request) -> None:
    request.session.pop(SESSION_KEY, None)


def session_principal(request: Request) -> dict | None:
    """The logged-in principal, or None if the session is incomplete.

    A session mid-enrollment or mid-password-change is deliberately NOT a
    logged-in session: forced TOTP enrollment and temp-password rotation are
    gates, not suggestions.
    """
    session = get_session(request)
    if not session.get("principal_id"):
        return None
    if session.get("needs_totp_enrollment") or session.get("must_change_password"):
        return None
    return session


# --- request metadata ------------------------------------------------------


def _parse_ip(value: str | None) -> str | None:
    """Normalise a candidate to a canonical IP string, or None if it isn't one.

    Everything that reaches the `$::inet` bind in the audit writer goes through
    here first: a non-IP value there raises client-side in asyncpg, and that
    exception is swallowed, so a login with a garbage `X-Forwarded-For` would
    otherwise write NO audit or lockout row (#64).
    """
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _peer_is_trusted(request: Request) -> bool:
    """Is the socket peer a proxy we configured to speak for the client?"""
    if config.TRUST_ALL_PROXIES:
        return True
    if not config.TRUSTED_PROXY_NETWORKS:
        return False
    peer = _parse_ip(request.client.host if request.client else None)
    if peer is None:
        return False
    addr = ipaddress.ip_address(peer)
    return any(addr in net for net in config.TRUSTED_PROXY_NETWORKS)


def client_ip(request: Request) -> str | None:
    """The caller's address as far as we can trust it.

    The forwarded headers (CF-Connecting-IP / X-Forwarded-For) are honoured
    ONLY when the socket peer is a configured trusted proxy (#65); otherwise
    they're client-controllable spoofing and we use the socket IP. Whatever we
    return is parsed to a real IP first (#64) so a garbage value can never
    reach the `::inet` bind. This is audit context, never an authorization
    input.
    """
    peer_ip = _parse_ip(request.client.host if request.client else None)
    if _peer_is_trusted(request):
        for header in ("cf-connecting-ip", "x-forwarded-for"):
            candidate = _parse_ip((request.headers.get(header) or "").split(",")[0])
            if candidate:
                return candidate
            # Header present but unparseable: fall through to the socket IP
            # rather than return garbage.
    return peer_ip


def user_agent(request: Request) -> str | None:
    agent = request.headers.get("user-agent")
    return agent[:500] if agent else None


# --- rate limiting ---------------------------------------------------------


async def too_many_attempts(bucket: str, limit: int, window_seconds: int) -> bool:
    """Fixed-window counter in valkey.

    Fails OPEN on a valkey outage: this guards the login form, and an outage
    of the counter shouldn't lock the operator out of their own gateway. The
    per-identity lockout in `auth_identities` is the durable defence.
    """
    key = f"torii:rl:{bucket}"
    try:
        client = cache.client()
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window_seconds)
        return count > limit
    except Exception:  # noqa: BLE001
        return False


async def login_rate_limited(ip: str | None) -> bool:
    if not ip:
        return False
    return await too_many_attempts(
        f"login:{ip}", config.LOGIN_MAX_ATTEMPTS * 4, config.LOGIN_LOCKOUT_SECONDS
    )


# --- call rate limiting (PRD Q19) -----------------------------------------


async def call_rate_limited(bucket: str, limit: int, *, fail_closed: bool) -> tuple[bool, int]:
    """Fixed-window counter for proxied calls. Returns (limited, retry_after).

    `fail_closed` decides what a valkey outage means, and the answer differs by
    who is calling — see `rate_limit_for` in torii.limits for the reasoning.
    """
    window = 60
    key = f"torii:callrl:{bucket}"
    try:
        client = cache.client()
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window)
            return False, 0
        if count > limit:
            retry_after = await client.ttl(key)
            return True, max(1, retry_after if retry_after and retry_after > 0 else window)
        return False, 0
    except Exception:  # noqa: BLE001 — the counter is unavailable, not the gateway
        return (True, window) if fail_closed else (False, 0)

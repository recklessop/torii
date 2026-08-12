"""OAuth 2.1 HTTP surface: metadata, DCR, authorize, token, revoke.

The authorize endpoint doubles as the login page (FR2). Forced TOTP
enrollment and temp-password rotation are gates inside that flow: a session
that hasn't cleared them is not a logged-in session, so a client cannot get a
code out of a half-finished login.
"""

import hmac
import logging
import secrets
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import audit, auth_backends, cache, config, credentials, db, oauth, web

log = logging.getLogger(__name__)

router = APIRouter()

# Where a mid-flow TOTP secret waits while the human types the code back.
ENROLL_PREFIX = "torii:enroll:"


# --- authorize-flow binding (Q26 / the audit's C1a) ------------------------
#
# Every /authorize creates a per-flow nonce, stored BOTH in the browser's
# session and on the pending record. Completing a flow (consent, or the
# straight-through path for an already-approved client) requires the two to
# match — so a request_id handed to a different browser cannot be finished by
# it. Kept in the OUTER session, not the torii_session sub-dict, so a login
# (which replaces that sub-dict) doesn't drop an in-flight authorization.


def _stamp_flow(request: Request, request_id: str, nonce: str) -> None:
    flows = dict(request.session.get("authflows") or {})
    flows[request_id] = nonce
    if len(flows) > 8:  # keep the cookie small; drop the oldest in-flight flows
        for stale in list(flows)[:-8]:
            flows.pop(stale, None)
    request.session["authflows"] = flows


def _flow_nonce(request: Request, request_id: str) -> str:
    return (request.session.get("authflows") or {}).get(request_id, "")


def _flow_nonce_ok(request: Request, request_id: str, pending) -> bool:
    got = _flow_nonce(request, request_id)
    return bool(got) and bool(pending.nonce) and hmac.compare_digest(got, pending.nonce)


def _clear_flow(request: Request, request_id: str) -> None:
    flows = dict(request.session.get("authflows") or {})
    if flows.pop(request_id, None) is not None:
        request.session["authflows"] = flows


def _consent_redirect(request_id: str) -> RedirectResponse:
    return RedirectResponse(f"/authorize/consent?request_id={request_id}", status_code=302)


# --- metadata --------------------------------------------------------------


def _metadata_response(payload: dict) -> JSONResponse:
    # Public, cacheable, and read by clients we don't control — no cookies.
    return JSONResponse(payload, headers={"Cache-Control": "public, max-age=300"})


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    return _metadata_response(oauth.authorization_server_metadata())


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    return _metadata_response(oauth.protected_resource_metadata())


# Claude has been seen probing the MCP-suffixed variant of the resource
# document; serving both costs nothing and removes a discovery failure mode.
@router.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata_for_mcp():
    return _metadata_response(oauth.protected_resource_metadata())


@router.get("/.well-known/oauth-protected-resource/{server}/mcp")
async def protected_resource_metadata_for_server(server: str):
    """Per-server resource metadata (Q13).

    Answered for any name, including servers the caller can't reach or that
    don't exist: this document says "the AS for this URL is torii", which is
    true regardless, and 404ing here would turn discovery into an
    enumeration oracle.
    """
    return _metadata_response(oauth.protected_resource_metadata(server))


# --- dynamic client registration -------------------------------------------


@router.post("/oauth/register")
async def register(request: Request):
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            registration = await oauth.register_client(conn, body, ip=web.client_ip(request))
        except oauth.OAuthError as exc:
            return JSONResponse(exc.as_dict(), status_code=exc.status)
    return JSONResponse(registration, status_code=201)


# --- authorize -------------------------------------------------------------


def _login_page(request, request_id, pending, error=None, username=None, status_code=200):
    return web.render(
        request,
        "login.html",
        {
            "action": "/authorize",
            "request_id": request_id,
            "client_name": getattr(pending, "client_name", None),
            "error": error,
            "username": username,
            "oidc_available": auth_backends.OIDC.available(),
        },
        status_code=status_code,
    )


def _error_page(request, exc: oauth.OAuthError):
    return web.render(
        request,
        "oauth_error.html",
        {"error": exc.error, "description": exc.description},
        status_code=exc.status,
    )


@router.get("/authorize")
async def authorize(request: Request):
    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            request_id, pending = await oauth.begin_authorization(
                conn, dict(request.query_params)
            )
        except oauth.OAuthError as exc:
            # An unvalidated redirect_uri is not a safe place to send errors,
            # so these render rather than redirect.
            return _error_page(request, exc)

    # Bind this flow to this browser (Q26): a nonce in the session and on the
    # pending. A logged-in session no longer completes here — it goes to the
    # consent step, which passes an already-approved client straight through
    # and shows the consent screen for a new one. That closes the silent
    # cross-site authorization that made this the audit's one critical.
    nonce = secrets.token_urlsafe(24)
    _stamp_flow(request, request_id, nonce)
    await oauth.bind_pending_nonce(request_id, nonce)

    if web.session_principal(request):
        return _consent_redirect(request_id)
    return _login_page(request, request_id, pending)


@router.get("/authorize/consent")
async def authorize_consent_page(request: Request):
    """The consent step. Reached only after the human is authenticated.

    Auto-completes for a client this principal has already approved (bound);
    otherwise renders the consent screen. Refuses a flow this browser did not
    start (the nonce check) — that is the C1a defence.
    """
    request_id = request.query_params.get("request_id", "")
    session = web.session_principal(request)
    if session is None:
        return _error_page(
            request, oauth.OAuthError("invalid_request", "session expired — start again")
        )
    pending = await oauth.load_pending(request_id)
    if pending is None:
        return _error_page(
            request, oauth.OAuthError("invalid_request", "authorization request expired")
        )
    if not _flow_nonce_ok(request, request_id, pending):
        return _error_page(
            request,
            oauth.OAuthError("invalid_request", "this authorization was not started here"),
        )

    pool = await db.pool()
    async with pool.acquire() as conn:
        if await oauth.client_bound_to(conn, pending.client_id, session["principal_id"]):
            location = await oauth.complete_authorization(
                conn, request_id, session["principal_id"],
                user_agent=web.user_agent(request), ip=web.client_ip(request),
            )
            _clear_flow(request, request_id)
            return RedirectResponse(location, status_code=302)
        row = await conn.fetchrow(
            "SELECT client_name FROM oauth_clients WHERE client_id = $1", pending.client_id
        )

    return web.render(
        request,
        "consent.html",
        {
            "request_id": request_id,
            "csrf": _flow_nonce(request, request_id),
            # client_name is attacker-chosen at DCR — shown, not trusted. The
            # redirect host is the fact that actually distinguishes a real
            # connector from an attacker's, so it's the prominent line.
            "client_name": (row and row["client_name"]) or pending.client_id,
            "redirect_host": urlparse(pending.redirect_uri).netloc or pending.redirect_uri,
            "scope": pending.scope or "mcp",
        },
    )


@router.post("/authorize/consent")
async def authorize_consent(request: Request):
    form = dict(await request.form())
    request_id = form.get("request_id", "")
    session = web.session_principal(request)
    if session is None:
        return _error_page(
            request, oauth.OAuthError("invalid_request", "session expired — start again")
        )
    pending = await oauth.load_pending(request_id)
    if pending is None:
        return _error_page(
            request, oauth.OAuthError("invalid_request", "authorization request expired")
        )

    # CSRF + flow binding: the submitted token, the session's nonce, and the
    # pending's nonce must all agree. A cross-site POST carries no session
    # cookie (SameSite=lax), and a leaked request_id lacks the nonce.
    session_nonce = _flow_nonce(request, request_id)
    csrf = form.get("csrf", "")
    if not (
        _flow_nonce_ok(request, request_id, pending)
        and session_nonce
        and hmac.compare_digest(csrf, session_nonce)
    ):
        return _error_page(
            request,
            oauth.OAuthError("invalid_request", "this authorization was not started here"),
        )
    _clear_flow(request, request_id)

    if form.get("decision") != "approve":
        await cache.client().delete(oauth.PENDING_PREFIX + request_id)
        return RedirectResponse(oauth.denied_location(pending), status_code=302)

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            location = await oauth.complete_authorization(
                conn, request_id, session["principal_id"],
                user_agent=web.user_agent(request), ip=web.client_ip(request),
            )
        except oauth.OAuthError as exc:
            return _error_page(request, exc)
    return RedirectResponse(location, status_code=302)


@router.post("/authorize")
async def authorize_login(request: Request):
    form = dict(await request.form())
    request_id = form.get("request_id", "")
    username = (form.get("username") or "").strip()
    ip = web.client_ip(request)

    pending = await oauth.load_pending(request_id)
    if pending is None:
        return _error_page(
            request, oauth.OAuthError("invalid_request", "authorization request expired")
        )

    if await web.login_rate_limited(ip):
        return _login_page(
            request, request_id, pending,
            error="Too many attempts from this address. Try again shortly.",
            username=username, status_code=429,
        )

    pool = await db.pool()
    async with pool.acquire() as conn:
        outcome = await auth_backends.LOCAL.authenticate(
            conn,
            username,
            password=form.get("password", ""),
            totp_code=form.get("totp_code", ""),
        )
        if not outcome.ok:
            await audit.record_auth_event(
                conn,
                event=audit.LOGIN_FAILURE,
                outcome="failure",
                principal_label=username,
                backend=auth_backends.LOCAL.name,
                ip=ip,
                user_agent=web.user_agent(request),
                detail={"reason": outcome.reason, "flow": "authorize"},
            )
            return _login_page(
                request, request_id, pending,
                error=_login_error_text(outcome.reason),
                username=username,
                status_code=401,
            )

        await audit.record_auth_event(
            conn,
            event=audit.LOGIN_SUCCESS,
            principal_id=outcome.principal_id,
            principal_label=outcome.username,
            backend=auth_backends.LOCAL.name,
            ip=ip,
            user_agent=web.user_agent(request),
            detail={"flow": "authorize"},
        )
        web.set_session(
            request,
            principal_id=outcome.principal_id,
            username=outcome.username,
            is_admin=outcome.is_admin,
            backend=auth_backends.LOCAL.name,
            needs_totp_enrollment=outcome.needs_totp_enrollment,
            must_change_password=outcome.must_change_password,
        )

        if outcome.needs_totp_enrollment:
            return await _start_enrollment(request, outcome, request_id)
        if outcome.must_change_password:
            return web.render(
                request,
                "change_password.html",
                {"action": "/authorize/password", "request_id": request_id},
            )

    # Authenticated and past the gates — hand off to the consent step (Q26),
    # which completes straight through for a client you've approved before and
    # shows the consent screen for a new one.
    return _consent_redirect(request_id)


def _login_error_text(reason: str) -> str:
    # Same generic collapse as the /ui login helper (#66): unknown user, wrong
    # password, disabled, and locked are indistinguishable to the client, and
    # only the audit `reason` tells them apart. TOTP_REQUIRED is the lone
    # exception because it's post-password and must prompt for the code.
    if reason == auth_backends.TOTP_REQUIRED:
        return "Enter the code from your authenticator."
    return "Those credentials didn't work."


async def _start_enrollment(request: Request, outcome, request_id: str | None, next_url=None):
    secret = credentials.generate_totp_secret()
    await cache.client().setex(
        ENROLL_PREFIX + outcome.principal_id, 900, secret
    )
    return web.render(
        request,
        "totp_enroll.html",
        {
            "action": "/authorize/totp",
            "request_id": request_id,
            "next_url": next_url,
            "secret": secret,
            "uri": credentials.totp_provisioning_uri(secret, outcome.username or ""),
            "qr_svg": credentials.totp_qr_svg(secret, outcome.username or ""),
        },
    )


@router.post("/authorize/totp")
async def authorize_totp(request: Request):
    """Confirm a freshly generated secret, then resume wherever we were."""
    form = dict(await request.form())
    session = web.get_session(request)
    principal_id = session.get("principal_id")
    if not principal_id or not session.get("needs_totp_enrollment"):
        return _error_page(
            request, oauth.OAuthError("invalid_request", "no enrollment in progress")
        )

    secret = await cache.client().get(ENROLL_PREFIX + principal_id)
    if not secret:
        return _error_page(
            request, oauth.OAuthError("invalid_request", "enrollment expired, sign in again")
        )

    # Single-use within the validity window (#74): the confirming code can't be
    # replayed to enroll or to satisfy a later prompt.
    if not await credentials.verify_totp_unused(
        secret, form.get("totp_code", ""), str(principal_id)
    ):
        return web.render(
            request,
            "totp_enroll.html",
            {
                "action": "/authorize/totp",
                "request_id": form.get("request_id"),
                "next_url": form.get("next"),
                "secret": secret,
                "uri": credentials.totp_provisioning_uri(secret, session.get("username") or ""),
                "qr_svg": credentials.totp_qr_svg(secret, session.get("username") or ""),
                "error": "That code didn't match. Try the current one.",
            },
            status_code=400,
        )

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE auth_identities
                  SET totp_secret = $2, totp_enrolled_at = now(), updated_at = now()
                WHERE principal_id = $1 AND backend = 'local'""",
            principal_id,
            secret,
        )
        await audit.record_auth_event(
            conn,
            event=audit.TOTP_ENROLLED,
            principal_id=principal_id,
            principal_label=session.get("username"),
            backend="local",
            ip=web.client_ip(request),
        )
        await cache.client().delete(ENROLL_PREFIX + principal_id)
        session["needs_totp_enrollment"] = False
        web.set_session(request, **session)

        if session.get("must_change_password"):
            return web.render(
                request,
                "change_password.html",
                {
                    "action": "/authorize/password",
                    "request_id": form.get("request_id"),
                    "next_url": form.get("next"),
                },
            )

        return await _resume(request, conn, form, session)


@router.post("/authorize/password")
async def authorize_password(request: Request):
    form = dict(await request.form())
    session = web.get_session(request)
    principal_id = session.get("principal_id")
    if not principal_id or not session.get("must_change_password"):
        return _error_page(
            request, oauth.OAuthError("invalid_request", "no password change in progress")
        )

    password = form.get("password", "")
    context = {
        "action": "/authorize/password",
        "request_id": form.get("request_id"),
        "next_url": form.get("next"),
    }
    if password != form.get("confirm", ""):
        return web.render(request, "change_password.html", context | {"error": "Those don't match."}, status_code=400)
    if len(password) < 12:
        return web.render(
            request,
            "change_password.html",
            context | {"error": "Use at least 12 characters."},
            status_code=400,
        )

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            password_hash = credentials.hash_password(password)
        except credentials.PasswordTooLong:
            return web.render(
                request,
                "change_password.html",
                context | {"error": "That password is too long (72 bytes max)."},
                status_code=400,
            )
        await conn.execute(
            """UPDATE auth_identities
                  SET password_hash = $2, password_is_temp = FALSE, updated_at = now()
                WHERE principal_id = $1 AND backend = 'local'""",
            principal_id,
            password_hash,
        )
        session["must_change_password"] = False
        web.set_session(request, **session)
        return await _resume(request, conn, form, session)


async def _resume(request: Request, conn, form: dict, session: dict):
    """After a gate clears, continue the OAuth flow or land in the UI."""
    request_id = form.get("request_id")
    if request_id:
        # Route through consent (Q26): the flow's nonce is checked there, which
        # is what stops a request_id handed to this session being completed on it.
        return _consent_redirect(request_id)
    return RedirectResponse(form.get("next") or "/ui", status_code=302)


# --- token and revocation --------------------------------------------------


@router.post("/oauth/token")
async def token(request: Request):
    form = dict(await request.form())
    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            body = await oauth.token(conn, form)
        except oauth.OAuthError as exc:
            return JSONResponse(
                exc.as_dict(),
                status_code=exc.status,
                headers={"Cache-Control": "no-store"},
            )
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


@router.post("/oauth/revoke")
async def revoke(request: Request):
    form = dict(await request.form())
    pool = await db.pool()
    async with pool.acquire() as conn:
        await oauth.revoke(conn, form)
    # RFC 7009: always 200, so this endpoint can't be used to probe for tokens.
    return JSONResponse({}, status_code=200)

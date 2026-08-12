"""The credential and admin UI (PRD FR4).

Layout is an app shell — persistent left sidebar, one route per function, user
menu bottom-left — rather than a single scrolling page. Each nav entry is its
own URL so it can be linked, bookmarked, and reasoned about:

    /ui                      overview
    /ui/grants               my effective access (read-only)
    /ui/keys                 my static keys
    /ui/connectors           my OAuth clients
    /ui/account              password + two-factor

    /ui/admin/principals     principal CRUD (+ /{id} detail)
    /ui/admin/upstreams      server registry, incl. public listing
    /ui/admin/groups         groups and their membership (+ /{id} detail)
    /ui/admin/grants         the grant editor, both levels
    /ui/admin/clients        OAuth client governance
    /ui/admin/audit          audit viewer with filters
    /ui/admin/config         config export

Admin pages are gated on `is_admin` here, but that flag never reaches the
authorization path: what any caller may actually invoke is decided by
`torii.rbac` alone (FR3). A bug in this file cannot widen gateway access.
"""

import json
import logging
import re
import secrets
from dataclasses import replace
from urllib.parse import urlparse

from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

import asyncpg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import (audit, auth_backends, cache, config, credentials, crypto, db, oauth,
               proxy, rbac, useragent, web)
from .upstreams import UpstreamUrlError, validate_upstream_url

log = logging.getLogger(__name__)

router = APIRouter(prefix="/ui")


# --- session gates ---------------------------------------------------------


def _require_login(request: Request):
    session = web.session_principal(request)
    if session is None:
        raw = web.get_session(request)
        if raw.get("principal_id"):
            # Mid-gate: TOTP enrollment or a forced password change hasn't
            # completed. Send them to the gate, not back to the login form.
            if raw.get("needs_totp_enrollment"):
                return RedirectResponse("/ui/enroll_totp", status_code=302)
            if raw.get("must_change_password"):
                return RedirectResponse("/ui/change_password", status_code=302)
        return RedirectResponse("/ui/login", status_code=302)
    return session


def _require_admin(request: Request):
    session = _require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.get("is_admin"):
        return _forbidden(request)
    return session


def _forbidden(request: Request):
    return web.render(
        request,
        "oauth_error.html",
        {"error": "forbidden", "description": "You are not an administrator."},
        status_code=403,
    )


def _redirected(value) -> bool:
    """True when a gate returned a response instead of a session dict."""
    return not isinstance(value, dict)


# --- shared page furniture -------------------------------------------------


async def _nav_counts(conn, session) -> dict:
    """Badge counts for the sidebar. Cheap queries; the sidebar is on every page."""
    counts = {
        "my_grants": await conn.fetchval(
            """SELECT count(*) FROM grants
                WHERE subject_type = 'principal' AND principal_id = $1""",
            session["principal_id"],
        ),
        "my_keys": await conn.fetchval(
            "SELECT count(*) FROM api_keys WHERE principal_id = $1 AND revoked_at IS NULL",
            session["principal_id"],
        ),
        "my_clients": await conn.fetchval(
            """SELECT count(*) FROM oauth_clients
                WHERE principal_id = $1 AND disabled_at IS NULL""",
            session["principal_id"],
        ),
        "my_services": await conn.fetchval(
            "SELECT count(*) FROM principals WHERE owner_id = $1",
            session["principal_id"],
        ),
    }
    if session.get("is_admin"):
        counts["principals"] = await conn.fetchval("SELECT count(*) FROM principals")
        counts["upstreams"] = await conn.fetchval("SELECT count(*) FROM upstreams")
        counts["groups"] = await conn.fetchval("SELECT count(*) FROM groups")
        counts["grants"] = await conn.fetchval("SELECT count(*) FROM grants")
    return counts


async def _page(request, conn, session, template, active, context=None):
    payload = {
        "show_nav": True,
        "nav_active": active,
        "nav_counts": await _nav_counts(conn, session),
    }
    payload.update(context or {})
    return web.render(request, template, payload)


def connector_display(row) -> str:
    """`owner · name (device)` — how a connector reads in ADMIN views.

    Owner goes first because that's what an admin scans for: with several
    humans, every self-registered row otherwise says "claude.ai" and there's
    nothing to tell them apart. The device hint comes from the browser at
    first authorization (Q16) and covers the case where one person has three
    of them.
    """
    owner = row.get("username") or row.get("owner")
    name = row.get("label") or row.get("client_name") or "connector"
    device = row.get("device")
    parts = f"{owner} · {name}" if owner else name
    return f"{parts} ({device})" if device and not row.get("label") else parts


def _via(row) -> str:
    """How a call arrived — a client id or a key fragment."""
    if row.get("client_id"):
        return row["client_id"]
    if row.get("api_key_id"):
        return f"key {str(row['api_key_id'])[:8]}…"
    return "—"


# --- login / logout -------------------------------------------------------


@router.get("/login")
async def login_page(request: Request):
    return web.render(request, "login.html", {"action": "/ui/login"})


@router.post("/login")
async def login(request: Request):
    form = dict(await request.form())
    username = (form.get("username") or "").strip()
    ip = web.client_ip(request)

    if await web.login_rate_limited(ip):
        return web.render(
            request, "login.html",
            {"action": "/ui/login", "username": username,
             "error": "Too many attempts from this address. Try again shortly."},
            status_code=429,
        )

    pool = await db.pool()
    async with pool.acquire() as conn:
        outcome = await auth_backends.LOCAL.authenticate(
            conn, username,
            password=form.get("password", ""),
            totp_code=form.get("totp_code", ""),
        )
        await audit.record_auth_event(
            conn,
            event=audit.LOGIN_SUCCESS if outcome.ok else audit.LOGIN_FAILURE,
            outcome="ok" if outcome.ok else "failure",
            principal_id=outcome.principal_id,
            principal_label=outcome.username or username,
            backend=auth_backends.LOCAL.name,
            ip=ip,
            user_agent=web.user_agent(request),
            detail={"flow": "ui", "reason": outcome.reason},
        )

    if not outcome.ok:
        return web.render(
            request, "login.html",
            {"action": "/ui/login", "username": username,
             "error": _login_error(outcome.reason)},
            status_code=401,
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
    return RedirectResponse("/ui", status_code=302)


def _login_error(reason: str) -> str:
    # Every pre-auth failure — unknown user, wrong password, disabled, locked,
    # no local credentials — reads identically so the form leaks nothing about
    # which usernames exist or which accounts are locked (#66). The distinct
    # `reason` still lands in the audit detail. TOTP_REQUIRED is the sole
    # exception: it's only reachable AFTER a correct password, so it reveals no
    # account state and the form needs it to prompt for the second factor.
    if reason == auth_backends.TOTP_REQUIRED:
        return "Enter the code from your authenticator."
    return "Those credentials didn't work."


@router.get("/enroll_totp")
async def enroll_totp_page(
    request: Request, error: str | None = None, request_id: str | None = None
):
    session = web.get_session(request)
    if not session.get("principal_id") or not session.get("needs_totp_enrollment"):
        return RedirectResponse("/ui", status_code=302)

    from .routes_oauth import ENROLL_PREFIX
    secret = await cache.client().get(ENROLL_PREFIX + session["principal_id"])
    if not secret:
        secret = credentials.generate_totp_secret()
        await cache.client().setex(ENROLL_PREFIX + session["principal_id"], 900, secret)
    username = session.get("username") or ""
    # request_id keeps a pending OAuth authorize alive when a passkey login
    # lands on this gate mid-flow — /authorize/totp's _resume completes it.
    return web.render(
        request, "totp_enroll.html",
        {"action": "/authorize/totp", "next_url": "/ui", "secret": secret,
         "uri": credentials.totp_provisioning_uri(secret, username),
         "qr_svg": credentials.totp_qr_svg(secret, username),
         "request_id": request_id, "error": error},
    )


@router.get("/change_password")
async def change_password_page(
    request: Request, error: str | None = None, request_id: str | None = None
):
    session = web.get_session(request)
    if not session.get("principal_id") or not session.get("must_change_password"):
        return RedirectResponse("/ui", status_code=302)
    return web.render(
        request, "change_password.html",
        {"action": "/authorize/password", "next_url": "/ui",
         "request_id": request_id, "error": error},
    )


@router.get("/logout")
async def logout(request: Request):
    web.clear_session(request)
    return RedirectResponse("/ui/login", status_code=302)


# --- passkeys (PRD Q25) ----------------------------------------------------
#
# The ceremony endpoints are the first /ui routes to read a JSON body (the
# DCR endpoint is the precedent). CSRF posture: a JSON POST with an
# application/json content type forces a CORS preflight cross-origin, and
# torii runs no CORS middleware, so a hostile page can't drive these.
#
# Challenges are one-shot: stored in valkey with a short TTL and consumed
# with GETDEL, so a challenge can never be replayed even when verification
# then fails. Login challenges are keyed by a random ref (there is no
# principal yet in the usernameless flow); the ref names no user and is a
# capability for exactly one ceremony.

WEBAUTHN_REG_PREFIX = "torii:webauthn:reg:"
WEBAUTHN_LOGIN_PREFIX = "torii:webauthn:login:"
WEBAUTHN_CHALLENGE_TTL = 300


async def _json_body(request: Request) -> dict | None:
    try:
        body = await request.json()
        return body if isinstance(body, dict) else None
    except Exception:  # noqa: BLE001
        return None


@router.post("/webauthn/register/options.json")
async def passkey_register_options(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return JSONResponse({"error": "sign in first"}, status_code=401)

    pool = await db.pool()
    async with pool.acquire() as conn:
        challenge = await credentials.start_passkey_registration(
            conn, session["principal_id"], session["username"]
        )
    await cache.client().setex(
        WEBAUTHN_REG_PREFIX + session["principal_id"],
        WEBAUTHN_CHALLENGE_TTL,
        bytes_to_base64url(challenge.challenge),
    )
    return JSONResponse({"options": json.loads(challenge.options_json)})


@router.post("/webauthn/register/verify.json")
async def passkey_register_verify(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return JSONResponse({"error": "sign in first"}, status_code=401)

    body = await _json_body(request)
    if body is None or not isinstance(body.get("credential"), dict):
        return JSONResponse({"error": "malformed request"}, status_code=400)

    stored = await cache.client().getdel(WEBAUTHN_REG_PREFIX + session["principal_id"])
    if not stored:
        return JSONResponse({"error": "That took too long — try again."}, status_code=401)

    name = (body.get("name") or "").strip() \
        or useragent.describe(web.user_agent(request)) or "passkey"

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            created = await credentials.register_passkey(
                conn, session["principal_id"], name,
                json.dumps(body["credential"]),
                base64url_to_bytes(stored if isinstance(stored, str) else stored.decode()),
            )
        except credentials.CredentialError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        await audit.record_auth_event(
            conn, event=audit.PASSKEY_ENROLLED,
            principal_id=session["principal_id"], principal_label=session["username"],
            backend="local", ip=web.client_ip(request),
            user_agent=web.user_agent(request),
            detail={"name": created["name"]},
        )
    return JSONResponse({"ok": True, "name": created["name"]})


@router.post("/webauthn/login/options.json")
async def passkey_login_options(request: Request):
    ip = web.client_ip(request)
    if await web.login_rate_limited(ip):
        return JSONResponse(
            {"error": "Too many attempts from this address. Try again shortly."},
            status_code=429,
        )
    challenge = credentials.start_passkey_login()
    ref = secrets.token_urlsafe(24)
    await cache.client().setex(
        WEBAUTHN_LOGIN_PREFIX + ref,
        WEBAUTHN_CHALLENGE_TTL,
        bytes_to_base64url(challenge.challenge),
    )
    return JSONResponse({"ref": ref, "options": json.loads(challenge.options_json)})


@router.post("/webauthn/login/verify.json")
async def passkey_login_verify(request: Request):
    ip = web.client_ip(request)
    if await web.login_rate_limited(ip):
        return JSONResponse(
            {"error": "Too many attempts from this address. Try again shortly."},
            status_code=429,
        )

    body = await _json_body(request)
    if body is None or not isinstance(body.get("ref"), str) \
            or not isinstance(body.get("credential"), dict):
        return JSONResponse({"error": "malformed request"}, status_code=400)

    stored = await cache.client().getdel(WEBAUTHN_LOGIN_PREFIX + body["ref"])
    if not stored:
        # Expired AND replayed land here on purpose — one indistinct answer.
        return JSONResponse({"error": "That took too long — try again."}, status_code=401)
    challenge = base64url_to_bytes(stored if isinstance(stored, str) else stored.decode())

    request_id = body.get("request_id") or None
    pool = await db.pool()
    async with pool.acquire() as conn:
        outcome = await credentials.authenticate_passkey(
            conn, json.dumps(body["credential"]), challenge
        )
        await audit.record_auth_event(
            conn,
            event=audit.LOGIN_SUCCESS if outcome.ok else audit.LOGIN_FAILURE,
            outcome="ok" if outcome.ok else "failure",
            principal_id=outcome.principal_id,
            principal_label=outcome.username,
            backend="local",
            ip=ip,
            user_agent=web.user_agent(request),
            detail={"flow": "authorize" if request_id else "ui",
                    "method": "passkey", "reason": outcome.reason,
                    "credential": outcome.credential_name},
        )

        if not outcome.ok:
            # unknown_credential and bad_passkey read identically out here —
            # the login page is an enumeration surface.
            message = "This account is disabled." \
                if outcome.reason == credentials.PASSKEY_DISABLED \
                else "That passkey didn't work."
            return JSONResponse({"error": message}, status_code=401)

        web.set_session(
            request,
            principal_id=outcome.principal_id,
            username=outcome.username,
            is_admin=outcome.is_admin,
            backend="local",
            needs_totp_enrollment=outcome.needs_totp_enrollment,
            must_change_password=outcome.must_change_password,
        )

        suffix = f"?request_id={request_id}" if request_id else ""
        if outcome.needs_totp_enrollment:
            return JSONResponse({"redirect": f"/ui/enroll_totp{suffix}"})
        if outcome.must_change_password:
            return JSONResponse({"redirect": f"/ui/change_password{suffix}"})
        if request_id:
            # Route through the consent step (Q26) rather than completing here;
            # the flow nonce set at GET /authorize is checked there.
            return JSONResponse({"redirect": f"/authorize/consent?request_id={request_id}"})
    return JSONResponse({"redirect": "/ui"})


@router.post("/account/webauthn/{cred_id}/delete")
async def delete_own_passkey(request: Request, cred_id: str):
    session = _require_login(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """DELETE FROM webauthn_credentials
                WHERE id = $1 AND principal_id = $2
               RETURNING name""",
            cred_id, session["principal_id"],
        )
        if row is None:
            return _forbidden(request)
        await audit.record_auth_event(
            conn, event=audit.PASSKEY_REVOKED,
            principal_id=session["principal_id"], principal_label=session["username"],
            backend="local", ip=web.client_ip(request),
            detail={"via": "self", "name": row["name"]},
        )
    return RedirectResponse("/ui/account", status_code=303)


@router.post("/admin/principals/{principal_id}/webauthn/{cred_id}/revoke")
async def admin_revoke_passkey(request: Request, principal_id: str, cred_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """DELETE FROM webauthn_credentials
                WHERE id = $1 AND principal_id = $2
               RETURNING name""",
            cred_id, principal_id,
        )
        if row is not None:
            await audit.record_auth_event(
                conn, event=audit.PASSKEY_REVOKED,
                principal_id=principal_id,
                backend="local", ip=web.client_ip(request),
                detail={"via": "admin", "by": session["username"], "name": row["name"]},
            )
    return RedirectResponse(f"/ui/admin/principals/{principal_id}", status_code=303)


# --- self-service: overview -----------------------------------------------


@router.get("")
@router.get("/")
async def overview(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session

    caller = rbac.Caller(principal_id=session["principal_id"], username=session["username"])
    pool = await db.pool()
    async with pool.acquire() as conn:
        granted = await rbac.effective_grants(conn, caller)
        counts = {
            "servers": len(granted),
            # Ask the upstreams for the real number. An `all` grant carries no
            # tool names, so counting only the explicit ones reported 0 for a
            # caller who could reach everything.
            "tools": await proxy.granted_tool_count(conn, granted, scope=session["principal_id"]),
            # NOT "keys"/"items"/"values": those are dict methods, and Jinja's
            # `counts.keys` resolves to the method rather than the value.
            "api_keys": await conn.fetchval(
                "SELECT count(*) FROM api_keys WHERE principal_id = $1 AND revoked_at IS NULL",
                session["principal_id"],
            ),
            "connectors": await conn.fetchval(
                """SELECT count(*) FROM oauth_clients
                    WHERE principal_id = $1 AND disabled_at IS NULL""",
                session["principal_id"],
            ),
        }
        recent = [
            dict(r) | {"via": _via(dict(r))}
            for r in await conn.fetch(
                """SELECT ts, upstream_name, tool_name, outcome, error_code,
                          client_id, api_key_id
                     FROM audit_calls WHERE principal_id = $1
                    ORDER BY id DESC LIMIT 8""",
                session["principal_id"],
            )
        ]
        public_count = await conn.fetchval(
            "SELECT count(*) FROM upstreams WHERE public_listed = TRUE"
        )
        return await _page(
            request, conn, session, "pages/overview.html", "overview",
            {"counts": counts, "recent": recent, "public_count": public_count},
        )


@router.get("/grants")
async def my_grants(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session

    caller = rbac.Caller(principal_id=session["principal_id"], username=session["username"])
    pool = await db.pool()
    async with pool.acquire() as conn:
        # The resolver's own answer, not a hand-rolled second query — this page
        # would be worse than useless if it disagreed with the gateway.
        resolved = await rbac.effective_grants(conn, caller)
        grants = [
            (name, "all" if scope.all_tools else sorted(scope.tools))
            for name, scope in sorted(resolved.items())
        ]

        # …and where each one came from. A group grant that can't be traced
        # back to its group is a grant nobody can debug.
        memberships = [r["name"] for r in await conn.fetch(
            """SELECT gr.name FROM group_members m JOIN groups gr ON gr.id = m.group_id
                WHERE m.principal_id = $1 ORDER BY gr.name""",
            session["principal_id"],
        )]
        sources: dict[str, list[str]] = {}
        for row in await conn.fetch(
            """SELECT u.name AS upstream, g.subject_type, g.group_name
                 FROM grants g JOIN upstreams u ON u.id = g.upstream_id
                WHERE (g.subject_type = 'principal' AND g.principal_id = $1)
                   OR (g.subject_type = 'group' AND g.group_name = ANY($2::text[]))
                ORDER BY u.name""",
            session["principal_id"], memberships,
        ):
            label = (
                "direct" if row["subject_type"] == "principal"
                else f"via group {row['group_name']}"
            )
            sources.setdefault(row["upstream"], []).append(label)
        narrowed = [
            dict(r) for r in await conn.fetch(
                """SELECT c.client_name, c.label, u.name AS upstream_name,
                          g.tool_scope, g.tools
                     FROM grants g
                     JOIN oauth_clients c ON c.client_id = g.client_id
                     JOIN upstreams u ON u.id = g.upstream_id
                    WHERE g.subject_type = 'client' AND c.principal_id = $1
                    ORDER BY c.client_name, u.name""",
                session["principal_id"],
            )
        ]
        return await _page(
            request, conn, session, "pages/my_grants.html", "my-grants",
            {"grants": grants, "narrowed": narrowed,
             "memberships": memberships, "sources": sources},
        )


# --- self-service: keys ---------------------------------------------------


async def _keys_page(request, session, minted=None, notice=None, error=None):
    caller = rbac.Caller(principal_id=session["principal_id"], username=session["username"])
    pool = await db.pool()
    async with pool.acquire() as conn:
        keys = [dict(r) for r in await conn.fetch(
            """SELECT k.id, k.name, k.key_prefix, k.created_at, k.last_used_at,
                      k.access_mode, k.rate_limit_per_min,
                      COALESCE(
                          array_agg(u.name ORDER BY u.name)
                              FILTER (WHERE u.name IS NOT NULL),
                          '{}'
                      ) AS scoped_to
                 FROM api_keys k
                 LEFT JOIN grants g
                        ON g.subject_type = 'key' AND g.api_key_id = k.id
                 LEFT JOIN upstreams u ON u.id = g.upstream_id
                WHERE k.principal_id = $1 AND k.revoked_at IS NULL
             GROUP BY k.id
             ORDER BY k.created_at DESC""",
            session["principal_id"],
        )]
        # Only offer servers the caller can actually reach: a key grant is
        # intersected with the baseline, so offering more would be a lie.
        granted = await rbac.effective_grants(conn, caller)
        my_servers = [
            {"name": r["name"], "title": r["display_name"] or r["name"]}
            for r in await conn.fetch(
                """SELECT name, display_name FROM upstreams
                    WHERE name = ANY($1::text[]) ORDER BY name""",
                list(granted),
            )
        ] if granted else []
        return await _page(
            request, conn, session, "pages/keys.html", "keys",
            {"keys": keys, "minted": minted, "notice": notice, "error": error,
             "my_servers": my_servers},
        )


@router.get("/keys")
async def keys_page(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session
    return await _keys_page(request, session)


@router.post("/keys")
async def create_key(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session
    form = await request.form()
    name = (form.get("name") or "").strip() or "unnamed"
    # Which servers this key may reach. Empty = inherit everything the
    # principal can reach (the previous behaviour, and still the default).
    scope_to = [s for s in form.getlist("scope_to") if s]

    pool = await db.pool()
    async with pool.acquire() as conn:
        key = await credentials.mint_api_key(
            conn, session["principal_id"], name,
            created_by=session["principal_id"],
            narrowed=bool(scope_to),
        )
        if scope_to:
            caller = rbac.Caller(
                principal_id=session["principal_id"], username=session["username"]
            )
            granted = await rbac.effective_grants(conn, caller)
            for server in scope_to:
                # Refuse to write a grant for something the caller can't reach.
                # Harmless either way (the resolver intersects), but a row that
                # promises access the owner doesn't have is a confusing lie.
                if server not in granted:
                    continue
                upstream_id = await conn.fetchval(
                    "SELECT id FROM upstreams WHERE name = $1", server
                )
                await conn.execute(
                    """INSERT INTO grants (subject_type, api_key_id, upstream_id,
                                           tool_scope, created_by)
                       VALUES ('key', $1::uuid, $2, 'all', $3)""",
                    key.id, upstream_id, session["principal_id"],
                )
        await audit.record_auth_event(
            conn, event=audit.KEY_CREATED,
            principal_id=session["principal_id"], principal_label=session["username"],
            api_key_id=key.id,
            detail={"name": name, "via": "self", "scoped_to": scope_to or "inherit"},
        )
    return await _keys_page(request, session, minted=key.secret)


@router.post("/keys/{key_id}/rate_limit")
async def set_key_rate_limit(request: Request, key_id: str):
    """Tighten (or clear) a key's own calls-per-minute ceiling.

    Self-service because it can only ever reduce risk: a lower number on your
    own key can't grant anything, and the default already applies if it's
    cleared.
    """
    session = _require_login(request)
    if _redirected(session):
        return session
    form = dict(await request.form())
    raw = (form.get("rate_limit_per_min") or "").strip()
    try:
        limit = int(raw) if raw else None
    except ValueError:
        return await _keys_page(request, session, error="Give a whole number of calls per minute.")
    if limit is not None and limit < 1:
        return await _keys_page(request, session, error="A limit has to be at least 1.")

    pool = await db.pool()
    async with pool.acquire() as conn:
        if not await conn.fetchval(
            "SELECT 1 FROM api_keys WHERE id = $1 AND principal_id = $2",
            key_id, session["principal_id"],
        ):
            return _forbidden(request)
        await conn.execute(
            "UPDATE api_keys SET rate_limit_per_min = $2 WHERE id = $1", key_id, limit
        )
    return RedirectResponse("/ui/keys", status_code=303)


@router.post("/keys/{key_id}/rotate")
async def rotate_key(request: Request, key_id: str):
    session = _require_login(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        if not await conn.fetchval(
            "SELECT 1 FROM api_keys WHERE id = $1 AND principal_id = $2",
            key_id, session["principal_id"],
        ):
            return _forbidden(request)
        new = await credentials.rotate_api_key(conn, key_id, actor_id=session["principal_id"])
        await audit.record_auth_event(
            conn, event=audit.KEY_ROTATED,
            principal_id=session["principal_id"], principal_label=session["username"],
            api_key_id=new.id, detail={"via": "self"},
        )
    return await _keys_page(request, session, minted=new.secret)


@router.post("/keys/{key_id}/revoke")
async def revoke_key(request: Request, key_id: str):
    session = _require_login(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        if not await conn.fetchval(
            "SELECT 1 FROM api_keys WHERE id = $1 AND principal_id = $2",
            key_id, session["principal_id"],
        ):
            return _forbidden(request)
        if await credentials.revoke_api_key(conn, key_id, reason="user_revoked"):
            await audit.record_auth_event(
                conn, event=audit.KEY_REVOKED,
                principal_id=session["principal_id"], principal_label=session["username"],
                api_key_id=key_id, detail={"via": "self"},
            )
    return RedirectResponse("/ui/keys", status_code=303)


# --- self-service: connectors --------------------------------------------


@router.get("/connectors")
async def connectors(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session
    return await _connectors_page(request, session)


async def _connectors_page(request, session, minted=None, error=None):
    caller = rbac.Caller(principal_id=session["principal_id"], username=session["username"])
    pool = await db.pool()
    async with pool.acquire() as conn:
        clients = [dict(r) for r in await conn.fetch(
            """SELECT c.client_id, c.client_name, c.label, c.last_seen_at,
                      c.access_mode, c.registered_via, c.created_at,
                      c.first_seen_user_agent, c.first_seen_ip,
                      count(DISTINCT t.id) FILTER (
                          WHERE t.revoked_at IS NULL AND t.expires_at > now()
                      ) AS tokens,
                      count(DISTINCT g.id) AS grant_count
                 FROM oauth_clients c
                 LEFT JOIN tokens t ON t.client_id = c.client_id
                 LEFT JOIN grants g ON g.client_id = c.client_id
                WHERE c.principal_id = $1 AND c.disabled_at IS NULL
             GROUP BY c.client_id ORDER BY c.client_name""",
            session["principal_id"],
        )]
        for row in clients:
            row["device"] = useragent.describe(row.get("first_seen_user_agent"))
            row["scope"] = {
                g["name"]: (list(g["tools"]) if g["tool_scope"] == "list" else "all")
                for g in await conn.fetch(
                    """SELECT u.name, g.tool_scope, g.tools
                         FROM grants g JOIN upstreams u ON u.id = g.upstream_id
                        WHERE g.subject_type = 'client' AND g.client_id = $1""",
                    row["client_id"],
                )
            }

        # The per-server connector URLs the caller can actually use. Built
        # from effective grants rather than the upstream table, so this page
        # never advertises an endpoint that would answer with an empty list.
        granted = await rbac.effective_grants(conn, caller)
        my_servers = [
            {"name": r["name"], "title": r["display_name"] or r["name"]}
            for r in await conn.fetch(
                """SELECT name, display_name FROM upstreams
                    WHERE name = ANY($1::text[]) ORDER BY name""",
                list(granted),
            )
        ] if granted else []
        narrow_new = await conn.fetchval(
            "SELECT narrow_new_clients FROM principals WHERE id = $1",
            session["principal_id"],
        )
        return await _page(
            request, conn, session, "pages/connectors.html", "connectors",
            {"clients": clients, "my_servers": my_servers, "minted": minted,
             "error": error, "narrow_new": narrow_new},
        )


@router.post("/connectors/provision")
async def provision_connector(request: Request):
    """Create a confidential client (id + secret) from the UI (Q14).

    Stable identity is the point: a DCR client gets a new id every time a
    connector is re-added, which drops its narrowing. One provisioned here
    keeps its grants across re-adds, and its secret means a stolen refresh
    token can't be redeemed alone.
    """
    session = _require_login(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    name = (form.get("client_name") or "").strip() or "claude.ai"
    label = (form.get("label") or "").strip()
    redirect_raw = (form.get("redirect_uris") or "").strip()
    redirect_uris = [u.strip() for u in redirect_raw.replace(",", " ").split() if u.strip()]
    if not redirect_uris:
        # What claude.ai web/mobile use; an Office add-in or a CLI needs its own.
        redirect_uris = ["https://claude.ai/api/mcp/auth_callback"]

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            oauth._validate_redirect_uris(redirect_uris)
        except oauth.OAuthError as exc:
            return await _connectors_page(request, session, error=exc.description)
        minted = await credentials.mint_oauth_client(
            conn, session["principal_id"], name, redirect_uris,
            label=label or None, narrowed=bool(form.get("narrowed")),
        )
        await audit.record_auth_event(
            conn, event=audit.DCR_REGISTERED,
            principal_id=session["principal_id"], principal_label=session["username"],
            client_id=minted.client_id,
            detail={"via": "ui", "label": label, "access_mode": minted.access_mode},
        )
    return await _connectors_page(request, session, minted=minted)


@router.get("/tools.json")
async def my_tools(request: Request, server: str):
    """Tools on a server the CALLER can reach, for the scope pickers.

    The admin discovery endpoint answers for any server; this one answers only
    for servers in the caller's own effective grants, and filters the list to
    the tools they actually hold. Otherwise the picker would advertise tools a
    user can't delegate, and every tick would be silently dropped.
    """
    session = _require_login(request)
    if _redirected(session):
        return session

    caller = rbac.Caller(principal_id=session["principal_id"], username=session["username"])
    pool = await db.pool()
    async with pool.acquire() as conn:
        granted = await rbac.effective_grants(conn, caller)
        scope = granted.get(server)
        if scope is None:
            return JSONResponse({"error": "you cannot reach that server"}, status_code=403)

        upstream = await proxy.load_upstream(conn, server)
        if upstream is None or not upstream.enabled:
            return JSONResponse({"error": "server unavailable", "tools": []}, status_code=502)
        try:
            result = await proxy.call_upstream(upstream, "tools/list", {})
        except proxy.UpstreamError as exc:
            return JSONResponse({"error": f"{exc.kind}: {exc.detail}"[:200], "tools": []},
                                status_code=502)

    tools = [
        {
            "name": tool["name"],
            "description": (tool.get("description") or "").strip(),
            "read_only": (tool.get("annotations") or {}).get("readOnlyHint"),
        }
        for tool in (result.get("tools") or [])
        if tool.get("name") and scope.contains(tool["name"])
    ]
    return JSONResponse({"server": server, "tools": tools})


@router.post("/connectors/{client_id}/scope")
async def set_connector_scope(request: Request, client_id: str):
    """Say what a limited connector may reach — self-service (Q21).

    Safe for a user to do because the resolver intersects: these grants bound
    the connector BELOW the owner's own access and can never extend it. Setting
    a scope also marks the connector limited, since picking servers and then
    leaving it inheriting everything is never what anyone meant.
    """
    session = _require_login(request)
    if _redirected(session):
        return session

    form = await request.form()
    servers = [s for s in form.getlist("scope_to") if s]
    # tools:<server> checkboxes refine a server to specific tools.
    per_server_tools: dict[str, list[str]] = {}
    for field, value in form.multi_items():
        if field.startswith("tools:") and value:
            per_server_tools.setdefault(field.split(":", 1)[1], []).append(value)

    caller = rbac.Caller(principal_id=session["principal_id"], username=session["username"])
    pool = await db.pool()
    async with pool.acquire() as conn:
        owned = await conn.fetchval(
            "SELECT 1 FROM oauth_clients WHERE client_id = $1 AND principal_id = $2",
            client_id, session["principal_id"],
        )
        if not owned:
            return _forbidden(request)

        granted = await rbac.effective_grants(conn, caller)

        # Replace rather than accumulate, so what the form shows is what the
        # resolver sees — the same reasoning as one grant row per subject.
        await conn.execute(
            "DELETE FROM grants WHERE subject_type = 'client' AND client_id = $1", client_id
        )
        for server in servers:
            if server not in granted:
                continue          # never write a grant that outruns the owner
            upstream_id = await conn.fetchval(
                "SELECT id FROM upstreams WHERE name = $1", server
            )
            tools = [t for t in per_server_tools.get(server, []) if t]
            await conn.execute(
                """INSERT INTO grants (subject_type, client_id, upstream_id,
                                       tool_scope, tools, created_by)
                   VALUES ('client', $1, $2, $3, $4, $5)""",
                client_id, upstream_id,
                "list" if tools else "all", tools, session["principal_id"],
            )

        await conn.execute(
            "UPDATE oauth_clients SET access_mode = 'narrowed', updated_at = now() "
            "WHERE client_id = $1",
            client_id,
        )
        await audit.record_auth_event(
            conn, event=audit.CLIENT_ACCESS_MODE_CHANGED,
            principal_id=session["principal_id"], principal_label=session["username"],
            client_id=client_id,
            detail={"access_mode": "narrowed", "servers": servers,
                    "tools": per_server_tools, "via": "self"},
        )
    return RedirectResponse("/ui/connectors", status_code=303)


@router.post("/connectors/{client_id}/access_mode")
async def set_client_access_mode(request: Request, client_id: str):
    """Limit a connector to its own grants, or let it inherit the baseline.

    Self-service is safe by construction: the resolver INTERSECTS client grants
    with the principal's baseline, so a user can only ever reduce their own
    reach this way, never extend it.
    """
    session = _require_login(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        owned = await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = $1 AND principal_id = $2",
            client_id, session["principal_id"],
        )
        if owned is None:
            return _forbidden(request)
        new_mode = "inherit" if owned == "narrowed" else "narrowed"
        await conn.execute(
            "UPDATE oauth_clients SET access_mode = $2, updated_at = now() WHERE client_id = $1",
            client_id, new_mode,
        )
        await audit.record_auth_event(
            conn, event=audit.CLIENT_ACCESS_MODE_CHANGED,
            principal_id=session["principal_id"], principal_label=session["username"],
            client_id=client_id, detail={"access_mode": new_mode, "via": "self"},
        )
    return RedirectResponse("/ui/connectors", status_code=303)


@router.post("/connectors/{client_id}/rename")
async def rename_connector(request: Request, client_id: str):
    """Name a connector something recognisable (Q16).

    Every claude.ai surface self-registers as "claude.ai", so without a label
    a phone and a desktop are indistinguishable rows.
    """
    session = _require_login(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    label = (form.get("label") or "").strip()[:60]
    pool = await db.pool()
    async with pool.acquire() as conn:
        owned = await conn.fetchval(
            "SELECT 1 FROM oauth_clients WHERE client_id = $1 AND principal_id = $2",
            client_id, session["principal_id"],
        )
        if not owned:
            return _forbidden(request)
        await conn.execute(
            "UPDATE oauth_clients SET label = NULLIF($2, ''), updated_at = now() WHERE client_id = $1",
            client_id, label,
        )
    return RedirectResponse("/ui/connectors", status_code=303)


@router.post("/clients/{client_id}/revoke")
async def revoke_own_client(request: Request, client_id: str):
    session = _require_login(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        if not await conn.fetchval(
            "SELECT 1 FROM oauth_clients WHERE client_id = $1 AND principal_id = $2",
            client_id, session["principal_id"],
        ):
            return _forbidden(request)
        await conn.execute(
            "UPDATE oauth_clients SET disabled_at = now() WHERE client_id = $1", client_id
        )
        killed = await credentials.revoke_client_tokens(conn, client_id, reason="user_revoked")
        await audit.record_auth_event(
            conn, event=audit.CLIENT_DISABLED,
            principal_id=session["principal_id"], principal_label=session["username"],
            client_id=client_id, detail={"tokens_killed": killed, "via": "self"},
        )
    return RedirectResponse("/ui/connectors", status_code=303)


# --- self-service: my service identities (Q17) ---------------------------


async def _services_page(request, session, minted=None, notice=None, error=None):
    caller = rbac.Caller(principal_id=session["principal_id"], username=session["username"])
    pool = await db.pool()
    async with pool.acquire() as conn:
        services = [dict(r) for r in await conn.fetch(
            """SELECT p.id, p.username, p.disabled_at,
                      COALESCE(
                          array_agg(DISTINCT u.name) FILTER (WHERE u.name IS NOT NULL),
                          '{}'
                      ) AS reaches
                 FROM principals p
                 LEFT JOIN grants g
                        ON g.subject_type = 'principal' AND g.principal_id = p.id
                 LEFT JOIN upstreams u ON u.id = g.upstream_id
                WHERE p.owner_id = $1
             GROUP BY p.id
             ORDER BY p.username""",
            session["principal_id"],
        )]
        # Each service's live keys, listed rather than counted: the same
        # service deployed twice needs two separately revocable credentials
        # (#39), and you can't revoke one you can't see.
        for service in services:
            # NOT "keys": Jinja resolves `service.keys` to the dict METHOD.
            service["live_keys"] = [dict(r) for r in await conn.fetch(
                """SELECT id, name, key_prefix, created_at, last_used_at,
                          rate_limit_per_min
                     FROM api_keys
                    WHERE principal_id = $1 AND revoked_at IS NULL
                    ORDER BY created_at""",
                service["id"],
            )]
        granted = await rbac.effective_grants(conn, caller)
        my_servers = [
            {"name": r["name"], "title": r["display_name"] or r["name"]}
            for r in await conn.fetch(
                """SELECT name, display_name FROM upstreams
                    WHERE name = ANY($1::text[]) ORDER BY name""",
                list(granted),
            )
        ] if granted else []
        return await _page(
            request, conn, session, "pages/services.html", "services",
            {"services": services, "my_servers": my_servers, "minted": minted,
             "notice": notice, "error": error},
        )


@router.get("/services")
async def services(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session
    return await _services_page(request, session)


@router.post("/services")
async def create_service(request: Request):
    """Provision a service identity under your own account.

    Safe to self-serve because a delegated service is bounded by its owner: it
    can never reach anything you can't, and it stops working if you're
    disabled (Q17). Access beyond your own still needs an admin, who can
    detach it into an independent service.
    """
    session = _require_login(request)
    if _redirected(session):
        return session

    form = await request.form()
    raw_name = (form.get("name") or "").strip().lower()
    # Same shape as any principal username, and namespaced under the owner so
    # two people can both have an "inventory-bot".
    slug = re.sub(r"[^a-z0-9-]+", "-", raw_name).strip("-")[:40]
    if not slug:
        return await _services_page(request, session, error="Give it a name.")
    username = f"{session['username']}/{slug}"
    reach = [r for r in form.getlist("reaches") if r]

    pool = await db.pool()
    async with pool.acquire() as conn:
        caller = rbac.Caller(
            principal_id=session["principal_id"], username=session["username"]
        )
        granted = await rbac.effective_grants(conn, caller)
        try:
            service_id = await conn.fetchval(
                """INSERT INTO principals (kind, username, owner_id)
                   VALUES ('service', $1, $2) RETURNING id""",
                username, session["principal_id"],
            )
        except Exception as exc:  # noqa: BLE001
            return await _services_page(request, session, error=f"Could not create: {exc}")

        for server in reach:
            if server not in granted:
                continue        # never write a grant that outruns the owner
            upstream_id = await conn.fetchval(
                "SELECT id FROM upstreams WHERE name = $1", server
            )
            await conn.execute(
                """INSERT INTO grants (subject_type, principal_id, upstream_id,
                                       tool_scope, created_by)
                   VALUES ('principal', $1, $2, 'all', $3)""",
                service_id, upstream_id, session["principal_id"],
            )

        key = await credentials.mint_api_key(
            conn, service_id, "default", created_by=session["principal_id"]
        )
        await audit.record_auth_event(
            conn, event=audit.KEY_CREATED,
            principal_id=service_id, principal_label=username,
            api_key_id=key.id,
            detail={"via": "self-service", "owner": session["username"], "reaches": reach},
        )
    return await _services_page(
        request, session, minted=key.secret,
        notice=f"Created {username}. Its key is shown once, below.",
    )


async def _owned_service(conn, session, service_id):
    return await conn.fetchval(
        """SELECT username FROM principals
            WHERE id::text = $1 AND owner_id = $2 AND kind = 'service'""",
        service_id, session["principal_id"],
    )


@router.post("/services/{service_id}/key")
async def issue_service_key(request: Request, service_id: str):
    """Add a key to a service (#39).

    Additive, not rotating. The same service deployed twice — a laptop and a
    Pi, prod and staging — needs credentials that can be revoked
    independently; issuing one used to revoke the others, which forced a
    redeploy of the innocent one. "Replace all" is still available as its own
    action for the single-deployment case.
    """
    session = _require_login(request)
    if _redirected(session):
        return session
    form = dict(await request.form())
    name = (form.get("name") or "").strip()[:60] or "default"
    replace = bool(form.get("replace"))

    pool = await db.pool()
    async with pool.acquire() as conn:
        username = await _owned_service(conn, session, service_id)
        if username is None:
            return _forbidden(request)
        if replace:
            await conn.execute(
                """UPDATE api_keys SET revoked_at = now(), revoked_reason = 'replaced'
                    WHERE principal_id = $1::uuid AND revoked_at IS NULL""",
                service_id,
            )
        key = await credentials.mint_api_key(
            conn, service_id, name, created_by=session["principal_id"]
        )
        await audit.record_auth_event(
            conn,
            event=audit.KEY_ROTATED if replace else audit.KEY_CREATED,
            principal_id=service_id, principal_label=username,
            api_key_id=key.id,
            detail={"via": "self-service", "owner": session["username"],
                    "name": name, "replaced_others": replace},
        )
    return await _services_page(request, session, minted=key.secret)


@router.post("/services/{service_id}/key/{key_id}/revoke")
async def revoke_service_key(request: Request, service_id: str, key_id: str):
    """Revoke one of a service's keys, leaving its others working."""
    session = _require_login(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        username = await _owned_service(conn, session, service_id)
        if username is None:
            return _forbidden(request)
        # Belongs to THIS service, not merely to a service you own.
        if not await conn.fetchval(
            "SELECT 1 FROM api_keys WHERE id = $1::uuid AND principal_id = $2::uuid",
            key_id, service_id,
        ):
            return _forbidden(request)
        if await credentials.revoke_api_key(conn, key_id, reason="owner_revoked"):
            await audit.record_auth_event(
                conn, event=audit.KEY_REVOKED,
                principal_id=service_id, principal_label=username,
                api_key_id=key_id,
                detail={"via": "self-service", "owner": session["username"]},
            )
    return RedirectResponse("/ui/services", status_code=303)


@router.post("/services/{service_id}/delete")
async def delete_service(request: Request, service_id: str):
    session = _require_login(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        username = await _owned_service(conn, session, service_id)
        if username is None:
            return _forbidden(request)
        await conn.execute("DELETE FROM principals WHERE id = $1::uuid", service_id)
    return RedirectResponse("/ui/services", status_code=303)


# --- self-service: account -----------------------------------------------


async def _account_page(request, session, error=None, notice=None):
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT p.totp_required, (i.totp_secret IS NOT NULL) AS enrolled
                 FROM principals p
                 LEFT JOIN auth_identities i
                        ON i.principal_id = p.id AND i.backend = 'local'
                WHERE p.id = $1""",
            session["principal_id"],
        )
        passkeys = [dict(r) for r in await conn.fetch(
            """SELECT id, name, created_at, last_used_at, backed_up
                 FROM webauthn_credentials
                WHERE principal_id = $1 ORDER BY created_at""",
            session["principal_id"],
        )]
        return await _page(
            request, conn, session, "pages/account.html", None,
            {"totp_required": row["totp_required"] if row else False,
             "totp_enrolled": row["enrolled"] if row else False,
             "passkeys": passkeys,
             "error": error, "notice": notice},
        )


@router.get("/account")
async def account(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session
    return await _account_page(request, session)


@router.post("/account/password")
async def change_own_password(request: Request):
    session = _require_login(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    current = form.get("current", "")
    password = form.get("password", "")

    if password != form.get("confirm", ""):
        return await _account_page(request, session, error="Those don't match.")
    if len(password) < 12:
        return await _account_page(request, session, error="Use at least 12 characters.")

    pool = await db.pool()
    async with pool.acquire() as conn:
        stored = await conn.fetchval(
            """SELECT password_hash FROM auth_identities
                WHERE principal_id = $1 AND backend = 'local'""",
            session["principal_id"],
        )
        # Requiring the current password is what stops a stolen session from
        # locking the owner out of their own account.
        if not credentials.verify_password(current, stored or ""):
            await audit.record_auth_event(
                conn, event=audit.LOGIN_FAILURE, outcome="failure",
                principal_id=session["principal_id"], principal_label=session["username"],
                backend="local", ip=web.client_ip(request),
                detail={"flow": "change_password", "reason": "bad_current_password"},
            )
            return await _account_page(
                request, session, error="That current password isn't right."
            )
        try:
            new_hash = credentials.hash_password(password)
        except credentials.PasswordTooLong:
            return await _account_page(
                request, session, error="That password is too long (72 bytes max)."
            )
        await conn.execute(
            """UPDATE auth_identities
                  SET password_hash = $2, password_is_temp = FALSE, updated_at = now()
                WHERE principal_id = $1 AND backend = 'local'""",
            session["principal_id"], new_hash,
        )
        # "I changed my password because I was compromised" must actually cut
        # the attacker off: revoke this principal's tokens and stamp the session
        # cutoff so every OTHER live cookie stops validating (#67).
        new_after = await conn.fetchval(
            """UPDATE principals SET sessions_valid_after = now(), updated_at = now()
                WHERE id = $1 RETURNING EXTRACT(EPOCH FROM sessions_valid_after)""",
            session["principal_id"],
        )
        revoked = await credentials.revoke_principal_tokens(
            conn, session["principal_id"], reason="password_changed"
        )
        await audit.record_auth_event(
            conn, event=audit.PASSWORD_CHANGED, principal_id=session["principal_id"],
            principal_label=session["username"], backend="local", ip=web.client_ip(request),
            detail={"tokens_revoked": revoked, "sessions": "revoked"},
        )
    # Keep THIS session alive: re-issue it with issued_at == the cutoff we just
    # set (same DB now()), so it isn't caught by its own revocation. float() so
    # it survives JSON serialization into the cookie (EXTRACT returns Decimal).
    web.set_session(request, **{**web.get_session(request), "issued_at": float(new_after)})
    return await _account_page(request, session, notice="Password updated.")


@router.post("/account/narrow_new_clients")
async def toggle_narrow_new_clients(request: Request):
    """Opt in to every newly registered connector starting with no access.

    Safer, not zero-touch: a new connector shows an empty tool list until its
    owner grants it something. That's the trade, so it's a choice.
    """
    session = _require_login(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE principals
                  SET narrow_new_clients = NOT narrow_new_clients, updated_at = now()
                WHERE id = $1""",
            session["principal_id"],
        )
    return RedirectResponse("/ui/connectors", status_code=303)


@router.post("/account/totp/start")
async def start_own_totp(request: Request):
    """Voluntary enrollment for someone TOTP isn't required for."""
    session = _require_login(request)
    if _redirected(session):
        return session

    raw = web.get_session(request)
    raw["needs_totp_enrollment"] = True
    web.set_session(request, **raw)
    return RedirectResponse("/ui/enroll_totp", status_code=303)


# --- admin ---------------------------------------------------------------


@router.get("/admin")
async def admin_root(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session
    return RedirectResponse("/ui/admin/principals", status_code=302)


async def _principals_page(request, session, minted=None, notice=None):
    pool = await db.pool()
    async with pool.acquire() as conn:
        principals = [dict(r) for r in await conn.fetch(
            """SELECT p.id, p.username, p.kind, p.is_admin, p.totp_required,
                      p.disabled_at, o.username AS owner,
                      (SELECT count(*) FROM grants g WHERE g.principal_id = p.id) AS grant_count,
                      (p.totp_required AND EXISTS (
                          SELECT 1 FROM auth_identities i
                           WHERE i.principal_id = p.id AND i.backend = 'local'
                             AND i.totp_secret IS NULL)) AS needs_totp
                 FROM principals p
                 LEFT JOIN principals o ON o.id = p.owner_id
                 ORDER BY p.username"""
        )]
        return await _page(
            request, conn, session, "pages/admin_principals.html", "principals",
            {"principals": principals, "minted": minted, "notice": notice},
        )


@router.get("/admin/principals")
async def admin_principals(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session
    return await _principals_page(request, session)


@router.post("/admin/principals")
async def create_principal(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    username = (form.get("username") or "").strip()
    kind = form.get("kind", "human")
    is_admin = bool(form.get("is_admin")) and kind == "human"
    totp_required = (is_admin or bool(form.get("totp_required"))) and kind == "human"

    if not username or kind not in ("human", "service"):
        return await _principals_page(request, session, notice="Bad principal details.")

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            principal_id = await conn.fetchval(
                """INSERT INTO principals (kind, username, is_admin, totp_required)
                   VALUES ($1, $2, $3, $4) RETURNING id""",
                kind, username, is_admin, totp_required,
            )
        except Exception as exc:  # noqa: BLE001
            return await _principals_page(request, session, notice=f"Could not create: {exc}")

        minted = None
        if kind == "human":
            temp = credentials.generate_temp_password()
            await conn.execute(
                """INSERT INTO auth_identities
                       (principal_id, backend, password_hash, password_is_temp)
                   VALUES ($1, 'local', $2, TRUE)""",
                principal_id, credentials.hash_password(temp),
            )
            minted = f"Temp password for {username}: {temp}"

    return await _principals_page(
        request, session, minted=minted, notice=f"Created {kind} '{username}'."
    )


@router.get("/admin/principals/{principal_id}")
async def principal_detail(
    request: Request, principal_id: str, minted: str | None = None, notice: str | None = None
):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT p.id, p.username, p.kind, p.is_admin, p.totp_required,
                      p.disabled_at, (i.totp_secret IS NOT NULL) AS totp_enrolled,
                      p.rate_limit_per_min, o.username AS owner
                 FROM principals p
                 LEFT JOIN principals o ON o.id = p.owner_id
                 LEFT JOIN auth_identities i
                        ON i.principal_id = p.id AND i.backend = 'local'
                WHERE p.id = $1""",
            principal_id,
        )
        if row is None:
            return _forbidden(request)
        memberships = [dict(r) for r in await conn.fetch(
            """SELECT gr.id, gr.name FROM group_members m
                 JOIN groups gr ON gr.id = m.group_id
                WHERE m.principal_id = $1 ORDER BY gr.name""",
            principal_id,
        )]
        joinable = [dict(r) for r in await conn.fetch(
            """SELECT gr.id, gr.name FROM groups gr
                WHERE NOT EXISTS (SELECT 1 FROM group_members m
                                   WHERE m.principal_id = $1 AND m.group_id = gr.id)
                ORDER BY gr.name""",
            principal_id,
        )]
        passkeys = [dict(r) for r in await conn.fetch(
            """SELECT id, name, created_at, last_used_at
                 FROM webauthn_credentials
                WHERE principal_id = $1 ORDER BY created_at""",
            principal_id,
        )]
        return await _page(
            request, conn, session, "pages/principal_detail.html", "principals",
            {"principal": dict(row), "minted": minted, "notice": notice,
             "memberships": memberships, "joinable": joinable, "passkeys": passkeys},
        )


@router.post("/admin/principals/{principal_id}/groups")
async def add_principal_to_group(request: Request, principal_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    form = await request.form()
    group_id = (form.get("group_id") or "").strip()
    if not group_id:
        return await principal_detail(request, principal_id, notice="Pick a group.")
    pool = await db.pool()
    async with pool.acquire() as conn:
        notice = await _add_member(conn, session, group_id, principal_id)
    if notice:
        return await principal_detail(request, principal_id, notice=notice)
    return RedirectResponse(f"/ui/admin/principals/{principal_id}", status_code=303)


@router.post("/admin/principals/{principal_id}/groups/{group_id}/delete")
async def remove_principal_from_group(request: Request, principal_id: str, group_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await _remove_member(conn, session, group_id, principal_id)
    return RedirectResponse(f"/ui/admin/principals/{principal_id}", status_code=303)


@router.post("/admin/principals/{principal_id}/reset_password")
async def reset_password(request: Request, principal_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session

    temp = credentials.generate_temp_password()
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username FROM principals WHERE id = $1 AND kind = 'human'", principal_id
        )
        if row is None:
            return _forbidden(request)
        password_hash = credentials.hash_password(temp)
        exists = await conn.fetchval(
            "SELECT 1 FROM auth_identities WHERE principal_id = $1 AND backend = 'local'",
            principal_id,
        )
        if exists:
            await conn.execute(
                """UPDATE auth_identities
                      SET password_hash = $2, password_is_temp = TRUE,
                          failed_attempts = 0, locked_until = NULL, updated_at = now()
                    WHERE principal_id = $1 AND backend = 'local'""",
                principal_id, password_hash,
            )
        else:
            await conn.execute(
                """INSERT INTO auth_identities
                       (principal_id, backend, password_hash, password_is_temp)
                   VALUES ($1, 'local', $2, TRUE)""",
                principal_id, password_hash,
            )
        # An admin reset is the compromised-account response: cut the old
        # credentials off completely — revoke the target's tokens and expire
        # every session cookie they still hold (#67).
        await conn.execute(
            "UPDATE principals SET sessions_valid_after = now() WHERE id = $1", principal_id
        )
        revoked = await credentials.revoke_principal_tokens(
            conn, principal_id, reason="admin_password_reset"
        )
        await audit.record_auth_event(
            conn, event=audit.PASSWORD_RESET, principal_id=principal_id,
            principal_label=row["username"], backend="local", ip=web.client_ip(request),
            detail={"by": session["principal_id"], "tokens_revoked": revoked, "sessions": "revoked"},
        )
    return await principal_detail(
        request, principal_id, minted=f"Temp password for {row['username']}: {temp}"
    )


@router.post("/admin/principals/{principal_id}/issue_key")
async def issue_key(request: Request, principal_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    name = (form.get("name") or "").strip() or "unnamed"
    pool = await db.pool()
    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT 1 FROM principals WHERE id = $1", principal_id):
            return _forbidden(request)
        key = await credentials.mint_api_key(
            conn, principal_id, name, created_by=session["principal_id"]
        )
        await audit.record_auth_event(
            conn, event=audit.KEY_CREATED,
            principal_id=session["principal_id"], principal_label=session["username"],
            api_key_id=key.id, detail={"name": name, "via": "admin", "for": principal_id},
        )
    return await principal_detail(request, principal_id, minted=key.secret)


@router.post("/admin/principals/{principal_id}/toggle_totp_required")
async def toggle_totp_required(request: Request, principal_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT is_admin, totp_required, username FROM principals WHERE id = $1",
            principal_id,
        )
        if row is None:
            return _forbidden(request)
        if row["is_admin"]:
            # The schema forbids it; answer clearly rather than surfacing a
            # constraint violation.
            return await principal_detail(
                request, principal_id,
                notice="Admin accounts always require an authenticator.",
            )
        await conn.execute(
            """UPDATE principals SET totp_required = NOT totp_required, updated_at = now()
                WHERE id = $1""",
            principal_id,
        )
        await audit.record_auth_event(
            conn, event=audit.TOTP_REQUIREMENT_CHANGED,
            principal_id=principal_id, principal_label=row["username"],
            detail={"totp_required": not row["totp_required"], "by": session["username"]},
        )
    return RedirectResponse(f"/ui/admin/principals/{principal_id}", status_code=303)


@router.post("/admin/principals/{principal_id}/reset_totp")
async def reset_totp(request: Request, principal_id: str):
    """The lost-phone path (Q11)."""
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, totp_required FROM principals WHERE id = $1", principal_id
        )
        if row is None:
            return _forbidden(request)
        await conn.execute(
            """UPDATE auth_identities
                  SET totp_secret = NULL, totp_enrolled_at = NULL,
                      failed_attempts = 0, locked_until = NULL, updated_at = now()
                WHERE principal_id = $1 AND backend = 'local'""",
            principal_id,
        )
        await audit.record_auth_event(
            conn, event=audit.TOTP_RESET,
            principal_id=principal_id, principal_label=row["username"],
            backend="local", ip=web.client_ip(request),
            detail={"by": session["username"], "still_required": row["totp_required"]},
        )
    return await principal_detail(
        request, principal_id,
        notice=(
            "Authenticator cleared. They enroll a new one on next sign-in."
            if row["totp_required"]
            else "Authenticator cleared. They can sign in with a password alone."
        ),
    )


@router.post("/admin/principals/{principal_id}/rate_limit")
async def set_principal_rate_limit(request: Request, principal_id: str):
    """The per-principal ceiling: applies to any of their credentials that
    doesn't name its own number."""
    session = _require_admin(request)
    if _redirected(session):
        return session
    form = dict(await request.form())
    raw = (form.get("rate_limit_per_min") or "").strip()
    try:
        limit = int(raw) if raw else None
    except ValueError:
        limit = None
    if limit is not None and limit < 1:
        limit = 1
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE principals SET rate_limit_per_min = $2, updated_at = now() WHERE id = $1",
            principal_id, limit,
        )
    return RedirectResponse(f"/ui/admin/principals/{principal_id}", status_code=303)


@router.post("/admin/principals/{principal_id}/detach_owner")
async def detach_owner(request: Request, principal_id: str):
    """Promote a delegated service to an independent one (Q17).

    Independent means: its own grants, its own lifecycle, survives the person
    who created it. That's why it takes an admin — a user could otherwise
    manufacture access that outlives their own.
    """
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, owner_id FROM principals WHERE id = $1 AND kind = 'service'",
            principal_id,
        )
        if row is None:
            return _forbidden(request)
        await conn.execute(
            "UPDATE principals SET owner_id = NULL, updated_at = now() WHERE id = $1",
            principal_id,
        )
        await audit.record_auth_event(
            conn, event=audit.SERVICE_DETACHED,
            principal_id=principal_id, principal_label=row["username"],
            detail={"by": session["username"]},
        )
    return RedirectResponse(f"/ui/admin/principals/{principal_id}", status_code=303)


@router.post("/admin/principals/{principal_id}/toggle_disabled")
async def toggle_disabled(request: Request, principal_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        current = await conn.fetchval(
            "SELECT disabled_at FROM principals WHERE id = $1", principal_id
        )
        if current is None:
            await conn.execute(
                """UPDATE principals SET disabled_at = now(), sessions_valid_after = now()
                    WHERE id = $1""",
                principal_id,
            )
            await credentials.revoke_principal_tokens(conn, principal_id, reason="admin_disabled")
        else:
            await conn.execute(
                "UPDATE principals SET disabled_at = NULL WHERE id = $1", principal_id
            )
    return RedirectResponse(f"/ui/admin/principals/{principal_id}", status_code=303)


# --- admin: upstreams ----------------------------------------------------


async def _upstreams_page(request, session, notice=None):
    pool = await db.pool()
    async with pool.acquire() as conn:
        # Health is per replica now (Q24), so the row-level pill is derived
        # rather than stored: "2/3 ok" is the honest summary of three replicas.
        upstreams = [dict(r) for r in await conn.fetch(
            """SELECT u.id, u.name, u.display_name, u.description, u.enabled,
                      u.public_listed,
                      COALESCE(e.urls, ARRAY[]::text[])   AS urls,
                      COALESCE(e.total, 0)                AS endpoint_count,
                      COALESCE(e.live, 0)                 AS enabled_count,
                      COALESCE(e.checked, 0)              AS checked_count,
                      COALESCE(e.healthy, 0)              AS healthy_count,
                      e.last_health_at
                 FROM upstreams u
                 LEFT JOIN LATERAL (
                     SELECT array_agg(x.url ORDER BY x.created_at, x.url) AS urls,
                            count(*)                                      AS total,
                            count(*) FILTER (WHERE x.enabled)             AS live,
                            count(*) FILTER (WHERE x.last_health_ok IS NOT NULL) AS checked,
                            count(*) FILTER (WHERE x.last_health_ok)      AS healthy,
                            max(x.last_health_at)                         AS last_health_at
                       FROM upstream_endpoints x WHERE x.upstream_id = u.id
                 ) e ON TRUE
                ORDER BY u.name"""
        )]
        return await _page(
            request, conn, session, "pages/admin_upstreams.html", "upstreams",
            {"upstreams": upstreams, "notice": notice},
        )


@router.get("/admin/upstreams")
async def admin_upstreams(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session
    return await _upstreams_page(request, session)


@router.post("/admin/upstreams")
async def create_upstream(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    try:
        timeout = int(form.get("timeout_seconds") or 30)
    except ValueError:
        timeout = 30

    # SSRF guard (#62): the URL becomes a server-side fetch target, so validate
    # the scheme/host and reject internal IP literals before it ever lands in a
    # row proxy.py will call.
    try:
        endpoint_url = validate_upstream_url(form.get("url") or "")
    except UpstreamUrlError as exc:
        return await _upstreams_page(request, session, notice=str(exc))

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            # One URL here; more replicas are added on the detail page. The
            # server and its first endpoint go in together, so a registration
            # can't leave an upstream nothing can route to.
            async with conn.transaction():
                upstream_id = await conn.fetchval(
                    """INSERT INTO upstreams
                           (name, display_name, description, auth_header_name,
                            auth_header_value, timeout_seconds, public_listed)
                       VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''),
                               NULLIF($5, ''), $6, $7)
                       RETURNING id""",
                    (form.get("name") or "").strip(),
                    (form.get("display_name") or "").strip(),
                    (form.get("description") or "").strip(),
                    (form.get("auth_header_name") or "").strip(),
                    crypto.encrypt_secret((form.get("auth_header_value") or "").strip()),
                    timeout,
                    bool(form.get("public_listed")),
                )
                await conn.execute(
                    "INSERT INTO upstream_endpoints (upstream_id, url) VALUES ($1, $2)",
                    upstream_id,
                    endpoint_url,
                )
        except Exception as exc:  # noqa: BLE001
            return await _upstreams_page(request, session, notice=f"Could not create: {exc}")
    return RedirectResponse("/ui/admin/upstreams", status_code=303)


@router.get("/admin/upstreams/{upstream_id}")
async def upstream_detail(request: Request, upstream_id: str, error: str | None = None):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT u.id, u.name, u.display_name, u.description,
                      u.auth_header_name,
                      (u.auth_header_value IS NOT NULL) AS has_auth_value,
                      u.timeout_seconds, u.enabled, u.public_listed,
                      u.public_summary, u.public_url,
                      (SELECT count(*) FROM grants g WHERE g.upstream_id = u.id) AS grant_count
                 FROM upstreams u WHERE u.id = $1""",
            upstream_id,
        )
        if row is None:
            return _forbidden(request)
        endpoints = [dict(r) for r in await conn.fetch(
            """SELECT id, url, enabled, last_health_at, last_health_ok, last_health_error
                 FROM upstream_endpoints WHERE upstream_id = $1
                ORDER BY created_at, url""",
            upstream_id,
        )]
        return await _page(
            request, conn, session, "pages/upstream_detail.html", "upstreams",
            {"upstream": dict(row), "endpoints": endpoints, "error": error},
        )


def _valid_public_url(raw: str) -> bool:
    """A `public_url` is rendered as `<a href>` on the crawlable directory page.

    So an unvalidated value is one `javascript:`/`data:` scheme away from being
    a stored-XSS sink the moment someone clicks it (#77). Accept only http/https
    absolute URLs with a host; reject everything else. Empty is handled by the
    caller (it means "no homepage").
    """
    try:
        parsed = urlparse(raw)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


@router.post("/admin/upstreams/{upstream_id}")
async def update_upstream(request: Request, upstream_id: str):
    """Edit everything about a registered server, slug included.

    The slug is the URL segment and the tool prefix, so renaming changes what
    clients must call — but grants reference the server by id, so a rename
    never silently drops access.
    """
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    try:
        timeout = int(form.get("timeout_seconds") or 30)
    except ValueError:
        timeout = 30
    public_url = (form.get("public_url") or "").strip()
    if public_url and not _valid_public_url(public_url):
        return await upstream_detail(
            request, upstream_id,
            error="Homepage URL must be an http:// or https:// link.",
        )

    try:
        # A blank value means "leave the stored credential alone" and passes
        # through as "". A non-blank value with no encryption key configured is
        # refused here rather than silently stored in plaintext (issue #73).
        new_value = crypto.encrypt_secret((form.get("auth_header_value") or "").strip()) or ""
    except crypto.PlaintextSecretRefused as exc:
        return await upstream_detail(request, upstream_id, error=str(exc))

    pool = await db.pool()
    async with pool.acquire() as conn:
        old = await conn.fetchrow("SELECT name FROM upstreams WHERE id = $1", upstream_id)
        if old is None:
            return _forbidden(request)
        try:
            await conn.execute(
                """UPDATE upstreams
                      SET name = $2,
                          display_name = NULLIF($3, ''),
                          description = NULLIF($4, ''),
                          public_summary = NULLIF($5, ''),
                          public_url = NULLIF($6, ''),
                          timeout_seconds = $7,
                          enabled = $8,
                          public_listed = $9,
                          auth_header_name = NULLIF($10, ''),
                          -- Blank means "leave the stored credential alone",
                          -- so an admin can edit other fields without having
                          -- to re-enter a secret they can't read.
                          auth_header_value = CASE
                              WHEN $11 = '' THEN auth_header_value ELSE $11 END,
                          updated_at = now()
                    WHERE id = $1""",
                upstream_id,
                (form.get("name") or "").strip(),
                (form.get("display_name") or "").strip(),
                (form.get("description") or "").strip(),
                (form.get("public_summary") or "").strip(),
                public_url,
                timeout,
                bool(form.get("enabled")),
                bool(form.get("public_listed")),
                (form.get("auth_header_name") or "").strip(),
                new_value,
            )
        except Exception as exc:  # noqa: BLE001
            return await upstream_detail(request, upstream_id, error=f"Could not save: {exc}")

        # The directory caches tool lists per slug; drop both names so a
        # rename can't leave a stale entry under the old one.
        for slug in {old["name"], (form.get("name") or "").strip()}:
            try:
                await cache.client().delete(f"torii:dirtools:{slug}")
            except Exception:  # noqa: BLE001
                pass

    return RedirectResponse(f"/ui/admin/upstreams/{upstream_id}", status_code=303)


@router.post("/admin/upstreams/{upstream_id}/clear_credential")
async def clear_upstream_credential(request: Request, upstream_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE upstreams SET auth_header_value = NULL, updated_at = now()
                WHERE id = $1""",
            upstream_id,
        )
    return RedirectResponse(f"/ui/admin/upstreams/{upstream_id}", status_code=303)


@router.post("/admin/upstreams/{upstream_id}/delete")
async def delete_upstream(request: Request, upstream_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        name = await conn.fetchval("SELECT name FROM upstreams WHERE id = $1", upstream_id)
        await conn.execute("DELETE FROM upstreams WHERE id = $1", upstream_id)
        if name:
            try:
                await cache.client().delete(f"torii:dirtools:{name}")
            except Exception:  # noqa: BLE001
                pass
    return RedirectResponse("/ui/admin/upstreams", status_code=303)


@router.get("/admin/upstreams/{upstream_id}/tools.json")
async def upstream_tools(request: Request, upstream_id: str):
    """Ask a server what tools it has, for the grant editor to tick.

    Nobody remembers a server's tool names six months later, and typing them
    from memory is how a grant ends up naming a tool that no longer exists.
    Cached briefly (a tool list is a property of the server), and a dead
    upstream returns an error the form can show rather than an empty list that
    looks like "this server has no tools".
    """
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream = await proxy.load_upstream_by_id(conn, upstream_id)
        if upstream is None:
            upstream = await proxy.load_upstream(conn, upstream_id)
        if upstream is None:
            return JSONResponse({"error": "no such server"}, status_code=404)

        try:
            result = await proxy.call_upstream(upstream, "tools/list", {})
        except proxy.UpstreamError as exc:
            return JSONResponse(
                {"error": f"{exc.kind}: {exc.detail}"[:200], "server": upstream.name},
                status_code=502,
            )

    tools = []
    for tool in result.get("tools") or []:
        if not tool.get("name"):
            continue
        annotations = tool.get("annotations") or {}
        tools.append({
            "name": tool["name"],
            "description": (tool.get("description") or "").strip(),
            # MCP's own hints, when a server bothers to send them — worth
            # surfacing, since "may modify data" changes how you grant.
            "read_only": annotations.get("readOnlyHint"),
            "destructive": annotations.get("destructiveHint"),
        })
    return JSONResponse({"server": upstream.name, "tools": tools})


@router.post("/admin/upstreams/{upstream_id}/toggle")
async def toggle_upstream(request: Request, upstream_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE upstreams SET enabled = NOT enabled, updated_at = now() WHERE id = $1",
            upstream_id,
        )
    return RedirectResponse("/ui/admin/upstreams", status_code=303)


@router.post("/admin/upstreams/{upstream_id}/toggle_public")
async def toggle_public(request: Request, upstream_id: str):
    """Publish or unpublish a server in the public directory (Q12)."""
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE upstreams SET public_listed = NOT public_listed, updated_at = now()
                WHERE id = $1""",
            upstream_id,
        )
        name = await conn.fetchval("SELECT name FROM upstreams WHERE id = $1", upstream_id)
        # Drop the cached tool list so an unlisted server stops being served
        # from cache immediately.
        try:
            await cache.client().delete(f"torii:dirtools:{name}")
        except Exception:  # noqa: BLE001
            pass
    return RedirectResponse("/ui/admin/upstreams", status_code=303)


@router.post("/admin/upstreams/{upstream_id}/check")
async def check_upstream(request: Request, upstream_id: str):
    """Ask EVERY replica for its tool list and record each result.

    Health is per replica (Q24): a check that only reached whichever replica
    round-robin happened to pick would say "ok" about a server that is half
    down, which is worse than not checking at all.
    """
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream = await proxy.load_upstream_by_id(conn, upstream_id)
        if upstream is None:
            return _forbidden(request)
        if not upstream.endpoints:
            return await _upstreams_page(
                request, session, notice=f"{upstream.name}: no endpoints to check"
            )

        healthy = 0
        for endpoint in upstream.endpoints:
            # One replica at a time: a single-endpoint copy of the upstream
            # keeps selection and failover out of a health check's way.
            solo = replace(upstream, endpoints=[endpoint])
            try:
                await proxy.call_upstream(solo, "tools/list", {})
                ok, error = True, None
                healthy += 1
            except proxy.UpstreamError as exc:
                ok, error = False, f"{exc.kind}: {exc.detail}"[:400]
            await conn.execute(
                """UPDATE upstream_endpoints
                      SET last_health_at = now(), last_health_ok = $2,
                          last_health_error = $3, updated_at = now()
                    WHERE id = $1""",
                endpoint.id, ok, error,
            )
        total = len(upstream.endpoints)
        note = (
            f"{upstream.name}: {healthy}/{total} "
            f"{'replica' if total == 1 else 'replicas'} ok"
        )
    return await _upstreams_page(request, session, notice=note)


# --- admin: upstream endpoints (replicas, Q24) ---------------------------


@router.post("/admin/upstreams/{upstream_id}/endpoints")
async def add_upstream_endpoint(request: Request, upstream_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = dict(await request.form())
    # SSRF guard (#62): same validation as registration — a replica URL is just
    # as much a server-side fetch target as the first endpoint.
    try:
        url = validate_upstream_url(form.get("url") or "")
    except UpstreamUrlError as exc:
        return await upstream_detail(request, upstream_id, error=str(exc))

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            await conn.execute(
                "INSERT INTO upstream_endpoints (upstream_id, url) VALUES ($1, $2)",
                upstream_id, url,
            )
        except Exception as exc:  # noqa: BLE001
            return await upstream_detail(request, upstream_id, error=f"Could not add: {exc}")
    return RedirectResponse(f"/ui/admin/upstreams/{upstream_id}", status_code=303)


@router.post("/admin/upstreams/{upstream_id}/endpoints/{endpoint_id}/toggle")
async def toggle_upstream_endpoint(request: Request, upstream_id: str, endpoint_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE upstream_endpoints SET enabled = NOT enabled, updated_at = now()
                WHERE id = $1 AND upstream_id = $2""",
            endpoint_id, upstream_id,
        )
    return RedirectResponse(f"/ui/admin/upstreams/{upstream_id}", status_code=303)


@router.post("/admin/upstreams/{upstream_id}/endpoints/{endpoint_id}/delete")
async def delete_upstream_endpoint(request: Request, upstream_id: str, endpoint_id: str):
    """Remove a replica — but never the last one.

    Schema can't hold this rule without a trigger, so it lives here and the
    proxy fails closed on zero endpoints. Refusing here is the difference
    between "can't do that" and a server that silently stops answering.
    """
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        remaining = await conn.fetchval(
            "SELECT count(*) FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        )
        if remaining <= 1:
            return await upstream_detail(
                request, upstream_id,
                error="A server needs at least one endpoint. Add another before removing this one.",
            )
        await conn.execute(
            "DELETE FROM upstream_endpoints WHERE id = $1 AND upstream_id = $2",
            endpoint_id, upstream_id,
        )
    return RedirectResponse(f"/ui/admin/upstreams/{upstream_id}", status_code=303)


# --- admin: grants -------------------------------------------------------


async def _grants_page(request, session, notice=None):
    pool = await db.pool()
    async with pool.acquire() as conn:
        grants = [
            {
                "id": r["id"],
                "subject_type": r["subject_type"],
                "subject_name": (
                    r["username"] or r["label"] or r["client_name"]
                    or r["group_name"] or r["key_name"] or "—"
                ),
                "subject_owner": r["key_owner"] or r["client_owner"],
                "group_id": r["group_id"],
                "upstream_name": r["upstream_name"],
                "tool_scope": r["tool_scope"],
                "tools": list(r["tools"] or []),
            }
            for r in await conn.fetch(
                """SELECT g.id, g.subject_type, g.group_name, g.tool_scope, g.tools,
                          u.name AS upstream_name, p.username,
                          c.client_name, c.label,
                          k.name AS key_name, k.key_prefix,
                          kp.username AS key_owner, cp.username AS client_owner,
                          gr.id AS group_id
                     FROM grants g
                     JOIN upstreams u ON u.id = g.upstream_id
                     LEFT JOIN groups gr ON gr.name = g.group_name
                     LEFT JOIN principals p ON p.id = g.principal_id
                     LEFT JOIN oauth_clients c ON c.client_id = g.client_id
                     LEFT JOIN principals cp ON cp.id = c.principal_id
                     LEFT JOIN api_keys k ON k.id = g.api_key_id
                     LEFT JOIN principals kp ON kp.id = k.principal_id
                    ORDER BY u.name, g.subject_type"""
            )
        ]
        principals = [dict(r) for r in await conn.fetch(
            "SELECT id, username, kind FROM principals ORDER BY username"
        )]
        upstreams = [dict(r) for r in await conn.fetch(
            "SELECT id, name, display_name, enabled FROM upstreams ORDER BY name"
        )]
        all_clients = [dict(r) for r in await conn.fetch(
            """SELECT c.client_id, c.client_name, c.label, c.access_mode,
                      c.first_seen_user_agent, p.username AS owner
                 FROM oauth_clients c
                 LEFT JOIN principals p ON p.id = c.principal_id
                WHERE c.disabled_at IS NULL
                ORDER BY p.username NULLS LAST, c.label, c.client_name"""
        )]
        all_keys = [dict(r) for r in await conn.fetch(
            """SELECT k.id, k.name, k.key_prefix, k.access_mode, p.username AS owner
                 FROM api_keys k JOIN principals p ON p.id = k.principal_id
                WHERE k.revoked_at IS NULL ORDER BY p.username, k.name"""
        )]
        for row in all_clients:
            row["device"] = useragent.describe(row.get("first_seen_user_agent"))
            row["display"] = connector_display(row)
        # Real groups, not the distinct free text that used to be scraped back
        # out of the grants table — a group is now a row with members, so the
        # picker can only offer ones that exist.
        known_groups = [dict(r) for r in await conn.fetch(
            """SELECT gr.id, gr.name,
                      (SELECT count(*) FROM group_members m WHERE m.group_id = gr.id)
                          AS member_count
                 FROM groups gr ORDER BY gr.name"""
        )]
        return await _page(
            request, conn, session, "pages/admin_grants.html", "grants",
            {"grants": grants, "principals": principals, "upstreams": upstreams,
             "all_clients": all_clients, "all_keys": all_keys,
             "known_groups": known_groups, "notice": notice},
        )


@router.get("/admin/grants")
async def admin_grants(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session
    return await _grants_page(request, session)


@router.post("/admin/grants")
async def create_grant(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = await request.form()
    upstream_name = (form.get("upstream_name") or "").strip()
    tool_scope = form.get("tool_scope", "all")

    # Tools arrive as ticked checkboxes now (the picker). A single value
    # containing commas is the older hand-typed shape — split it, since a tool
    # name can't contain a comma. Both forms therefore keep working.
    tools = []
    for value in list(form.getlist("tools")) + list(form.getlist("tools_text")):
        tools.extend(t.strip() for t in value.split(",") if t.strip())

    # One dropdown answers "who", encoded as "<kind>:<reference>", so the form
    # never asks an operator what a "subject type" is.
    who = (form.get("who") or "").strip()
    group_name_input = (form.get("group_name") or "").strip()
    if group_name_input:
        subject_type, reference = "group", group_name_input
    elif ":" in who:
        subject_type, reference = who.split(":", 1)
    else:
        subject_type, reference = form.get("subject_type", "principal"), (
            form.get("subject_ref") or ""
        ).strip()
    subject_type = subject_type.strip()
    reference = reference.strip()

    if not reference or not upstream_name:
        return await _grants_page(
            request, session, notice="Pick who it's for and which server."
        )
    if tool_scope == "list" and not tools:
        return await _grants_page(request, session, notice="List scope needs at least one tool.")
    if tool_scope == "all" and tools:
        return await _grants_page(request, session, notice="Clear the tool list, or pick 'a list…'.")

    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await conn.fetchval(
            "SELECT id FROM upstreams WHERE name = $1", upstream_name
        )
        if upstream_id is None:
            return await _grants_page(request, session, notice=f"No upstream named {upstream_name}.")

        principal_id = client_id = group_name = api_key_id = None
        if subject_type == "principal":
            principal_id = await conn.fetchval(
                """SELECT id FROM principals
                    WHERE username = $1 OR id::text = $1""",
                reference,
            )
            if principal_id is None:
                return await _grants_page(request, session, notice=f"No principal {reference!r}.")
        elif subject_type == "client":
            client_id = await conn.fetchval(
                "SELECT client_id FROM oauth_clients WHERE client_id = $1", reference
            )
            if client_id is None:
                return await _grants_page(request, session, notice=f"No connector {reference!r}.")
        elif subject_type == "key":
            api_key_id = await conn.fetchval(
                "SELECT id FROM api_keys WHERE id::text = $1 AND revoked_at IS NULL", reference
            )
            if api_key_id is None:
                return await _grants_page(request, session, notice=f"No live key {reference!r}.")
        elif subject_type == "group":
            # The foreign key would refuse an unknown group anyway; catching it
            # here is the difference between a sentence and a constraint dump.
            group_name = await conn.fetchval(
                "SELECT name FROM groups WHERE name = $1 OR id::text = $1", reference
            )
            if group_name is None:
                return await _grants_page(
                    request, session,
                    notice=f"No group named {reference!r}. Create it under Groups first.",
                )
        else:
            return await _grants_page(request, session, notice="Pick who this grant is for.")

        try:
            await conn.execute(
                """INSERT INTO grants
                       (subject_type, principal_id, client_id, group_name, api_key_id,
                        upstream_id, tool_scope, tools, created_by)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                subject_type, principal_id, client_id, group_name, api_key_id,
                upstream_id, tool_scope, tools, session["principal_id"],
            )
            # A key/client grant means "limit this credential to what I tick"
            # (Q14/Q15). The credential must be marked NARROWED so the resolver
            # bounds it by these grants — and keeps bounding it even if one of
            # its upstreams is later disabled (#60). That is enforced in the
            # schema: the grants_narrow_credential trigger (migration 0015)
            # stamps the mode on any client/key-scoped insert, so no write path,
            # here or elsewhere, can leave a scoped credential at 'inherit'.
        except Exception as exc:  # noqa: BLE001
            return await _grants_page(request, session, notice=f"Could not grant: {exc}")
    return RedirectResponse("/ui/admin/grants", status_code=303)


@router.post("/admin/grants/{grant_id}/delete")
async def delete_grant(request: Request, grant_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)
    return RedirectResponse("/ui/admin/grants", status_code=303)


# --- admin: groups -------------------------------------------------------
#
# A group is a named set of principals whose grants apply to every member
# (#54). It adds no authorization path: membership is read inside
# `rbac.load_context`, so both MCP endpoint shapes and every UI view get the
# same answer from the same resolver. Nothing here decides access.


async def _groups_page(request, session, notice=None):
    pool = await db.pool()
    async with pool.acquire() as conn:
        groups = [dict(r) for r in await conn.fetch(
            """SELECT gr.id, gr.name, gr.description, gr.idp_claim,
                      (SELECT count(*) FROM group_members m WHERE m.group_id = gr.id)
                          AS member_count,
                      (SELECT count(*) FROM grants g
                        WHERE g.subject_type = 'group' AND g.group_name = gr.name)
                          AS grant_count
                 FROM groups gr ORDER BY gr.name"""
        )]
        return await _page(
            request, conn, session, "pages/admin_groups.html", "groups",
            {"groups": groups, "notice": notice},
        )


@router.get("/admin/groups")
async def admin_groups(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session
    return await _groups_page(request, session)


@router.post("/admin/groups")
async def create_group(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = await request.form()
    # Trimmed, never lowercased: `groups_name_ci_idx` stops a near-duplicate,
    # but the name an admin typed is the name they see everywhere.
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip() or None
    idp_claim = (form.get("idp_claim") or "").strip() or None
    if not name:
        return await _groups_page(request, session, notice="A group needs a name.")

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            group_id = await conn.fetchval(
                """INSERT INTO groups (name, description, idp_claim, created_by)
                   VALUES ($1, $2, $3, $4) RETURNING id""",
                name, description, idp_claim, session["principal_id"],
            )
        except asyncpg.UniqueViolationError:
            return await _groups_page(
                request, session, notice=f"A group called {name!r} already exists."
            )
        except Exception as exc:  # noqa: BLE001
            return await _groups_page(request, session, notice=f"Could not create: {exc}")
        await audit.record_auth_event(
            conn, event=audit.GROUP_CREATED,
            principal_id=session["principal_id"], principal_label=session["username"],
            detail={"group": name, "idp_claim": idp_claim},
        )
    return RedirectResponse(f"/ui/admin/groups/{group_id}", status_code=303)


@router.get("/admin/groups/{group_id}")
async def group_detail(request: Request, group_id: str, notice: str | None = None):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        group = await conn.fetchrow(
            "SELECT id, name, description, idp_claim, created_at FROM groups WHERE id = $1",
            group_id,
        )
        if group is None:
            return _forbidden(request)
        members = [dict(r) for r in await conn.fetch(
            """SELECT p.id, p.username, p.kind, p.disabled_at, m.added_at
                 FROM group_members m JOIN principals p ON p.id = m.principal_id
                WHERE m.group_id = $1 ORDER BY p.username""",
            group_id,
        )]
        candidates = [dict(r) for r in await conn.fetch(
            """SELECT p.id, p.username, p.kind FROM principals p
                WHERE NOT EXISTS (SELECT 1 FROM group_members m
                                   WHERE m.group_id = $1 AND m.principal_id = p.id)
                ORDER BY p.username""",
            group_id,
        )]
        grants = [dict(r) for r in await conn.fetch(
            """SELECT g.id, u.name AS upstream_name, g.tool_scope, g.tools
                 FROM grants g JOIN upstreams u ON u.id = g.upstream_id
                WHERE g.subject_type = 'group' AND g.group_name = $1
                ORDER BY u.name""",
            group["name"],
        )]
        return await _page(
            request, conn, session, "pages/group_detail.html", "groups",
            {"group": dict(group), "members": members, "candidates": candidates,
             "grants": grants, "notice": notice},
        )


@router.post("/admin/groups/{group_id}")
async def update_group(request: Request, group_id: str):
    """Rename or re-describe. A rename cascades to the group's grants through
    the foreign key, so access follows the name rather than breaking on it."""
    session = _require_admin(request)
    if _redirected(session):
        return session

    form = await request.form()
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip() or None
    idp_claim = (form.get("idp_claim") or "").strip() or None
    if not name:
        return await group_detail(request, group_id, notice="A group needs a name.")

    pool = await db.pool()
    async with pool.acquire() as conn:
        try:
            updated = await conn.execute(
                """UPDATE groups SET name = $2, description = $3, idp_claim = $4,
                          updated_at = now()
                    WHERE id = $1""",
                group_id, name, description, idp_claim,
            )
        except asyncpg.UniqueViolationError:
            return await group_detail(
                request, group_id, notice=f"Another group already uses {name!r}."
            )
        except Exception as exc:  # noqa: BLE001
            return await group_detail(request, group_id, notice=f"Could not save: {exc}")
        if updated.endswith(" 0"):
            return _forbidden(request)
    return RedirectResponse(f"/ui/admin/groups/{group_id}", status_code=303)


@router.post("/admin/groups/{group_id}/delete")
async def delete_group(request: Request, group_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        name = await conn.fetchval("SELECT name FROM groups WHERE id = $1", group_id)
        if name is None:
            return _forbidden(request)
        # Members and the group's grants go with it, by cascade. That is the
        # point: a grant naming a group that no longer exists is a grant
        # nobody can reason about.
        await conn.execute("DELETE FROM groups WHERE id = $1", group_id)
        await audit.record_auth_event(
            conn, event=audit.GROUP_DELETED,
            principal_id=session["principal_id"], principal_label=session["username"],
            detail={"group": name},
        )
    return RedirectResponse("/ui/admin/groups", status_code=303)


async def _add_member(conn, session, group_id, principal_id):
    """Returns a notice on failure, None on success. Shared by the group page
    and the principal page — an operator reaches for whichever is in front of
    them, and both must do the same thing."""
    row = await conn.fetchrow(
        """SELECT (SELECT name FROM groups WHERE id = $1::uuid) AS group_name,
                  (SELECT username FROM principals WHERE id = $2::uuid) AS username""",
        group_id, principal_id,
    )
    if row["group_name"] is None:
        return "No such group."
    if row["username"] is None:
        return "No such principal."
    added = await conn.execute(
        """INSERT INTO group_members (group_id, principal_id, added_by)
           VALUES ($1, $2, $3) ON CONFLICT DO NOTHING""",
        group_id, principal_id, session["principal_id"],
    )
    if added.endswith(" 0"):
        return f"{row['username']} is already in {row['group_name']}."
    await audit.record_auth_event(
        conn, event=audit.GROUP_MEMBER_ADDED,
        principal_id=principal_id, principal_label=row["username"],
        detail={"group": row["group_name"], "by": session["username"]},
    )
    return None


async def _remove_member(conn, session, group_id, principal_id):
    row = await conn.fetchrow(
        """SELECT (SELECT name FROM groups WHERE id = $1::uuid) AS group_name,
                  (SELECT username FROM principals WHERE id = $2::uuid) AS username""",
        group_id, principal_id,
    )
    removed = await conn.execute(
        "DELETE FROM group_members WHERE group_id = $1 AND principal_id = $2",
        group_id, principal_id,
    )
    if removed.endswith(" 0"):
        return
    await audit.record_auth_event(
        conn, event=audit.GROUP_MEMBER_REMOVED,
        principal_id=principal_id, principal_label=row["username"],
        detail={"group": row["group_name"], "by": session["username"]},
    )


@router.post("/admin/groups/{group_id}/members")
async def add_group_member(request: Request, group_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session
    form = await request.form()
    principal_id = (form.get("principal_id") or "").strip()
    if not principal_id:
        return await group_detail(request, group_id, notice="Pick someone to add.")
    pool = await db.pool()
    async with pool.acquire() as conn:
        notice = await _add_member(conn, session, group_id, principal_id)
    if notice:
        return await group_detail(request, group_id, notice=notice)
    return RedirectResponse(f"/ui/admin/groups/{group_id}", status_code=303)


@router.post("/admin/groups/{group_id}/members/{principal_id}/delete")
async def remove_group_member(request: Request, group_id: str, principal_id: str):
    """Takes effect on the member's very next call — membership is resolved in
    `rbac.load_context`, not baked into a token."""
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        await _remove_member(conn, session, group_id, principal_id)
    return RedirectResponse(f"/ui/admin/groups/{group_id}", status_code=303)


# --- admin: OAuth clients ------------------------------------------------


@router.get("/admin/clients")
async def admin_clients(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        clients = [dict(r) for r in await conn.fetch(
            """SELECT c.client_id, c.client_name, c.label, c.last_seen_at,
                      c.disabled_at, c.created_at, c.access_mode,
                      c.first_seen_user_agent, c.first_seen_ip, p.username,
                      count(DISTINCT t.id) FILTER (
                          WHERE t.revoked_at IS NULL AND t.expires_at > now()
                      ) AS tokens,
                      count(DISTINCT g.id) AS grant_count
                 FROM oauth_clients c
                 LEFT JOIN principals p ON p.id = c.principal_id
                 LEFT JOIN tokens t ON t.client_id = c.client_id
                 LEFT JOIN grants g ON g.client_id = c.client_id
             GROUP BY c.client_id, p.username
             ORDER BY c.disabled_at NULLS FIRST, p.username NULLS LAST, c.label, c.client_name"""
        )]
        for row in clients:
            row["device"] = useragent.describe(row.get("first_seen_user_agent"))
            row["display"] = connector_display(row)
        return await _page(
            request, conn, session, "pages/admin_clients.html", "clients",
            {"clients": clients},
        )


@router.post("/admin/clients/{client_id}/rename")
async def admin_rename_client(request: Request, client_id: str):
    """Let an admin label someone else's connector.

    Benign metadata, and the admin is the one reading the audit trail — if a
    row says "wife · claude.ai (Safari on iPhone)" they should be able to make
    it say "wife · her phone".
    """
    session = _require_admin(request)
    if _redirected(session):
        return session
    form = dict(await request.form())
    label = (form.get("label") or "").strip()[:60]
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE oauth_clients SET label = NULLIF($2, ''), updated_at = now() WHERE client_id = $1",
            client_id, label,
        )
    return RedirectResponse("/ui/admin/clients", status_code=303)


@router.post("/admin/clients/{client_id}/revoke")
async def admin_revoke_client(request: Request, client_id: str):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE oauth_clients SET disabled_at = now() WHERE client_id = $1", client_id
        )
        killed = await credentials.revoke_client_tokens(conn, client_id, reason="admin_revoked")
        await audit.record_auth_event(
            conn, event=audit.CLIENT_DISABLED,
            principal_id=session["principal_id"], principal_label=session["username"],
            client_id=client_id, detail={"tokens_killed": killed, "via": "admin"},
        )
    return RedirectResponse("/ui/admin/clients", status_code=303)


# --- admin: audit --------------------------------------------------------


@router.get("/admin/audit")
async def admin_audit(
    request: Request,
    principal: str | None = None,
    upstream: str | None = None,
    outcome: str | None = None,
    view: str | None = None,
):
    session = _require_admin(request)
    if _redirected(session):
        return session

    filters = {
        "principal": (principal or "").strip() or None,
        "upstream": (upstream or "").strip() or None,
        "outcome": (outcome or "").strip() or None,
        "view": "auth" if view == "auth" else "calls",
    }

    pool = await db.pool()
    async with pool.acquire() as conn:
        rows, events = [], []
        if filters["view"] == "auth":
            events = [
                dict(r) | {"detail": json.dumps(json.loads(r["detail"]))
                           if isinstance(r["detail"], str) else json.dumps(r["detail"])}
                for r in await conn.fetch(
                    """SELECT ts, event, outcome, principal_label, client_id, ip, detail
                         FROM audit_auth_events
                        WHERE ($1::text IS NULL OR principal_label ILIKE '%' || $1 || '%')
                        ORDER BY id DESC LIMIT 200""",
                    filters["principal"],
                )
            ]
        else:
            rows = [
                dict(r) | {"via": _via(dict(r))}
                for r in await conn.fetch(
                    """SELECT ts, principal_label, upstream_name, endpoint_url,
                              tool_name, outcome,
                              error_code, latency_ms, client_id, api_key_id
                         FROM audit_calls
                        WHERE ($1::text IS NULL OR principal_label ILIKE '%' || $1 || '%')
                          AND ($2::text IS NULL OR upstream_name ILIKE '%' || $2 || '%')
                          AND ($3::text IS NULL OR outcome = $3)
                        ORDER BY id DESC LIMIT 200""",
                    filters["principal"], filters["upstream"], filters["outcome"],
                )
            ]
        return await _page(
            request, conn, session, "pages/admin_audit.html", "audit",
            {"rows": rows, "events": events, "filters": filters},
        )


# --- admin: config export ------------------------------------------------


@router.get("/admin/config")
async def admin_config(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session
    pool = await db.pool()
    async with pool.acquire() as conn:
        return await _page(request, conn, session, "pages/admin_config.html", "config")


@router.get("/admin/config.json")
async def export_config(request: Request):
    session = _require_admin(request)
    if _redirected(session):
        return session

    pool = await db.pool()
    async with pool.acquire() as conn:
        principals = [dict(r) for r in await conn.fetch(
            """SELECT id, username, kind, is_admin, totp_required, disabled_at, created_at
                 FROM principals"""
        )]
        upstreams = [dict(r) for r in await conn.fetch(
            """SELECT u.id, u.name, u.description, u.auth_header_name, u.timeout_seconds,
                      u.enabled, u.public_listed,
                      COALESCE((SELECT array_agg(e.url ORDER BY e.created_at, e.url)
                                  FROM upstream_endpoints e WHERE e.upstream_id = u.id),
                               ARRAY[]::text[]) AS urls
                 FROM upstreams u"""
        )]
        groups = [dict(r) for r in await conn.fetch(
            """SELECT gr.name, gr.description, gr.idp_claim,
                      COALESCE((SELECT array_agg(p.username ORDER BY p.username)
                                  FROM group_members m
                                  JOIN principals p ON p.id = m.principal_id
                                 WHERE m.group_id = gr.id),
                               ARRAY[]::text[]) AS members
                 FROM groups gr ORDER BY gr.name"""
        )]
        grants = [dict(r) for r in await conn.fetch(
            """SELECT g.subject_type, g.tool_scope, g.tools,
                      u.name AS upstream_name, p.username AS principal_username,
                      g.client_id, g.group_name
                 FROM grants g
                 JOIN upstreams u ON u.id = g.upstream_id
                 LEFT JOIN principals p ON p.id = g.principal_id"""
        )]

    def scrub(value):
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if hasattr(value, "isoformat"):
            return value.isoformat()
        if hasattr(value, "hex") and not isinstance(value, (bytes, str, int, float)):
            return str(value)
        return value

    return JSONResponse(
        scrub({
            "issuer": config.PUBLIC_BASE_URL,
            "principals": principals,
            "upstreams": upstreams,
            "groups": groups,
            "grants": grants,
        }),
        headers={"Content-Disposition": 'attachment; filename="torii-config.json"'},
        media_type="application/json",
    )

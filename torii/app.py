"""FastAPI application factory.

Route surface as it grows (PRD section 5): /mcp (proxy core),
/.well-known/* + /oauth/* (authorization server), /ui (credential and
admin GUI). Today: /healthz only.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from . import audit, crypto, startup

from . import (
    __version__,
    cache,
    config,
    db,
    directory,
    health,
    metrics,
    middleware,
    proxy,
    routes_oauth,
    routes_ui,
)

log = logging.getLogger(__name__)


async def _retention_loop():
    """Purge audit rows older than the retention window, every 24 hours."""
    interval = 24 * 3600
    while True:
        try:
            pool = await db.pool()
            async with pool.acquire() as conn:
                removed = await audit.purge_expired(conn, config.AUDIT_RETENTION_DAYS)
            log.info("audit retention purge: %s", removed)
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001
            log.exception("audit retention purge failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=config.LOG_LEVEL,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # Print each security-relevant setting's posture and refuse to start on the
    # worst combinations (e.g. an https origin with no SESSION_SECRET). This
    # runs before anything binds, so a misconfiguration fails the boot rather
    # than surfacing later as a mysterious auth bug. #80.
    startup.validate(os.environ)

    await db.migrate()

    # Fail loudly at boot rather than per-request: an encrypted credential with
    # no key would otherwise surface as every proxied call failing for a reason
    # that points at the upstream instead of at the missing key.
    pool = await db.pool()
    async with pool.acquire() as conn:
        await crypto.assert_key_present_if_needed(conn)

    retention = asyncio.create_task(_retention_loop())
    log.info("torii %s listening on %s:%s", __version__, config.HOST, config.PORT)
    try:
        yield
    finally:
        retention.cancel()
        try:
            await retention
        except asyncio.CancelledError:
            pass
        await db.close()
        await cache.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="torii",
        description="MCP gateway: OAuth 2.1, tool-level RBAC, audit.",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if config.ENABLE_DOCS else None,
        redoc_url=None,
        openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
    )
    # Re-validate the live principal behind a logged-in cookie (#61, #67). Added
    # before SessionMiddleware so it wraps INSIDE it — request.session must be
    # populated before this runs.
    app.add_middleware(middleware.SessionRevalidationMiddleware)
    # Signed cookie sessions for the login/authorize pages and /ui. Lax rather
    # than Strict so the redirect back from an OAuth client still carries it.
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.SESSION_SECRET,
        session_cookie="torii_session",
        https_only=config.SESSION_HTTPS_ONLY,
        same_site="lax",
        max_age=config.SESSION_TTL,
    )
    app.add_middleware(middleware.BearerAuthMiddleware)
    # Outermost so its headers ride on every response, including error and
    # redirect responses produced deeper in the stack (#59).
    app.add_middleware(middleware.SecurityHeadersMiddleware)
    app.include_router(health.router)
    app.include_router(directory.router)
    app.include_router(metrics.router)
    app.include_router(routes_oauth.router)
    app.include_router(routes_ui.router)
    app.include_router(proxy.router)
    return app


app = create_app()

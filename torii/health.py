"""/healthz — liveness for the tunnel and the deploy mechanism.

Per-upstream health (PRD FR5) joins this response when the upstream
registry lands with the proxy core.
"""

from fastapi import APIRouter, Response
from fastapi.responses import RedirectResponse

from . import __version__, cache, db

router = APIRouter()


@router.get("/", include_in_schema=False)
async def root():
    """Send a human at the bare hostname to the UI.

    Without this, the root path 404s with FastAPI's `{"detail":"Not Found"}`,
    which reads as "the service is broken" rather than "you want /ui".
    """
    return RedirectResponse("/ui", status_code=302)


@router.get("/healthz")
async def healthz(response: Response) -> dict:
    checks = {
        "database": await db.healthcheck(),
        "valkey": await cache.healthcheck(),
    }
    ok = all(c["ok"] for c in checks.values())
    response.status_code = 200 if ok else 503
    return {
        "status": "ok" if ok else "degraded",
        "service": "torii",
        "version": __version__,
        "checks": checks,
    }

"""/healthz contract: 200 when every dependency answers, 503 when one
doesn't — the deploy mechanism and the tunnel both key off that."""

import httpx
import pytest

from torii import __version__, app as app_module, cache, db


@pytest.fixture
def client():
    transport = httpx.ASGITransport(app=app_module.app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def test_healthz_ok(client, monkeypatch):
    monkeypatch.setattr(db, "healthcheck", lambda: _ok())
    monkeypatch.setattr(cache, "healthcheck", lambda: _ok())

    async with client as c:
        r = await c.get("/healthz")

    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "torii"
    assert body["version"] == __version__
    assert body["checks"] == {"database": {"ok": True}, "valkey": {"ok": True}}


async def test_healthz_degraded_when_database_down(client, monkeypatch):
    monkeypatch.setattr(db, "healthcheck", lambda: _fail("ConnectionRefusedError: no"))
    monkeypatch.setattr(cache, "healthcheck", lambda: _ok())

    async with client as c:
        r = await c.get("/healthz")

    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"]["ok"] is False
    assert body["checks"]["valkey"]["ok"] is True


async def test_healthz_degraded_when_valkey_down(client, monkeypatch):
    monkeypatch.setattr(db, "healthcheck", lambda: _ok())
    monkeypatch.setattr(cache, "healthcheck", lambda: _fail("TimeoutError: "))

    async with client as c:
        r = await c.get("/healthz")

    assert r.status_code == 503
    assert r.json()["checks"]["valkey"]["ok"] is False


async def test_db_healthcheck_reports_error_instead_of_raising(monkeypatch):
    """A dead database must degrade /healthz, never 500 it."""

    async def boom():
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(db, "pool", boom)
    result = await db.healthcheck()

    assert result["ok"] is False
    assert "ConnectionRefusedError" in result["error"]


async def test_cache_healthcheck_reports_error_instead_of_raising(monkeypatch):
    class DeadClient:
        async def ping(self):
            raise OSError("no route to host")

    monkeypatch.setattr(cache, "client", DeadClient)
    result = await cache.healthcheck()

    assert result["ok"] is False
    assert "OSError" in result["error"]


async def _ok() -> dict:
    return {"ok": True}


async def _fail(error: str) -> dict:
    return {"ok": False, "error": error}

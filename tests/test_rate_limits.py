"""Call rate limits (PRD Q19).

The brake for a stolen credential. What matters: it can't be dodged by
switching endpoint shape, it's visible in the audit like any other denial, and
a valkey outage fails in the direction that suits the caller.
"""

import os

import httpx
import pytest

from conftest import make_upstream
from torii import app as app_module
from torii import cache, config, credentials, db, limits, web

OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit("/", 1)[0]
    + "/torii_oauth",
)


@pytest.fixture
async def client(oauth_database, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL", oauth_database)
    db._pool = None
    cache._client = None
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """TRUNCATE audit_calls, audit_auth_events, tokens, grants, api_keys,
                        auth_identities, oauth_clients, upstreams, principals
                        RESTART IDENTITY CASCADE"""
        )
        keys = [k async for k in cache.client().scan_iter("torii:callrl:*")]
        if keys:
            await cache.client().delete(*keys)
    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="https://torii.test") as http:
        yield http
    await db.close()
    await cache.close()


async def _caller_key(kind="human", *, key_limit=None, principal_limit=None, grant=True):
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            """INSERT INTO principals (kind, username, rate_limit_per_min)
               VALUES ($1, 'caller', $2) RETURNING id""",
            kind, principal_limit,
        )
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:1/mcp")
        if grant:
            await conn.execute(
                """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
                   VALUES ('principal', $1, $2, 'all')""",
                principal_id, upstream_id,
            )
        key = await credentials.mint_api_key(conn, principal_id, "k")
        if key_limit:
            await conn.execute(
                "UPDATE api_keys SET rate_limit_per_min = $2 WHERE id = $1::uuid",
                key.id, key_limit,
            )
        return key.secret


def _rpc(id_, method="tools/list", params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


# --- precedence ------------------------------------------------------------


async def test_precedence_is_key_then_principal_then_default(client, monkeypatch):
    from torii.rbac import Caller

    monkeypatch.setattr(config, "DEFAULT_RATE_LIMIT_PER_MIN", 99)
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'p') RETURNING id"
        )
        key = await credentials.mint_api_key(conn, principal_id, "k")
        caller = Caller(principal_id=str(principal_id), api_key_id=key.id)

        assert (await limits.rate_limit_for(conn, caller)).source == "default"
        assert (await limits.rate_limit_for(conn, caller)).per_minute == 99

        await conn.execute(
            "UPDATE principals SET rate_limit_per_min = 30 WHERE id = $1", principal_id
        )
        resolved = await limits.rate_limit_for(conn, caller)
        assert (resolved.source, resolved.per_minute) == ("principal", 30)

        await conn.execute(
            "UPDATE api_keys SET rate_limit_per_min = 5 WHERE id = $1::uuid", key.id
        )
        resolved = await limits.rate_limit_for(conn, caller)
        assert (resolved.source, resolved.per_minute) == ("key", 5)


async def test_two_keys_of_one_principal_do_not_share_a_budget(client):
    """Counting per credential is what makes a per-key limit meaningful."""
    from torii.rbac import Caller

    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'p') RETURNING id"
        )
        first = await credentials.mint_api_key(conn, principal_id, "a")
        second = await credentials.mint_api_key(conn, principal_id, "b")
        one = await limits.rate_limit_for(conn, Caller(principal_id=str(principal_id), api_key_id=first.id))
        two = await limits.rate_limit_for(conn, Caller(principal_id=str(principal_id), api_key_id=second.id))
    assert one.bucket != two.bucket


# --- enforcement ----------------------------------------------------------


async def test_calls_are_refused_past_the_limit(client):
    secret = await _caller_key(key_limit=3)
    headers = {"Authorization": f"Bearer {secret}"}

    for i in range(3):
        assert (await client.post("/mcp", headers=headers, json=_rpc(i))).status_code == 200

    refused = await client.post("/mcp", headers=headers, json=_rpc(99))
    body = refused.json()
    assert body["error"]["code"] == -32004
    assert body["error"]["data"]["limit"] == 3
    assert body["error"]["data"]["retry_after_seconds"] >= 1
    assert refused.headers["retry-after"]


async def test_the_limit_cannot_be_dodged_by_switching_endpoint_shape(client):
    """One budget across /mcp and /<slug>/mcp — otherwise alternating them
    doubles the allowance."""
    secret = await _caller_key(key_limit=4)
    headers = {"Authorization": f"Bearer {secret}"}

    for i, path in enumerate(["/mcp", "/wk/mcp", "/mcp", "/wk/mcp"]):
        assert (await client.post(path, headers=headers, json=_rpc(i))).status_code == 200

    for path in ("/mcp", "/wk/mcp"):
        refused = await client.post(path, headers=headers, json=_rpc(50))
        assert refused.json()["error"]["code"] == -32004, path


async def test_a_refusal_is_audited_like_any_other_denial(client):
    secret = await _caller_key(key_limit=1)
    headers = {"Authorization": f"Bearer {secret}"}
    await client.post("/mcp", headers=headers, json=_rpc(1))
    await client.post("/mcp", headers=headers, json=_rpc(2))

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT outcome, error_code FROM audit_calls ORDER BY id DESC LIMIT 1"
        )
    assert (row["outcome"], row["error_code"]) == ("denied", "rate_limited")


async def test_the_handshake_is_never_rate_limited(client):
    """Refusing initialize would look like a broken gateway, and it reaches no
    upstream."""
    secret = await _caller_key(key_limit=1)
    headers = {"Authorization": f"Bearer {secret}"}
    await client.post("/mcp", headers=headers, json=_rpc(1))          # spends it

    for _ in range(5):
        response = await client.post(
            "/mcp", headers=headers,
            json=_rpc(2, "initialize", {"protocolVersion": "2025-06-18"}),
        )
        assert response.status_code == 200
        assert "result" in response.json()


# --- what an outage means -------------------------------------------------


async def test_a_counter_outage_fails_open_for_a_human(monkeypatch):
    """Locking the operator out of their own gateway because valkey blinked is
    worse than an unmetered minute — same call the login limiter makes."""
    async def boom():
        raise OSError("valkey down")
    monkeypatch.setattr(cache, "client", boom)

    limited, _ = await web.call_rate_limited("principal:x", 10, fail_closed=False)
    assert limited is False


async def test_a_counter_outage_fails_closed_for_a_service(monkeypatch):
    """A leaked machine credential is the threat this defends against, and a
    service can retry."""
    async def boom():
        raise OSError("valkey down")
    monkeypatch.setattr(cache, "client", boom)

    limited, retry_after = await web.call_rate_limited("key:x", 10, fail_closed=True)
    assert limited is True
    assert retry_after > 0


async def test_service_principals_fail_closed_and_humans_open(client):
    from torii.rbac import Caller

    pool = await db.pool()
    async with pool.acquire() as conn:
        human = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'h') RETURNING id"
        )
        service = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('service', 's') RETURNING id"
        )
        human_key = await credentials.mint_api_key(conn, human, "h")
        service_key = await credentials.mint_api_key(conn, service, "s")

        assert (await limits.rate_limit_for(
            conn, Caller(principal_id=str(human), api_key_id=human_key.id)
        )).fail_closed is False
        assert (await limits.rate_limit_for(
            conn, Caller(principal_id=str(service), kind="service", api_key_id=service_key.id)
        )).fail_closed is True

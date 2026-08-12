"""The proxy core.

An in-process fake MCP upstream serves whatever tools each test asks for, and
`torii.proxy` routes real HTTP through to it. That covers the parts static
tests can't: namespacing on the wire, filtered listing across a real
concurrent fan-out, error shaping on upstream timeout, audit rows written on
every outcome.
"""

import asyncio
import os
import threading
import time
from wsgiref.simple_server import make_server

import httpx
import pytest

from conftest import make_upstream
from torii import cache, config, credentials, db
from torii import app as app_module
from torii.rbac import Caller

USERNAME = "alice"
PASSWORD = "very-long-real-password"


# --- fake upstream ---------------------------------------------------------


class FakeUpstream:
    """A minimal MCP-shaped JSON-RPC endpoint.

    Handlers are (method) -> callable(params) -> result. A callable may sleep
    to force a timeout, or raise to force an upstream error.
    """

    def __init__(self):
        self.handlers = {}

    def set_tools(self, tools):
        self.handlers["tools/list"] = lambda params: {"tools": tools}

    def set_call(self, fn):
        self.handlers["tools/call"] = fn

    def __call__(self, environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        import json
        body = json.loads(environ["wsgi.input"].read(length) or b"{}")
        method = body.get("method")
        params = body.get("params") or {}
        handler = self.handlers.get(method)
        if handler is None:
            payload = {"jsonrpc": "2.0", "id": body.get("id"),
                       "error": {"code": -32601, "message": f"no {method}"}}
        else:
            try:
                payload = {"jsonrpc": "2.0", "id": body.get("id"),
                           "result": handler(params)}
            except Exception as exc:  # noqa: BLE001
                payload = {"jsonrpc": "2.0", "id": body.get("id"),
                           "error": {"code": -32000, "message": str(exc)}}
        encoded = json.dumps(payload).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(encoded)))])
        return [encoded]


@pytest.fixture
def upstream():
    fake = FakeUpstream()
    server = make_server("127.0.0.1", 0, fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fake.host, fake.port = server.server_address
    fake.url = f"http://{fake.host}:{fake.port}/mcp"
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def second_upstream():
    fake = FakeUpstream()
    server = make_server("127.0.0.1", 0, fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fake.host, fake.port = server.server_address
    fake.url = f"http://{fake.host}:{fake.port}/mcp"
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


# --- app harness -----------------------------------------------------------


OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit(
        "/", 1
    )[0]
    + "/torii_oauth",
)


@pytest.fixture
async def client(oauth_database, monkeypatch):
    """HTTP client against the app, sharing the OAuth-tests database."""
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
        keys = [k async for k in cache.client().scan_iter("torii:*")]
        if keys:
            await cache.client().delete(*keys)

    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="https://torii.test") as http:
        yield http

    await db.close()
    await cache.close()


async def _principal(username="alice", kind="human"):
    pool = await db.pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ($1, $2) RETURNING id",
            kind,
            username,
        )


async def _register_upstream(name, url, enabled=True):
    pool = await db.pool()
    async with pool.acquire() as conn:
        return await make_upstream(conn, name, url, enabled=enabled)


async def _grant(principal_id, upstream_id, scope="all", tools=()):
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope, tools)
               VALUES ('principal', $1, $2, $3, $4)""",
            principal_id,
            upstream_id,
            scope,
            list(tools),
        )


async def _mint_key(principal_id):
    pool = await db.pool()
    async with pool.acquire() as conn:
        minted = await credentials.mint_api_key(conn, principal_id, "test")
        return minted.secret


def _rpc(id_, method, params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


# --- unauth and shape -----------------------------------------------------


async def test_mcp_requires_a_bearer_token(client):
    response = await client.post("/mcp", json=_rpc(1, "tools/list"))
    assert response.status_code == 401
    assert "/.well-known/oauth-protected-resource" in response.headers["www-authenticate"]


async def test_bad_bearer_is_401(client):
    response = await client.post(
        "/mcp",
        headers={"Authorization": "Bearer nope"},
        json=_rpc(1, "tools/list"),
    )
    assert response.status_code == 401


async def test_get_and_delete_answer_405(client):
    for verb in ("get", "delete"):
        response = await getattr(client, verb)("/mcp")
        assert response.status_code == 405
        assert response.headers["allow"] == "POST"


# --- initialize -----------------------------------------------------------


async def test_initialize_advertises_torii_and_the_clients_protocol(client, upstream):
    principal_id = await _principal()
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "initialize", {"protocolVersion": "2025-03-26"}),
    )
    body = response.json()
    assert body["result"]["serverInfo"]["name"] == "torii"
    assert body["result"]["protocolVersion"] == "2025-03-26"


# --- tools/list -----------------------------------------------------------


async def test_tools_list_is_empty_for_a_caller_with_no_grants(client, upstream):
    principal_id = await _principal()
    await _register_upstream("knowledge", upstream.url)
    upstream.set_tools([{"name": "get_doc", "description": "get a doc"}])
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    assert response.status_code == 200
    assert response.json()["result"] == {"tools": []}


async def test_tools_list_is_namespaced_and_filtered(client, upstream):
    principal_id = await _principal()
    upstream_id = await _register_upstream("knowledge", upstream.url)
    upstream.set_tools([
        {"name": "get_doc", "description": "get a doc"},
        {"name": "search_knowledge", "description": "search"},
        {"name": "run_sql", "description": "sql"},
    ])
    await _grant(principal_id, upstream_id, scope="list", tools=["search_knowledge", "get_doc"])
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    tools = {t["name"] for t in response.json()["result"]["tools"]}
    # Namespaced, and run_sql is filtered out even though the upstream offered it.
    assert tools == {"knowledge__get_doc", "knowledge__search_knowledge"}


async def test_tools_list_omits_ungranted_upstreams_entirely(client, upstream, second_upstream):
    """FR1: an ungranted upstream is invisible, not merely undeniable."""
    principal_id = await _principal()
    wk_id = await _register_upstream("knowledge", upstream.url)
    await _register_upstream("brain", second_upstream.url)
    upstream.set_tools([{"name": "get_doc"}])
    second_upstream.set_tools([{"name": "capture_thought"}])
    await _grant(principal_id, wk_id, scope="all")
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    tools = {t["name"] for t in response.json()["result"]["tools"]}
    assert tools == {"knowledge__get_doc"}


async def test_tools_list_survives_one_upstream_being_down(client, upstream, second_upstream):
    principal_id = await _principal()
    up_id = await _register_upstream("knowledge", upstream.url)
    down_id = await _register_upstream("brain", "http://127.0.0.1:1/nope")
    upstream.set_tools([{"name": "get_doc"}])
    await _grant(principal_id, up_id)
    await _grant(principal_id, down_id)
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    tools = {t["name"] for t in response.json()["result"]["tools"]}
    assert tools == {"knowledge__get_doc"}


# --- tools/call -----------------------------------------------------------


async def test_tools_call_forwards_the_stripped_name(client, upstream):
    seen = {}
    def record(params):
        seen["params"] = params
        return {"content": [{"type": "text", "text": "ok"}]}
    upstream.set_call(record)

    principal_id = await _principal()
    upstream_id = await _register_upstream("knowledge", upstream.url)
    await _grant(principal_id, upstream_id)
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(2, "tools/call", {"name": "knowledge__get_doc", "arguments": {"id": "42"}}),
    )
    body = response.json()
    assert body["result"] == {"content": [{"type": "text", "text": "ok"}]}
    # Upstream saw the un-namespaced tool name and the original arguments.
    assert seen["params"]["name"] == "get_doc"
    assert seen["params"]["arguments"] == {"id": "42"}


async def test_tools_call_denies_ungranted_tool(client, upstream):
    principal_id = await _principal()
    upstream_id = await _register_upstream("knowledge", upstream.url)
    await _grant(principal_id, upstream_id, scope="list", tools=["get_doc"])
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(3, "tools/call", {"name": "knowledge__run_sql", "arguments": {}}),
    )
    body = response.json()
    assert body["error"]["code"] == -32001
    assert body["error"]["data"]["reason"] == "tool_not_granted"


async def test_tools_call_denies_malformed_names(client):
    principal_id = await _principal()
    key = await _mint_key(principal_id)
    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(4, "tools/call", {"name": "not_namespaced", "arguments": {}}),
    )
    assert response.json()["error"]["code"] == -32602


async def test_upstream_timeout_becomes_a_clean_mcp_error(client, upstream):
    upstream.set_call(lambda params: time.sleep(3) or {})

    principal_id = await _principal()
    upstream_id = await _register_upstream("knowledge", upstream.url)
    await _grant(principal_id, upstream_id)
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute("UPDATE upstreams SET timeout_seconds = 1 WHERE id = $1", upstream_id)
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(5, "tools/call", {"name": "knowledge__get_doc", "arguments": {}}),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["error"]["code"] == -32002
    assert "timeout" in body["error"]["message"]


async def test_upstream_error_hides_the_internal_replica_url(client):
    """#76: a failing upstream must not hand the caller its internal LAN URL.
    A dead endpoint yields a network error whose server-side detail names the
    URL — the client must see only a generic category."""
    principal_id = await _principal()
    upstream_id = await _register_upstream(
        "knowledge", "http://127.0.0.1:1/secret-replica-path"
    )
    await _grant(principal_id, upstream_id)
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(7, "tools/call", {"name": "knowledge__get_doc", "arguments": {}}),
    )
    raw = response.text
    assert response.json()["error"]["code"] == -32002  # network -> unavailable
    assert "secret-replica-path" not in raw, "leaked the internal URL path"
    assert "127.0.0.1:1" not in raw, "leaked the internal host:port"


async def test_upstream_error_hides_the_raw_upstream_body(client):
    """#76: the upstream's raw response bytes (a stack trace, say) must not be
    echoed back to the caller as error data — only to the server log."""
    secret = "INTERNAL-STACKTRACE-do-not-leak-9f3a"

    def app(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        environ["wsgi.input"].read(length)
        body = secret.encode()
        start_response("500 Internal Server Error",
                       [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))])
        return [body]

    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    url = f"http://{host}:{port}/mcp"
    try:
        principal_id = await _principal()
        upstream_id = await _register_upstream("knowledge", url)
        await _grant(principal_id, upstream_id)
        key = await _mint_key(principal_id)

        response = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {key}"},
            json=_rpc(8, "tools/call", {"name": "knowledge__get_doc", "arguments": {}}),
        )
        raw = response.text
        assert response.json()["error"]["code"] in (-32002, -32003)
        assert secret not in raw, "leaked the raw upstream body"
        assert str(port) not in raw, "leaked the internal port"
    finally:
        server.shutdown()
        server.server_close()


async def test_upstream_rpc_error_passes_through_shaped(client, upstream):
    def boom(params):
        raise RuntimeError("upstream broke")
    upstream.set_call(boom)

    principal_id = await _principal()
    upstream_id = await _register_upstream("knowledge", upstream.url)
    await _grant(principal_id, upstream_id)
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(6, "tools/call", {"name": "knowledge__get_doc", "arguments": {}}),
    )
    assert response.json()["error"]["code"] == -32003


# --- audit ---------------------------------------------------------------


async def test_ok_denied_and_error_all_get_audited(client, upstream):
    upstream.set_tools([{"name": "get_doc"}])
    upstream.set_call(lambda params: {"content": []} if params["name"] == "get_doc" else (_ for _ in ()).throw(RuntimeError("no")))

    principal_id = await _principal()
    upstream_id = await _register_upstream("knowledge", upstream.url)
    await _grant(principal_id, upstream_id, scope="list", tools=["get_doc"])
    key = await _mint_key(principal_id)
    headers = {"Authorization": f"Bearer {key}"}

    await client.post("/mcp", headers=headers, json=_rpc(1, "tools/list"))
    await client.post("/mcp", headers=headers, json=_rpc(2, "tools/call",
        {"name": "knowledge__get_doc", "arguments": {}}))
    await client.post("/mcp", headers=headers, json=_rpc(3, "tools/call",
        {"name": "knowledge__forbidden", "arguments": {}}))

    pool = await db.pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT method, outcome, tool_name, error_code FROM audit_calls ORDER BY id"
        )
    outcomes = [(r["method"], r["outcome"], r["error_code"]) for r in rows]
    assert outcomes == [
        ("tools/list", "ok", None),
        ("tools/call", "ok", None),
        ("tools/call", "denied", "tool_not_granted"),
    ]


async def test_bad_bearer_writes_an_auth_failure(client):
    await client.post(
        "/mcp",
        headers={"Authorization": "Bearer nope-still"},
        json=_rpc(1, "tools/list"),
    )
    pool = await db.pool()
    async with pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'auth_failure'"
        )
    assert count == 1


# --- ceiling: no admin bypass on the proxy either -------------------------


async def test_admin_flag_grants_no_tools_at_the_proxy(client, upstream):
    """The admin flag governs the /ui admin screens only. The proxy must not
    read it — a principal with no grants sees nothing regardless of is_admin."""
    principal_id = await _principal()
    upstream_id = await _register_upstream("knowledge", upstream.url)
    upstream.set_tools([{"name": "get_doc"}])
    pool = await db.pool()
    async with pool.acquire() as conn:
        # totp_required comes along because an admin row can't exist without
        # it (Q11) — irrelevant to the proxy, which is exactly the point.
        await conn.execute(
            "UPDATE principals SET is_admin = TRUE, totp_required = TRUE WHERE id = $1",
            principal_id,
        )
    key = await _mint_key(principal_id)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    assert response.json()["result"] == {"tools": []}

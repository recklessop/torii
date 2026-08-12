"""Per-server MCP endpoints, `/<server>/mcp` (PRD Q13).

The point of these is ergonomic — a client that wants one server shouldn't
carry the whole estate's tool list — so the tests care about two things:

1. The naming really is different (bare here, prefixed on the aggregate).
2. Authorization is really NOT different. A second endpoint shape is a
   second chance to get access control wrong, so every deny that holds on
   `/mcp` must hold identically here.
"""

import os
import threading
from wsgiref.simple_server import make_server

import httpx
import pytest

from conftest import make_upstream
from torii import app as app_module
from torii import cache, config, credentials, db

OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit("/", 1)[0]
    + "/torii_oauth",
)


class FakeUpstream:
    def __init__(self, tools, name="fake"):
        self.tools = tools
        self.name = name
        self.calls = []

    def __call__(self, environ, start_response):
        import json
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = json.loads(environ["wsgi.input"].read(length) or b"{}")
        method = body.get("method")
        params = body.get("params") or {}
        if method == "tools/list":
            result = {"tools": self.tools}
        elif method == "tools/call":
            self.calls.append(params)
            result = {"content": [{"type": "text", "text": f"ran {params.get('name')}"}]}
        else:
            result = {}
        encoded = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(encoded)))])
        return [encoded]


def _serve(fake):
    server = make_server("127.0.0.1", 0, fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    fake.url = f"http://{host}:{port}/mcp"
    return server


@pytest.fixture
def wk():
    fake = FakeUpstream([
        {"name": "search_knowledge", "description": "search"},
        {"name": "get_doc", "description": "fetch"},
    ])
    server = _serve(fake)
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def brain():
    fake = FakeUpstream([{"name": "capture_thought", "description": "capture"}])
    server = _serve(fake)
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


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
    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="https://torii.test") as http:
        yield http
    await db.close()
    await cache.close()


async def _setup(name, url, *, scope="all", tools=(), username="alice"):
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "SELECT id FROM principals WHERE username = $1", username
        ) or await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', $1) RETURNING id", username
        )
        upstream_id = await make_upstream(conn, name, url)
        if scope:
            await conn.execute(
                """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope, tools)
                   VALUES ('principal', $1, $2, $3, $4)""",
                principal_id, upstream_id, scope, list(tools),
            )
        key = await credentials.mint_api_key(conn, principal_id, "test")
        return principal_id, key.secret


def _rpc(id_, method, params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


# --- naming ---------------------------------------------------------------


async def test_per_server_tools_are_bare(client, wk):
    _, key = await _setup("knowledge", wk.url)
    response = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    names = {t["name"] for t in response.json()["result"]["tools"]}
    assert names == {"search_knowledge", "get_doc"}


async def test_aggregate_tools_stay_prefixed(client, wk):
    _, key = await _setup("knowledge", wk.url)
    response = await client.post(
        "/mcp", headers={"Authorization": f"Bearer {key}"}, json=_rpc(1, "tools/list")
    )
    names = {t["name"] for t in response.json()["result"]["tools"]}
    assert names == {"knowledge__search_knowledge", "knowledge__get_doc"}


async def test_per_server_endpoint_shows_only_its_own_server(client, wk, brain):
    """The whole reason this exists: one server's endpoint doesn't carry the
    other server's tools."""
    _, key = await _setup("knowledge", wk.url)
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval("SELECT id FROM principals LIMIT 1")
        brain_id = await make_upstream(conn, "brain", brain.url)
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, brain_id,
        )

    aggregate = await client.post(
        "/mcp", headers={"Authorization": f"Bearer {key}"}, json=_rpc(1, "tools/list")
    )
    assert len(aggregate.json()["result"]["tools"]) == 3

    per_server = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(2, "tools/list"),
    )
    names = {t["name"] for t in per_server.json()["result"]["tools"]}
    assert names == {"search_knowledge", "get_doc"}


async def test_initialize_identifies_the_server(client, wk):
    _, key = await _setup("knowledge", wk.url)
    response = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "initialize", {"protocolVersion": "2025-06-18"}),
    )
    assert response.json()["result"]["serverInfo"]["name"] == "torii/knowledge"


# --- calling --------------------------------------------------------------


async def test_bare_name_calls_through(client, wk):
    _, key = await _setup("knowledge", wk.url)
    response = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(2, "tools/call", {"name": "get_doc", "arguments": {"id": "7"}}),
    )
    assert response.json()["result"]["content"][0]["text"] == "ran get_doc"
    # Upstream sees the bare name and the original arguments.
    assert wk.calls[-1]["name"] == "get_doc"
    assert wk.calls[-1]["arguments"] == {"id": "7"}


async def test_namespaced_name_is_tolerated_on_its_own_endpoint(client, wk):
    """A client that carried a name over from the aggregate endpoint should
    work rather than fail confusingly."""
    _, key = await _setup("knowledge", wk.url)
    response = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(3, "tools/call", {"name": "knowledge__get_doc", "arguments": {}}),
    )
    assert "result" in response.json()
    assert wk.calls[-1]["name"] == "get_doc"


async def test_another_servers_namespaced_name_is_refused(client, wk, brain):
    """Not silently routed elsewhere — that would make the URL a lie."""
    _, key = await _setup("knowledge", wk.url)
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval("SELECT id FROM principals LIMIT 1")
        brain_id = await make_upstream(conn, "brain", brain.url)
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, brain_id,
        )

    response = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(4, "tools/call", {"name": "brain__capture_thought", "arguments": {}}),
    )
    assert response.json()["error"]["code"] == -32602
    assert brain.calls == []


# --- authorization is identical -------------------------------------------


async def test_ungranted_server_is_an_empty_list_not_a_404(client, wk):
    """Answering 404 would confirm which servers exist; an empty list is the
    same answer the aggregate endpoint gives."""
    _, key = await _setup("knowledge", wk.url, scope=None)
    response = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    assert response.status_code == 200
    assert response.json()["result"] == {"tools": []}


async def test_nonexistent_server_answers_like_an_ungranted_one(client, wk):
    _, key = await _setup("knowledge", wk.url)
    response = await client.post(
        "/no-such-server/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    assert response.status_code == 200
    assert response.json()["result"] == {"tools": []}


async def test_tool_scope_is_enforced_on_the_per_server_endpoint(client, wk):
    _, key = await _setup("knowledge", wk.url, scope="list", tools=["get_doc"])

    listed = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/list"),
    )
    assert {t["name"] for t in listed.json()["result"]["tools"]} == {"get_doc"}

    denied = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(2, "tools/call", {"name": "search_knowledge", "arguments": {}}),
    )
    assert denied.json()["error"]["code"] == -32001
    assert denied.json()["error"]["data"]["reason"] == "tool_not_granted"
    assert wk.calls == []


async def test_calling_an_ungranted_server_is_denied(client, wk):
    _, key = await _setup("knowledge", wk.url, scope=None)
    response = await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(2, "tools/call", {"name": "get_doc", "arguments": {}}),
    )
    assert response.json()["error"]["data"]["reason"] == "no_grant"
    assert wk.calls == []


async def test_unauthenticated_is_401_with_per_server_discovery(client, wk):
    await _setup("knowledge", wk.url)
    response = await client.post("/knowledge/mcp", json=_rpc(1, "tools/list"))
    assert response.status_code == 401
    # The hint points at THIS endpoint's resource metadata.
    assert "/.well-known/oauth-protected-resource/knowledge/mcp" in (
        response.headers["www-authenticate"]
    )


async def test_calls_are_audited_with_the_server(client, wk):
    _, key = await _setup("knowledge", wk.url)
    await client.post(
        "/knowledge/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(2, "tools/call", {"name": "get_doc", "arguments": {}}),
    )
    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT upstream_name, tool_name, outcome FROM audit_calls ORDER BY id DESC LIMIT 1"
        )
    assert row["upstream_name"] == "knowledge"
    assert row["tool_name"] == "get_doc"
    assert row["outcome"] == "ok"


# --- discovery ------------------------------------------------------------


async def test_per_server_resource_metadata(client):
    response = await client.get("/.well-known/oauth-protected-resource/knowledge/mcp")
    assert response.status_code == 200
    body = response.json()
    assert body["resource"] == f"{config.PUBLIC_BASE_URL}/knowledge/mcp"
    assert body["authorization_servers"] == [config.PUBLIC_BASE_URL]


async def test_session_verbs_answer_405_on_per_server_endpoints(client):
    for verb in ("get", "delete"):
        response = await getattr(client, verb)("/knowledge/mcp")
        assert response.status_code == 405


# --- reserved names -------------------------------------------------------


@pytest.mark.parametrize("name", ["ui", "mcp", "oauth", "directory", "healthz", "admin"])
async def test_reserved_names_are_refused(client, name):
    """An upstream named after one of torii's own routes would shadow the
    gateway. The schema refuses it, so no form handler can let one in."""
    import asyncpg

    pool = await db.pool()
    async with pool.acquire() as conn:
        with pytest.raises(asyncpg.IntegrityConstraintViolationError):
            await make_upstream(conn, name, "http://x/mcp")


# --- editable slug (Q13) --------------------------------------------------


async def test_renaming_the_slug_moves_the_endpoint_and_keeps_grants(client, wk):
    """MetaMCP-style: the slug is the URL. Editing it must move the endpoint
    and the tool prefix, without touching who can reach the server."""
    _, key = await _setup("knowledge", wk.url)
    headers = {"Authorization": f"Bearer {key}"}

    before = await client.post("/knowledge/mcp", headers=headers, json=_rpc(1, "tools/list"))
    assert len(before.json()["result"]["tools"]) == 2

    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await conn.fetchval("SELECT id FROM upstreams WHERE name = 'knowledge'")
        grants_before = await conn.fetchval("SELECT count(*) FROM grants")
        await conn.execute("UPDATE upstreams SET name = 'hpe-notes' WHERE id = $1", upstream_id)

        # The grant references the server by id, so it survives untouched.
        assert await conn.fetchval("SELECT count(*) FROM grants") == grants_before

    # New endpoint works...
    after = await client.post("/hpe-notes/mcp", headers=headers, json=_rpc(2, "tools/list"))
    assert {t["name"] for t in after.json()["result"]["tools"]} == {"search_knowledge", "get_doc"}

    # ...the old one is now just an unknown server, i.e. an empty list.
    stale = await client.post("/knowledge/mcp", headers=headers, json=_rpc(3, "tools/list"))
    assert stale.json()["result"] == {"tools": []}

    # And the aggregate endpoint's prefixes follow the new slug.
    aggregate = await client.post("/mcp", headers=headers, json=_rpc(4, "tools/list"))
    names = {t["name"] for t in aggregate.json()["result"]["tools"]}
    assert names == {"hpe-notes__search_knowledge", "hpe-notes__get_doc"}


async def test_display_name_is_free_text_and_separate_from_the_slug(client, wk):
    """The slug carries the URL constraints; the label doesn't have to."""
    await _setup("knowledge", wk.url)
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE upstreams SET display_name = $1 WHERE name = 'knowledge'",
            "Work Knowledge — HPE / DRaaS",
        )
        row = await conn.fetchrow(
            "SELECT name, display_name FROM upstreams WHERE name = 'knowledge'"
        )
    assert row["name"] == "knowledge"
    assert row["display_name"] == "Work Knowledge — HPE / DRaaS"

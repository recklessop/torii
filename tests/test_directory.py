"""The public MCP directory (PRD Q12).

This is the only unauthenticated, crawlable surface on the gateway, so the
tests lean hard on what it must NOT do: leak LAN URLs, leak auth headers,
list private servers, confirm that a private server exists, or grant anybody
access by being readable.
"""

import os
import threading
from wsgiref.simple_server import make_server

import httpx
import pytest

from conftest import make_upstream
from torii import app as app_module
from torii import cache, config, credentials, db, directory

OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit("/", 1)[0]
    + "/torii_oauth",
)

SECRET_HEADER_VALUE = "Bearer super-secret-upstream-token"
LAN_URL_HOST = "10.99.99.99"


class FakeUpstream:
    """Serves a tool list so the directory has something to publish."""

    def __init__(self, tools):
        self.tools = tools

    def __call__(self, environ, start_response):
        import json
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = json.loads(environ["wsgi.input"].read(length) or b"{}")
        payload = {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {"tools": self.tools},
        }
        encoded = json.dumps(payload).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(encoded)))])
        return [encoded]


@pytest.fixture
def upstream():
    fake = FakeUpstream([
        {"name": "search_knowledge", "description": "Search the knowledge base."},
        {"name": "get_doc", "description": "Fetch one document."},
    ])
    server = make_server("127.0.0.1", 0, fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    fake.url = f"http://{host}:{port}/mcp"
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
        keys = [k async for k in cache.client().scan_iter("torii:*")]
        if keys:
            await cache.client().delete(*keys)

    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://torii.test", follow_redirects=False
    ) as http:
        yield http

    await db.close()
    await cache.close()


async def _register(name, url, *, public, description="A server.", enabled=True):
    pool = await db.pool()
    async with pool.acquire() as conn:
        return await make_upstream(
            conn, name, url,
            description=description,
            auth_header_name="Authorization",
            auth_header_value=SECRET_HEADER_VALUE,
            enabled=enabled,
            public_listed=public,
        )


# --- listing ---------------------------------------------------------------


async def test_directory_needs_no_authentication(client, upstream):
    await _register("knowledge", upstream.url, public=True)
    response = await client.get("/directory")
    assert response.status_code == 200
    assert "knowledge" in response.text


async def test_only_public_servers_are_listed(client, upstream):
    await _register("public-one", upstream.url, public=True)
    await _register("private-one", upstream.url, public=False)

    response = await client.get("/directory")
    assert "public-one" in response.text
    assert "private-one" not in response.text


async def test_private_server_page_is_404_and_does_not_confirm_existence(client, upstream):
    """A private server and a nonexistent one must answer identically —
    otherwise the directory becomes an enumeration oracle."""
    await _register("private-one", upstream.url, public=False)

    private = await client.get("/directory/private-one")
    absent = await client.get("/directory/no-such-server")

    assert private.status_code == 404
    assert absent.status_code == 404
    assert "private-one" not in private.text or "isn't in the public directory" in private.text


async def test_server_page_lists_namespaced_tools(client, upstream):
    await _register("knowledge", upstream.url, public=True)
    response = await client.get("/directory/knowledge")
    assert response.status_code == 200
    assert "knowledge__search_knowledge" in response.text
    assert "Search the knowledge base." in response.text


async def test_directory_never_leaks_the_lan_url_or_auth_header(client):
    """The two things that would turn a public listing into a security
    problem: where the backend actually is, and the credential to reach it."""
    await _register("knowledge", f"http://{LAN_URL_HOST}:8500/mcp", public=True)

    for path in ("/directory", "/directory/knowledge", "/directory.json"):
        response = await client.get(path)
        assert LAN_URL_HOST not in response.text, f"LAN URL leaked at {path}"
        assert SECRET_HEADER_VALUE not in response.text, f"auth header value leaked at {path}"
        assert "enc:v1:" not in response.text, f"ciphertext leaked at {path}"
        assert "super-secret-upstream-token" not in response.text, f"credential leaked at {path}"
        # The string "Authorization" does appear as a row label describing the
        # gateway's OAuth support — that's documentation, not the upstream's
        # header. What must never appear is its value, asserted above.


async def test_offline_server_still_lists_without_its_tools(client):
    """A backend being down must not blank the page."""
    await _register("knowledge", "http://127.0.0.1:1/mcp", public=True, enabled=False)
    response = await client.get("/directory/knowledge")
    assert response.status_code == 200
    assert "offline" in response.text.lower()


# --- machine-readable ------------------------------------------------------


async def test_directory_json_describes_the_gateway_and_servers(client, upstream):
    await _register("knowledge", upstream.url, public=True, description="HPE notes.")
    response = await client.get("/directory.json")
    assert response.status_code == 200
    body = response.json()

    assert body["gateway"]["mcp_endpoint"].endswith("/mcp")
    assert body["gateway"]["transport"] == "streamable-http"
    assert body["gateway"]["authorization"]["dynamic_registration"] is True
    names = [s["name"] for s in body["servers"]]
    assert names == ["knowledge"]
    assert body["servers"][0]["summary"] == "HPE notes."
    assert any(t["name"] == "get_doc" for t in body["servers"][0]["tools"])


async def test_directory_json_excludes_private_servers(client, upstream):
    await _register("public-one", upstream.url, public=True)
    await _register("private-one", upstream.url, public=False)
    body = (await client.get("/directory.json")).json()
    assert [s["name"] for s in body["servers"]] == ["public-one"]


# --- crawlability ----------------------------------------------------------


async def test_directory_is_indexable_but_the_app_is_not(client, upstream):
    await _register("knowledge", upstream.url, public=True)

    directory = await client.get("/directory")
    assert 'content="index, follow"' in directory.text

    login = await client.get("/ui/login")
    assert 'content="noindex, nofollow"' in login.text


async def test_robots_allows_the_directory_and_blocks_the_rest(client):
    response = await client.get("/robots.txt")
    assert response.status_code == 200
    body = response.text
    assert "Allow: /directory" in body
    for blocked in ("/ui", "/mcp", "/oauth", "/authorize"):
        assert f"Disallow: {blocked}" in body
    assert "Sitemap:" in body


async def test_sitemap_lists_public_servers_only(client, upstream):
    await _register("public-one", upstream.url, public=True)
    await _register("private-one", upstream.url, public=False)

    response = await client.get("/sitemap.xml")
    assert response.status_code == 200
    assert "/directory/public-one" in response.text
    assert "private-one" not in response.text


async def test_pages_carry_structured_data_for_agents(client, upstream):
    await _register("knowledge", upstream.url, public=True)

    listing = await client.get("/directory")
    assert 'application/ld+json' in listing.text
    assert '"@type": "CollectionPage"' in listing.text

    detail = await client.get("/directory/knowledge")
    assert '"@type": "SoftwareApplication"' in detail.text


async def test_marketplace_is_an_alias(client):
    """The name is claimed now so paid listings later need no re-indexing."""
    response = await client.get("/marketplace")
    assert response.status_code == 302
    assert response.headers["location"] == "/directory"


# --- listing is not access -------------------------------------------------


async def test_listing_a_server_grants_nobody_access(client, upstream):
    """The whole point: a published server is readable-about and uncallable."""
    await _register("knowledge", upstream.url, public=True)

    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'nobody') RETURNING id"
        )
        key = await credentials.mint_api_key(conn, principal_id, "test")

    # It's in the public directory...
    assert "knowledge" in (await client.get("/directory")).text

    # ...and still invisible to a caller with no grant.
    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key.secret}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.json()["result"] == {"tools": []}

    denied = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key.secret}"},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "knowledge__get_doc", "arguments": {}}},
    )
    assert denied.json()["error"]["data"]["reason"] == "no_grant"


async def test_unlisting_removes_it_immediately(client, upstream):
    """Including from the tool-list cache — an unpublish has to bite now."""
    upstream_id = await _register("knowledge", upstream.url, public=True)
    assert "knowledge" in (await client.get("/directory")).text
    # Warm the tool cache.
    await client.get("/directory/knowledge")

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE upstreams SET public_listed = FALSE WHERE id = $1", upstream_id
        )

    assert "knowledge" not in (await client.get("/directory")).text
    assert (await client.get("/directory/knowledge")).status_code == 404


async def test_directory_json_gives_agents_the_per_server_endpoint(client, upstream):
    """An agent reading the JSON should get the exact URL to connect to for a
    single server, plus the prefix it would see on the aggregate."""
    await _register("knowledge", upstream.url, public=True)
    body = (await client.get("/directory.json")).json()

    assert body["gateway"]["per_server_endpoint"].endswith("/{server}/mcp")
    server = body["servers"][0]
    assert server["mcp_endpoint"] == f"{config.PUBLIC_BASE_URL}/knowledge/mcp"
    assert server["tool_prefix_on_aggregate"] == "knowledge__"


async def test_server_page_leads_with_its_own_endpoint(client, upstream):
    await _register("knowledge", upstream.url, public=True)
    text = (await client.get("/directory/knowledge")).text
    assert f"{config.PUBLIC_BASE_URL}/knowledge/mcp" in text
    # And the JSON-LD action points at the server, not the aggregate.
    assert f'"target": "{config.PUBLIC_BASE_URL}/knowledge/mcp"' in text


# --- stored XSS via JSON-LD (#59) ------------------------------------------

BREAKOUT = "</script><script>alert(document.cookie)</script>"


async def _register_summary(name, summary, *, public=True):
    pool = await db.pool()
    async with pool.acquire() as conn:
        return await make_upstream(
            conn, name, "http://127.0.0.1:1/mcp",
            public_summary=summary,
            public_listed=public,
            enabled=False,  # keep the backend out of it; we're testing the summary
        )


async def test_json_ld_escapes_a_script_breakout_in_the_summary(client):
    """An admin-set public_summary carrying `</script>` must not break out of
    the JSON-LD block. json.dumps alone does NOT escape `<`/`>`, so this is the
    regression guard for the stored-XSS hole (#59)."""
    await _register_summary("evil", BREAKOUT)

    for path in ("/directory", "/directory/evil"):
        text = (await client.get(path)).text
        assert BREAKOUT not in text, f"unescaped </script> reached {path}"
        # The payload still ships — as inert, escaped JSON — so the data isn't
        # silently dropped, it's neutralised.
        assert "\\u003c/script\\u003e" in text, f"expected escaped form at {path}"


async def test_json_ld_escapes_a_script_breakout_in_a_tool_name(client, monkeypatch):
    """The other injection source: an upstream-advertised tool NAME. It flows
    into featureList in the per-server JSON-LD."""
    async def fake_tools(_upstream):
        return [{"name": BREAKOUT, "namespaced": f"evil__{BREAKOUT}", "description": ""}]

    monkeypatch.setattr(directory, "public_tools", fake_tools)
    await _register("evil", "http://127.0.0.1:1/mcp", public=True)

    text = (await client.get("/directory/evil")).text
    assert BREAKOUT not in text
    assert "\\u003c/script\\u003e" in text


# --- security headers / CSP (#59) ------------------------------------------


async def test_security_headers_are_present_app_wide(client, upstream):
    await _register("knowledge", upstream.url, public=True)
    # A public page and an app page: the headers ride on every response.
    for path in ("/directory", "/ui/login"):
        response = await client.get(path)
        csp = response.headers.get("content-security-policy")
        assert csp is not None, f"no CSP on {path}"
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("referrer-policy") == "no-referrer"


# --- unauthenticated pool exhaustion / rate limit (#63) --------------------


async def test_directory_rate_limits_a_hammering_visitor(client, upstream, monkeypatch):
    """The directory is anonymous and crawlable; past a per-IP ceiling it must
    turn requests away with a 429 rather than let a flood pin the DB pool."""
    monkeypatch.setattr(directory, "DIR_RL_PER_IP_LIMIT", 3)
    await _register("knowledge", upstream.url, public=True)

    statuses = [(await client.get("/directory")).status_code for _ in range(6)]
    assert 429 in statuses, f"never rate limited: {statuses}"
    # The first few are served; the limit bites only after the ceiling.
    assert statuses[0] == 200

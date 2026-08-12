"""Talking to both shapes of MCP server (PRD Q23).

Streamable HTTP servers come in two flavours and torii has to speak both:

* STATELESS — every POST stands alone. What torii assumed originally, and what
  our own tenants happen to be (finder sets stateless_http=True on
  purpose).
* SESSION-BASED — `initialize` returns an `Mcp-Session-Id` that every later
  request must carry, 400ing without it. **This is the SDK default**, so it's
  what most third-party servers are — and torii couldn't talk to any of them.
"""

import json
import threading
from wsgiref.simple_server import make_server

import pytest

from torii import proxy


class StatefulServer:
    """Refuses anything without a session id, like the SDK's default mode."""

    def __init__(self):
        self.sessions = set()
        self.seen_initialized = False
        self.calls = []
        self.rejections = 0

    def __call__(self, environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = json.loads(environ["wsgi.input"].read(length) or b"{}")
        method = body.get("method")
        session = environ.get("HTTP_MCP_SESSION_ID")

        def reply(payload, status="200 OK", headers=None):
            encoded = json.dumps(payload).encode()
            start_response(status, [("Content-Type", "application/json"),
                                    ("Content-Length", str(len(encoded)))] + (headers or []))
            return [encoded]

        if method == "initialize":
            new_session = f"sess-{len(self.sessions) + 1}"
            self.sessions.add(new_session)
            return reply(
                {"jsonrpc": "2.0", "id": body.get("id"),
                 "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                            "serverInfo": {"name": "stateful", "version": "1"}}},
                headers=[("Mcp-Session-Id", new_session)],
            )

        if session not in self.sessions:
            self.rejections += 1
            return reply(
                {"jsonrpc": "2.0", "id": body.get("id"),
                 "error": {"code": -32600, "message": "Bad Request: No valid session ID provided"}},
                status="400 Bad Request",
            )

        if method == "notifications/initialized":
            self.seen_initialized = True
            return reply({})

        self.calls.append((method, session))
        if method == "tools/list":
            return reply({"jsonrpc": "2.0", "id": body.get("id"),
                          "result": {"tools": [{"name": "stateful_tool"}]}})
        return reply({"jsonrpc": "2.0", "id": body.get("id"),
                      "result": {"content": [{"type": "text", "text": "ok"}]}})

    def expire_all(self):
        """What an upstream restart looks like from torii's side."""
        self.sessions.clear()


class StatelessServer:
    """Answers anything, never issues a session — finder's shape."""

    def __init__(self):
        self.saw_session_header = False
        self.initializes = 0

    def __call__(self, environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = json.loads(environ["wsgi.input"].read(length) or b"{}")
        if environ.get("HTTP_MCP_SESSION_ID"):
            self.saw_session_header = True
        if body.get("method") == "initialize":
            self.initializes += 1
        payload = {"jsonrpc": "2.0", "id": body.get("id"),
                   "result": {"tools": [{"name": "stateless_tool"}]}}
        encoded = json.dumps(payload).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(encoded)))])
        return [encoded]


def _serve(app):
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/mcp"


@pytest.fixture(autouse=True)
def _clear_sessions():
    proxy._sessions.clear()
    yield
    proxy._sessions.clear()


@pytest.fixture
def stateful():
    app = StatefulServer()
    server, url = _serve(app)
    app.url = url
    try:
        yield app
    finally:
        server.shutdown(); server.server_close()


@pytest.fixture
def stateless():
    app = StatelessServer()
    server, url = _serve(app)
    app.url = url
    try:
        yield app
    finally:
        server.shutdown(); server.server_close()


def _upstream(url, name="server", id_="u1"):
    return proxy.Upstream(
        id=id_, name=name,
        endpoints=[proxy.Endpoint(id="e1", url=url)],
        auth_header_name=None, auth_header_value=None, timeout=10, enabled=True,
    )


# --- session-based servers -------------------------------------------------


async def test_a_session_based_server_works(stateful):
    """The bug: torii POSTed straight to tools/list with no handshake, and an
    SDK-default server answered "No valid session ID provided"."""
    result = await proxy.call_upstream(_upstream(stateful.url), "tools/list", {})
    assert [t["name"] for t in result["tools"]] == ["stateful_tool"]
    assert stateful.seen_initialized, "the spec's initialized notification was never sent"


async def test_the_session_is_reused_across_calls(stateful):
    """One handshake per caller, not per call."""
    upstream = _upstream(stateful.url)
    for _ in range(3):
        await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")
    assert len(stateful.sessions) == 1
    assert {session for _, session in stateful.calls} == stateful.sessions


async def test_each_principal_gets_its_own_session(stateful):
    """A session is somewhere a server may keep state, and torii multiplexes
    many principals onto one backend — sharing would leak between callers."""
    upstream = _upstream(stateful.url)
    await proxy.call_upstream(upstream, "tools/list", {}, scope="alice")
    await proxy.call_upstream(upstream, "tools/list", {}, scope="bob")
    assert len(stateful.sessions) == 2


async def test_an_expired_session_is_recovered_without_the_caller_noticing(stateful):
    """Every upstream restart expires its sessions. Without recovery, every
    caller is stranded until torii itself restarts."""
    upstream = _upstream(stateful.url)
    await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")
    stateful.expire_all()

    result = await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")
    assert [t["name"] for t in result["tools"]] == ["stateful_tool"]
    assert len(stateful.sessions) == 1        # a fresh one


async def test_tool_calls_carry_the_session_too(stateful):
    upstream = _upstream(stateful.url)
    await proxy.call_upstream(upstream, "tools/call", {"name": "x"}, scope="p1")
    methods = [method for method, _ in stateful.calls]
    assert "tools/call" in methods


# --- stateless servers -----------------------------------------------------


async def test_a_stateless_server_still_works_untouched(stateless):
    """finder and knowledge are this shape; they must not regress."""
    result = await proxy.call_upstream(_upstream(stateless.url), "tools/list", {})
    assert [t["name"] for t in result["tools"]] == ["stateless_tool"]


async def test_no_handshake_is_forced_on_a_stateless_server(stateless):
    """Don't pay for a round trip a stateless server doesn't need."""
    upstream = _upstream(stateless.url)
    for _ in range(3):
        await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")
    assert stateless.initializes == 0
    assert stateless.saw_session_header is False

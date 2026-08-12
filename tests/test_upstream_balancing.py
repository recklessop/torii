"""Several URLs per upstream (PRD Q24, issue #51).

Two things are under test and only one of them is the feature:

* **Balancing and affinity.** Calls spread across the replicas of a stateless
  server; a caller on a session-based server is pinned to whichever replica
  issued their session, because a session is valid nowhere else.
* **Retry safety.** A call is retried on another replica ONLY if it provably
  never reached the first. An MCP tool call isn't required to be idempotent,
  so a 500 after the side effect is indistinguishable from a 500 before it,
  and a read timeout means the request was delivered. The tests that assert
  the second replica saw ZERO requests are the double-execution guards, and
  they are the reason this feature is not a one-liner.
"""

import json
import os
import socket
import threading
import time
from wsgiref.simple_server import make_server

import httpx
import pytest

from conftest import add_endpoint, make_upstream
from torii import app as app_module
from torii import cache, config, credentials, db, proxy

OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit("/", 1)[0]
    + "/torii_oauth",
)


# --- replicas --------------------------------------------------------------


def _reply(start_response, payload, status="200 OK", headers=None):
    encoded = json.dumps(payload).encode()
    start_response(status, [("Content-Type", "application/json"),
                            ("Content-Length", str(len(encoded)))] + (headers or []))
    return [encoded]


class Replica:
    """A stateless MCP replica that can be told to misbehave.

    `mode` is "ok", "500", or "slow" — the three shapes the retry rule has to
    tell apart.
    """

    def __init__(self, label, mode="ok", delay=0.0):
        self.label = label
        self.mode = mode
        self.delay = delay
        self.requests = []

    def __call__(self, environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = json.loads(environ["wsgi.input"].read(length) or b"{}")
        self.requests.append(body.get("method"))
        if self.delay:
            time.sleep(self.delay)
        if self.mode == "500":
            return _reply(
                start_response,
                {"jsonrpc": "2.0", "id": body.get("id"),
                 "error": {"code": -32000, "message": "boom"}},
                status="500 Internal Server Error",
            )
        return _reply(start_response, {
            "jsonrpc": "2.0", "id": body.get("id"),
            "result": {"served_by": self.label, "tools": [{"name": "a_tool"}]},
        })


class SessionReplica:
    """A session-based replica: its session ids are valid only on itself.

    That is the whole hazard Q24 names — balance one of these without affinity
    and the second request lands somewhere that never heard of the session.
    """

    def __init__(self, label):
        self.label = label
        self.sessions = set()
        self.initializes = 0
        self.requests = []      # methods that got through
        self.rejections = 0

    def __call__(self, environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = json.loads(environ["wsgi.input"].read(length) or b"{}")
        method = body.get("method")
        session = environ.get("HTTP_MCP_SESSION_ID")

        if method == "initialize":
            self.initializes += 1
            new_session = f"{self.label}-{self.initializes}"
            self.sessions.add(new_session)
            return _reply(
                start_response,
                {"jsonrpc": "2.0", "id": body.get("id"),
                 "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                            "serverInfo": {"name": self.label, "version": "1"}}},
                headers=[("Mcp-Session-Id", new_session)],
            )

        if session not in self.sessions:
            self.rejections += 1
            return _reply(
                start_response,
                {"jsonrpc": "2.0", "id": body.get("id"),
                 "error": {"code": -32600, "message": "Bad Request: No valid session ID provided"}},
                status="400 Bad Request",
            )

        if method == "notifications/initialized":
            return _reply(start_response, {})

        self.requests.append(method)
        return _reply(start_response, {
            "jsonrpc": "2.0", "id": body.get("id"),
            "result": {"served_by": self.label, "tools": [{"name": "a_tool"}]},
        })


def _serve(app):
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    app.url = f"http://{host}:{port}/mcp"
    return server


@pytest.fixture
def replicas(request):
    """N live replicas, torn down together."""
    made = []

    def build(*specs):
        for index, spec in enumerate(specs):
            label = f"r{index + 1}"
            app = spec(label) if callable(spec) else Replica(label, mode=spec)
            server = _serve(app)
            request.addfinalizer(lambda s=server: (s.shutdown(), s.server_close()))
            made.append(app)
        return made

    return build


def _dead_url():
    """A port nothing is listening on — a refused connection, not a slow one."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}/mcp"


@pytest.fixture(autouse=True)
def _clean_selection_state():
    proxy._sessions.clear()
    proxy._round_robin.clear()
    yield
    proxy._sessions.clear()
    proxy._round_robin.clear()


def _upstream(*urls, name="server", timeout=10, enabled=(), id_="u1"):
    """An upstream over the given URLs, endpoint N disabled if listed in `enabled`."""
    endpoints = [
        proxy.Endpoint(id=f"e{i + 1}", url=url, enabled=(i not in enabled))
        for i, url in enumerate(urls)
    ]
    return proxy.Upstream(
        id=id_, name=name, endpoints=endpoints,
        auth_header_name=None, auth_header_value=None, timeout=timeout, enabled=True,
    )


# --- balancing -------------------------------------------------------------


async def test_a_stateless_upstream_spreads_calls_across_its_replicas(replicas):
    """No flag, no branch on server type: a stateless server issues no session,
    so nothing is ever pinned and the pick happens per call."""
    a, b = replicas("ok", "ok")
    upstream = _upstream(a.url, b.url)

    served = []
    for _ in range(6):
        result = await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")
        served.append(result["served_by"])

    assert set(served) == {"r1", "r2"}
    assert len(a.requests) == 3 and len(b.requests) == 3


async def test_a_session_based_caller_is_pinned_to_one_replica(replicas):
    """A session id is only valid on the replica that issued it. Balancing one
    of these per call would 400 on every request after the first."""
    a, b = replicas(SessionReplica, SessionReplica)
    upstream = _upstream(a.url, b.url)

    served = {
        (await proxy.call_upstream(upstream, "tools/list", {}, scope="alice"))["served_by"]
        for _ in range(5)
    }

    assert len(served) == 1, "the caller wandered between replicas"
    assert a.initializes + b.initializes == 1, "one handshake per caller, not per call"


async def test_two_principals_can_be_pinned_to_different_replicas(replicas):
    """Balancing a session-based server happens at session creation — that IS
    the spread, and it's why affinity doesn't mean 'everyone on replica one'."""
    a, b = replicas(SessionReplica, SessionReplica)
    upstream = _upstream(a.url, b.url)

    alice = (await proxy.call_upstream(upstream, "tools/list", {}, scope="alice"))["served_by"]
    bob = (await proxy.call_upstream(upstream, "tools/list", {}, scope="bob"))["served_by"]

    assert {alice, bob} == {"r1", "r2"}
    assert a.initializes == 1 and b.initializes == 1


async def test_a_disabled_endpoint_is_never_selected(replicas):
    a, b = replicas("ok", "ok")
    upstream = _upstream(a.url, b.url, enabled=(1,))

    for _ in range(4):
        await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")

    assert len(a.requests) == 4
    assert b.requests == []


async def test_zero_enabled_endpoints_fails_closed(replicas):
    """Not an unhandled exception — the schema can't hold "at least one
    endpoint" without a trigger, so the proxy has to."""
    a, = replicas("ok")
    upstream = _upstream(a.url, enabled=(0,))

    with pytest.raises(proxy.UpstreamError) as raised:
        await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")

    assert raised.value.kind == "no_endpoint"
    assert a.requests == []


# --- the retry rule --------------------------------------------------------


async def test_a_refused_connection_fails_over_to_another_replica(replicas):
    """The one failure that IS safe to retry: nothing reached the first one."""
    live, = replicas("ok")
    upstream = _upstream(_dead_url(), live.url)

    result, endpoint = await proxy.call_upstream_detailed(
        upstream, "tools/call", {"name": "a_tool"}, scope="p1"
    )

    assert result["served_by"] == "r1"
    assert endpoint.url == live.url
    assert len(live.requests) == 1


async def test_a_500_is_never_retried_on_another_replica(replicas):
    """The double-execution guard. A 500 after the tool ran is indistinguishable
    from a 500 before it, so the call stays failed."""
    broken, spare = replicas("500", "ok")
    upstream = _upstream(broken.url, spare.url)

    with pytest.raises(proxy.UpstreamError) as raised:
        await proxy.call_upstream(upstream, "tools/call", {"name": "a_tool"}, scope="p1")

    assert raised.value.kind == "http"
    assert spare.requests == [], "a 500 was retried elsewhere — the tool may have run twice"


async def test_a_read_timeout_is_never_retried_on_another_replica(replicas):
    """The other double-execution guard: the request WAS delivered. Slow is not
    the same as unreached, however much the failover story wants it to be."""
    slow, spare = replicas(lambda label: Replica(label, delay=3.0), "ok")
    upstream = _upstream(slow.url, spare.url, timeout=1)

    with pytest.raises(proxy.UpstreamError) as raised:
        await proxy.call_upstream(upstream, "tools/call", {"name": "a_tool"}, scope="p1")

    assert raised.value.kind == "timeout"
    assert spare.requests == [], "a delivered request was retried — the tool may have run twice"


async def test_a_jsonrpc_error_is_never_retried_on_another_replica(replicas):
    """An error BODY means the server ran far enough to answer."""
    class Erroring(Replica):
        def __call__(self, environ, start_response):
            length = int(environ.get("CONTENT_LENGTH") or 0)
            body = json.loads(environ["wsgi.input"].read(length) or b"{}")
            self.requests.append(body.get("method"))
            return _reply(start_response, {
                "jsonrpc": "2.0", "id": body.get("id"),
                "error": {"code": -32000, "message": "the tool exploded halfway"},
            })

    erroring, spare = replicas(Erroring, "ok")
    upstream = _upstream(erroring.url, spare.url)

    with pytest.raises(proxy.UpstreamError) as raised:
        await proxy.call_upstream(upstream, "tools/call", {"name": "a_tool"}, scope="p1")

    assert raised.value.kind == "rpc"
    assert spare.requests == []


async def test_every_replica_down_is_one_clean_error(replicas):
    upstream = _upstream(_dead_url(), _dead_url(), _dead_url())

    with pytest.raises(proxy.UpstreamError) as raised:
        await proxy.call_upstream(upstream, "tools/call", {"name": "a_tool"}, scope="p1")

    assert raised.value.kind == "network"
    assert raised.value.endpoint is not None, "the failing replica should be named"


def test_the_walk_visits_each_replica_once_and_is_bounded():
    """A wide fleet must not turn one caller's request into a long serial walk,
    and no replica may be tried twice inside a single call."""
    upstream = _upstream(*[f"http://127.0.0.1:900{i}/mcp" for i in range(6)])

    walk = proxy._walk(upstream, pinned_key=None)

    assert len(walk) == proxy.MAX_ENDPOINT_ATTEMPTS
    assert len({e.key for e in walk}) == len(walk)


def test_the_pinned_replica_is_walked_first():
    upstream = _upstream(*[f"http://127.0.0.1:900{i}/mcp" for i in range(4)])

    walk = proxy._walk(upstream, pinned_key="e3")

    assert walk[0].key == "e3"


# --- session recovery across replicas --------------------------------------


async def test_an_expired_session_recovers_onto_another_replica(replicas):
    """An upstream restart clears its sessions. "No valid session" proves the
    server never ran the call, so this is safe to move — and moving is right,
    because the usual cause is that replica having just restarted."""
    a, b = replicas(SessionReplica, SessionReplica)
    upstream = _upstream(a.url, b.url)

    first = await proxy.call_upstream(upstream, "tools/call", {"name": "a_tool"}, scope="p1")
    home = a if first["served_by"] == "r1" else b
    away = b if home is a else a
    home.sessions.clear()                       # what a restart looks like

    second = await proxy.call_upstream(upstream, "tools/call", {"name": "a_tool"}, scope="p1")

    assert second["served_by"] == away.label
    # Exactly one execution of the second call, not one per replica.
    assert home.requests.count("tools/call") == 1
    assert away.requests.count("tools/call") == 1


async def test_the_pinned_replica_disappearing_repins_without_the_caller_noticing(replicas):
    a, b = replicas(SessionReplica, SessionReplica)
    upstream = _upstream(a.url, b.url)

    first = await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")
    pinned_label = first["served_by"]

    # The admin takes that replica out of rotation.
    for endpoint in upstream.endpoints:
        if endpoint.url == (a.url if pinned_label == "r1" else b.url):
            endpoint.enabled = False

    second = await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")

    assert second["served_by"] != pinned_label
    assert (a.initializes + b.initializes) == 2, "it should have re-handshaked, once"


async def test_a_single_endpoint_upstream_still_re_handshakes_in_place(replicas):
    """The pre-Q24 behaviour, unchanged: with nowhere else to go, recovery
    happens on the same replica rather than failing the caller."""
    a, = replicas(SessionReplica)
    upstream = _upstream(a.url)

    await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")
    a.sessions.clear()
    result = await proxy.call_upstream(upstream, "tools/list", {}, scope="p1")

    assert result["served_by"] == "r1"
    assert a.initializes == 2


# --- through the gateway, with audit ---------------------------------------


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


async def _grant_everything(name, *urls):
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'alice') RETURNING id"
        )
        upstream_id = await make_upstream(conn, name, urls=list(urls))
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, upstream_id,
        )
        key = await credentials.mint_api_key(conn, principal_id, "test")
        return upstream_id, key.secret


def _rpc(id_, method, params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


async def test_the_audit_row_names_the_replica_that_served_the_call(client, replicas):
    """Without this, debugging a flaky backend behind several endpoints is
    guesswork."""
    dead = _dead_url()
    live, = replicas("ok")
    _, key = await _grant_everything("wk", dead, live.url)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/call", {"name": "wk__a_tool", "arguments": {}}),
    )
    assert response.json()["result"]["served_by"] == "r1"

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT endpoint_url, endpoint_id, outcome FROM audit_calls
                WHERE method = 'tools/call' ORDER BY id DESC LIMIT 1"""
        )
    assert row["outcome"] == "ok"
    assert row["endpoint_url"] == live.url
    assert row["endpoint_id"] is not None


async def test_a_failed_call_audits_the_replica_that_failed(client):
    _, key = await _grant_everything("wk", _dead_url())

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/call", {"name": "wk__a_tool", "arguments": {}}),
    )
    assert response.json()["error"]["code"] == proxy.UPSTREAM_UNAVAILABLE

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT endpoint_url, outcome, error_code FROM audit_calls
                WHERE method = 'tools/call' ORDER BY id DESC LIMIT 1"""
        )
    assert row["outcome"] == "upstream_error"
    assert row["endpoint_url"] is not None, "the failing replica is the one you most need named"


async def test_an_upstream_with_no_enabled_endpoint_is_a_clean_error(client):
    upstream_id, key = await _grant_everything("wk", "http://127.0.0.1:9/mcp")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE upstream_endpoints SET enabled = FALSE WHERE upstream_id = $1", upstream_id
        )

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/call", {"name": "wk__a_tool", "arguments": {}}),
    )

    assert response.status_code == 200
    assert response.json()["error"]["code"] == proxy.UPSTREAM_UNAVAILABLE

    pool = await db.pool()
    async with pool.acquire() as conn:
        outcome = await conn.fetchval(
            "SELECT outcome FROM audit_calls WHERE method = 'tools/call' ORDER BY id DESC LIMIT 1"
        )
    assert outcome == "upstream_error"


async def test_a_second_endpoint_keeps_the_gateway_up_while_one_backend_is_down(client, replicas):
    """The homelab motive: a backend restart stops being a caller-visible
    outage."""
    live, = replicas("ok")
    upstream_id, key = await _grant_everything("wk", live.url)
    pool = await db.pool()
    async with pool.acquire() as conn:
        # The original endpoint "goes down"; a second replica is up.
        await conn.execute(
            "UPDATE upstream_endpoints SET url = $2 WHERE upstream_id = $1",
            upstream_id, _dead_url(),
        )
        await add_endpoint(conn, upstream_id, live.url)

    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}"},
        json=_rpc(1, "tools/call", {"name": "wk__a_tool", "arguments": {}}),
    )
    assert response.json()["result"]["served_by"] == "r1"

"""The proxy core: an MCP endpoint on `/mcp` that fans out to upstreams.

Torii speaks JSON-RPC 2.0 over streamable HTTP toward Claude clients and
turns their tool-shaped requests into HTTP calls to upstream MCP servers, of
the shape those servers already accept.

Every read of the tool list, and every invoke, is gated by `torii.rbac`. What
this module owns:

* Namespace: each tool arrives as `<upstream>__<tool>`. On invoke, this
  splits it, checks it, and forwards the un-namespaced `<tool>` upstream.
* Filtered listing: `tools/list` reads every enabled upstream in parallel and
  hands back only the tools this caller has an effective grant for. Ungranted
  upstreams are silently absent (FR1).
* Passthrough: nothing about a tool's result is transformed. Torii is
  infrastructure, not a router with opinions.
* Upstream failure isolation: per-upstream timeouts, and a clean MCP error
  when an upstream throws — the client session must not hang because a
  backend is wedged.
* Audit: one row per request, in every outcome — ok, denied, error,
  upstream_error.

What this module does NOT do:

* Authenticate. `middleware.py` resolves the caller from the Authorization
  header (bearer OAuth token or `tor_` key) and stashes it on the request;
  proxy handlers just read it.
* Cache. Tool lists change when grants change; freshness matters more here
  than latency.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import audit, cache, config, crypto, db, limits, naming, oauth, rbac, web

log = logging.getLogger(__name__)

# JSON-RPC error codes we use. -32601/-32602 are standard; -32000 is the
# JSON-RPC "server error" range for our application-level failures.
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
FORBIDDEN = -32001
UPSTREAM_UNAVAILABLE = -32002
UPSTREAM_ERROR = -32003
RATE_LIMITED = -32004

# --- resilience limits (issues #70, #71) ----------------------------------
#
# Torii runs a single uvicorn worker, so one hostile or wedged upstream can
# take the whole gateway down. These ceilings keep a backend from doing that:
#
# * MAX_RESPONSE_BYTES caps the DECOMPRESSED size of any single upstream
#   response. httpx auto-inflates gzip, so a few hundred KB on the wire can
#   become gigabytes in memory — we stream and abort the moment the running
#   total crosses the ceiling, having materialised at most that much.
# * The absolute deadline (`_post`): httpx's read timeout is per read, so a
#   drip of one byte just under it never trips. We wrap every upstream call in
#   an absolute asyncio deadline derived from `upstream.timeout` instead.
# * TOOLS_LIST_DEADLINE bounds the whole `tools/list` fan-out so one slow
#   backend can't stall a caller's entire tool list.
# * MAX_CACHED_TOOL_NAMES caps the upstream-derived list we write to valkey,
#   so a backend can't bloat the cache the way it can't bloat a response.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # 8 MiB
TOOLS_LIST_DEADLINE = 30.0  # seconds, for the aggregate fan-out
MAX_CACHED_TOOL_NAMES = 2000

router = APIRouter()


@dataclass
class Endpoint:
    """One replica of an upstream (PRD Q24).

    A server may run in more than one place; each place is a row in
    `upstream_endpoints`. Everything else about the server — credential,
    timeout, slug, grants — is shared, because it is one server.
    """

    id: str
    url: str
    enabled: bool = True

    @property
    def key(self) -> str:
        # Hand-built endpoints (tests, ad-hoc checks) may carry no id; the URL
        # identifies a replica just as well for cache keying.
        return self.id or self.url


@dataclass
class Upstream:
    id: str
    name: str
    endpoints: list[Endpoint]
    auth_header_name: str | None
    auth_header_value: str | None
    timeout: int
    enabled: bool

    @property
    def live_endpoints(self) -> list[Endpoint]:
        return [e for e in self.endpoints if e.enabled]

    def request_headers(self) -> dict:
        headers = {"Accept": "application/json, text/event-stream"}
        # Torii never forwards its own credentials upstream (section 7). Only
        # the per-upstream header configured for that backend goes with the
        # request.
        #
        # Decryption happens HERE, at the single point of use, rather than in
        # each of the five places that build an Upstream — so a new caller
        # can't forget to do it, and the plaintext never sits on the object
        # for longer than one request.
        if self.auth_header_name and self.auth_header_value:
            secret = crypto.decrypt_secret(self.auth_header_value)
            if secret:
                headers[self.auth_header_name] = secret
        return headers


# ONE loader, deliberately. An Upstream used to be assembled from four
# different SELECTs in five places, and a per-upstream endpoint list assembled
# five times is a list one of them forgets to filter on `enabled`.
_UPSTREAM_SELECT = """
    SELECT u.id, u.name, u.auth_header_name, u.auth_header_value,
           u.timeout_seconds, u.enabled,
           COALESCE((
               SELECT json_agg(json_build_object(
                          'id', e.id, 'url', e.url, 'enabled', e.enabled)
                      ORDER BY e.created_at, e.url)
                 FROM upstream_endpoints e
                WHERE e.upstream_id = u.id
           ), '[]'::json)::text AS endpoints
      FROM upstreams u
"""


def _upstream_from_row(row) -> Upstream:
    return Upstream(
        id=str(row["id"]),
        name=row["name"],
        endpoints=[
            Endpoint(id=str(e["id"]), url=e["url"], enabled=e["enabled"])
            for e in json.loads(row["endpoints"])
        ],
        auth_header_name=row["auth_header_name"],
        auth_header_value=row["auth_header_value"],
        timeout=row["timeout_seconds"],
        enabled=row["enabled"],
    )


async def load_upstreams(conn) -> list[Upstream]:
    rows = await conn.fetch(f"{_UPSTREAM_SELECT} WHERE u.enabled = TRUE ORDER BY u.name")
    return [_upstream_from_row(r) for r in rows]


async def load_upstream(conn, name: str) -> Upstream | None:
    """One upstream by slug, endpoints included.

    Slug only. The proxy authorizes against the slug, so looking one up by
    anything else here would open a gap between what was checked and what gets
    called — a slug is even shaped like a UUID string.
    """
    row = await conn.fetchrow(f"{_UPSTREAM_SELECT} WHERE u.name = $1", name)
    return _upstream_from_row(row) if row is not None else None


async def load_upstream_by_id(conn, upstream_id: str) -> Upstream | None:
    """One upstream by id — the admin UI's shape, where the id is the handle."""
    row = await conn.fetchrow(f"{_UPSTREAM_SELECT} WHERE u.id::text = $1", str(upstream_id))
    return _upstream_from_row(row) if row is not None else None


# --- upstream RPC ---------------------------------------------------------


class UpstreamError(Exception):
    def __init__(self, upstream: str, kind: str, detail: str, endpoint: Endpoint | None = None):
        super().__init__(f"{upstream}: {kind}: {detail}")
        self.upstream = upstream
        self.kind = kind
        self.detail = detail
        # Which replica failed — the one you most need named when debugging.
        self.endpoint = endpoint


# --- upstream sessions (PRD Q23) ------------------------------------------
#
# Streamable HTTP has two server shapes and torii has to speak both:
#
#   STATELESS — every POST stands alone. What torii did originally, and what
#     finder and knowledge happen to be (finder sets
#     stateless_http=True deliberately, "products auth per-request").
#   SESSION-BASED — the server answers `initialize` with an `Mcp-Session-Id`
#     header and then REQUIRES it on every later request, 400ing without one.
#     This is what the official SDKs do by DEFAULT, so it's what most
#     third-party servers will be.
#
# Sessions are keyed per (upstream, caller) rather than per upstream. A
# session is a place a server may keep state, and torii multiplexes many
# principals onto one backend — sharing one session across them would let one
# caller's state leak into another's calls. The cost is one extra handshake
# per caller per upstream, cached.
#
# With several replicas (Q24) the PINNED REPLICA JOINS THE CACHED VALUE rather
# than the key: a session is only valid on the replica that issued it, so the
# caller must keep going back to that one. Putting the replica in the key
# instead would let a single caller accumulate a session on every replica and
# never converge on one.

MCP_PROTOCOL_VERSION = "2025-06-18"
SESSION_IDLE_SECONDS = 1800

# (upstream, scope) -> (endpoint key, session id, last seen)
_sessions: dict[tuple[str, str], tuple[str, str, float]] = {}


def _session_key(upstream: Upstream, scope: str | None) -> tuple[str, str]:
    return (upstream.id or upstream.name, scope or "torii")


def forget_session(upstream: Upstream, scope: str | None = None) -> None:
    _sessions.pop(_session_key(upstream, scope), None)


def _cached_session(upstream: Upstream, scope: str | None) -> tuple[str, str] | None:
    """The (endpoint key, session id) this caller is pinned to, if any."""
    entry = _sessions.get(_session_key(upstream, scope))
    if not entry:
        return None
    endpoint_key, session_id, seen = entry
    if time.monotonic() - seen > SESSION_IDLE_SECONDS:
        # Idle expiry also unpins the caller, which rebalances for free.
        forget_session(upstream, scope)
        return None
    return endpoint_key, session_id


def _remember_session(
    upstream: Upstream, scope: str | None, endpoint: Endpoint, session_id: str
) -> None:
    _sessions[_session_key(upstream, scope)] = (endpoint.key, session_id, time.monotonic())


# --- replica selection (PRD Q24) ------------------------------------------
#
# Round robin, on `enabled` alone. Torii runs a single uvicorn worker
# (`torii/server.py`), so this in-process counter is coherent; a future
# multi-worker deploy still spreads, just less evenly.

MAX_ENDPOINT_ATTEMPTS = 3

_round_robin: dict[str, int] = {}


def _selection_order(upstream: Upstream) -> list[Endpoint]:
    """The enabled replicas, rotated so consecutive calls start elsewhere."""
    live = upstream.live_endpoints
    if not live:
        return []
    key = upstream.id or upstream.name
    turn = _round_robin.get(key, 0)
    _round_robin[key] = turn + 1
    start = turn % len(live)
    return live[start:] + live[:start]


def _walk(upstream: Upstream, pinned_key: str | None) -> list[Endpoint]:
    """Which replicas to try, in order, for one call.

    The pinned replica goes first when it is still around — a session is only
    valid there. Everything after it is failover, bounded so a wide fleet
    can't turn one caller's request into a long serial walk.
    """
    order = _selection_order(upstream)
    if pinned_key is not None:
        pinned = next((e for e in order if e.key == pinned_key), None)
        if pinned is not None:
            order = [pinned] + [e for e in order if e.key != pinned_key]
    return order[: min(len(order), MAX_ENDPOINT_ATTEMPTS)]


class _SessionGone(Exception):
    """The server says our session is missing, unknown or expired.

    Worth its own type because it is the ONE response torii may safely retry:
    a "no valid session" answer proves the server never ran the call.
    """


def _looks_like_a_session_problem(status: int, payload: dict, text: str) -> bool:
    """A server telling us the session is missing, unknown or expired.

    Matched loosely on purpose: the spec says 400/404 but the wording is the
    server author's, and getting this wrong means a stuck session that only a
    restart clears.
    """
    if status not in (400, 404):
        return False
    message = str(payload.get("error", {}).get("message", "")) + " " + text[:200]
    return "session" in message.lower()


@dataclass
class _Response:
    """A fully-read upstream response, capped in size.

    Streaming the body ourselves (rather than touching `response.text`) is the
    only way to enforce a ceiling BEFORE the whole thing is in memory. This
    stands in for the httpx response everywhere the rest of the module reads
    one — status, headers, text, json — so nothing downstream changes.
    """

    status_code: int
    headers: httpx.Headers
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.content)


async def _post(
    http: httpx.AsyncClient,
    upstream: Upstream,
    endpoint: Endpoint,
    *,
    body: dict,
    headers: dict,
) -> _Response:
    """POST to one replica under a size ceiling and an absolute deadline.

    Two hostile/degenerate upstream behaviours are neutralised here, at the one
    place every upstream call passes through:

    * A decompression bomb (#70): we count DECOMPRESSED bytes as httpx yields
      them and abort past `MAX_RESPONSE_BYTES`, so the worker never holds the
      inflated body.
    * A slow drip (#71): httpx's read timeout is per read, so a byte-a-second
      trickle never trips it. `asyncio.timeout` puts a single wall-clock
      deadline over the entire request+read, derived from `upstream.timeout`.

    Both raise a non-retryable `UpstreamError`: the request reached the server,
    so failing over would risk double execution (the module's retry rule).
    Connect-time httpx errors still propagate untouched, so failover keeps
    working for the one case that IS safe to retry.
    """
    try:
        async with asyncio.timeout(float(upstream.timeout)):
            async with http.stream("POST", endpoint.url, json=body, headers=headers) as response:
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        # Named at WARNING with the URL so an operator can find
                        # the offending backend; the caller gets only "too_large".
                        log.warning(
                            "upstream %s at %s exceeded the %d-byte response cap",
                            upstream.name, endpoint.url, MAX_RESPONSE_BYTES,
                        )
                        raise UpstreamError(
                            upstream.name, "too_large",
                            f"response exceeded {MAX_RESPONSE_BYTES} bytes",
                            endpoint=endpoint,
                        )
                    chunks.append(chunk)
                content = b"".join(chunks)
                return _Response(response.status_code, response.headers, content)
    except asyncio.TimeoutError:
        # Delivered, then slow past the wall-clock budget. Same class as an
        # httpx read timeout: the tool may already have run, so never retried.
        raise UpstreamError(
            upstream.name, "timeout", f"{upstream.timeout}s deadline", endpoint=endpoint
        ) from None


async def _initialize(
    http: httpx.AsyncClient, upstream: Upstream, endpoint: Endpoint, scope: str | None
) -> str | None:
    """Handshake WITH ONE REPLICA, returning a session id when it issues one.

    A server that returns no session header is stateless; we simply never send
    one, which is the behaviour torii had before this existed.

    The endpoint is passed in rather than picked here on purpose: handshaking
    with replica A and then sending the real request to replica B produces a
    session that is valid nowhere, and the symptom looks like an upstream
    fault. Every caller of this replays on the same `endpoint` it passed.
    """
    body = {
        "jsonrpc": "2.0",
        "id": "torii-init",
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "torii", "version": _version()},
        },
    }
    response = await _post(http, upstream, endpoint, body=body, headers=upstream.request_headers())
    if response.status_code >= 400:
        raise UpstreamError(
            upstream.name,
            "initialize",
            f"{response.status_code}: {response.text[:200]}",
            endpoint=endpoint,
        )

    session_id = response.headers.get("mcp-session-id")
    if not session_id:
        return None

    _remember_session(upstream, scope, endpoint, session_id)
    # The spec requires this notification before normal traffic; a stateful
    # server may reject calls made before it.
    headers = upstream.request_headers() | {
        "Mcp-Session-Id": session_id,
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    try:
        await _post(
            http, upstream, endpoint,
            body={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            headers=headers,
        )
    except (httpx.RequestError, UpstreamError):
        # The handshake itself succeeded; a failed notification isn't worth
        # failing the caller's request over.
        log.debug("notifications/initialized to %s failed", upstream.name)
    return session_id


async def call_upstream(
    upstream: Upstream, method: str, params: dict, request_id=None, scope: str | None = None
) -> dict:
    """One JSON-RPC call to one upstream. Returns the parsed `result` dict."""
    result, _endpoint = await call_upstream_detailed(
        upstream, method, params, request_id=request_id, scope=scope
    )
    return result


async def call_upstream_detailed(
    upstream: Upstream, method: str, params: dict, request_id=None, scope: str | None = None
) -> tuple[dict, Endpoint]:
    """One JSON-RPC call, returning the `result` dict AND the replica that served it.

    Handles both server shapes (see above): reuses a cached session when the
    upstream is session-based, opens one on demand, and retries once if the
    server says the session is gone — which happens on every upstream restart
    and would otherwise strand every caller until torii restarted too.

    Across several replicas (Q24) it also does replica selection and failover.
    The one safety rule that matters:

        A CALL IS RETRIED ON ANOTHER REPLICA ONLY IF IT PROVABLY NEVER
        REACHED THE FIRST.

    That means a failure to connect, and a server answering "no valid session"
    — nothing else. An MCP tool call is not required to be idempotent, so a
    500 after the side effect is indistinguishable from a 500 before it, and a
    read timeout means the request was delivered and may well have run.
    Retrying either of those double-executes.

    Any transport failure or JSON-RPC error becomes an `UpstreamError` so the
    caller can shape it into the client's response without leaking internals.
    """
    body = {"jsonrpc": "2.0", "id": request_id or "torii", "method": method, "params": params}

    async def attempt(http: httpx.AsyncClient, endpoint: Endpoint, session_id: str | None):
        headers = upstream.request_headers()
        if session_id:
            headers["Mcp-Session-Id"] = session_id
            headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
        response = await _post(http, upstream, endpoint, body=body, headers=headers)
        if response.status_code in (400, 404) and _looks_like_a_session_problem(
            response.status_code, _safe_payload(response) or {}, response.text
        ):
            raise _SessionGone()
        return response

    async def handshake_and_replay(http: httpx.AsyncClient, endpoint: Endpoint):
        """Open a session on this replica and send the request to the SAME one."""
        session_id = await _initialize(http, upstream, endpoint, scope)
        headers = upstream.request_headers()
        if session_id:
            headers["Mcp-Session-Id"] = session_id
            headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
        return await _post(http, upstream, endpoint, body=body, headers=headers)

    pinned = _cached_session(upstream, scope)
    order = _walk(upstream, pinned[0] if pinned else None)
    if not order:
        # Fail closed and audited, never an unhandled exception.
        raise UpstreamError(upstream.name, "no_endpoint", "no enabled endpoint is configured")

    # Bound the connect wait so failover is quick and the caller's own budget
    # still holds across the walk.
    timeout = httpx.Timeout(upstream.timeout, connect=min(5.0, float(upstream.timeout)))
    last_error: UpstreamError | None = None

    async with httpx.AsyncClient(timeout=timeout) as http:
        # True once a replica has told us our session is gone: the next one is
        # then known to need a handshake, so don't waste a doomed probe on it.
        needs_handshake = False

        for index, endpoint in enumerate(order):
            is_last = index == len(order) - 1
            session_id = None
            if not needs_handshake and pinned and pinned[0] == endpoint.key:
                session_id = pinned[1]

            try:
                if needs_handshake:
                    response = await handshake_and_replay(http, endpoint)
                else:
                    response = await attempt(http, endpoint, session_id)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                # Nothing reached this replica, so another one is safe.
                last_error = UpstreamError(
                    upstream.name, "network", f"{endpoint.url}: {exc}", endpoint=endpoint
                )
                continue
            except httpx.TimeoutException:
                # Delivered, then slow. The tool may already have run.
                raise UpstreamError(
                    upstream.name, "timeout", f"{upstream.timeout}s", endpoint=endpoint
                ) from None
            except httpx.RequestError as exc:
                # Read/write/protocol errors all happen after bytes went out.
                raise UpstreamError(
                    upstream.name, "network", str(exc), endpoint=endpoint
                ) from None
            except _SessionGone:
                forget_session(upstream, scope)
                if session_id is not None and not is_last:
                    # We HELD a session here and it was rejected, so this
                    # replica lost our state — almost always a restart. Move
                    # on rather than handshake with it again. Safe to move at
                    # all only because the server proved it never ran the call.
                    #
                    # With no session in hand this was just the first-contact
                    # probe (Q23: don't force a handshake on a stateless
                    # server), and the right replica to open a session with is
                    # the one selection already picked — this one.
                    needs_handshake = True
                    continue
                try:
                    response = await handshake_and_replay(http, endpoint)
                except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                    last_error = UpstreamError(
                        upstream.name, "network", f"{endpoint.url}: {exc}", endpoint=endpoint
                    )
                    continue
                except httpx.TimeoutException:
                    raise UpstreamError(
                        upstream.name, "timeout", f"{upstream.timeout}s", endpoint=endpoint
                    ) from None
                except httpx.RequestError as exc:
                    raise UpstreamError(
                        upstream.name, "network", str(exc), endpoint=endpoint
                    ) from None
            else:
                if session_id:
                    _remember_session(upstream, scope, endpoint, session_id)  # keep it warm

            return _result_of(response, upstream, endpoint), endpoint

    raise last_error or UpstreamError(upstream.name, "network", "no replica answered")


def _result_of(response, upstream: Upstream, endpoint: Endpoint) -> dict:
    text = response.text
    payload = _safe_payload(response)
    if payload is None:
        raise UpstreamError(upstream.name, "malformed", text[:200], endpoint=endpoint)

    if response.status_code >= 500:
        raise UpstreamError(
            upstream.name, "http", f"{response.status_code}: {text[:200]}", endpoint=endpoint
        )

    if "error" in payload:
        error = payload["error"]
        raise UpstreamError(
            upstream.name,
            "rpc",
            f"{error.get('code')}: {error.get('message')}",
            endpoint=endpoint,
        )
    return payload.get("result") or {}


def _safe_payload(response) -> dict | None:
    """Parse a response body, unwrapping the single SSE frame some MCP servers
    send instead of plain JSON. None means it wasn't JSON at all."""
    text = response.text
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        return _parse_sse(text)
    try:
        return response.json()
    except ValueError:
        return None


def _parse_sse(text: str) -> dict:
    import json

    for line in text.splitlines():
        if line.startswith("data:"):
            data = line[5:].strip()
            if data and data != "[DONE]":
                try:
                    return json.loads(data)
                except ValueError:
                    continue
    return {}


# --- JSON-RPC handling ----------------------------------------------------


@dataclass
class ProxyOutcome:
    body: dict
    audit_outcome: str
    audit_error: str | None = None
    upstream_name: str | None = None
    upstream_id: str | None = None
    tool_name: str | None = None
    # Which replica served (or failed) the call — Q24. Recorded on both paths.
    endpoint_id: str | None = None
    endpoint_url: str | None = None


def _rpc_error(request_id, code: int, message: str, data=None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def _rpc_result(request_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


async def handle_initialize(request_id, params, server: str | None = None) -> ProxyOutcome:
    """Answer the client-hello without touching any upstream.

    Torii negotiates the client's requested protocol version rather than
    forwarding it: it's the client's view of us, not our view of them. On a
    per-server endpoint the name says which server, so a client listing
    several connectors can tell them apart.
    """
    version = (params or {}).get("protocolVersion") or "2025-06-18"
    name = f"torii/{server}" if server else "torii"
    return ProxyOutcome(
        body=_rpc_result(
            request_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": name, "version": _version()},
            },
        ),
        audit_outcome="ok",
    )


def _version() -> str:
    from . import __version__
    return __version__


async def handle_tools_list(conn, caller, request_id) -> ProxyOutcome:
    granted = await rbac.effective_grants(conn, caller)
    if not granted:
        # An empty toolset is the correct answer for a caller with no grants.
        return ProxyOutcome(body=_rpc_result(request_id, {"tools": []}), audit_outcome="ok")

    upstreams = {u.name: u for u in await load_upstreams(conn) if u.name in granted}

    async def list_one(upstream: Upstream):
        try:
            return upstream, await call_upstream(
                upstream, "tools/list", {}, scope=caller.principal_id
            )
        except UpstreamError as exc:
            log.warning("tools/list from %s failed: %s", upstream.name, exc)
            return upstream, None

    # An overall deadline over the fan-out, on top of each call's own absolute
    # deadline (#71): a wedged backend drops out of the list instead of holding
    # the caller's whole tools/list. A dropped upstream contributes no tools,
    # exactly like an unreachable one.
    tasks = [asyncio.create_task(list_one(u)) for u in upstreams.values()]
    results: list[tuple[Upstream, dict | None]] = []
    if tasks:
        done, pending = await asyncio.wait(tasks, timeout=TOOLS_LIST_DEADLINE)
        for task in pending:
            task.cancel()
        if pending:
            log.warning(
                "tools/list fan-out hit the %ss deadline; %d upstream(s) dropped",
                TOOLS_LIST_DEADLINE, len(pending),
            )
        results = [task.result() for task in done]

    tools: list[dict] = []
    for upstream, result in results:
        if result is None:
            continue
        scope = granted[upstream.name]
        for tool in result.get("tools", []) or []:
            if not scope.contains(tool["name"]):
                continue
            named = dict(tool)
            named["name"] = naming.namespaced(upstream.name, tool["name"])
            tools.append(named)

    return ProxyOutcome(body=_rpc_result(request_id, {"tools": tools}), audit_outcome="ok")


TOOL_COUNT_CACHE_PREFIX = "torii:toolcount:"
TOOL_COUNT_CACHE_TTL = 300


async def granted_tool_count(conn, granted: dict, scope: str | None = None) -> int:
    """How many tools the caller can actually call, across granted servers.

    An `all` grant carries no tool names, so the only honest answer comes from
    asking the upstream. Counts are cached per upstream (they're a property of
    the server, not the caller) so rendering a page doesn't fan out to every
    backend on each refresh.

    An unreachable upstream contributes 0 rather than failing the caller — a
    dashboard number is not worth a 500.
    """
    if not granted:
        return 0

    upstreams = {u.name: u for u in await load_upstreams(conn) if u.name in granted}
    total = 0

    async def names_for(upstream: Upstream) -> list[str]:
        key = TOOL_COUNT_CACHE_PREFIX + upstream.name
        try:
            cached = await cache.client().get(key)
            if cached:
                return json.loads(cached)
        except Exception:  # noqa: BLE001 — cache is an optimisation
            pass
        try:
            result = await call_upstream(upstream, "tools/list", {}, scope=scope)
        except UpstreamError:
            return []
        names = [t["name"] for t in (result.get("tools") or []) if t.get("name")]
        if len(names) > MAX_CACHED_TOOL_NAMES:
            # A backend can't be allowed to bloat the cache any more than it can
            # bloat a response (#70). Truncate before it reaches valkey; the
            # count is a dashboard nicety, not an authorization input.
            log.warning(
                "upstream %s returned %d tool names; caching only %d",
                upstream.name, len(names), MAX_CACHED_TOOL_NAMES,
            )
            names = names[:MAX_CACHED_TOOL_NAMES]
        try:
            await cache.client().setex(key, TOOL_COUNT_CACHE_TTL, json.dumps(names))
        except Exception:  # noqa: BLE001
            pass
        return names

    results = await asyncio.gather(*(names_for(u) for u in upstreams.values()))
    for upstream, names in zip(upstreams.values(), results):
        scope = granted[upstream.name]
        total += sum(1 for name in names if scope.contains(name))
    return total


async def handle_tools_call(conn, caller, request_id, params) -> ProxyOutcome:
    name = (params or {}).get("name", "")
    arguments = (params or {}).get("arguments", {}) or {}

    try:
        upstream_name, tool_name = naming.split(name)
    except naming.MalformedToolName:
        return ProxyOutcome(
            body=_rpc_error(request_id, INVALID_PARAMS, f"unknown tool {name!r}"),
            audit_outcome="denied",
            audit_error="malformed_name",
            tool_name=name or None,
        )

    return await _invoke(conn, caller, request_id, upstream_name, tool_name, arguments)


async def _invoke(conn, caller, request_id, upstream_name, tool_name, arguments) -> ProxyOutcome:
    """Check and forward one tool call.

    Shared by both endpoints on purpose: the per-server URL is a naming
    convenience, never a second authorization path.
    """
    decision = await rbac.check(conn, caller, upstream_name, tool_name)
    if not decision.allowed:
        return ProxyOutcome(
            body=_rpc_error(
                request_id,
                FORBIDDEN,
                "access denied",
                data={"reason": decision.reason},
            ),
            audit_outcome="denied",
            audit_error=decision.reason,
            upstream_name=upstream_name,
            tool_name=tool_name,
        )

    upstream = await load_upstream(conn, upstream_name)
    if upstream is None or not upstream.enabled:
        return ProxyOutcome(
            body=_rpc_error(request_id, UPSTREAM_UNAVAILABLE, f"{upstream_name}: unavailable"),
            audit_outcome="upstream_error",
            audit_error="upstream_missing",
            upstream_name=upstream_name,
            tool_name=tool_name,
        )

    try:
        result, endpoint = await call_upstream_detailed(
            upstream,
            "tools/call",
            {"name": tool_name, "arguments": arguments},
            request_id=request_id,
            scope=caller.principal_id,
        )
    except UpstreamError as exc:
        # The full detail carries the internal replica URL and raw upstream
        # bytes — it stays in the server log, never in the client's response
        # (#76). The client gets the upstream slug (which it already named) and
        # a generic failure category; nothing about internal addressing.
        log.warning(
            "upstream %s call failed (%s): %s [endpoint=%s]",
            exc.upstream, exc.kind, exc.detail,
            exc.endpoint.url if exc.endpoint else None,
        )
        code = (
            UPSTREAM_UNAVAILABLE
            if exc.kind in ("timeout", "network", "no_endpoint")
            else UPSTREAM_ERROR
        )
        return ProxyOutcome(
            body=_rpc_error(
                request_id, code, f"{exc.upstream}: {exc.kind}",
                data={"upstream": exc.upstream, "kind": exc.kind},
            ),
            audit_outcome="upstream_error",
            audit_error=exc.kind,
            upstream_id=upstream.id,
            upstream_name=upstream.name,
            tool_name=tool_name,
            endpoint_id=exc.endpoint.id if exc.endpoint else None,
            endpoint_url=exc.endpoint.url if exc.endpoint else None,
        )

    return ProxyOutcome(
        body=_rpc_result(request_id, result),
        audit_outcome="ok",
        upstream_id=upstream.id,
        upstream_name=upstream.name,
        tool_name=tool_name,
        endpoint_id=endpoint.id,
        endpoint_url=endpoint.url,
    )


@dataclass
class RpcRequest:
    id: object
    method: str
    params: dict = field(default_factory=dict)


async def handle_tools_list_for_server(conn, caller, request_id, server: str) -> ProxyOutcome:
    """`tools/list` on a single-server endpoint.

    Tool names come back BARE here. On `/knowledge/mcp` the
    `knowledge__` prefix is pure noise — it costs context on every
    request and tells the client nothing it didn't get from the URL.
    """
    granted = await rbac.effective_grants(conn, caller)
    scope = granted.get(server)
    if scope is None:
        # Same answer as an ungranted server on the aggregate endpoint: an
        # empty list, not an error. The client learns nothing about whether
        # the server exists.
        return ProxyOutcome(body=_rpc_result(request_id, {"tools": []}), audit_outcome="ok")

    upstream = await load_upstream(conn, server)
    if upstream is None or not upstream.enabled:
        return ProxyOutcome(body=_rpc_result(request_id, {"tools": []}), audit_outcome="ok")

    try:
        result, endpoint = await call_upstream_detailed(
            upstream, "tools/list", {}, scope=caller.principal_id
        )
    except UpstreamError as exc:
        # Same leak, same fix as _invoke (#76): URL and raw body to the log,
        # a generic category to the client.
        log.warning(
            "upstream %s tools/list failed (%s): %s [endpoint=%s]",
            exc.upstream, exc.kind, exc.detail,
            exc.endpoint.url if exc.endpoint else None,
        )
        return ProxyOutcome(
            body=_rpc_error(
                request_id, UPSTREAM_UNAVAILABLE, f"{exc.upstream}: {exc.kind}",
                data={"upstream": exc.upstream, "kind": exc.kind},
            ),
            audit_outcome="upstream_error",
            audit_error=exc.kind,
            upstream_id=upstream.id,
            upstream_name=upstream.name,
            endpoint_id=exc.endpoint.id if exc.endpoint else None,
            endpoint_url=exc.endpoint.url if exc.endpoint else None,
        )

    tools = [
        tool for tool in (result.get("tools") or []) if scope.contains(tool.get("name", ""))
    ]
    return ProxyOutcome(
        body=_rpc_result(request_id, {"tools": tools}),
        audit_outcome="ok",
        upstream_id=upstream.id,
        upstream_name=upstream.name,
        endpoint_id=endpoint.id,
        endpoint_url=endpoint.url,
    )


async def handle_tools_call_for_server(
    conn, caller, request_id, params, server: str
) -> ProxyOutcome:
    """`tools/call` on a single-server endpoint.

    Accepts the bare name (what this endpoint advertises) and also the
    namespaced form, so a client that carries a name over from the aggregate
    endpoint still works instead of failing confusingly.
    """
    name = (params or {}).get("name", "")
    arguments = (params or {}).get("arguments", {}) or {}

    tool_name = name
    if naming.SEPARATOR in name:
        try:
            prefix, candidate = naming.split(name)
        except naming.MalformedToolName:
            prefix, candidate = None, name
        if prefix == server:
            tool_name = candidate
        elif prefix is not None:
            # A namespaced name for a DIFFERENT server on this endpoint is a
            # mistake worth naming, not silently routing elsewhere.
            return ProxyOutcome(
                body=_rpc_error(
                    request_id, INVALID_PARAMS,
                    f"{name!r} does not belong to {server!r}",
                ),
                audit_outcome="denied",
                audit_error="wrong_server",
                upstream_name=server,
                tool_name=candidate,
            )

    if not tool_name:
        return ProxyOutcome(
            body=_rpc_error(request_id, INVALID_PARAMS, "a tool name is required"),
            audit_outcome="denied",
            audit_error="malformed_name",
            upstream_name=server,
        )

    return await _invoke(conn, caller, request_id, server, tool_name, arguments)


async def dispatch(conn, caller, rpc: RpcRequest, server: str | None = None) -> ProxyOutcome:
    """Route one JSON-RPC call.

    `server` is set on the per-server endpoints (`/<server>/mcp`) and None on
    the aggregate one (`/mcp`). Authorization is identical either way — same
    resolver, same grants; only the naming and the visible surface differ.
    """
    if rpc.method == "initialize":
        return await handle_initialize(rpc.id, rpc.params, server=server)
    if rpc.method == "notifications/initialized":
        return ProxyOutcome(body={}, audit_outcome="ok")
    if rpc.method == "tools/list":
        if server is None:
            return await handle_tools_list(conn, caller, rpc.id)
        return await handle_tools_list_for_server(conn, caller, rpc.id, server)
    if rpc.method == "tools/call":
        if server is None:
            return await handle_tools_call(conn, caller, rpc.id, rpc.params)
        return await handle_tools_call_for_server(conn, caller, rpc.id, rpc.params, server)
    return ProxyOutcome(
        body=_rpc_error(rpc.id, METHOD_NOT_FOUND, f"method {rpc.method!r} is not implemented"),
        audit_outcome="error",
        audit_error="method_not_found",
    )


# --- HTTP entry ------------------------------------------------------------


def _authenticated(request: Request) -> rbac.Caller | None:
    return getattr(request.state, "caller", None)


def _as_uuid(value):
    """Audit columns are UUIDs; hand-built ids (tests, checks) aren't always."""
    if not value:
        return None
    try:
        import uuid
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


@router.post("/mcp")
async def mcp(request: Request):
    """The aggregate endpoint: every granted server, tools namespaced."""
    return await _serve(request, server=None)


@router.post("/{server}/mcp")
async def mcp_for_server(request: Request, server: str):
    """A single server's endpoint (PRD Q13).

    Same auth, same grants, same audit as the aggregate — this exists so a
    client that only wants one server doesn't carry the whole estate's tool
    list in its context, and gets bare tool names while it's at it.

    An unknown or ungranted server answers with an empty tool list rather
    than a 404, so this endpoint can't be used to enumerate the estate.
    """
    return await _serve(request, server=server)


async def _serve(request: Request, server: str | None):
    caller = _authenticated(request)
    if caller is None:
        return JSONResponse(
            {"error": "unauthorized"},
            status_code=401,
            headers={"WWW-Authenticate": oauth.www_authenticate_header(server)},
        )

    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse(
            _rpc_error(None, INVALID_PARAMS, "invalid JSON body"),
            status_code=400,
        )

    rpc = RpcRequest(
        id=payload.get("id"),
        method=payload.get("method", ""),
        params=payload.get("params") or {},
    )

    started = time.perf_counter()
    pool = await db.pool()
    async with pool.acquire() as conn:
        # Rate limit here, before dispatch, so both endpoint shapes share one
        # budget — otherwise a caller could double their allowance by
        # alternating /mcp and /<slug>/mcp. Exempt initialize and the
        # notification: refusing a handshake would look like a broken gateway,
        # and neither reaches an upstream.
        if rpc.method not in ("initialize", "notifications/initialized"):
            limit = await limits.rate_limit_for(conn, caller)
            limited, retry_after = await web.call_rate_limited(
                limit.bucket, limit.per_minute, fail_closed=limit.fail_closed
            )
            if limited:
                await audit.record_call(
                    conn,
                    method=rpc.method,
                    outcome="denied",
                    error_code="rate_limited",
                    principal_id=caller.principal_id,
                    principal_label=caller.username,
                    client_id=caller.client_id,
                    api_key_id=caller.api_key_id,
                    upstream_name=server,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    request_id=str(rpc.id) if rpc.id is not None else None,
                )
                return JSONResponse(
                    _rpc_error(
                        rpc.id, RATE_LIMITED,
                        f"rate limit exceeded ({limit.per_minute}/min)",
                        data={"retry_after_seconds": retry_after, "limit": limit.per_minute},
                    ),
                    # A JSON-RPC error body, not a bare HTTP 429: an MCP client
                    # parses the body, and Retry-After is added for anything
                    # that looks at headers.
                    headers={"Retry-After": str(retry_after)},
                )

        outcome = await dispatch(conn, caller, rpc, server=server)
        latency_ms = int((time.perf_counter() - started) * 1000)
        # Notifications carry no id and produce no response body — audit them
        # only if there was actual work to record.
        if rpc.method != "notifications/initialized":
            await audit.record_call(
                conn,
                method=rpc.method,
                outcome=outcome.audit_outcome,
                principal_id=caller.principal_id,
                principal_label=caller.username,
                client_id=caller.client_id,
                api_key_id=caller.api_key_id,
                upstream_id=_as_uuid(outcome.upstream_id),
                upstream_name=outcome.upstream_name,
                endpoint_id=_as_uuid(outcome.endpoint_id),
                endpoint_url=outcome.endpoint_url,
                tool_name=outcome.tool_name,
                error_code=outcome.audit_error,
                latency_ms=latency_ms,
                request_id=str(rpc.id) if rpc.id is not None else None,
            )

    if rpc.method == "notifications/initialized":
        return JSONResponse({}, status_code=202)
    return JSONResponse(outcome.body)


# GET/DELETE on an MCP endpoint are the streamable-HTTP session verbs. Torii
# is stateless per request today, so we answer 405 rather than pretend to hold
# a session.
@router.get("/mcp")
@router.delete("/mcp")
@router.get("/{server}/mcp")
@router.delete("/{server}/mcp")
async def mcp_session_verb(server: str | None = None):
    return JSONResponse(
        {"error": "method not allowed"},
        status_code=405,
        headers={"Allow": "POST"},
    )

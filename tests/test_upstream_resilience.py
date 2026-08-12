"""Hostile / degenerate upstream hardening (issues #70, #71, #76).

Torii runs a single worker in front of upstreams it does not fully trust once
third-party servers land. A backend must not be able to take the gateway down
by returning too much, too slowly — nor learn the caller anything about the
estate's internal addressing when it fails. The direct-call tests here cover
the size ceiling and the absolute deadline; the client-facing leak is asserted
end to end through the app harness in `test_proxy.py`.
"""

import json
import threading
import time
from wsgiref.simple_server import make_server

import pytest

from torii import proxy


def _serve(app):
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/mcp"


@pytest.fixture(autouse=True)
def _clean_state():
    proxy._sessions.clear()
    proxy._round_robin.clear()
    yield
    proxy._sessions.clear()
    proxy._round_robin.clear()


def _upstream(url, timeout=10):
    return proxy.Upstream(
        id="u1", name="server",
        endpoints=[proxy.Endpoint(id="e1", url=url)],
        auth_header_name=None, auth_header_value=None, timeout=timeout, enabled=True,
    )


# --- #70: response size ceiling -------------------------------------------


async def test_an_oversized_upstream_body_is_a_clean_error_not_an_oom(monkeypatch):
    """A hostile upstream returning more than the ceiling is aborted mid-stream
    and surfaced as a plain upstream error — never materialised whole."""
    monkeypatch.setattr(proxy, "MAX_RESPONSE_BYTES", 2048)
    oversized = "x" * 20000

    def app(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        environ["wsgi.input"].read(length)
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": "torii", "result": {"tools": [{"name": oversized}]}}
        ).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(payload)))])
        return [payload]

    server, url = _serve(app)
    try:
        with pytest.raises(proxy.UpstreamError) as raised:
            await proxy.call_upstream(_upstream(url), "tools/list", {})
        assert raised.value.kind == "too_large"
    finally:
        server.shutdown(); server.server_close()


async def test_a_body_under_the_ceiling_still_works(monkeypatch):
    """The ceiling doesn't clip normal traffic: a small body reads fine."""
    monkeypatch.setattr(proxy, "MAX_RESPONSE_BYTES", 2048)

    def app(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        environ["wsgi.input"].read(length)
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": "torii", "result": {"tools": [{"name": "get_doc"}]}}
        ).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(payload)))])
        return [payload]

    server, url = _serve(app)
    try:
        result = await proxy.call_upstream(_upstream(url), "tools/list", {})
        assert [t["name"] for t in result["tools"]] == ["get_doc"]
    finally:
        server.shutdown(); server.server_close()


# --- #71: absolute deadline over a per-read one ---------------------------


async def test_a_slow_drip_trips_the_absolute_deadline(monkeypatch):
    """httpx's read timeout is PER READ, so a trickle whose gaps stay under it
    never trips — the classic slow-drip that holds a worker forever. The
    absolute asyncio deadline caps the whole request regardless."""
    def app(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        environ["wsgi.input"].read(length)
        start_response("200 OK", [("Content-Type", "application/json")])

        def drip():
            # Each 0.3s gap is well under the 1s timeout, so no single read
            # ever times out; the total (~3s) far exceeds the 1s deadline.
            for _ in range(10):
                time.sleep(0.3)
                yield b" "
            yield b'{"jsonrpc":"2.0","id":"torii","result":{"tools":[]}}'

        return drip()

    server, url = _serve(app)
    try:
        started = time.monotonic()
        with pytest.raises(proxy.UpstreamError) as raised:
            await proxy.call_upstream(_upstream(url, timeout=1), "tools/list", {})
        elapsed = time.monotonic() - started
        assert raised.value.kind == "timeout"
        # Proves the DEADLINE fired, not the drip simply finishing: it aborts
        # around the 1s budget, long before the ~3s the full drip would take.
        assert elapsed < 2.5, f"deadline did not fire early (took {elapsed:.1f}s)"
    finally:
        server.shutdown(); server.server_close()

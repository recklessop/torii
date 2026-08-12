"""Prometheus /metrics endpoint (FR5 hardening).

Tests verify the exposition format and that the metric families reflect
what's in the audit tables.  No monkeypatching of the DB — the whole point
is that the endpoint derives metrics from real audit rows.
"""

import httpx
import pytest

from torii import app as app_module
from torii import cache, config, db


SCRAPE_TOKEN = "test-scrape-token"


@pytest.fixture(autouse=True)
def _metrics_token(monkeypatch):
    """/metrics is gated (see the access-control tests at the bottom), so the
    behavioural tests scrape as an authorized collector. Individual tests
    override this to check the unauthenticated paths."""
    monkeypatch.setattr(config, "METRICS_TOKEN", SCRAPE_TOKEN)


async def _scrape(client):
    return await client.get("/metrics", headers={"Authorization": f"Bearer {SCRAPE_TOKEN}"})


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


async def _seed_audit_calls(rows: list[dict]) -> None:
    pool = await db.pool()
    async with pool.acquire() as conn:
        for r in rows:
            await conn.execute(
                """INSERT INTO audit_calls
                       (method, upstream_name, outcome, error_code, latency_ms)
                   VALUES ($1, $2, $3, $4, $5)""",
                r.get("method", "tools/list"),
                r.get("upstream_name"),
                r.get("outcome", "ok"),
                r.get("error_code"),
                r.get("latency_ms"),
            )


async def _seed_auth_events(rows: list[dict]) -> None:
    pool = await db.pool()
    async with pool.acquire() as conn:
        for r in rows:
            await conn.execute(
                """INSERT INTO audit_auth_events (event, outcome) VALUES ($1, $2)""",
                r["event"],
                r.get("outcome", "ok"),
            )


async def _seed_token() -> None:
    """Insert an active (non-expired, non-revoked) access token."""
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO principals (kind, username) VALUES ('human', 'tester')
               ON CONFLICT DO NOTHING"""
        )
        pid = await conn.fetchval("SELECT id FROM principals WHERE username = 'tester'")
        await conn.execute(
            """INSERT INTO oauth_clients
                   (client_id, client_name, principal_id, redirect_uris, token_endpoint_auth_method)
               VALUES ('metrics-test', 'test', $1, ARRAY['https://example.com/cb'], 'none')""",
            pid,
        )
        await conn.execute(
            """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at)
               VALUES ('access', 'abc123', $1, 'metrics-test', now() + interval '1 day')""",
            pid,
        )


# ------------------------------------------------------------------- empty

async def test_metrics_empty(client):
    """With no audit rows, every series emits a zero so the output is valid
    Prometheus rather than absent."""
    r = await _scrape(client)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=")

    text = r.text
    assert 'torii_calls_total{outcome="",upstream=""} 0.0' in text
    assert 'torii_active_tokens' in text
    assert '0.0' in text


# ------------------------------------------------------------------- calls

async def test_metrics_calls_by_upstream_outcome(client):
    await _seed_audit_calls([
        {"upstream_name": "wk", "outcome": "ok"},
        {"upstream_name": "wk", "outcome": "ok"},
        {"upstream_name": "wk", "outcome": "denied", "error_code": "no_tool"},
        {"upstream_name": "brain", "outcome": "ok"},
    ])

    r = await _scrape(client)

    text = r.text
    # Labels are sorted alphabetically by prometheus_client
    assert 'torii_calls_total{outcome="ok",upstream="brain"} 1.0' in text
    assert 'torii_calls_total{outcome="denied",upstream="wk"} 1.0' in text
    assert 'torii_calls_total{outcome="ok",upstream="wk"} 2.0' in text


# ------------------------------------------------------------------- denies

async def test_metrics_deny_reasons(client):
    await _seed_audit_calls([
        {"upstream_name": "wk", "outcome": "denied", "error_code": "no_tool"},
        {"upstream_name": "wk", "outcome": "denied", "error_code": "no_tool"},
        {"upstream_name": "brain", "outcome": "denied", "error_code": "not_authorized"},
        {"upstream_name": "wk", "outcome": "ok"},
    ])

    r = await _scrape(client)

    text = r.text
    assert 'torii_deny_reasons_total{reason="no_tool"} 2.0' in text
    assert 'torii_deny_reasons_total{reason="not_authorized"} 1.0' in text


async def test_metrics_no_deny_reasons_emits_zero(client):
    """When no denies exist, emit a zero-valued series so it's queryable
    even when absent (absent series in PromQL produce no results)."""
    await _seed_audit_calls([
        {"upstream_name": "wk", "outcome": "ok"},
    ])

    r = await _scrape(client)
    assert 'torii_deny_reasons_total{reason=""} 0.0' in r.text


# ---------------------------------------------------------------- latency

async def test_metrics_upstream_latency(client):
    await _seed_audit_calls([
        {"upstream_name": "wk", "outcome": "ok", "latency_ms": 50},
        {"upstream_name": "wk", "outcome": "ok", "latency_ms": 100},
        {"upstream_name": "wk", "outcome": "ok", "latency_ms": 200},
        {"upstream_name": "brain", "outcome": "ok", "latency_ms": 10},
    ])

    r = await _scrape(client)
    text = r.text

    assert 'torii_upstream_latency_count{upstream="brain"} 1.0' in text
    assert 'torii_upstream_latency_count{upstream="wk"} 3.0' in text
    # sum: 50+100+200 = 350ms = 0.35 seconds
    assert 'torii_upstream_latency_sum{upstream="wk"} 0.35' in text
    # quantile labels sorted alphabetically
    assert 'torii_upstream_latency{quantile="0.5",upstream="wk"}' in text
    assert 'torii_upstream_latency{quantile="0.95",upstream="wk"}' in text
    assert 'torii_upstream_latency{quantile="0.99",upstream="wk"}' in text


async def test_metrics_latency_empty(client):
    """No latency data means zero-valued series for each metric."""
    await _seed_audit_calls([
        {"upstream_name": "wk", "outcome": "ok"},  # no latency_ms
    ])

    r = await _scrape(client)
    text = r.text
    assert 'torii_upstream_latency_count{upstream=""} 0.0' in text


# ---------------------------------------------------------------- tokens

async def test_metrics_active_tokens(client):
    await _seed_token()

    r = await _scrape(client)
    assert 'torii_active_tokens' in r.text
    assert '1.0' in r.text


async def test_metrics_active_tokens_empty(client):
    r = await _scrape(client)
    assert 'torii_active_tokens' in r.text
    assert '0.0' in r.text


# ---------------------------------------------------------------- auth failures

async def test_metrics_auth_failures(client):
    await _seed_auth_events([
        {"event": "login_failure", "outcome": "failure"},
        {"event": "login_failure", "outcome": "failure"},
        {"event": "auth_failure", "outcome": "failure"},
    ])

    r = await _scrape(client)
    text = r.text
    assert 'torii_auth_failures_total{event="auth_failure"} 1.0' in text
    assert 'torii_auth_failures_total{event="login_failure"} 2.0' in text


async def test_metrics_auth_failures_empty(client):
    r = await _scrape(client)
    assert 'torii_auth_failures_total{event=""} 0.0' in r.text


# ---------------------------------------------------------------- HELP / TYPE

async def test_metrics_help_and_type_lines(client):
    """Every metric family should have a HELP and TYPE line."""
    r = await _scrape(client)
    # prometheus_client uses the name without _total suffix for HELP/TYPE
    assert "# HELP torii_calls_total" in r.text
    assert "# TYPE torii_calls_total counter" in r.text
    assert "# HELP torii_deny_reasons_total" in r.text
    assert "# TYPE torii_deny_reasons_total counter" in r.text
    assert "# HELP torii_active_tokens" in r.text
    assert "# TYPE torii_active_tokens gauge" in r.text
    assert "# HELP torii_auth_failures_total" in r.text
    assert "# TYPE torii_auth_failures_total counter" in r.text


# --- access control (added in review of PR #27) -----------------------------
#
# The endpoint shipped unauthenticated. On an internet-facing host these
# series name every upstream, including private ones the public directory
# deliberately refuses to confirm — so an open /metrics is an enumeration
# oracle, not just noisy observability.


async def test_metrics_is_absent_when_no_token_is_configured(client, monkeypatch):
    """Off by default: no token, no endpoint. 404 rather than 401 so its
    existence isn't advertised either."""
    monkeypatch.setattr(config, "METRICS_TOKEN", "")
    response = await client.get("/metrics")
    assert response.status_code == 404


async def test_metrics_requires_a_bearer_token(client, monkeypatch):
    monkeypatch.setattr(config, "METRICS_TOKEN", "a-scrape-token")
    assert (await client.get("/metrics")).status_code == 401
    assert (await client.get("/metrics", headers={"Authorization": "Bearer wrong"})).status_code == 401
    assert (await client.get("/metrics", headers={"Authorization": "a-scrape-token"})).status_code == 401


async def test_metrics_serves_with_the_right_token(client, monkeypatch):
    monkeypatch.setattr(config, "METRICS_TOKEN", "a-scrape-token")
    response = await client.get("/metrics", headers={"Authorization": "Bearer a-scrape-token"})
    assert response.status_code == 200
    assert "torii_" in response.text


async def test_unauthenticated_metrics_cannot_enumerate_private_upstreams(client, monkeypatch):
    """The concrete leak: a private upstream's name must not be readable by
    someone who could not learn it from /directory."""
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO upstreams (name, public_listed)
               VALUES ('secret-internal', FALSE)"""
        )
        await conn.execute(
            """INSERT INTO audit_calls (method, outcome, upstream_name)
               VALUES ('tools/call', 'ok', 'secret-internal')"""
        )

    monkeypatch.setattr(config, "METRICS_TOKEN", "")
    assert "secret-internal" not in (await client.get("/metrics")).text

    monkeypatch.setattr(config, "METRICS_TOKEN", "a-scrape-token")
    assert "secret-internal" not in (await client.get("/metrics")).text
    # Only an authorized scrape sees it.
    authorized = await client.get("/metrics", headers={"Authorization": "Bearer a-scrape-token"})
    assert "secret-internal" in authorized.text


async def test_scrape_survives_null_labels_from_real_audit_rows(client):
    """Regression: a live scrape 500'd with "'<' not supported between
    instances of 'NoneType' and 'str'".

    upstream_name, error_code and tool_name are all nullable in audit_calls —
    a tools/list call belongs to no single upstream, and an ok call has no
    error code — so the label sort has to tolerate None. Every earlier test
    happened to populate these columns, which is why the suite was green
    while the real endpoint was broken.
    """
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO audit_calls (method, outcome, upstream_name, tool_name,
                                        error_code, latency_ms)
               VALUES
                 ('tools/list', 'ok',     NULL,       NULL,      NULL,         12),
                 ('tools/call', 'denied', NULL,       NULL,      NULL,          3),
                 ('tools/call', 'ok',     'knowledge', 'get_doc', NULL,   40),
                 ('tools/call', 'denied', 'knowledge', 'run_sql', 'no_grant', 2)"""
        )
        await conn.execute(
            "INSERT INTO audit_auth_events (event, outcome) VALUES ('auth_failure', 'failure')"
        )

    response = await _scrape(client)
    assert response.status_code == 200, response.text
    assert "torii_calls_total" in response.text
    # The NULL-upstream row is still counted, under an empty label.
    assert 'upstream=""' in response.text
    assert "knowledge" in response.text

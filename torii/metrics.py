"""Prometheus /metrics endpoint (PRD FR5 hardening).

Series exposed:
    torii_calls_total{upstream,outcome}
    torii_deny_reasons_total{reason}
    torii_upstream_latency_seconds{upstream,quantile}
    torii_upstream_latency_count{upstream}
    torii_upstream_latency_sum{upstream}
    torii_active_tokens
    torii_auth_failures_total{event}

The audit tables already hold everything, so each scrape queries them
directly rather than maintaining in-process counters.  No middleware
instrumentation needed.
"""

import hmac

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

from . import config, db

router = APIRouter()

# ------------------------------------------------------------------- queries

_CALLS_SQL = """
    SELECT upstream_name, outcome, COUNT(*)::float8 AS total
    FROM audit_calls
    GROUP BY upstream_name, outcome
    ORDER BY upstream_name, outcome
"""

_DENIES_SQL = """
    SELECT error_code, COUNT(*)::float8 AS total
    FROM audit_calls
    WHERE outcome = 'denied'
    GROUP BY error_code
    ORDER BY error_code
"""

_LATENCY_SQL = """
    SELECT upstream_name,
           COUNT(*)::float8                                    AS count,
           COALESCE(SUM(latency_ms), 0)::float8 / 1000.0       AS sum_seconds,
           percentile_cont(0.5)  WITHIN GROUP (ORDER BY latency_ms)::float8 / 1000.0 AS p50,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::float8 / 1000.0 AS p95,
           percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms)::float8 / 1000.0 AS p99
    FROM audit_calls
    WHERE latency_ms IS NOT NULL
    GROUP BY upstream_name
    ORDER BY upstream_name
"""

_TOKENS_SQL = """
    SELECT COUNT(*)::float8 AS total
    FROM tokens
    WHERE revoked_at IS NULL AND expires_at > now()
"""

_AUTH_FAILURES_SQL = """
    SELECT event, COUNT(*)::float8 AS total
    FROM audit_auth_events
    WHERE outcome = 'failure'
    GROUP BY event
    ORDER BY event
"""


async def _fetch_metrics_data() -> dict:
    pool = await db.pool()
    async with pool.acquire() as conn:
        calls_rows = await conn.fetch(_CALLS_SQL)
        denies_rows = await conn.fetch(_DENIES_SQL)
        latency_rows = await conn.fetch(_LATENCY_SQL)
        token_count = await conn.fetchval(_TOKENS_SQL)
        auth_rows = await conn.fetch(_AUTH_FAILURES_SQL)

    calls = {(r["upstream_name"], r["outcome"]): r["total"] for r in calls_rows}
    denies = {r["error_code"]: r["total"] for r in denies_rows}
    latency = {
        r["upstream_name"]: {
            "count": r["count"],
            "sum": r["sum_seconds"],
            "p50": r["p50"],
            "p95": r["p95"],
            "p99": r["p99"],
        }
        for r in latency_rows
    }
    auth_failures = {r["event"]: r["total"] for r in auth_rows}

    return {
        "calls": calls,
        "denies": denies,
        "latency": latency,
        "active_tokens": token_count or 0,
        "auth_failures": auth_failures,
    }


# ------------------------------------------------------- custom collector

class _AuditCollector:
    """Pre-populated collector that emits Prometheus metric families from
    a snapshot of the audit tables.

    Usage — the async handler calls generate_latest(_registry) after
    setting the data:

        collector.set_data(await _fetch_metrics_data())
        output = generate_latest(_registry)
    """

    def __init__(self):
        self.data: dict = {}

    def set_data(self, data: dict) -> None:
        self.data = data

    def collect(self):
        # NOTE: upstream_name, error_code and tool_name are all NULLABLE in
        # audit_calls — a tools/list call belongs to no single upstream, and an
        # ok call has no error code. Every sort below therefore needs a key
        # that coerces None, because Python won't order None against str. The
        # label values are already coerced with `or ""` at add_metric time;
        # the sort was the part that raised a 500 on real data.
        data = self.data

        # -- torii_calls_total
        calls_fam = CounterMetricFamily(
            "torii_calls", "MCP calls by upstream and outcome",
            labels=["upstream", "outcome"],
        )
        calls = data.get("calls", {})
        if calls:
            for (upstream, outcome), total in sorted(
                calls.items(), key=lambda kv: (kv[0][0] or "", kv[0][1] or "")
            ):
                calls_fam.add_metric([upstream or "", outcome or ""], total)
        else:
            calls_fam.add_metric(["", ""], 0)
        yield calls_fam

        # -- torii_deny_reasons_total
        denies_fam = CounterMetricFamily(
            "torii_deny_reasons", "Denied calls by reason code",
            labels=["reason"],
        )
        denies = data.get("denies", {})
        if denies:
            for reason, total in sorted(denies.items(), key=lambda kv: kv[0] or ""):
                denies_fam.add_metric([reason or ""], total)
        else:
            denies_fam.add_metric([""], 0)
        yield denies_fam

        # -- torii_upstream_latency_seconds (summary-shaped quantiles)
        latency = data.get("latency", {})
        latency_fam = GaugeMetricFamily(
            "torii_upstream_latency",
            "Upstream call latency in seconds",
            labels=["upstream", "quantile"],
        )
        latency_count_fam = GaugeMetricFamily(
            "torii_upstream_latency_count",
            "Total number of measured upstream calls",
            labels=["upstream"],
        )
        latency_sum_fam = GaugeMetricFamily(
            "torii_upstream_latency_sum",
            "Sum of upstream call latency in seconds",
            labels=["upstream"],
        )
        if latency:
            for upstream_name, q in latency.items():
                label = upstream_name or ""
                latency_fam.add_metric([label, "0.5"], q.get("p50", 0))
                latency_fam.add_metric([label, "0.95"], q.get("p95", 0))
                latency_fam.add_metric([label, "0.99"], q.get("p99", 0))
                latency_count_fam.add_metric([label], q.get("count", 0))
                latency_sum_fam.add_metric([label], q.get("sum", 0))
        else:
            latency_fam.add_metric(["", "0.5"], 0)
            latency_count_fam.add_metric([""], 0)
            latency_sum_fam.add_metric([""], 0)
        yield latency_fam
        yield latency_count_fam
        yield latency_sum_fam

        # -- torii_active_tokens
        tokens = GaugeMetricFamily(
            "torii_active_tokens", "Currently valid OAuth tokens and API keys",
            labels=[],
        )
        tokens.add_metric([], data.get("active_tokens", 0))
        yield tokens

        # -- torii_auth_failures_total
        auth_fam = CounterMetricFamily(
            "torii_auth_failures", "Authentication failures by event type",
            labels=["event"],
        )
        auth_failures = data.get("auth_failures", {})
        if auth_failures:
            for event, total in sorted(auth_failures.items(), key=lambda kv: kv[0] or ""):
                auth_fam.add_metric([event], total)
        else:
            auth_fam.add_metric([""], 0)
        yield auth_fam


_registry = CollectorRegistry()
_collector = _AuditCollector()
_registry.register(_collector)


# --------------------------------------------------------------- endpoint

def _authorized(request: Request) -> bool:
    """Constant-time bearer check against METRICS_TOKEN."""
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        return False
    return hmac.compare_digest(presented.strip(), config.METRICS_TOKEN)


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    """Prometheus scrape target.

    Gated, and 404 rather than 401 when no token is configured: these series
    name every upstream including the private ones, which is precisely what
    the public directory refuses to reveal (FR8). An unauthenticated scrape
    would turn observability into an enumeration oracle, so the endpoint does
    not exist until an operator opts in.
    """
    if not config.METRICS_TOKEN:
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    if not _authorized(request):
        return JSONResponse(
            {"detail": "unauthorized"},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="torii metrics"'},
        )

    data = await _fetch_metrics_data()
    _collector.set_data(data)
    output = generate_latest(_registry)
    return Response(content=output, media_type=CONTENT_TYPE_LATEST)

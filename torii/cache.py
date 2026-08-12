"""Valkey client. Session, rate-limit, and short-lived OAuth state (auth
codes, PKCE challenges) live here; anything durable belongs in Postgres."""

import redis.asyncio as redis

from . import config

_client: redis.Redis | None = None


def client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(config.VALKEY_URL, decode_responses=True)
    return _client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def healthcheck() -> dict:
    try:
        await client().ping()
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001 — health output, never re-raised
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

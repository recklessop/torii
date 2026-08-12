"""asyncpg pool + entrypoint-auto migrations (idempotent, advisory-locked)."""

import logging
import pathlib

import asyncpg

from . import config

log = logging.getLogger(__name__)

MIGRATIONS_DIR = pathlib.Path(__file__).parent / "migrations"
ADVISORY_LOCK_KEY = 0x70721  # arbitrary app-wide constant

_pool: asyncpg.Pool | None = None


async def pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(config.DATABASE_URL, min_size=1, max_size=10)
    return _pool


async def close() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def migrate() -> None:
    """Apply pending SQL migrations in filename order, under an advisory
    lock so concurrent replicas don't race each other."""
    p = await pool()
    async with p.acquire() as conn:
        await conn.execute("SELECT pg_advisory_lock($1)", ADVISORY_LOCK_KEY)
        try:
            await conn.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                       name TEXT PRIMARY KEY,
                       applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                   )"""
            )
            applied = {
                r["name"] for r in await conn.fetch("SELECT name FROM schema_migrations")
            }
            for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
                if path.name in applied:
                    continue
                log.info("applying migration %s", path.name)
                async with conn.transaction():
                    await conn.execute(path.read_text())
                    await conn.execute(
                        "INSERT INTO schema_migrations (name) VALUES ($1)", path.name
                    )
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1)", ADVISORY_LOCK_KEY)


async def healthcheck() -> dict:
    try:
        p = await pool()
        async with p.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001 — health output, never re-raised
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

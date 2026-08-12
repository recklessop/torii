"""Shared fixtures.

The schema tests need a real Postgres — CHECK constraints and partial
unique indexes are the thing under test, and nothing but Postgres
enforces them. They skip (never fail) when no database is reachable, so
`pytest` still passes on a bare checkout; CI and the dev box run them for
real. Point them somewhere disposable with TORII_TEST_DATABASE_URL.
"""

import os

# The boot-time config check (#80) refuses to start with an https
# PUBLIC_BASE_URL and no SESSION_SECRET — which is exactly the test env
# (PUBLIC_BASE_URL=https://torii.test). Give the suite a stable, non-empty
# secret before `torii.config` is imported so the app under test starts as a
# correctly-configured deployment would, rather than tripping the guard.
os.environ.setdefault("SESSION_SECRET", "test-session-secret-not-for-production")

import asyncpg
import pytest
import pytest_asyncio

from torii import config, db

TEST_DATABASE_URL = os.environ.get("TORII_TEST_DATABASE_URL", config.DATABASE_URL)

# CI sets this. The schema tests ARE the spec for the authorization model, so
# a missing database there must be a red build, not a quiet skip.
REQUIRE_TEST_DB = os.environ.get("TORII_REQUIRE_TEST_DB", "").strip().lower() in (
    "1",
    "true",
    "yes",
)


@pytest_asyncio.fixture(scope="session")
async def migrated_database():
    """Apply every migration once, or skip the whole DB suite."""
    try:
        conn = await asyncpg.connect(TEST_DATABASE_URL, timeout=5)
    except Exception as exc:  # noqa: BLE001 — no database is a skip, not a failure
        message = f"no test database at {TEST_DATABASE_URL}: {type(exc).__name__}: {exc}"
        if REQUIRE_TEST_DB:
            pytest.fail(message, pytrace=False)
        pytest.skip(message)
    await conn.close()

    original = config.DATABASE_URL
    config.DATABASE_URL = TEST_DATABASE_URL
    try:
        await db.migrate()
        yield TEST_DATABASE_URL
    finally:
        await db.close()
        config.DATABASE_URL = original


OAUTH_DATABASE_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    TEST_DATABASE_URL.rsplit("/", 1)[0] + "/torii_oauth",
)


@pytest_asyncio.fixture(scope="session")
async def oauth_database():
    """A second database for the suites that drive the whole ASGI app.

    Those tests TRUNCATE between cases, which would fight the rollback-based
    isolation the schema/RBAC tests rely on — so they get their own database.
    It lives here rather than in one test module because four modules use it,
    and having only one of them create it made the suite order-dependent
    (green locally where a previous run had left the database behind, red in
    CI where it hadn't).
    """
    admin_url, _, target = OAUTH_DATABASE_URL.rpartition("/")
    try:
        admin = await asyncpg.connect(admin_url + "/postgres", timeout=5)
    except Exception as exc:  # noqa: BLE001
        message = f"no test database server for {OAUTH_DATABASE_URL}: {exc}"
        if REQUIRE_TEST_DB:
            pytest.fail(message, pytrace=False)
        pytest.skip(message)
    try:
        if not await admin.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", target):
            await admin.execute(f'CREATE DATABASE "{target}"')
    finally:
        await admin.close()

    original = config.DATABASE_URL
    config.DATABASE_URL = OAUTH_DATABASE_URL
    db._pool = None
    try:
        await db.migrate()
        yield OAUTH_DATABASE_URL
    finally:
        await db.close()
        db._pool = None
        config.DATABASE_URL = original


async def make_upstream(conn, name, url="http://127.0.0.1:9/mcp", *, urls=None, **columns):
    """Register an upstream and its endpoint(s), returning the upstream id.

    An upstream's URLs live in `upstream_endpoints` (Q24), so inserting a row
    into `upstreams` is no longer enough to make a server reachable. Every
    test goes through here rather than writing the two-table insert itself —
    one place to change, and no test can quietly forget the endpoint.
    """
    columns = {k: v for k, v in columns.items() if v is not None}
    names = ["name"] + list(columns)
    placeholders = ", ".join(f"${i}" for i in range(1, len(names) + 1))
    upstream_id = await conn.fetchval(
        f"INSERT INTO upstreams ({', '.join(names)}) VALUES ({placeholders}) RETURNING id",
        name,
        *columns.values(),
    )
    for endpoint_url in (urls if urls is not None else [url]):
        await conn.execute(
            "INSERT INTO upstream_endpoints (upstream_id, url) VALUES ($1, $2)",
            upstream_id,
            endpoint_url,
        )
    return upstream_id


async def add_endpoint(conn, upstream_id, url, enabled=True):
    return await conn.fetchval(
        """INSERT INTO upstream_endpoints (upstream_id, url, enabled)
           VALUES ($1, $2, $3) RETURNING id""",
        upstream_id, url, enabled,
    )


@pytest_asyncio.fixture
async def conn(migrated_database):
    """A connection whose work is rolled back, so tests can't see each
    other's rows and the database is left as it was found."""
    connection = await asyncpg.connect(migrated_database)
    transaction = connection.transaction()
    await transaction.start()
    try:
        yield connection
    finally:
        await transaction.rollback()
        await connection.close()

"""Audit retention (PRD Q7).

The nightly job's job: keep tables from growing forever, and clean up dead
tokens that are worth nothing without their audit context. Anything younger
than the window stays.
"""

import pytest

from torii import audit

pytestmark = pytest.mark.asyncio


async def test_purge_removes_only_rows_older_than_the_window(conn):
    await conn.execute(
        """INSERT INTO audit_calls (method, outcome, ts) VALUES
              ('tools/call', 'ok', now() - interval '400 days'),
              ('tools/call', 'ok', now() - interval '10 days')"""
    )
    await conn.execute(
        """INSERT INTO audit_auth_events (event, outcome, ts) VALUES
              ('login_success', 'ok', now() - interval '400 days'),
              ('login_success', 'ok', now() - interval '10 days')"""
    )

    removed = await audit.purge_expired(conn, retention_days=365)

    assert removed["audit_calls"] == 1
    assert removed["audit_auth_events"] == 1
    assert await conn.fetchval("SELECT count(*) FROM audit_calls") == 1
    assert await conn.fetchval("SELECT count(*) FROM audit_auth_events") == 1


async def test_purge_removes_long_expired_tokens_too(conn):
    principal_id = await conn.fetchval(
        "INSERT INTO principals (kind, username) VALUES ('human', 'x') RETURNING id"
    )
    client_id = await conn.fetchval(
        """INSERT INTO oauth_clients (client_id, client_name, principal_id)
           VALUES ('cl', 'claude.ai', $1) RETURNING client_id""",
        principal_id,
    )
    await conn.execute(
        """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at)
           VALUES
             ('access', 'a-fresh', $1, $2, now() + interval '1 hour'),
             ('access', 'a-old',   $1, $2, now() - interval '400 days'),
             ('access', 'a-mid',   $1, $2, now() - interval '10 days')""",
        principal_id, client_id,
    )

    removed = await audit.purge_expired(conn, retention_days=365)
    assert removed["tokens"] == 1

    remaining = {r["token_hash"] for r in await conn.fetch("SELECT token_hash FROM tokens")}
    assert remaining == {"a-fresh", "a-mid"}


async def test_purge_never_removes_a_row_written_today(conn):
    await conn.execute(
        "INSERT INTO audit_calls (method, outcome) VALUES ('tools/call', 'ok')"
    )
    await conn.execute(
        "INSERT INTO audit_auth_events (event, outcome) VALUES ('login_success', 'ok')"
    )

    removed = await audit.purge_expired(conn, retention_days=1)
    assert removed == {"audit_calls": 0, "audit_auth_events": 0, "tokens": 0}

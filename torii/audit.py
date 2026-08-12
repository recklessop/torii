"""Audit writers (PRD FR5).

Two rules the rest of the code relies on:

* **A denied call is still a call.** Every deny writes a row, including from
  callers that never authenticated — that's the whole point of the trail.
* **Auditing never breaks the request.** A failure to write is logged and
  swallowed; an audit outage must not become an outage.

No argument or result payloads are recorded. `upstreams.capture_payloads`
exists for the opt-in debug case and nothing here reads it yet (P4).
"""

import json
import logging

import asyncpg

log = logging.getLogger(__name__)

# Auth event names. Stable strings — the audit viewer filters on them.
LOGIN_SUCCESS = "login_success"
LOGIN_FAILURE = "login_failure"
LOGOUT = "logout"
TOTP_ENROLLED = "totp_enrolled"
TOTP_RESET = "totp_reset"
TOTP_REQUIREMENT_CHANGED = "totp_requirement_changed"
LOCKOUT = "lockout"
TOKEN_ISSUED = "token_issued"
TOKEN_REFRESHED = "token_refreshed"
TOKEN_REVOKED = "token_revoked"
TOKEN_REPLAY = "token_replay"
TOKEN_GRANT_FAILURE = "token_grant_failure"
PASSWORD_CHANGED = "password_changed"
PASSWORD_RESET = "password_reset"
DCR_REGISTERED = "dcr_registered"
CLIENT_AUTHORIZED = "client_authorized"
CLIENT_DISABLED = "client_disabled"
CLIENT_ACCESS_MODE_CHANGED = "client_access_mode_changed"
SERVICE_DETACHED = "service_detached"
GROUP_CREATED = "group_created"
GROUP_DELETED = "group_deleted"
GROUP_MEMBER_ADDED = "group_member_added"
GROUP_MEMBER_REMOVED = "group_member_removed"
PASSKEY_ENROLLED = "passkey_enrolled"
PASSKEY_REVOKED = "passkey_revoked"
KEY_CREATED = "key_created"
KEY_ROTATED = "key_rotated"
KEY_REVOKED = "key_revoked"
AUTH_FAILURE = "auth_failure"


async def record_call(
    conn: asyncpg.Connection,
    *,
    method: str,
    outcome: str,
    principal_id=None,
    principal_label: str | None = None,
    client_id: str | None = None,
    api_key_id=None,
    upstream_id=None,
    upstream_name: str | None = None,
    endpoint_id=None,
    endpoint_url: str | None = None,
    tool_name: str | None = None,
    error_code: str | None = None,
    latency_ms: int | None = None,
    request_id: str | None = None,
    session_id: str | None = None,
) -> None:
    try:
        await conn.execute(
            """INSERT INTO audit_calls
                   (principal_id, principal_label, client_id, api_key_id,
                    upstream_id, upstream_name, endpoint_id, endpoint_url,
                    tool_name, method, outcome,
                    error_code, latency_ms, request_id, session_id)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)""",
            principal_id,
            principal_label,
            client_id,
            api_key_id,
            upstream_id,
            upstream_name,
            endpoint_id,
            endpoint_url,
            tool_name,
            method,
            outcome,
            error_code,
            latency_ms,
            request_id,
            session_id,
        )
    except Exception:  # noqa: BLE001 — an audit outage must not be an outage
        log.exception("failed to write audit_calls row (%s %s)", method, outcome)


async def record_auth_event(
    conn: asyncpg.Connection,
    *,
    event: str,
    outcome: str = "ok",
    principal_id=None,
    principal_label: str | None = None,
    client_id: str | None = None,
    api_key_id=None,
    backend: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: dict | None = None,
) -> None:
    try:
        await conn.execute(
            """INSERT INTO audit_auth_events
                   (event, outcome, principal_id, principal_label, client_id,
                    api_key_id, backend, ip, user_agent, detail)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8::inet,$9,$10::jsonb)""",
            event,
            outcome,
            principal_id,
            principal_label,
            client_id,
            api_key_id,
            backend,
            ip,
            user_agent,
            json.dumps(detail or {}),
        )
    except Exception:  # noqa: BLE001
        log.exception("failed to write audit_auth_events row (%s)", event)


async def purge_expired(conn: asyncpg.Connection, retention_days: int) -> dict[str, int]:
    """Retention job (Q7: one year for everything). Returns rows removed.

    Also revokes tokens that have been expired for the retention window plus
    a small grace — nothing authenticates them, but the row is worth zero
    without them.
    """
    days = int(retention_days)
    calls = await conn.execute(
        f"DELETE FROM audit_calls WHERE ts < now() - interval '{days} days'"
    )
    events = await conn.execute(
        f"DELETE FROM audit_auth_events WHERE ts < now() - interval '{days} days'"
    )
    tokens = await conn.execute(
        f"""DELETE FROM tokens
             WHERE (revoked_at IS NOT NULL AND revoked_at < now() - interval '{days} days')
                OR (expires_at < now() - interval '{days} days')"""
    )
    return {
        "audit_calls": int(calls.split()[-1]),
        "audit_auth_events": int(events.split()[-1]),
        "tokens": int(tokens.split()[-1]),
    }

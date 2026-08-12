"""Resolving which rate limit applies to a caller (PRD Q19).

Two decisions live here, both worth stating because neither is obvious:

**Precedence is key → principal → default.** NULL means "ask the next level
up", so raising the global default lifts everyone who hasn't been given a
specific number — which is what an operator expects a default to do.

**What a valkey outage means depends on who is calling.** For a human it fails
OPEN: locking the operator out of his own gateway because the counter blinked is a
worse outcome than an unmetered minute, and it matches the login limiter, which
already fails open deliberately. For a service principal it fails CLOSED: a
leaked machine credential is exactly the threat this defends against, and a
service can retry. The asymmetry is the point, not an inconsistency.
"""

from dataclasses import dataclass

from . import config


@dataclass(frozen=True)
class Limit:
    per_minute: int
    bucket: str
    fail_closed: bool
    source: str          # 'key' | 'principal' | 'default' — for the audit detail


async def rate_limit_for(conn, caller) -> Limit:
    row = None
    if caller.api_key_id is not None:
        row = await conn.fetchrow(
            """SELECT k.rate_limit_per_min AS key_limit,
                      p.rate_limit_per_min AS principal_limit,
                      p.kind
                 FROM api_keys k JOIN principals p ON p.id = k.principal_id
                WHERE k.id = $1::uuid""",
            caller.api_key_id,
        )
    if row is None:
        row = await conn.fetchrow(
            """SELECT NULL::int AS key_limit, rate_limit_per_min AS principal_limit, kind
                 FROM principals WHERE id = $1""",
            caller.principal_id,
        )

    key_limit = row["key_limit"] if row else None
    principal_limit = row["principal_limit"] if row else None
    kind = (row["kind"] if row else "human") or "human"

    if key_limit:
        per_minute, source = key_limit, "key"
    elif principal_limit:
        per_minute, source = principal_limit, "principal"
    else:
        per_minute, source = config.DEFAULT_RATE_LIMIT_PER_MIN, "default"

    # Count against the credential when there is one, so two keys of the same
    # principal don't consume each other's budget — but against the principal
    # otherwise, so an OAuth client can't dodge the limit by re-registering.
    bucket = (
        f"key:{caller.api_key_id}" if caller.api_key_id
        else f"principal:{caller.principal_id}"
    )
    return Limit(
        per_minute=per_minute,
        bucket=bucket,
        fail_closed=(kind == "service"),
        source=source,
    )

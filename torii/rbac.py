"""The authorization choke point. Every list and every invoke goes through
`check()` or `effective_grants()`; nothing else in the codebase decides
access.

The model (PRD FR3, Q2/Q8/Q9/Q25):

    baseline  = union(principal grants, group grants)
    effective = baseline narrowed by the CREDENTIAL the call arrived on
                (an OAuth client's own grants, or a static key's own grants)
    default   = deny

A caller is in a group either by a local `group_members` row or by an IdP
claim mapped through `groups.idp_claim` (Q25). Both resolve through the same
`subject_type = 'group'` grant rows and the same union — a group can only
ever WIDEN the baseline, never narrow it, so per-client and per-key ceilings
still bite on top. There is no implicit "everyone" group; a member of no
group, and a group with no grants, both resolve to nothing.

Properties this module is responsible for, in the order they bite:

1. **Default deny.** No grant row, no access. An empty result is the normal
   state for a new principal, not an error.
2. **No admin bypass.** There is no branch on `is_admin` anywhere in this
   file. the operator's wide access is wide grant rows, nothing more.
3. **The database is the authority.** `check()` re-reads the principal, the
   client, and the grants on every call rather than trusting a caller
   struct assembled at authentication time, so disabling a principal or a
   client takes effect on the next call, not on the next token refresh.
4. **Client narrowing is a ceiling, not a patch.** If the calling client
   carries ANY grant of its own, that set is the whole of what the client
   may reach — its grants intersect the baseline. A client with no grants
   of its own inherits the principal's baseline untouched...

   ...UNLESS it is explicitly `narrowed` (Q14). A narrowed credential is
   limited to its own grants full stop, so having none means having nothing.
   That distinction exists because DCR mints a new client_id on every
   registration: without it, removing and re-adding a narrowed connector
   came back with the principal's full baseline, and the narrowing
   evaporated silently.

5. **A delegated service is bounded by its owner** (Q17). A service principal
   with `owner_id` set is a deputy of a person: its effective access is
   intersected with that human's baseline, and it is denied outright when the
   owner is disabled. That is what makes self-provisioning safe — a user can
   create one and delegate to it, but never beyond themselves. An independent
   service (no owner) is unaffected and keeps its own lifecycle.

6. **Static keys narrow the same way** (Q15). A `tor_` key can carry its own
   grants and its own mode, so a user with access to several servers can mint
   a key that reaches exactly one. Note what does NOT provide isolation: the
   per-server URL. `/<slug>/mcp` is a naming convenience served by this same
   resolver (Q13), so a key with baseline access reaches everything whichever
   URL it is pointed at. Scope belongs in the grant, never in the hostname.

   The alternative reading — narrow per-upstream, inherit elsewhere — was
   rejected: it means adding a narrow grant for the phone on one upstream
   silently leaves every OTHER upstream wide open on the phone, which
   defeats the stolen-phone scenario the feature exists for (Q8).
"""

from dataclasses import dataclass, field

import asyncpg


@dataclass(frozen=True)
class ToolSet:
    """Either every tool on an upstream, or an explicit set of them."""

    all_tools: bool = False
    tools: frozenset[str] = frozenset()

    def contains(self, tool: str) -> bool:
        return self.all_tools or tool in self.tools

    def is_empty(self) -> bool:
        return not self.all_tools and not self.tools

    def union(self, other: "ToolSet") -> "ToolSet":
        if self.all_tools or other.all_tools:
            return ALL_TOOLS
        return ToolSet(tools=self.tools | other.tools)

    def intersect(self, other: "ToolSet") -> "ToolSet":
        if self.all_tools and other.all_tools:
            return ALL_TOOLS
        if self.all_tools:
            return ToolSet(tools=other.tools)
        if other.all_tools:
            return ToolSet(tools=self.tools)
        return ToolSet(tools=self.tools & other.tools)


ALL_TOOLS = ToolSet(all_tools=True)
NO_TOOLS = ToolSet()


def listed(*tools: str) -> ToolSet:
    return ToolSet(tools=frozenset(tools))


# Reasons are audit values (audit_calls.error_code). Keep them stable.
OK = "ok"
NO_GRANT = "no_grant"
TOOL_NOT_GRANTED = "tool_not_granted"
CLIENT_NARROWED = "client_narrowed"
UPSTREAM_DISABLED = "upstream_disabled"
PRINCIPAL_DISABLED = "principal_disabled"
PRINCIPAL_UNKNOWN = "principal_unknown"
CLIENT_UNKNOWN = "client_unknown"
OWNER_DISABLED = "owner_disabled"
OWNER_NARROWED = "owner_narrowed"

# oauth_clients.access_mode values (Q14).
INHERIT = "inherit"
NARROWED = "narrowed"


@dataclass(frozen=True)
class Caller:
    """Who is asking. Assembled by the auth layer from a token or a key."""

    principal_id: str
    username: str = ""
    kind: str = "human"
    # The OAuth client this call arrived on, when it arrived on one. None for
    # static-key callers, which therefore can't be narrowed per client.
    client_id: str | None = None
    api_key_id: str | None = None
    # IdP group CLAIMS (Q9). Always empty until the Authentik connector lands.
    # Local torii group membership is deliberately NOT here: it is read from
    # the database on every call (see `_GRANT_SQL`), so removing someone from
    # a group bites on the next call rather than on the next token refresh.
    groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class GrantRow:
    subject_type: str
    upstream_name: str
    tool_scope: str
    tools: tuple[str, ...] = ()
    upstream_enabled: bool = True


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    upstream: str | None = None
    tool: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class Context:
    """Everything the resolver needs, read fresh from the database."""

    rows: tuple[GrantRow, ...] = ()
    principal_disabled: bool = False
    principal_exists: bool = True
    # None when the caller isn't using an OAuth client at all.
    client_valid: bool | None = None
    # 'inherit' | 'narrowed' | None, for whichever credential the call arrived
    # on — an OAuth client (Q14) or a static key (Q15). A caller presents one
    # or the other, never both, so one field covers both cases.
    credential_access_mode: str | None = None
    # Set when this principal is a DELEGATED service (Q17): it has an owner,
    # so its access is bounded by that human's.
    has_owner: bool = False
    owner_disabled: bool = False
    disabled_upstreams: frozenset[str] = field(default_factory=frozenset)


# --- pure resolution -------------------------------------------------------


def _merge(rows, subject_types) -> dict[str, ToolSet]:
    merged: dict[str, ToolSet] = {}
    for row in rows:
        if row.subject_type not in subject_types or not row.upstream_enabled:
            continue
        scope = ALL_TOOLS if row.tool_scope == "all" else ToolSet(tools=frozenset(row.tools))
        if scope.is_empty():
            # A 'list' grant with no tools grants nothing. The schema forbids
            # writing one; this is the belt to that suspenders.
            continue
        merged[row.upstream_name] = merged.get(row.upstream_name, NO_TOOLS).union(scope)
    return merged


def resolve(context: Context, caller: Caller) -> dict[str, ToolSet]:
    """The caller's effective grants: upstream name -> reachable tools.

    An upstream absent from the result is invisible to this caller — that is
    what makes ungranted servers unlistable rather than merely undeniable
    (FR1).
    """
    if not context.principal_exists or context.principal_disabled:
        return {}
    if caller.client_id is not None and context.client_valid is not True:
        return {}
    # A delegated service stops working when its owner does — that's the
    # property that makes self-provisioning safe (Q17).
    if context.has_owner and context.owner_disabled:
        return {}

    baseline = _merge(context.rows, ("principal", "group"))
    if context.has_owner:
        # Bounded by the owner: the service can hold a grant its owner lost,
        # and it must not take effect.
        owner = _merge(context.rows, ("owner",))
        baseline = {
            name: baseline[name].intersect(owner[name])
            for name in baseline
            if name in owner
        }
        baseline = {n: scope for n, scope in baseline.items() if not scope.is_empty()}
    ceiling = _merge(context.rows, ("client", "key"))

    # A credential narrows IFF it is explicitly marked NARROWED — not merely
    # because it currently carries grant rows. Inferring narrowing from
    # bool(ceiling) was the #60 bug: disabling one upstream drops that
    # upstream's ceiling rows (see _merge), which could empty the ceiling and
    # flip a scoped credential back to its owner's full baseline. Every path
    # that scopes a credential now sets the mode when it writes the grant, so
    # the mode is the single source of truth. Static keys and OAuth clients are
    # treated identically here on purpose: one rule, one code path.
    narrowed = (
        caller.client_id is not None or caller.api_key_id is not None
    ) and context.credential_access_mode == NARROWED
    if not narrowed:
        effective = baseline
    else:
        # A narrowed client with no grants of its own reaches nothing: the
        # intersection with an empty ceiling is empty, which is the point.
        effective = {
            name: baseline[name].intersect(ceiling[name])
            for name in baseline
            if name in ceiling
        }

    return {name: scope for name, scope in effective.items() if not scope.is_empty()}


def decide(context: Context, caller: Caller, upstream: str, tool: str) -> Decision:
    """Allow or deny one call, with a reason worth writing to the audit log."""

    def deny(reason: str) -> Decision:
        return Decision(False, reason, upstream, tool)

    if not context.principal_exists:
        return deny(PRINCIPAL_UNKNOWN)
    if context.principal_disabled:
        return deny(PRINCIPAL_DISABLED)
    if caller.client_id is not None and context.client_valid is not True:
        return deny(CLIENT_UNKNOWN)
    if context.has_owner and context.owner_disabled:
        return deny(OWNER_DISABLED)

    baseline = _merge(context.rows, ("principal", "group"))
    if context.has_owner:
        owner = _merge(context.rows, ("owner",))
        bounded = {
            name: baseline[name].intersect(owner[name])
            for name in baseline
            if name in owner
        }
        if upstream in baseline and (
            upstream not in bounded or not bounded[upstream].contains(tool)
        ):
            return deny(OWNER_NARROWED)
        baseline = {n: s for n, s in bounded.items() if not s.is_empty()}
    ceiling = _merge(context.rows, ("client", "key"))

    if upstream not in baseline:
        # Distinguish "granted but the upstream is switched off" from "never
        # granted" — the first is an operator action, the second is an
        # access-control event, and conflating them muddies the audit.
        if upstream in context.disabled_upstreams:
            return deny(UPSTREAM_DISABLED)
        return deny(NO_GRANT)
    if not baseline[upstream].contains(tool):
        return deny(TOOL_NOT_GRANTED)

    # Narrowing driven by mode only, matching resolve() (#60). Inferring it
    # from bool(ceiling) here too would let the two disagree — resolve could
    # call a credential un-narrowed while decide still bounded it — the moment
    # a disabled upstream emptied the ceiling.
    if (
        caller.client_id is not None or caller.api_key_id is not None
    ) and context.credential_access_mode == NARROWED:
        if upstream not in ceiling or not ceiling[upstream].contains(tool):
            return deny(CLIENT_NARROWED)

    return Decision(True, OK, upstream, tool)


# --- database-backed entry points -----------------------------------------

# A group applies to this caller two ways, and both are read here rather than
# trusted from the caller struct (property 3 above): a LOCAL membership row,
# or an IdP claim mapped onto a group by `groups.idp_claim` (#17, dormant —
# `caller.groups` is empty until the connector lands). `idp_claim IS NULL`
# means local-only, and a NULL never matches a claim.
_GROUP_MATCH = """
       SELECT gr.name FROM groups gr
        WHERE gr.id IN (SELECT gm.group_id FROM group_members gm
                         WHERE gm.principal_id = {principal})
           OR (gr.idp_claim IS NOT NULL AND gr.idp_claim = ANY({claims}))
"""

_GRANT_SQL = f"""
SELECT g.subject_type,
       g.tool_scope,
       g.tools,
       u.name    AS upstream_name,
       u.enabled AS upstream_enabled
  FROM grants g
  JOIN upstreams u ON u.id = g.upstream_id
 WHERE (g.subject_type = 'principal' AND g.principal_id = $1)
    OR (g.subject_type = 'group'     AND g.group_name IN (
{_GROUP_MATCH.format(principal="$1", claims="$2::text[]")}    ))
    OR (g.subject_type = 'client'    AND g.client_id = $3)
    OR (g.subject_type = 'key'       AND g.api_key_id = $4)
"""

# The owner's baseline, relabelled so the resolver can intersect without a
# second concept (Q17). It has to union the owner's group-derived grants for
# the same reason the caller's does: once a human can get access via a group,
# reading only their `principal` rows UNDERSTATES their baseline, and a
# delegated service would be denied things its owner can plainly do.
#
# The owner's IdP claims aren't knowable at this moment — they live in the
# owner's token, not in this request — so only their LOCAL memberships count
# here. That is fail-closed: a deputy may be capped below an owner whose
# access is purely federated, never above.
_OWNER_GRANT_SQL = f"""
SELECT 'owner' AS subject_type, g.tool_scope, g.tools,
       u.name AS upstream_name, u.enabled AS upstream_enabled
  FROM grants g
  JOIN upstreams u ON u.id = g.upstream_id
 WHERE (g.subject_type = 'principal' AND g.principal_id = $1)
    OR (g.subject_type = 'group'     AND g.group_name IN (
{_GROUP_MATCH.format(principal="$1", claims="ARRAY[]::text[]")}    ))
"""


async def load_context(conn: asyncpg.Connection, caller: Caller) -> Context:
    """Read the authorization state for this caller, now.

    Deliberately uncached: these tables are tiny, and a stale grant cache is
    the failure mode this whole project exists to eliminate. If profiling
    ever demands caching, it belongs behind an explicit invalidation on
    grant writes, not here.
    """
    principal = await conn.fetchrow(
        """SELECT p.id, p.disabled_at, p.owner_id,
                  o.disabled_at AS owner_disabled_at
             FROM principals p
             LEFT JOIN principals o ON o.id = p.owner_id
            WHERE p.id = $1""",
        caller.principal_id,
    )
    if principal is None:
        return Context(principal_exists=False)

    client_valid: bool | None = None
    credential_access_mode: str | None = None
    if caller.client_id is not None:
        # A client only counts as this caller's if it is bound to this
        # principal and not disabled. Anything else denies outright rather
        # than falling back to the principal's baseline — falling back would
        # turn "this client is revoked" into "this client has full access".
        client_row = await conn.fetchrow(
            """SELECT access_mode FROM oauth_clients
                WHERE client_id = $1 AND principal_id = $2 AND disabled_at IS NULL""",
            caller.client_id,
            caller.principal_id,
        )
        client_valid = client_row is not None
        credential_access_mode = client_row["access_mode"] if client_row else None
    elif caller.api_key_id is not None:
        # The key's liveness is already established by authentication; this
        # only reads how it scopes. A key belonging to another principal can't
        # arrive here, because the caller was built from the key itself.
        credential_access_mode = await conn.fetchval(
            "SELECT access_mode FROM api_keys WHERE id = $1::uuid AND revoked_at IS NULL",
            caller.api_key_id,
        )

    rows = await conn.fetch(
        _GRANT_SQL,
        caller.principal_id,
        list(caller.groups),
        caller.client_id,
        caller.api_key_id,
    )
    owner_rows = []
    if principal["owner_id"] is not None:
        owner_rows = await conn.fetch(_OWNER_GRANT_SQL, principal["owner_id"])
    grants = tuple(
        GrantRow(
            subject_type=r["subject_type"],
            upstream_name=r["upstream_name"],
            tool_scope=r["tool_scope"],
            tools=tuple(r["tools"] or ()),
            upstream_enabled=r["upstream_enabled"],
        )
        for r in list(rows) + list(owner_rows)
    )
    disabled = frozenset(g.upstream_name for g in grants if not g.upstream_enabled)

    return Context(
        rows=grants,
        principal_disabled=principal["disabled_at"] is not None,
        principal_exists=True,
        client_valid=client_valid,
        credential_access_mode=credential_access_mode,
        has_owner=principal["owner_id"] is not None,
        owner_disabled=principal["owner_disabled_at"] is not None,
        disabled_upstreams=disabled,
    )


async def effective_grants(
    conn: asyncpg.Connection, caller: Caller
) -> dict[str, ToolSet]:
    return resolve(await load_context(conn, caller), caller)


async def check(
    conn: asyncpg.Connection, caller: Caller, upstream: str, tool: str
) -> Decision:
    return decide(await load_context(conn, caller), caller, upstream, tool)

"""The resolver against real rows.

`test_rbac.py` pins the logic; this pins the loader — that the SQL selects
exactly the grants belonging to this caller, and that revocations take effect
immediately because nothing is cached.
"""


from conftest import make_upstream
from torii import rbac
from torii.rbac import ALL_TOOLS, Caller, listed


async def _principal(conn, username, kind="human"):
    return await conn.fetchval(
        "INSERT INTO principals (kind, username) VALUES ($1, $2) RETURNING id",
        kind,
        username,
    )


async def _upstream(conn, name, enabled=True):
    return await make_upstream(conn, name, "http://127.0.0.1:9000/mcp", enabled=enabled)


async def _client(conn, client_id, principal_id, label="phone"):
    return await conn.fetchval(
        """INSERT INTO oauth_clients (client_id, client_name, principal_id, label)
           VALUES ($1, 'claude.ai', $2, $3) RETURNING client_id""",
        client_id,
        principal_id,
        label,
    )


async def _group(conn, name, idp_claim=None):
    return await conn.fetchval(
        "INSERT INTO groups (name, idp_claim) VALUES ($1, $2) RETURNING id",
        name, idp_claim,
    )


async def _member(conn, group_id, principal_id):
    await conn.execute(
        "INSERT INTO group_members (group_id, principal_id) VALUES ($1, $2)",
        group_id, principal_id,
    )


async def _grant(conn, upstream_id, *, principal_id=None, client_id=None,
                 group_name=None, scope="all", tools=()):
    subject_type = (
        "principal" if principal_id else "client" if client_id else "group"
    )
    # A client/key-scoped insert flips the credential to 'narrowed' via the
    # grants_narrow_credential trigger (migration 0015) — the same schema path
    # production uses — so the helper does not set the mode itself (#60).
    return await conn.fetchval(
        """INSERT INTO grants
               (subject_type, principal_id, client_id, group_name,
                upstream_id, tool_scope, tools)
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id""",
        subject_type,
        principal_id,
        client_id,
        group_name,
        upstream_id,
        scope,
        list(tools),
    )


# --- loading ---------------------------------------------------------------


async def test_zero_grants_is_an_empty_tool_list(conn):
    """The P1 exit criterion: a new human sees nothing at all."""
    principal_id = await _principal(conn, "newcomer")
    await _upstream(conn, "knowledge")
    caller = Caller(principal_id=str(principal_id), username="newcomer")
    assert await rbac.effective_grants(conn, caller) == {}


async def test_principal_grant_resolves(conn):
    principal_id = await _principal(conn, "alice")
    upstream_id = await _upstream(conn, "knowledge")
    await _grant(conn, upstream_id, principal_id=principal_id)
    caller = Caller(principal_id=str(principal_id), username="alice")
    assert await rbac.effective_grants(conn, caller) == {"knowledge": ALL_TOOLS}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).allowed


async def test_another_principals_grants_are_invisible(conn):
    mine = await _principal(conn, "mine")
    theirs = await _principal(conn, "theirs")
    upstream_id = await _upstream(conn, "brain")
    await _grant(conn, upstream_id, principal_id=theirs)
    caller = Caller(principal_id=str(mine), username="mine")
    assert await rbac.effective_grants(conn, caller) == {}
    assert not (await rbac.check(conn, caller, "brain", "capture_thought")).allowed


async def test_group_grant_requires_membership(conn):
    """A group grant is inert for anyone who isn't in the group. Membership is
    a row, not a claim on the caller — which is what makes removal immediate."""
    member_id = await _principal(conn, "wife")
    stranger_id = await _principal(conn, "neighbour")
    upstream_id = await _upstream(conn, "notebook")
    group_id = await _group(conn, "family")
    await _member(conn, group_id, member_id)
    await _grant(conn, upstream_id, group_name="family", scope="list", tools=["list_notes"])

    member = Caller(principal_id=str(member_id))
    stranger = Caller(principal_id=str(stranger_id))

    assert await rbac.effective_grants(conn, member) == {"notebook": listed("list_notes")}
    assert await rbac.effective_grants(conn, stranger) == {}
    # A group name presented as an IdP claim is NOT membership: the group has
    # no idp_claim, so nothing federated can satisfy it.
    liar = Caller(principal_id=str(stranger_id), groups=("family",))
    assert await rbac.effective_grants(conn, liar) == {}


async def test_removing_a_member_denies_on_the_very_next_call(conn):
    """The property that proves membership is resolved in `load_context` and
    not baked into the caller at authentication time: no re-auth, no refresh,
    the next call is simply denied."""
    principal_id = await _principal(conn, "kid")
    upstream_id = await _upstream(conn, "notebook")
    group_id = await _group(conn, "family")
    await _member(conn, group_id, principal_id)
    await _grant(conn, upstream_id, group_name="family")

    caller = Caller(principal_id=str(principal_id))
    assert (await rbac.check(conn, caller, "notebook", "list_notes")).allowed

    await conn.execute(
        "DELETE FROM group_members WHERE group_id = $1 AND principal_id = $2",
        group_id, principal_id,
    )
    assert (await rbac.check(conn, caller, "notebook", "list_notes")).reason == (
        rbac.NO_GRANT
    )


async def test_the_baseline_is_the_union_of_direct_and_group_grants(conn):
    """A group only ever widens. It never replaces what someone already has,
    and it never takes anything away."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    notebook = await _upstream(conn, "notebook")
    await _grant(conn, wk, principal_id=principal_id, scope="list", tools=["get_doc"])
    group_id = await _group(conn, "family")
    await _member(conn, group_id, principal_id)
    await _grant(conn, notebook, group_name="family")
    # Same upstream from both sides: the tool sets merge rather than one winning.
    await _grant(conn, wk, group_name="family", scope="list", tools=["search_knowledge"])

    caller = Caller(principal_id=str(principal_id))
    assert await rbac.effective_grants(conn, caller) == {
        "knowledge": listed("get_doc", "search_knowledge"),
        "notebook": ALL_TOOLS,
    }


async def test_an_empty_group_grants_nothing(conn):
    """Default deny holds: there is no implicit 'everyone' group."""
    principal_id = await _principal(conn, "outsider")
    upstream_id = await _upstream(conn, "notebook")
    await _group(conn, "empty")
    await _grant(conn, upstream_id, group_name="empty")

    assert await rbac.effective_grants(conn, Caller(principal_id=str(principal_id))) == {}


async def test_a_group_with_no_grants_gives_a_member_nothing(conn):
    principal_id = await _principal(conn, "member")
    await _upstream(conn, "notebook")
    group_id = await _group(conn, "family")
    await _member(conn, group_id, principal_id)

    assert await rbac.effective_grants(conn, Caller(principal_id=str(principal_id))) == {}


async def test_a_narrowed_credential_still_bounds_group_access(conn):
    """Union at the baseline, intersect at the ceiling. A group must not leak
    past a deliberately limited connector."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    notebook = await _upstream(conn, "notebook")
    group_id = await _group(conn, "family")
    await _member(conn, group_id, principal_id)
    await _grant(conn, wk, group_name="family")
    await _grant(conn, notebook, group_name="family")

    phone = await _client(conn, "cl_phone", principal_id, "phone")
    await _grant(conn, wk, client_id=phone, scope="list", tools=["get_doc"])

    on_phone = Caller(principal_id=str(principal_id), client_id=phone)
    assert await rbac.effective_grants(conn, on_phone) == {
        "knowledge": listed("get_doc")
    }
    assert (await rbac.check(conn, on_phone, "notebook", "list_notes")).reason == (
        rbac.CLIENT_NARROWED
    )


async def test_an_idp_claim_matches_only_a_group_that_maps_it(conn):
    """The Authentik seam (#17), dormant: `Caller.groups` carries claims, and a
    claim satisfies a group only when that group declares the mapping."""
    principal_id = await _principal(conn, "federated")
    notebook = await _upstream(conn, "notebook")
    wk = await _upstream(conn, "knowledge")
    await _group(conn, "staff", idp_claim="torii-staff")
    await _group(conn, "local-only")
    await _grant(conn, notebook, group_name="staff")
    await _grant(conn, wk, group_name="local-only")

    # The claim value, not the group's own name, is what maps.
    assert await rbac.effective_grants(
        conn, Caller(principal_id=str(principal_id), groups=("torii-staff",))
    ) == {"notebook": ALL_TOOLS}
    assert await rbac.effective_grants(
        conn, Caller(principal_id=str(principal_id), groups=("staff",))
    ) == {}
    # A group with no claim can never be satisfied by one, whatever it's called.
    assert await rbac.effective_grants(
        conn, Caller(principal_id=str(principal_id), groups=("local-only",))
    ) == {}


async def test_a_group_does_not_change_the_disabled_upstream_reason(conn):
    """UPSTREAM_DISABLED vs NO_GRANT is an audit distinction worth keeping:
    the first is an operator action, the second an access-control event."""
    principal_id = await _principal(conn, "member")
    upstream_id = await _upstream(conn, "notebook", enabled=False)
    group_id = await _group(conn, "family")
    await _member(conn, group_id, principal_id)
    await _grant(conn, upstream_id, group_name="family")

    caller = Caller(principal_id=str(principal_id))
    assert (await rbac.check(conn, caller, "notebook", "list_notes")).reason == (
        rbac.UPSTREAM_DISABLED
    )


async def test_a_disabled_principal_gains_nothing_from_a_group(conn):
    principal_id = await _principal(conn, "suspended")
    upstream_id = await _upstream(conn, "notebook")
    group_id = await _group(conn, "family")
    await _member(conn, group_id, principal_id)
    await _grant(conn, upstream_id, group_name="family")
    await conn.execute(
        "UPDATE principals SET disabled_at = now() WHERE id = $1", principal_id
    )

    caller = Caller(principal_id=str(principal_id))
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "notebook", "list_notes")).reason == (
        rbac.PRINCIPAL_DISABLED
    )


async def test_a_service_principal_can_be_a_group_member(conn):
    """Allowed by the schema on purpose. An INDEPENDENT service in a group
    gets the group's grants; a delegated one stays capped by its owner, which
    the owner-bounding tests below cover."""
    service_id = await _principal(conn, "shared-bot", kind="service")
    upstream_id = await _upstream(conn, "notebook")
    group_id = await _group(conn, "bots")
    await _member(conn, group_id, service_id)
    await _grant(conn, upstream_id, group_name="bots")

    caller = Caller(principal_id=str(service_id), kind="service")
    assert await rbac.effective_grants(conn, caller) == {"notebook": ALL_TOOLS}


async def test_client_narrowing_end_to_end(conn):
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    brain = await _upstream(conn, "brain")
    await _grant(conn, wk, principal_id=principal_id)
    await _grant(conn, brain, principal_id=principal_id)
    phone = await _client(conn, "cl_phone", principal_id, "phone")
    await _grant(conn, wk, client_id=phone, scope="list", tools=["search_knowledge"])

    baseline = Caller(principal_id=str(principal_id), username="alice")
    on_phone = Caller(principal_id=str(principal_id), username="alice", client_id=phone)

    assert set(await rbac.effective_grants(conn, baseline)) == {"knowledge", "brain"}
    assert await rbac.effective_grants(conn, on_phone) == {
        "knowledge": listed("search_knowledge")
    }
    assert not (await rbac.check(conn, on_phone, "brain", "capture_thought")).allowed


async def test_disabling_the_narrowed_upstream_does_not_widen_the_client(conn):
    """#60 regression — ceiling evaporation.

    A phone client is narrowed to knowledge only. Disable that upstream and
    the client's ceiling has no rows left. The bug was inferring 'not narrowed'
    from the now-empty ceiling and falling the client back to its owner's full
    baseline — handing the *narrowed* phone access to brain. Narrowing is driven by
    the mode, so a narrowed credential whose only grant is gone reaches nothing,
    never its baseline."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    brain = await _upstream(conn, "brain")
    await _grant(conn, wk, principal_id=principal_id)
    await _grant(conn, brain, principal_id=principal_id)
    phone = await _client(conn, "cl_phone", principal_id, "phone")
    await _grant(conn, wk, client_id=phone, scope="list", tools=["search_knowledge"])

    # Operator disables the one upstream the phone was scoped to.
    await conn.execute("UPDATE upstreams SET enabled = false WHERE id = $1", wk)

    on_phone = Caller(principal_id=str(principal_id), username="alice", client_id=phone)
    # Ceiling is empty, but the client stays narrowed: no fallback to the baseline.
    assert await rbac.effective_grants(conn, on_phone) == {}
    assert not (await rbac.check(conn, on_phone, "brain", "capture_thought")).allowed


async def test_an_unnarrowed_client_inherits_the_baseline(conn):
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=principal_id)
    desktop = await _client(conn, "cl_desktop", principal_id, "desktop")

    caller = Caller(principal_id=str(principal_id), client_id=desktop)
    assert await rbac.effective_grants(conn, caller) == {"knowledge": ALL_TOOLS}


async def test_grants_of_another_principals_client_do_not_apply(conn):
    """A client id is only meaningful in the context of the principal it is
    bound to. Presenting someone else's client id must deny, not narrow."""
    mine = await _principal(conn, "mine")
    theirs = await _principal(conn, "theirs")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=mine)
    their_client = await _client(conn, "cl_theirs", theirs, "their phone")
    await _grant(conn, wk, client_id=their_client, scope="list", tools=["get_doc"])

    caller = Caller(principal_id=str(mine), client_id=their_client)
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).reason == (
        rbac.CLIENT_UNKNOWN
    )


async def test_disabled_client_denies_instead_of_inheriting(conn):
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=principal_id)
    phone = await _client(conn, "cl_phone", principal_id, "phone")
    await conn.execute(
        "UPDATE oauth_clients SET disabled_at = now() WHERE client_id = $1", phone
    )

    caller = Caller(principal_id=str(principal_id), client_id=phone)
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).reason == (
        rbac.CLIENT_UNKNOWN
    )


async def test_disabled_upstream_disappears(conn):
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge", enabled=False)
    await _grant(conn, wk, principal_id=principal_id)

    caller = Caller(principal_id=str(principal_id))
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).reason == (
        rbac.UPSTREAM_DISABLED
    )


async def test_disabled_principal_denies_everything(conn):
    principal_id = await _principal(conn, "suspended")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=principal_id)
    await conn.execute(
        "UPDATE principals SET disabled_at = now() WHERE id = $1", principal_id
    )

    caller = Caller(principal_id=str(principal_id))
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).reason == (
        rbac.PRINCIPAL_DISABLED
    )


async def test_unknown_principal_denies(conn):
    caller = Caller(principal_id="99999999-9999-9999-9999-999999999999")
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "wk", "get_doc")).reason == (
        rbac.PRINCIPAL_UNKNOWN
    )


async def test_revoking_a_grant_takes_effect_on_the_next_call(conn):
    """Nothing is cached, deliberately: a stale grant cache is the failure
    mode this project exists to eliminate."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    grant_id = await _grant(conn, wk, principal_id=principal_id)
    caller = Caller(principal_id=str(principal_id))

    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).allowed
    await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)
    assert not (await rbac.check(conn, caller, "knowledge", "get_doc")).allowed


async def test_narrowing_a_grant_takes_effect_on_the_next_call(conn):
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    grant_id = await _grant(conn, wk, principal_id=principal_id)
    caller = Caller(principal_id=str(principal_id))

    assert (await rbac.check(conn, caller, "knowledge", "run_sql")).allowed
    await conn.execute(
        "UPDATE grants SET tool_scope = 'list', tools = $2 WHERE id = $1",
        grant_id,
        ["get_doc"],
    )
    assert not (await rbac.check(conn, caller, "knowledge", "run_sql")).allowed
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).allowed


async def test_service_principal_with_a_key_resolves_normally(conn):
    """Static-key callers run the same path: same tables, same resolver, no
    parallel authorization logic (FR2)."""
    principal_id = await _principal(conn, "acme-prod", kind="service")
    srv = await _upstream(conn, "finder")
    await _grant(conn, srv, principal_id=principal_id, scope="list", tools=["search"])
    key_id = await conn.fetchval(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash)
           VALUES ($1, 'acme', 'tor_abc', 'hash') RETURNING id""",
        principal_id,
    )

    caller = Caller(
        principal_id=str(principal_id),
        username="acme-prod",
        kind="service",
        api_key_id=str(key_id),
    )
    assert await rbac.effective_grants(conn, caller) == {"finder": listed("search")}
    assert not (await rbac.check(conn, caller, "finder", "fetch")).allowed


# --- access_mode against real rows (Q14) -----------------------------------


async def test_a_narrowed_client_row_denies_with_no_grants(conn):
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=principal_id)
    client_id = await conn.fetchval(
        """INSERT INTO oauth_clients (client_id, client_name, principal_id, access_mode)
           VALUES ('cl_phone', 'claude.ai', $1, 'narrowed') RETURNING client_id""",
        principal_id,
    )
    caller = Caller(principal_id=str(principal_id), client_id=client_id)
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).reason == (
        rbac.CLIENT_NARROWED
    )


async def test_re_registering_a_connector_does_not_regain_baseline(conn):
    """The scenario the column exists for: the phone is limited, the connector
    is removed and re-added (new client_id), and the principal has asked for
    new clients to start limited. The replacement must NOT come back with
    everything."""
    principal_id = await conn.fetchval(
        """INSERT INTO principals (kind, username, narrow_new_clients)
           VALUES ('human', 'alice', TRUE) RETURNING id"""
    )
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=principal_id)

    # The replacement registration: fresh id, no grants, marked at bind time.
    replacement = await conn.fetchval(
        """INSERT INTO oauth_clients (client_id, client_name, principal_id, access_mode)
           VALUES ('cl_phone_v2', 'claude.ai', $1, 'narrowed') RETURNING client_id""",
        principal_id,
    )
    caller = Caller(principal_id=str(principal_id), client_id=replacement)
    assert await rbac.effective_grants(conn, caller) == {}


async def test_default_client_mode_inherits(conn):
    """Unchanged default: a plain new connector works without setup."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=principal_id)
    client_id = await _client(conn, "cl_desktop", principal_id)

    assert await conn.fetchval(
        "SELECT access_mode FROM oauth_clients WHERE client_id = $1", client_id
    ) == "inherit"
    caller = Caller(principal_id=str(principal_id), client_id=client_id)
    assert await rbac.effective_grants(conn, caller) == {"knowledge": ALL_TOOLS}


# --- scoped static keys (Q15) ----------------------------------------------


async def _key(conn, principal_id, name="k", narrowed=False):
    row = await conn.fetchrow(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash, access_mode)
           VALUES ($1, $2, 'tor_x', $3, $4) RETURNING id""",
        principal_id, name, f"hash-{name}", "narrowed" if narrowed else "inherit",
    )
    return row["id"]


async def test_a_scoped_key_reaches_only_its_own_server(conn):
    """The question this answers: a user with two servers mints a key for one."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    srv = await _upstream(conn, "finder")
    await _grant(conn, wk, principal_id=principal_id)
    await _grant(conn, srv, principal_id=principal_id)

    key_id = await _key(conn, principal_id, "wk-only", narrowed=True)
    await conn.execute(
        """INSERT INTO grants (subject_type, api_key_id, upstream_id, tool_scope)
           VALUES ('key', $1, $2, 'all')""",
        key_id, wk,
    )

    caller = Caller(principal_id=str(principal_id), api_key_id=str(key_id))
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).allowed
    assert (await rbac.check(conn, caller, "finder", "web_search")).reason == (
        rbac.CLIENT_NARROWED
    )


async def test_the_per_server_url_is_not_a_boundary(conn):
    """An inheriting key reaches everything regardless of which endpoint it is
    pointed at — the resolver is the same for /mcp and /<slug>/mcp, so scope
    has to come from the grant, not the URL. This is why key scoping exists."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    srv = await _upstream(conn, "finder")
    await _grant(conn, wk, principal_id=principal_id)
    await _grant(conn, srv, principal_id=principal_id)

    key_id = await _key(conn, principal_id, "unscoped")
    caller = Caller(principal_id=str(principal_id), api_key_id=str(key_id))
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge", "finder"}


async def test_a_narrowed_key_with_no_grants_reaches_nothing(conn):
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=principal_id)
    key_id = await _key(conn, principal_id, "empty", narrowed=True)

    caller = Caller(principal_id=str(principal_id), api_key_id=str(key_id))
    assert await rbac.effective_grants(conn, caller) == {}


async def test_a_key_grant_cannot_exceed_the_owners_baseline(conn):
    """A key grant is intersected, so it can never hand out access the owner
    doesn't have — which is what makes self-service key scoping safe."""
    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    admin_srv = await _upstream(conn, "acme-admin")
    await _grant(conn, wk, principal_id=principal_id, scope="list", tools=["get_doc"])

    key_id = await _key(conn, principal_id, "greedy", narrowed=True)
    for upstream_id in (wk, admin_srv):
        await conn.execute(
            """INSERT INTO grants (subject_type, api_key_id, upstream_id, tool_scope)
               VALUES ('key', $1, $2, 'all')""",
            key_id, upstream_id,
        )

    caller = Caller(principal_id=str(principal_id), api_key_id=str(key_id))
    assert await rbac.effective_grants(conn, caller) == {"knowledge": listed("get_doc")}
    assert not (await rbac.check(conn, caller, "acme-admin", "run_sql")).allowed


async def test_rotating_a_scoped_key_keeps_its_scope(conn):
    """Otherwise rotation would silently hand back a key with full baseline."""
    from torii import credentials

    principal_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    srv = await _upstream(conn, "finder")
    await _grant(conn, wk, principal_id=principal_id)
    await _grant(conn, srv, principal_id=principal_id)

    original = await credentials.mint_api_key(conn, principal_id, "wk-only", narrowed=True)
    await conn.execute(
        """INSERT INTO grants (subject_type, api_key_id, upstream_id, tool_scope)
           VALUES ('key', $1::uuid, $2, 'all')""",
        original.id, wk,
    )
    replacement = await credentials.rotate_api_key(conn, original.id)

    caller = Caller(principal_id=str(principal_id), api_key_id=replacement.id)
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}
    assert await conn.fetchval(
        "SELECT access_mode FROM api_keys WHERE id = $1::uuid", replacement.id
    ) == "narrowed"


# --- delegated services, bounded by their owner (Q17) ----------------------


async def _service_of(conn, owner_id, username="alice/bot"):
    return await conn.fetchval(
        """INSERT INTO principals (kind, username, owner_id)
           VALUES ('service', $1, $2) RETURNING id""",
        username, owner_id,
    )


async def test_a_delegated_service_cannot_exceed_its_owner(conn):
    """The property that makes self-provisioning safe: a grant the owner
    doesn't have simply doesn't take effect."""
    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    admin_srv = await _upstream(conn, "acme-admin")
    await _grant(conn, wk, principal_id=owner_id)          # owner has wk only

    service_id = await _service_of(conn, owner_id)
    await _grant(conn, wk, principal_id=service_id)
    await _grant(conn, admin_srv, principal_id=service_id)  # beyond the owner

    caller = Caller(principal_id=str(service_id), kind="service")
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}
    assert (await rbac.check(conn, caller, "acme-admin", "run_sql")).reason == (
        rbac.OWNER_NARROWED
    )


async def test_a_delegated_service_narrows_when_its_owner_does(conn):
    """The owner loses access; the deputy loses it in the same breath."""
    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    owner_grant = await _grant(conn, wk, principal_id=owner_id)
    service_id = await _service_of(conn, owner_id)
    await _grant(conn, wk, principal_id=service_id)

    caller = Caller(principal_id=str(service_id), kind="service")
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).allowed

    await conn.execute("DELETE FROM grants WHERE id = $1", owner_grant)
    assert await rbac.effective_grants(conn, caller) == {}


async def test_tool_scope_is_intersected_with_the_owners(conn):
    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=owner_id, scope="list", tools=["get_doc"])
    service_id = await _service_of(conn, owner_id)
    await _grant(conn, wk, principal_id=service_id)   # 'all' — capped to get_doc

    caller = Caller(principal_id=str(service_id), kind="service")
    assert await rbac.effective_grants(conn, caller) == {"knowledge": listed("get_doc")}
    assert not (await rbac.check(conn, caller, "knowledge", "search_knowledge")).allowed


async def test_disabling_the_owner_stops_the_delegated_service(conn):
    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    await _grant(conn, wk, principal_id=owner_id)
    service_id = await _service_of(conn, owner_id)
    await _grant(conn, wk, principal_id=service_id)

    caller = Caller(principal_id=str(service_id), kind="service")
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).allowed

    await conn.execute("UPDATE principals SET disabled_at = now() WHERE id = $1", owner_id)
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).reason == (
        rbac.OWNER_DISABLED
    )


async def test_an_independent_service_is_not_bounded_by_anyone(conn):
    """Promotion is the whole point: no owner, own lifecycle, survives people."""
    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    service_id = await _service_of(conn, owner_id, "acme-prod")
    await _grant(conn, wk, principal_id=service_id)
    # The owner has NO grants, so while delegated the service reaches nothing.
    caller = Caller(principal_id=str(service_id), kind="service")
    assert await rbac.effective_grants(conn, caller) == {}

    await conn.execute("UPDATE principals SET owner_id = NULL WHERE id = $1", service_id)
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}

    # And it survives the person who created it being disabled.
    await conn.execute("UPDATE principals SET disabled_at = now() WHERE id = $1", owner_id)
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}


async def test_an_owners_group_access_counts_towards_the_cap(conn):
    """The regression groups would otherwise introduce. The owner-bounding
    query used to read only the owner's `principal` rows, so an owner whose
    access came from a GROUP looked like an owner with no access — and their
    deputy was denied things they can plainly do. Fail-closed, silent, and
    only visible in production."""
    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    group_id = await _group(conn, "family")
    await _member(conn, group_id, owner_id)
    await _grant(conn, wk, group_name="family")      # owner's ONLY access

    service_id = await _service_of(conn, owner_id)
    await _grant(conn, wk, principal_id=service_id)

    caller = Caller(principal_id=str(service_id), kind="service")
    assert await rbac.effective_grants(conn, caller) == {"knowledge": ALL_TOOLS}

    # …and the cap still bites the moment the owner leaves the group.
    await conn.execute(
        "DELETE FROM group_members WHERE group_id = $1 AND principal_id = $2",
        group_id, owner_id,
    )
    assert await rbac.effective_grants(conn, caller) == {}
    assert (await rbac.check(conn, caller, "knowledge", "get_doc")).reason == (
        rbac.OWNER_NARROWED
    )


async def test_a_delegated_service_is_still_capped_by_its_owner_in_a_group(conn):
    """A deputy joining a group does not escape its owner: the group widens
    the deputy's baseline, and the owner's ceiling cuts it straight back."""
    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    admin_srv = await _upstream(conn, "acme-admin")
    await _grant(conn, wk, principal_id=owner_id)     # owner has wk only

    service_id = await _service_of(conn, owner_id)
    group_id = await _group(conn, "bots")
    await _member(conn, group_id, service_id)
    await _grant(conn, admin_srv, group_name="bots")  # beyond the owner
    await _grant(conn, wk, group_name="bots")

    caller = Caller(principal_id=str(service_id), kind="service")
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}
    assert (await rbac.check(conn, caller, "acme-admin", "run_sql")).reason == (
        rbac.OWNER_NARROWED
    )


async def test_a_delegated_services_key_still_narrows(conn):
    """Q15 and Q17 compose: owner cap, then the key's own ceiling."""
    from torii import credentials

    owner_id = await _principal(conn, "alice")
    wk = await _upstream(conn, "knowledge")
    srv = await _upstream(conn, "finder")
    for upstream_id in (wk, srv):
        await _grant(conn, upstream_id, principal_id=owner_id)
    service_id = await _service_of(conn, owner_id)
    for upstream_id in (wk, srv):
        await _grant(conn, upstream_id, principal_id=service_id)

    key = await credentials.mint_api_key(conn, service_id, "scoped", narrowed=True)
    await conn.execute(
        """INSERT INTO grants (subject_type, api_key_id, upstream_id, tool_scope)
           VALUES ('key', $1::uuid, $2, 'all')""",
        key.id, wk,
    )
    caller = Caller(principal_id=str(service_id), kind="service", api_key_id=key.id)
    assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}

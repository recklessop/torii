"""The schema's job is to make illegal authorization states unrepresentable.

These tests are about what the database REFUSES. The RBAC resolver (step 3)
is tested separately for what it allows; here we prove it can never be
handed a grant row that means "everyone", "no one in particular", or "some
tools, unspecified".
"""

import asyncpg
import pytest

from conftest import make_upstream


# --- helpers ---------------------------------------------------------------


async def _principal(conn, username="alice", kind="human", is_admin=False):
    return await conn.fetchval(
        """INSERT INTO principals (kind, username, is_admin)
           VALUES ($1, $2, $3) RETURNING id""",
        kind,
        username,
        is_admin,
    )


async def _upstream(conn, name="knowledge", url="http://127.0.0.1:9000/mcp"):
    return await make_upstream(conn, name, url)


def _rejects(conn, exception=asyncpg.CheckViolationError):
    """Assert the next statement violates a constraint, inside a savepoint so
    the rolled-back attempt doesn't abort the test's transaction."""
    return _Rejects(conn, exception)


class _Rejects:
    def __init__(self, conn, exception):
        self._transaction = conn.transaction()
        self._raises = pytest.raises(exception)

    async def __aenter__(self):
        await self._transaction.start()
        self._raises.__enter__()

    async def __aexit__(self, exc_type, exc, tb):
        await self._transaction.rollback()
        return self._raises.__exit__(exc_type, exc, tb)


async def _client(conn, principal_id, client_id="cl_phone", label="phone"):
    return await conn.fetchval(
        """INSERT INTO oauth_clients (client_id, client_name, principal_id, label)
           VALUES ($1, $2, $3, $4) RETURNING client_id""",
        client_id,
        "claude.ai",
        principal_id,
        label,
    )


# --- migrations ------------------------------------------------------------


async def test_every_table_exists(conn):
    rows = await conn.fetch(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
    )
    tables = {r["tablename"] for r in rows}
    assert {
        "schema_migrations",
        "principals",
        "auth_identities",
        "oauth_clients",
        "tokens",
        "api_keys",
        "upstreams",
        "grants",
        "audit_calls",
        "audit_auth_events",
    } <= tables


async def test_migration_is_recorded_and_not_reapplied(conn):
    count = await conn.fetchval(
        "SELECT count(*) FROM schema_migrations WHERE name = '0001_init.sql'"
    )
    assert count == 1


async def test_default_deny_is_the_empty_state(conn):
    """A fresh principal holds no grants — access exists only as a row."""
    principal_id = await _principal(conn)
    assert await conn.fetchval(
        "SELECT count(*) FROM grants WHERE principal_id = $1", principal_id
    ) == 0


# --- principals ------------------------------------------------------------


async def test_usernames_are_unique(conn):
    await _principal(conn, "alice")
    with pytest.raises(asyncpg.UniqueViolationError):
        await _principal(conn, "alice")


async def test_principal_kind_is_constrained(conn):
    with pytest.raises(asyncpg.CheckViolationError):
        await _principal(conn, "robot", kind="daemon")


async def test_service_principal_cannot_be_admin(conn):
    """Service principals have no UI login, so an admin flag on one would be
    a contradiction that only ever confuses an audit."""
    with pytest.raises(asyncpg.CheckViolationError):
        await _principal(conn, "acme-prod", kind="service", is_admin=True)


# --- auth identities (the federation seam) --------------------------------


async def test_local_identity_requires_a_password_hash(conn):
    principal_id = await _principal(conn)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            "INSERT INTO auth_identities (principal_id, backend) VALUES ($1, 'local')",
            principal_id,
        )


async def test_oidc_identity_requires_provider_and_subject(conn):
    principal_id = await _principal(conn)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO auth_identities (principal_id, backend, provider)
               VALUES ($1, 'oidc', 'authentik')""",
            principal_id,
        )


async def test_one_local_credential_per_principal(conn):
    principal_id = await _principal(conn)
    sql = """INSERT INTO auth_identities (principal_id, backend, password_hash)
             VALUES ($1, 'local', 'bcrypt$fake')"""
    await conn.execute(sql, principal_id)
    async with _rejects(conn, asyncpg.UniqueViolationError):
        await conn.execute(sql, principal_id)


async def test_local_and_oidc_identities_coexist_on_one_principal(conn):
    """Q9b: a human may hold both, and both resolve to the same principal
    and therefore the same grants."""
    principal_id = await _principal(conn)
    await conn.execute(
        """INSERT INTO auth_identities (principal_id, backend, password_hash)
           VALUES ($1, 'local', 'bcrypt$fake')""",
        principal_id,
    )
    await conn.execute(
        """INSERT INTO auth_identities (principal_id, backend, provider, subject)
           VALUES ($1, 'oidc', 'authentik', 'sub-123')""",
        principal_id,
    )
    assert await conn.fetchval(
        "SELECT count(*) FROM auth_identities WHERE principal_id = $1", principal_id
    ) == 2


async def test_one_principal_per_idp_subject(conn):
    """Two principals claiming the same IdP subject would make JIT
    provisioning ambiguous."""
    first = await _principal(conn, "second-human")
    second = await _principal(conn, "third-human")
    sql = """INSERT INTO auth_identities (principal_id, backend, provider, subject)
             VALUES ($1, 'oidc', 'authentik', 'shared-sub')"""
    await conn.execute(sql, first)
    async with _rejects(conn, asyncpg.UniqueViolationError):
        await conn.execute(sql, second)


# --- upstreams -------------------------------------------------------------


async def test_upstream_name_must_survive_tool_namespacing(conn):
    """Names land in <server>__<tool>; anything with an underscore, space, or
    capital makes that namespace ambiguous or unparseable."""
    for bad in ("Work_Knowledge", "work knowledge", "work_knowledge", "-lead", ""):
        async with _rejects(conn):
            await _upstream(conn, bad)
    assert await _upstream(conn, "knowledge")


async def test_upstream_names_are_unique(conn):
    await _upstream(conn, "brain")
    with pytest.raises(asyncpg.UniqueViolationError):
        await _upstream(conn, "brain")


async def test_upstream_timeout_is_bounded(conn):
    for seconds in (0, 301):
        async with _rejects(conn):
            await conn.execute(
                """INSERT INTO upstreams (name, timeout_seconds)
                   VALUES ('slow', $1)""",
                seconds,
            )


async def test_the_same_url_cannot_be_registered_twice_on_one_upstream(conn):
    """The same URL twice is a typo, never a second replica — and a duplicate
    would quietly double that backend's share of the round robin."""
    upstream_id = await _upstream(conn, "wk", "http://127.0.0.1:9000/mcp")
    async with _rejects(conn, asyncpg.UniqueViolationError):
        await conn.execute(
            "INSERT INTO upstream_endpoints (upstream_id, url) VALUES ($1, $2)",
            upstream_id, "http://127.0.0.1:9000/mcp",
        )


async def test_a_non_http_endpoint_url_is_refused_at_the_db(conn):
    """Belt-and-braces to validate_upstream_url (#62): even a code path that
    bypasses the handler cannot land a `file://`/`ftp://` fetch target the
    proxy would dereference. The scheme prefix is the most a CHECK can promise;
    host-range validation stays in the app layer."""
    upstream_id = await _upstream(conn, "wk", "http://127.0.0.1:9000/mcp")
    for bad in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x/", "notaurl"):
        async with _rejects(conn, asyncpg.CheckViolationError):
            await conn.execute(
                "INSERT INTO upstream_endpoints (upstream_id, url) VALUES ($1, $2)",
                upstream_id, bad,
            )


async def test_the_same_url_may_serve_two_different_upstreams(conn):
    """One host can front two logical servers; that isn't a duplicate."""
    await _upstream(conn, "wk", "http://127.0.0.1:9000/mcp")
    await _upstream(conn, "brain", "http://127.0.0.1:9000/mcp")


async def test_endpoints_go_when_their_upstream_goes(conn):
    upstream_id = await _upstream(conn, "wk")
    await conn.execute("DELETE FROM upstreams WHERE id = $1", upstream_id)
    assert await conn.fetchval(
        "SELECT count(*) FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
    ) == 0


async def test_audit_keeps_the_replica_url_after_the_replica_is_removed(conn):
    """Same rule as upstream_name: the id goes, the history stays readable."""
    upstream_id = await _upstream(conn, "wk")
    endpoint_id = await conn.fetchval(
        "SELECT id FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
    )
    await conn.execute(
        """INSERT INTO audit_calls (method, outcome, endpoint_id, endpoint_url)
           VALUES ('tools/call', 'ok', $1, 'http://127.0.0.1:9000/mcp')""",
        endpoint_id,
    )
    await conn.execute("DELETE FROM upstream_endpoints WHERE id = $1", endpoint_id)

    row = await conn.fetchrow("SELECT endpoint_id, endpoint_url FROM audit_calls LIMIT 1")
    assert row["endpoint_id"] is None
    assert row["endpoint_url"] == "http://127.0.0.1:9000/mcp"


async def test_payload_capture_is_off_by_default(conn):
    upstream_id = await _upstream(conn)
    assert await conn.fetchval(
        "SELECT capture_payloads FROM upstreams WHERE id = $1", upstream_id
    ) is False


# --- grants: the authorization model --------------------------------------


async def test_principal_grant_with_all_tools(conn):
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    grant_id = await conn.fetchval(
        """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
           VALUES ('principal', $1, $2, 'all') RETURNING id""",
        principal_id,
        upstream_id,
    )
    assert grant_id


async def test_tool_list_grant(conn):
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    tools = await conn.fetchval(
        """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope, tools)
           VALUES ('principal', $1, $2, 'list', $3) RETURNING tools""",
        principal_id,
        upstream_id,
        ["search_knowledge", "get_doc"],
    )
    assert tools == ["search_knowledge", "get_doc"]


async def test_grant_needs_a_subject(conn):
    """No wildcard grant: a row with no subject at all is unrepresentable."""
    upstream_id = await _upstream(conn)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO grants (subject_type, upstream_id, tool_scope)
               VALUES ('principal', $1, 'all')""",
            upstream_id,
        )


async def test_grant_cannot_carry_two_subjects(conn):
    """A row that is both a principal grant and a client grant would make
    narrowing (Q8) undecidable."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    client_id = await _client(conn, principal_id)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, client_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, $3, 'all')""",
            principal_id,
            client_id,
            upstream_id,
        )


async def test_grant_subject_must_match_its_type(conn):
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('client', $1, $2, 'all')""",
            principal_id,
            upstream_id,
        )


async def test_group_grant_cannot_be_blank_or_wildcard(conn):
    """FR3: no wildcard group. An empty or whitespace group name is the
    closest thing to one, so the schema refuses it."""
    upstream_id = await _upstream(conn)
    for bad in ("", "   "):
        async with _rejects(conn):
            await conn.execute(
                """INSERT INTO grants (subject_type, group_name, upstream_id, tool_scope)
                   VALUES ('group', $1, $2, 'all')""",
                bad,
                upstream_id,
            )


# --- groups (#54) ----------------------------------------------------------


async def _group(conn, name="family", **columns):
    names = ["name"] + list(columns)
    placeholders = ", ".join(f"${i}" for i in range(1, len(names) + 1))
    return await conn.fetchval(
        f"INSERT INTO groups ({', '.join(names)}) VALUES ({placeholders}) RETURNING id",
        name, *columns.values(),
    )


async def test_a_grant_cannot_name_a_group_that_does_not_exist(conn):
    """The point of the foreign key. Before it, `group_name` was free text, so
    a typo was silently a group of zero people that nobody could see was
    broken."""
    upstream_id = await _upstream(conn)
    async with _rejects(conn, asyncpg.ForeignKeyViolationError):
        await conn.execute(
            """INSERT INTO grants (subject_type, group_name, upstream_id, tool_scope)
               VALUES ('group', 'famly', $1, 'all')""",
            upstream_id,
        )


async def test_deleting_a_group_takes_its_grants_with_it(conn):
    """A grant naming a group that no longer exists is a grant nobody can
    reason about — so the cascade is the schema's answer, not a handler's."""
    upstream_id = await _upstream(conn)
    group_id = await _group(conn)
    await conn.execute(
        """INSERT INTO grants (subject_type, group_name, upstream_id, tool_scope)
           VALUES ('group', 'family', $1, 'all')""",
        upstream_id,
    )
    await conn.execute("DELETE FROM groups WHERE id = $1", group_id)
    assert await conn.fetchval("SELECT count(*) FROM grants") == 0


async def test_renaming_a_group_carries_its_grants(conn):
    """Access follows the name rather than breaking on it — which is why the
    key is the name and not a second `group_id` column on grants."""
    upstream_id = await _upstream(conn)
    group_id = await _group(conn)
    await conn.execute(
        """INSERT INTO grants (subject_type, group_name, upstream_id, tool_scope)
           VALUES ('group', 'family', $1, 'all')""",
        upstream_id,
    )
    await conn.execute("UPDATE groups SET name = 'household' WHERE id = $1", group_id)
    assert await conn.fetchval("SELECT group_name FROM grants") == "household"


async def test_group_names_are_unique_case_insensitively(conn):
    """'Family' and 'family' as two groups is a support call waiting to
    happen: an admin grants one and adds members to the other."""
    await _group(conn, "family")
    async with _rejects(conn, asyncpg.UniqueViolationError):
        await _group(conn, "Family")


async def test_a_group_name_cannot_be_blank(conn):
    for bad in ("", "   "):
        async with _rejects(conn):
            await _group(conn, bad)


async def test_a_principal_can_only_be_in_a_group_once(conn):
    group_id = await _group(conn)
    principal_id = await _principal(conn)
    await conn.execute(
        "INSERT INTO group_members (group_id, principal_id) VALUES ($1, $2)",
        group_id, principal_id,
    )
    async with _rejects(conn, asyncpg.UniqueViolationError):
        await conn.execute(
            "INSERT INTO group_members (group_id, principal_id) VALUES ($1, $2)",
            group_id, principal_id,
        )


async def test_deleting_a_principal_removes_their_memberships(conn):
    """Otherwise a recycled UUID would inherit someone else's access."""
    group_id = await _group(conn)
    principal_id = await _principal(conn)
    await conn.execute(
        "INSERT INTO group_members (group_id, principal_id) VALUES ($1, $2)",
        group_id, principal_id,
    )
    await conn.execute("DELETE FROM principals WHERE id = $1", principal_id)
    assert await conn.fetchval("SELECT count(*) FROM group_members") == 0


async def test_two_groups_cannot_claim_the_same_idp_group(conn):
    """One claim maps to one group, or the mapping isn't a mapping (#17)."""
    await _group(conn, "staff", idp_claim="torii-staff")
    async with _rejects(conn, asyncpg.UniqueViolationError):
        await _group(conn, "employees", idp_claim="torii-staff")


async def test_several_groups_may_be_local_only(conn):
    """A NULL claim is 'no IdP can satisfy this', and that has to be the
    common case — so NULLs must not collide under the unique index."""
    await _group(conn, "family")
    await _group(conn, "bots")
    assert await conn.fetchval("SELECT count(*) FROM groups WHERE idp_claim IS NULL") == 2


async def test_list_scope_requires_a_non_empty_list(conn):
    """'list' with no tools would silently mean "nothing" — or worse, be read
    as "everything" by a buggy resolver."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'list')""",
            principal_id,
            upstream_id,
        )


async def test_all_scope_rejects_a_tool_list(conn):
    """Two sources of truth for one grant's tools is a bug waiting to be
    resolved the wrong way."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope, tools)
               VALUES ('principal', $1, $2, 'all', $3)""",
            principal_id,
            upstream_id,
            ["get_doc"],
        )


async def test_scoping_a_client_stamps_narrowed_at_the_schema(conn):
    """#60: narrowing is driven by access_mode, so a client that carries a
    scoped grant MUST read 'narrowed' — enforced by the grants_narrow_credential
    trigger, not by whichever handler happened to write the grant. Inserting the
    grant directly (no handler in the loop) still flips the mode."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    client_id = await _client(conn, principal_id)
    assert await conn.fetchval(
        "SELECT access_mode FROM oauth_clients WHERE client_id = $1", client_id
    ) == "inherit"

    await conn.execute(
        """INSERT INTO grants (subject_type, client_id, upstream_id, tool_scope)
           VALUES ('client', $1, $2, 'all')""",
        client_id,
        upstream_id,
    )
    assert await conn.fetchval(
        "SELECT access_mode FROM oauth_clients WHERE client_id = $1", client_id
    ) == "narrowed"


async def test_scoping_a_key_stamps_narrowed_at_the_schema(conn):
    """Same invariant for static keys — one trigger, both credential kinds."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    key_id = await conn.fetchval(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash)
           VALUES ($1, 'k', 'tor_k', 'h1') RETURNING id""",
        principal_id,
    )
    assert await conn.fetchval(
        "SELECT access_mode FROM api_keys WHERE id = $1", key_id
    ) == "inherit"

    await conn.execute(
        """INSERT INTO grants (subject_type, api_key_id, upstream_id, tool_scope)
           VALUES ('key', $1, $2, 'all')""",
        key_id,
        upstream_id,
    )
    assert await conn.fetchval(
        "SELECT access_mode FROM api_keys WHERE id = $1", key_id
    ) == "narrowed"


async def test_removing_a_scoped_grant_does_not_widen_the_credential(conn):
    """The trigger is one-directional on purpose: scoping narrows, but deleting
    the last grant leaves the credential 'narrowed' (reaching nothing), never
    silently back at the owner's full baseline."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    client_id = await _client(conn, principal_id)
    grant_id = await conn.fetchval(
        """INSERT INTO grants (subject_type, client_id, upstream_id, tool_scope)
           VALUES ('client', $1, $2, 'all') RETURNING id""",
        client_id,
        upstream_id,
    )
    await conn.execute("DELETE FROM grants WHERE id = $1", grant_id)
    assert await conn.fetchval(
        "SELECT access_mode FROM oauth_clients WHERE client_id = $1", client_id
    ) == "narrowed"


async def test_one_grant_row_per_subject_and_upstream(conn):
    """The editor edits a grant in place; two rows for the same pair would
    make the effective scope depend on row order."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    await conn.execute(
        """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
           VALUES ('principal', $1, $2, 'all')""",
        principal_id,
        upstream_id,
    )
    with pytest.raises(asyncpg.UniqueViolationError):
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope, tools)
               VALUES ('principal', $1, $2, 'list', $3)""",
            principal_id,
            upstream_id,
            ["get_doc"],
        )


async def test_principal_and_client_grants_coexist(conn):
    """Per-client narrowing (Q8): the baseline and the narrowed set are
    separate rows on the same upstream."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    client_id = await _client(conn, principal_id)
    await conn.execute(
        """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
           VALUES ('principal', $1, $2, 'all')""",
        principal_id,
        upstream_id,
    )
    await conn.execute(
        """INSERT INTO grants (subject_type, client_id, upstream_id, tool_scope, tools)
           VALUES ('client', $1, $2, 'list', $3)""",
        client_id,
        upstream_id,
        ["search_knowledge"],
    )
    assert await conn.fetchval(
        "SELECT count(*) FROM grants WHERE upstream_id = $1", upstream_id
    ) == 2


async def test_deleting_an_upstream_removes_its_grants(conn):
    """A removed upstream must not leave grants that a re-added upstream of
    the same name would silently inherit."""
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    await conn.execute(
        """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
           VALUES ('principal', $1, $2, 'all')""",
        principal_id,
        upstream_id,
    )
    await conn.execute("DELETE FROM upstreams WHERE id = $1", upstream_id)
    assert await conn.fetchval("SELECT count(*) FROM grants") == 0


async def test_deleting_a_principal_removes_its_grants_and_credentials(conn):
    principal_id = await _principal(conn)
    upstream_id = await _upstream(conn)
    await conn.execute(
        """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
           VALUES ('principal', $1, $2, 'all')""",
        principal_id,
        upstream_id,
    )
    await conn.execute(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash)
           VALUES ($1, 'laptop', 'tor_abc123', 'hash-1')""",
        principal_id,
    )
    await conn.execute("DELETE FROM principals WHERE id = $1", principal_id)
    assert await conn.fetchval("SELECT count(*) FROM grants") == 0
    assert await conn.fetchval("SELECT count(*) FROM api_keys") == 0


# --- credentials -----------------------------------------------------------


async def test_api_key_hashes_are_unique(conn):
    principal_id = await _principal(conn)
    await conn.execute(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash)
           VALUES ($1, 'one', 'tor_aaa', 'same-hash')""",
        principal_id,
    )
    with pytest.raises(asyncpg.UniqueViolationError):
        await conn.execute(
            """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash)
               VALUES ($1, 'two', 'tor_bbb', 'same-hash')""",
            principal_id,
        )


async def test_api_key_rotation_chain(conn):
    principal_id = await _principal(conn)
    old = await conn.fetchval(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash)
           VALUES ($1, 'laptop', 'tor_old', 'hash-old') RETURNING id""",
        principal_id,
    )
    new = await conn.fetchval(
        """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash, rotated_from)
           VALUES ($1, 'laptop', 'tor_new', 'hash-new', $2) RETURNING id""",
        principal_id,
        old,
    )
    assert await conn.fetchval(
        "SELECT rotated_from FROM api_keys WHERE id = $1", new
    ) == old


async def test_token_kinds_are_constrained(conn):
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at)
               VALUES ('id_token', 'h', $1, $2, now() + interval '1 hour')""",
            principal_id,
            client_id,
        )


async def test_refresh_rotation_chain(conn):
    """Rotation must be reconstructible: a replayed refresh token has to be
    traceable to the token that replaced it."""
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    first = await conn.fetchval(
        """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at)
           VALUES ('refresh', 'r1', $1, $2, now() + interval '30 days') RETURNING id""",
        principal_id,
        client_id,
    )
    second = await conn.fetchval(
        """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at, rotated_from)
           VALUES ('refresh', 'r2', $1, $2, now() + interval '30 days', $3) RETURNING id""",
        principal_id,
        client_id,
        first,
    )
    assert await conn.fetchval(
        "SELECT rotated_from FROM tokens WHERE id = $1", second
    ) == first


async def test_revoking_a_client_revokes_its_tokens(conn):
    """Per-client revocation has to be immediate and total (FR2)."""
    principal_id = await _principal(conn)
    client_id = await _client(conn, principal_id)
    await conn.execute(
        """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at)
           VALUES ('access', 'a1', $1, $2, now() + interval '1 hour')""",
        principal_id,
        client_id,
    )
    await conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
    assert await conn.fetchval("SELECT count(*) FROM tokens") == 0


async def test_dcr_client_can_exist_unbound(conn):
    """Registration alone grants nothing (FR2), so a just-registered client
    has no principal — and no grant can name it as a subject's baseline."""
    client_id = await conn.fetchval(
        """INSERT INTO oauth_clients (client_id, client_name)
           VALUES ('cl_fresh', 'claude.ai') RETURNING client_id"""
    )
    assert await conn.fetchval(
        "SELECT principal_id FROM oauth_clients WHERE client_id = $1", client_id
    ) is None


# --- audit -----------------------------------------------------------------


async def test_audit_outcomes_are_constrained(conn):
    with pytest.raises(asyncpg.CheckViolationError):
        await conn.execute(
            """INSERT INTO audit_calls (method, outcome) VALUES ('tools/call', 'maybe')"""
        )


async def test_denied_calls_are_auditable_without_a_principal(conn):
    """An unauthenticated or unknown caller still has to leave a record."""
    await conn.execute(
        """INSERT INTO audit_calls (method, outcome, principal_label, upstream_name, tool_name)
           VALUES ('tools/call', 'denied', 'unknown', 'acme-admin', 'run_sql')"""
    )
    row = await conn.fetchrow("SELECT * FROM audit_calls WHERE outcome = 'denied'")
    assert row["principal_id"] is None
    assert row["principal_label"] == "unknown"


async def test_audit_history_survives_deleting_the_principal(conn):
    """Deleting a principal must not erase what it did — the labels are
    denormalized precisely so accountability outlives the row."""
    principal_id = await _principal(conn, "departed")
    upstream_id = await _upstream(conn, "brain")
    await conn.execute(
        """INSERT INTO audit_calls
               (principal_id, principal_label, upstream_id, upstream_name,
                tool_name, method, outcome, latency_ms)
           VALUES ($1, 'departed', $2, 'brain', 'search_thoughts', 'tools/call', 'ok', 42)""",
        principal_id,
        upstream_id,
    )
    await conn.execute("DELETE FROM principals WHERE id = $1", principal_id)

    row = await conn.fetchrow("SELECT * FROM audit_calls")
    assert row is not None
    assert row["principal_id"] is None
    assert row["principal_label"] == "departed"
    assert row["tool_name"] == "search_thoughts"


async def test_auth_events_record_failures_with_no_principal(conn):
    await conn.execute(
        """INSERT INTO audit_auth_events (event, outcome, principal_label, ip, detail)
           VALUES ('login_failure', 'failure', 'nosuchuser', '203.0.113.7', $1)""",
        '{"reason": "unknown_principal"}',
    )
    row = await conn.fetchrow("SELECT * FROM audit_auth_events")
    assert row["principal_id"] is None
    assert str(row["ip"]) == "203.0.113.7"
    assert row["detail"] == '{"reason": "unknown_principal"}'

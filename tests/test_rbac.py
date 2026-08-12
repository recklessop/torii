"""The authorization spec.

These tests are the contract for `torii.rbac`. If a behaviour here and the
PRD disagree, one of them is a bug — nothing else in the codebase is allowed
to have an opinion about access.

Negative cases outnumber positive ones on purpose: the failure that matters
is "saw something it shouldn't", not "couldn't see something it should".
"""

import ast
import inspect

import pytest

from torii import rbac
from torii.rbac import (
    ALL_TOOLS,
    CLIENT_NARROWED,
    CLIENT_UNKNOWN,
    NO_GRANT,
    OK,
    PRINCIPAL_DISABLED,
    PRINCIPAL_UNKNOWN,
    TOOL_NOT_GRANTED,
    UPSTREAM_DISABLED,
    Caller,
    Context,
    GrantRow,
    listed,
)

PRINCIPAL = "11111111-1111-1111-1111-111111111111"


def human(client_id=None, groups=()):
    return Caller(principal_id=PRINCIPAL, username="alice", client_id=client_id, groups=groups)


def service():
    return Caller(principal_id=PRINCIPAL, username="acme-prod", kind="service")


def grant(subject_type, upstream, scope="all", tools=(), enabled=True):
    return GrantRow(subject_type, upstream, scope, tuple(tools), enabled)


def context(*rows, **kwargs):
    kwargs.setdefault("client_valid", None)
    # A credential that carries grants of its own is NARROWED — the invariant
    # the write paths now enforce (#60): scoping a key/connector sets its mode.
    # Default the resolver-test context to match unless a test overrides the
    # mode to probe it directly.
    if "credential_access_mode" not in kwargs and any(
        r.subject_type in ("client", "key") for r in rows
    ):
        kwargs["credential_access_mode"] = rbac.NARROWED
    return Context(rows=tuple(rows), **kwargs)


# --- default deny ----------------------------------------------------------


def test_no_grants_means_no_tools():
    assert rbac.resolve(context(), human()) == {}


def test_no_grants_denies_every_call():
    decision = rbac.decide(context(), human(), "knowledge", "search_knowledge")
    assert not decision.allowed
    assert decision.reason == NO_GRANT


def test_grant_on_one_upstream_does_not_leak_to_another():
    ctx = context(grant("principal", "knowledge"))
    assert not rbac.decide(ctx, human(), "acme-admin", "run_sql")
    assert "acme-admin" not in rbac.resolve(ctx, human())


def test_ungranted_upstream_is_invisible_not_merely_denied():
    """FR1: `tools/list` shows nothing from an ungranted server, so a client
    can't even learn the server exists."""
    ctx = context(grant("principal", "knowledge"))
    assert set(rbac.resolve(ctx, human())) == {"knowledge"}


# --- principal grants ------------------------------------------------------


def test_all_scope_allows_any_tool():
    ctx = context(grant("principal", "brain"))
    assert rbac.decide(ctx, human(), "brain", "capture_thought").reason == OK
    assert rbac.decide(ctx, human(), "brain", "anything_at_all").allowed


def test_list_scope_allows_only_listed_tools():
    ctx = context(grant("principal", "wk", "list", ["search_knowledge", "get_doc"]))
    assert rbac.decide(ctx, human(), "wk", "search_knowledge").allowed
    denied = rbac.decide(ctx, human(), "wk", "list_docs")
    assert not denied.allowed
    assert denied.reason == TOOL_NOT_GRANTED


def test_tool_names_are_matched_exactly():
    ctx = context(grant("principal", "wk", "list", ["get_doc"]))
    for near_miss in ("get_docs", "get_do", "Get_Doc", "get_doc ", " get_doc"):
        assert not rbac.decide(ctx, human(), "wk", near_miss).allowed


def test_two_list_grants_on_one_upstream_union():
    ctx = context(
        grant("principal", "wk", "list", ["get_doc"]),
        grant("group", "wk", "list", ["search_knowledge"], enabled=True),
    )
    assert rbac.resolve(ctx, human(groups=("staff",)))["wk"] == listed(
        "get_doc", "search_knowledge"
    )


def test_all_beats_list_when_unioned():
    ctx = context(
        grant("principal", "wk", "list", ["get_doc"]),
        grant("group", "wk", "all"),
    )
    assert rbac.resolve(ctx, human(groups=("staff",)))["wk"] == ALL_TOOLS


def test_empty_list_grant_grants_nothing():
    """The schema forbids writing one; if a row ever appears anyway it must
    not be read as "everything"."""
    ctx = context(grant("principal", "wk", "list", []))
    assert rbac.resolve(ctx, human()) == {}
    assert not rbac.decide(ctx, human(), "wk", "get_doc").allowed


# --- group grants (Q9/Q25) -------------------------------------------------
#
# Membership is resolved by the LOADER, not here: a `group` row only reaches
# this context if the caller is in that group (locally, or by a mapped IdP
# claim). What these pin is the resolver's half of the contract — group rows
# join the baseline, and never become a ceiling. `test_rbac_db.py` pins the
# membership half.


def test_group_grant_applies_to_a_member():
    ctx = context(grant("group", "wk", "list", ["get_doc"]))
    assert rbac.decide(ctx, human(), "wk", "get_doc").allowed


def test_group_grants_are_not_wildcards():
    """No rows, no access — there is no implicit "everyone" group."""
    ctx = context()
    assert rbac.resolve(ctx, human(groups=())) == {}


def test_a_group_widens_the_baseline_but_never_the_ceiling():
    """A group grant is unioned into the baseline and then cut by whatever
    the credential is limited to. It must not smuggle access past a narrowed
    connector."""
    ctx = context(
        grant("group", "wk", "all"),
        grant("group", "brain", "all"),
        grant("client", "wk", "list", ["get_doc"]),
        client_valid=True,
    )
    assert rbac.resolve(ctx, human(client_id="cl_phone")) == {"wk": listed("get_doc")}
    assert rbac.decide(ctx, human(client_id="cl_phone"), "brain", "capture").reason == (
        rbac.CLIENT_NARROWED
    )


# --- per-client narrowing (Q8) --------------------------------------------


def test_client_with_no_grants_inherits_the_baseline():
    ctx = context(grant("principal", "wk"), client_valid=True)
    assert rbac.decide(ctx, human(client_id="cl_desktop"), "wk", "get_doc").allowed


def test_client_grant_narrows_below_the_baseline():
    """The headline case: the principal may reach everything on wk, but the
    phone may only search."""
    ctx = context(
        grant("principal", "wk"),
        grant("client", "wk", "list", ["search_knowledge"]),
        client_valid=True,
    )
    phone = human(client_id="cl_phone")
    assert rbac.decide(ctx, phone, "wk", "search_knowledge").allowed
    narrowed = rbac.decide(ctx, phone, "wk", "get_doc")
    assert not narrowed.allowed
    assert narrowed.reason == CLIENT_NARROWED


def test_client_grants_are_a_ceiling_across_every_upstream():
    """A narrowed client must NOT keep full access to upstreams its own
    grants don't mention — otherwise narrowing the phone onto one server
    leaves every other server open on the phone (the stolen-phone case)."""
    ctx = context(
        grant("principal", "wk"),
        grant("principal", "brain"),
        grant("client", "wk", "list", ["search_knowledge"]),
        client_valid=True,
    )
    phone = human(client_id="cl_phone")
    assert set(rbac.resolve(ctx, phone)) == {"wk"}
    assert rbac.decide(ctx, phone, "brain", "capture_thought").reason == CLIENT_NARROWED


def test_client_grant_cannot_exceed_the_baseline():
    """Narrowing only narrows. A client grant for an upstream the principal
    can't reach grants nothing — no privilege escalation via DCR."""
    ctx = context(
        grant("principal", "wk", "list", ["get_doc"]),
        grant("client", "wk", "all"),
        grant("client", "acme-admin", "all"),
        client_valid=True,
    )
    phone = human(client_id="cl_phone")
    assert rbac.resolve(ctx, phone) == {"wk": listed("get_doc")}
    assert not rbac.decide(ctx, phone, "acme-admin", "run_sql").allowed
    assert not rbac.decide(ctx, phone, "wk", "search_knowledge").allowed


def test_client_and_baseline_lists_intersect():
    ctx = context(
        grant("principal", "wk", "list", ["get_doc", "search_knowledge"]),
        grant("client", "wk", "list", ["search_knowledge", "list_docs"]),
        client_valid=True,
    )
    phone = human(client_id="cl_phone")
    assert rbac.resolve(ctx, phone) == {"wk": listed("search_knowledge")}


def test_disjoint_client_grant_leaves_nothing_visible():
    ctx = context(
        grant("principal", "wk", "list", ["get_doc"]),
        grant("client", "wk", "list", ["run_sql"]),
        client_valid=True,
    )
    phone = human(client_id="cl_phone")
    assert rbac.resolve(ctx, phone) == {}
    assert rbac.decide(ctx, phone, "wk", "get_doc").reason == CLIENT_NARROWED


def test_static_key_callers_are_not_narrowed():
    """A key has no OAuth client, so client grants belonging to some other
    client must not apply to it — in either direction."""
    ctx = context(grant("principal", "wk"), client_valid=None)
    assert rbac.decide(ctx, service(), "wk", "anything").allowed


# --- revocation and disablement -------------------------------------------


def test_unknown_principal_is_denied():
    ctx = Context(principal_exists=False)
    assert rbac.decide(ctx, human(), "wk", "get_doc").reason == PRINCIPAL_UNKNOWN
    assert rbac.resolve(ctx, human()) == {}


def test_disabled_principal_is_denied_despite_grants():
    ctx = context(grant("principal", "wk"), principal_disabled=True)
    assert rbac.decide(ctx, human(), "wk", "get_doc").reason == PRINCIPAL_DISABLED
    assert rbac.resolve(ctx, human()) == {}


def test_revoked_client_denies_rather_than_falling_back():
    """The dangerous failure mode: if an unknown or disabled client fell back
    to the principal's baseline, revoking a client would GRANT it full
    access."""
    ctx = context(grant("principal", "wk"), client_valid=False)
    phone = human(client_id="cl_phone")
    assert rbac.decide(ctx, phone, "wk", "get_doc").reason == CLIENT_UNKNOWN
    assert rbac.resolve(ctx, phone) == {}


def test_disabled_upstream_is_denied_and_invisible():
    ctx = context(
        grant("principal", "wk", enabled=False),
        disabled_upstreams=frozenset({"wk"}),
    )
    assert rbac.decide(ctx, human(), "wk", "get_doc").reason == UPSTREAM_DISABLED
    assert rbac.resolve(ctx, human()) == {}


def test_disabled_upstream_is_distinguishable_from_never_granted():
    """Operator action vs access-control event — the audit shouldn't conflate
    them."""
    ctx = context(
        grant("principal", "wk", enabled=False),
        disabled_upstreams=frozenset({"wk"}),
    )
    assert rbac.decide(ctx, human(), "wk", "x").reason == UPSTREAM_DISABLED
    assert rbac.decide(ctx, human(), "never-granted", "x").reason == NO_GRANT


# --- no admin bypass -------------------------------------------------------


def test_no_admin_bypass_exists_in_the_resolver():
    """FR3 is a structural claim, not a behavioural one: there is no code
    path that grants access on the basis of being an admin.

    Assert on the module's own syntax tree — identifiers, attributes and
    string literals, with docstrings excluded so the prose above may discuss
    the rule it enforces — so that adding such a path has to fail a test.
    """
    tree = ast.parse(inspect.getsource(rbac))

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value not in docstrings:
                names.add(node.value)

    offenders = sorted(n for n in names if "admin" in n.lower())
    assert offenders == [], f"admin-aware code on the authorization path: {offenders}"


def test_caller_has_no_admin_field():
    """A resolver that can't see an admin flag can't branch on one."""
    assert not any("admin" in f for f in Caller.__dataclass_fields__)


# --- ToolSet algebra -------------------------------------------------------


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (ALL_TOOLS, ALL_TOOLS, ALL_TOOLS),
        (ALL_TOOLS, listed("a"), ALL_TOOLS),
        (listed("a"), listed("b"), listed("a", "b")),
    ],
)
def test_toolset_union(left, right, expected):
    assert left.union(right) == expected


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (ALL_TOOLS, ALL_TOOLS, ALL_TOOLS),
        (ALL_TOOLS, listed("a"), listed("a")),
        (listed("a"), ALL_TOOLS, listed("a")),
        (listed("a", "b"), listed("b", "c"), listed("b")),
        (listed("a"), listed("b"), rbac.NO_TOOLS),
    ],
)
def test_toolset_intersect(left, right, expected):
    assert left.intersect(right) == expected


def test_decision_is_falsey_when_denied():
    assert not rbac.Decision(False, NO_GRANT)
    assert rbac.Decision(True, OK)


# --- access_mode: narrowing that survives re-registration (Q14) ------------


def test_narrowed_client_with_no_grants_reaches_nothing():
    """The hole this closes: DCR mints a new client_id on every registration,
    so a re-added connector had no client grants and therefore inherited the
    principal's whole baseline. A client marked `narrowed` is bounded by its
    own grants even when it has none."""
    ctx = context(
        grant("principal", "wk"),
        grant("principal", "brain"),
        client_valid=True,
        credential_access_mode=rbac.NARROWED,
    )
    phone = human(client_id="cl_phone")
    assert rbac.resolve(ctx, phone) == {}
    assert rbac.decide(ctx, phone, "wk", "get_doc").reason == CLIENT_NARROWED
    assert rbac.decide(ctx, phone, "brain", "capture_thought").reason == CLIENT_NARROWED


def test_inheriting_client_with_no_grants_still_inherits():
    """The default has to keep working — a normal connector shouldn't need
    setup before it can see anything."""
    ctx = context(grant("principal", "wk"), client_valid=True,
                  credential_access_mode=rbac.INHERIT)
    assert rbac.decide(ctx, human(client_id="cl_desktop"), "wk", "get_doc").allowed


def test_narrowed_client_with_grants_intersects_as_before():
    ctx = context(
        grant("principal", "wk"),
        grant("client", "wk", "list", ["search_knowledge"]),
        client_valid=True,
        credential_access_mode=rbac.NARROWED,
    )
    phone = human(client_id="cl_phone")
    assert rbac.resolve(ctx, phone) == {"wk": listed("search_knowledge")}
    assert not rbac.decide(ctx, phone, "wk", "get_doc").allowed


def test_client_grants_do_not_narrow_when_the_mode_is_inherit():
    """#60: narrowing is driven by the mode, not by the presence of grant rows.

    Inferring it from bool(ceiling) was the bug — a disabled upstream drops that
    upstream's rows and could empty the ceiling, silently widening a scoped
    credential back to its owner's baseline. So an `inherit` connector reaches
    the full baseline even if stray grant rows exist; the write paths
    (create_grant, self-service scoping) and migration 0014 guarantee a credential
    that IS scoped carries `narrowed`, so this 'inherit + rows' state is only ever
    stale data, and the resolver treats the mode as the single source of truth."""
    ctx = context(
        grant("principal", "wk"),
        grant("principal", "brain"),
        grant("client", "wk", "list", ["search_knowledge"]),
        client_valid=True,
        credential_access_mode=rbac.INHERIT,
    )
    phone = human(client_id="cl_phone")
    # Not narrowed: inherits the full baseline; the stray grant row is ignored.
    assert set(rbac.resolve(ctx, phone)) == {"wk", "brain"}
    assert rbac.decide(ctx, phone, "brain", "capture_thought").allowed
    assert rbac.decide(ctx, phone, "wk", "get_doc").allowed


def test_narrowing_a_client_can_never_exceed_the_baseline():
    """Self-service narrowing is safe because the resolver intersects: a user
    limiting their own connector can only reduce their reach, never extend it."""
    ctx = context(
        grant("principal", "wk", "list", ["get_doc"]),
        grant("client", "wk", "all"),
        grant("client", "acme-admin", "all"),
        client_valid=True,
        credential_access_mode=rbac.NARROWED,
    )
    phone = human(client_id="cl_phone")
    assert rbac.resolve(ctx, phone) == {"wk": listed("get_doc")}
    assert not rbac.decide(ctx, phone, "acme-admin", "run_sql").allowed


def test_access_mode_is_irrelevant_to_static_key_callers():
    ctx = context(grant("principal", "wk"), client_valid=None,
                  credential_access_mode=None)
    assert rbac.decide(ctx, service(), "wk", "anything").allowed

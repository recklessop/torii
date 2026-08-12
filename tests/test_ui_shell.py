"""The app-shell behaviours from #25.

These are structural: the JS itself isn't executed here, so what's asserted is
that each affordance is present, wired to a stable id, persisted, and free of
external assets. Behaviour is verified by hand — but "the markup is missing
entirely" is exactly the regression that a template edit causes and nobody
notices.
"""

import os
import pathlib
import re

import httpx
import pytest

from torii import app as app_module
from torii import cache, config, credentials, db

BASE = pathlib.Path(__file__).resolve().parent.parent / "torii" / "templates" / "base.html"
SHELL = BASE.read_text()

OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit("/", 1)[0]
    + "/torii_oauth",
)


@pytest.fixture
async def client(oauth_database, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL", oauth_database)
    db._pool = None
    cache._client = None
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """TRUNCATE audit_calls, audit_auth_events, tokens, grants, api_keys,
                        auth_identities, oauth_clients, upstreams, principals
                        RESTART IDENTITY CASCADE"""
        )
    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="https://torii.test") as http:
        yield http
    await db.close()
    await cache.close()


async def _signed_in(client):
    import pyotp
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            """INSERT INTO principals (kind, username, is_admin, totp_required)
               VALUES ('human', 'admin', TRUE, TRUE) RETURNING id"""
        )
        secret = credentials.generate_totp_secret()
        await conn.execute(
            """INSERT INTO auth_identities
                   (principal_id, backend, password_hash, totp_secret, totp_enrolled_at)
               VALUES ($1, 'local', $2, $3, now())""",
            principal_id, credentials.hash_password("a-long-real-password"), secret,
        )
    await client.post("/ui/login", data={
        "username": "admin", "password": "a-long-real-password",
        "totp_code": pyotp.TOTP(secret).now(),
    }, follow_redirects=False)
    return principal_id


# --- collapsible sections --------------------------------------------------


def test_sections_are_collapsible_with_stable_ids():
    """Renaming a section id silently loses every user's saved state, so the
    ids are asserted rather than left to chance."""
    assert 'data-section="my-access"' in SHELL
    assert 'data-section="administration"' in SHELL
    assert "data-toggle-section" in SHELL
    assert "torii:section:" in SHELL.replace("'torii:' + key", "torii:") or "section:" in SHELL


def test_section_state_is_persisted():
    assert "localStorage" in SHELL
    assert "classList.toggle('closed')" in SHELL


# --- rail ------------------------------------------------------------------


def test_the_sidebar_collapses_to_a_rail_and_remembers_it():
    assert 'id="rail-toggle"' in SHELL
    assert ".shell.railed" in SHELL
    assert "remember('rail'" in SHELL


def test_the_rail_hides_labels_but_keeps_icons():
    assert ".shell.railed .nav a span:not(.ico)" in SHELL
    assert ".shell.railed .nav-label" in SHELL


# --- drawer ----------------------------------------------------------------


def test_narrow_screens_get_a_real_drawer():
    assert 'id="drawer-open"' in SHELL
    assert ".shell.drawer-open .sidebar { transform: translateX(0); }" in SHELL
    # A drawer that only closes one way feels broken, so all three exist.
    assert "Escape" in SHELL
    assert "closest('.sidebar a')" in SHELL
    assert "if (!event.target.closest('.sidebar')) closeDrawer();" in SHELL


def test_the_rail_is_disabled_inside_the_drawer():
    """An icon rail inside a 280px drawer is friction with no benefit."""
    media = SHELL[SHELL.index("@media (max-width: 820px)"):]
    assert ".railtoggle { display: none; }" in media


# --- theme -----------------------------------------------------------------


def test_theme_can_be_forced_either_way():
    assert ':root[data-theme="light"]' in SHELL
    assert ':root[data-theme="dark"]' in SHELL
    # The OS rule must not beat an explicit dark choice.
    assert ':root:not([data-theme="dark"])' in SHELL


def test_theme_is_applied_before_paint():
    """Otherwise you see a flash of the wrong theme on every page load."""
    head = SHELL[: SHELL.index("</head>")]
    assert "torii:theme" in head
    assert "data-theme" in head


def test_theme_choice_includes_returning_to_the_os_preference():
    assert 'data-theme-choice="system"' in SHELL
    assert "removeAttribute('data-theme')" in SHELL


# --- no external assets ----------------------------------------------------


def test_the_shell_pulls_in_nothing_external():
    """No bundler, and a strict no-external-requests posture."""
    for construct in ("<link", "src=\"http", "cdn.", "unpkg", "googleapis", "@import"):
        assert construct not in SHELL, construct


# --- it actually renders ---------------------------------------------------


async def test_a_signed_in_page_carries_the_whole_shell(client):
    await _signed_in(client)
    page = await client.get("/ui")
    assert page.status_code == 200
    for marker in ('id="shell"', 'id="rail-toggle"', 'id="drawer-open"',
                   'id="themepick"', 'data-section="my-access"',
                   'data-section="administration"'):
        assert marker in page.text, marker


async def test_the_login_page_has_no_shell_furniture(client):
    """You shouldn't get navigation before you're authenticated."""
    page = await client.get("/ui/login")
    for marker in ('id="rail-toggle"', 'id="drawer-open"', 'class="sidebar"'):
        assert marker not in page.text, marker


# --- passkeys (Q25) --------------------------------------------------------

LOGIN = (pathlib.Path(__file__).resolve().parent.parent
         / "torii" / "templates" / "login.html").read_text()
ACCOUNT = (pathlib.Path(__file__).resolve().parent.parent
           / "torii" / "templates" / "pages" / "account.html").read_text()


def test_the_login_page_offers_a_passkey_and_feature_detects():
    """The button must self-hide off HTTPS — plain-HTTP LAN access keeps the
    password form and nothing else."""
    for marker in ('id="passkey-signin"', 'id="passkey-button"',
                   "window.isSecureContext", "window.PublicKeyCredential",
                   "navigator.credentials.get"):
        assert marker in LOGIN, marker


def test_the_account_page_offers_passkey_enrollment():
    for marker in ('id="passkey-enroll"', 'id="passkey-add"',
                   "navigator.credentials.create"):
        assert marker in ACCOUNT, marker


def test_the_passkey_pages_pull_in_nothing_external():
    for construct in ("src=\"http", "cdn.", "unpkg", "googleapis", "@import"):
        assert construct not in LOGIN, construct
        assert construct not in ACCOUNT, construct


# --- breathing room (Q22) --------------------------------------------------


def test_a_spacing_scale_exists_rather_than_per_rule_numbers():
    """Consistency is what makes a layout feel deliberate; ad-hoc pixel values
    per rule are what made it feel cramped."""
    assert "--s1:" in SHELL and "--s4:" in SHELL and "--s6:" in SHELL
    assert "padding: var(--s4) var(--s5)" in SHELL


def test_content_is_wide_enough_for_the_tables_it_holds():
    """A 1080px column beside a 250px sidebar wastes half a wide monitor while
    the audit table scrolls sideways."""
    assert "max-width: 1400px" in SHELL


def test_prose_stays_readable_even_though_tables_are_wide():
    """Full-width paragraphs at 1400px are unreadable — the measure is capped
    separately from the table width."""
    assert "max-width: 78ch" in SHELL


def test_dense_rows_of_controls_use_cards_not_table_cells():
    """Connectors and services carry a rename box, a scope editor and buttons
    per row. Tables are for scanning, not for forms."""
    assert ".entity {" in SHELL
    assert ".entity-actions" in SHELL

    connectors = (pathlib.Path(__file__).resolve().parent.parent
                  / "torii" / "templates" / "pages" / "connectors.html").read_text()
    services = (pathlib.Path(__file__).resolve().parent.parent
                / "torii" / "templates" / "pages" / "services.html").read_text()
    for page, name in ((connectors, "connectors"), (services, "services")):
        assert 'class="entity"' in page, name
        # The old shape: a <form> inside a <td>.
        assert "<td>\n          <form" not in page, name

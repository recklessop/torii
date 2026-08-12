"""The credential and admin UI.

Not template snapshot tests — those go stale on cosmetic edits. These pin
behaviour: gates that must not be bypassable (admin-only pages, mid-gate
sessions), operator actions that must audit, and end-to-end flows (mint a
key, sign in, hit /mcp with it).
"""

import os

import httpx
import pyotp
import pytest

from conftest import add_endpoint, make_upstream
from torii import app as app_module
from torii import cache, config, credentials, db, rbac

USERNAME = "admin"
PASSWORD = "an-admin-password-really-long"


OAUTH_DB_URL = os.environ.get(
    "TORII_OAUTH_TEST_DATABASE_URL",
    (os.environ.get("TORII_TEST_DATABASE_URL", "") or config.DATABASE_URL).rsplit(
        "/", 1
    )[0]
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
                        auth_identities, oauth_clients, upstreams, group_members,
                        groups, principals
                        RESTART IDENTITY CASCADE"""
        )
        keys = [k async for k in cache.client().scan_iter("torii:*")]
        if keys:
            await cache.client().delete(*keys)

    transport = httpx.ASGITransport(app=app_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="https://torii.test") as http:
        yield http

    await db.close()
    await cache.close()


async def _seed_admin(is_admin=True, temp=False, totp=True):
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            """INSERT INTO principals (kind, username, is_admin, totp_required)
               VALUES ('human', $1, $2, TRUE) RETURNING id""",
            USERNAME,
            is_admin,
        )
        secret = credentials.generate_totp_secret() if totp else None
        await conn.execute(
            """INSERT INTO auth_identities
                   (principal_id, backend, password_hash, password_is_temp, totp_secret,
                    totp_enrolled_at)
               VALUES ($1, 'local', $2, $3, $4::text,
                       CASE WHEN $4::text IS NULL THEN NULL ELSE now() END)""",
            principal_id,
            credentials.hash_password(PASSWORD),
            temp,
            secret,
        )
    return str(principal_id), secret


async def _sign_in(client, secret):
    return await client.post(
        "/ui/login",
        data={
            "username": USERNAME,
            "password": PASSWORD,
            "totp_code": pyotp.TOTP(secret).now() if secret else "",
        },
        follow_redirects=False,
    )


# --- login gates -----------------------------------------------------------


async def test_ui_root_redirects_to_login_when_signed_out(client):
    response = await client.get("/ui", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/ui/login"


async def test_correct_credentials_sign_in(client):
    _, secret = await _seed_admin()
    response = await _sign_in(client, secret)
    assert response.status_code == 302
    assert response.headers["location"] == "/ui"
    self_page = await client.get("/ui", follow_redirects=False)
    assert self_page.status_code == 200
    assert USERNAME in self_page.text


async def test_ui_login_rejects_bad_credentials_and_audits(client):
    await _seed_admin()
    response = await client.post(
        "/ui/login",
        data={"username": USERNAME, "password": "wrong", "totp_code": "000000"},
    )
    assert response.status_code == 401
    pool = await db.pool()
    async with pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'login_failure'"
        )
    assert count == 1


async def test_ui_login_missing_totp_is_refused(client):
    _, _ = await _seed_admin()
    response = await client.post(
        "/ui/login",
        data={"username": USERNAME, "password": PASSWORD},
    )
    assert response.status_code == 401


async def test_logout_clears_the_session(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    await client.get("/ui/logout", follow_redirects=False)
    self_page = await client.get("/ui", follow_redirects=False)
    assert self_page.status_code == 302


# --- admin gate ------------------------------------------------------------


async def test_non_admin_cannot_reach_admin_pages(client):
    _, secret = await _seed_admin(is_admin=False)
    await _sign_in(client, secret)
    response = await client.get("/ui/admin/principals", follow_redirects=False)
    assert response.status_code == 403


async def test_admin_can_reach_admin_pages(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    response = await client.get("/ui/admin/principals", follow_redirects=False)
    assert response.status_code == 200
    assert "Principals" in response.text


# --- self-service: keys -----------------------------------------------------


async def test_self_can_mint_rotate_and_revoke_a_key(client):
    principal_id, secret = await _seed_admin()
    await _sign_in(client, secret)

    minted = await client.post("/ui/keys", data={"name": "laptop"})
    assert minted.status_code == 200
    assert "tor_" in minted.text
    key_secret = _extract_secret(minted.text)
    assert key_secret.startswith("tor_")

    # The key authenticates against /mcp before rotation.
    response = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key_secret}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 200

    pool = await db.pool()
    async with pool.acquire() as conn:
        key_id = await conn.fetchval(
            "SELECT id FROM api_keys WHERE principal_id = $1 AND revoked_at IS NULL",
            principal_id,
        )

    rotated = await client.post(f"/ui/keys/{key_id}/rotate")
    assert rotated.status_code == 200
    new_secret = _extract_secret(rotated.text)
    assert new_secret != key_secret

    # Old key is dead; new key works.
    dead = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key_secret}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert dead.status_code == 401
    live = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {new_secret}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert live.status_code == 200


async def test_self_cannot_rotate_someone_elses_key(client):
    """Ownership check is enforced regardless of who is asking."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        other = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'other') RETURNING id"
        )
        other_key = await credentials.mint_api_key(conn, other, "not-yours")

    await _sign_in(client, secret)
    response = await client.post(f"/ui/keys/{other_key.id}/rotate")
    assert response.status_code == 403

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT revoked_at FROM api_keys WHERE id = $1", other_key.id
        ) is None


def _extract_secret(html: str) -> str:
    marker = '<div class="secret">'
    start = html.index(marker) + len(marker)
    return html[start : html.index("</div>", start)].strip()


# --- admin: principals -----------------------------------------------------


async def test_admin_creates_a_human_with_a_temp_password(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    response = await client.post(
        "/ui/admin/principals", data={"username": "wife", "kind": "human"}
    )
    assert response.status_code == 200
    assert "Temp password" in response.text

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT p.id, p.is_admin, i.password_is_temp
                 FROM principals p JOIN auth_identities i
                   ON i.principal_id = p.id AND i.backend = 'local'
                WHERE p.username = 'wife'"""
        )
    assert row["is_admin"] is False
    assert row["password_is_temp"] is True


async def test_admin_creates_a_service_principal_and_mints_a_key(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    await client.post("/ui/admin/principals", data={"username": "acme", "kind": "service"})
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "SELECT id FROM principals WHERE username = 'acme'"
        )
    minted = await client.post(
        f"/ui/admin/principals/{principal_id}/issue_key",
        data={"name": "acme-prod"},
    )
    assert minted.status_code == 200
    assert "tor_" in minted.text


async def test_disabling_a_principal_revokes_every_token(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    pool = await db.pool()
    async with pool.acquire() as conn:
        target_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'target') RETURNING id"
        )
        client_id = await conn.fetchval(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id)
               VALUES ('cl_target', 'claude.ai', $1) RETURNING client_id""",
            target_id,
        )
        await credentials.issue_token_pair(conn, target_id, client_id)

    response = await client.post(
        f"/ui/admin/principals/{target_id}/toggle_disabled",
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM tokens WHERE principal_id = $1 AND revoked_at IS NULL",
            target_id,
        ) == 0


# --- admin: upstreams and grants ------------------------------------------


async def test_admin_creates_upstream_grants_and_deletes_them(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    await client.post(
        "/ui/admin/upstreams",
        data={"name": "knowledge", "url": "http://localhost:9000/mcp"},
    )
    await client.post(
        "/ui/admin/principals", data={"username": "reader", "kind": "human"}
    )
    await client.post(
        "/ui/admin/grants",
        data={
            "subject_type": "principal",
            "subject_ref": "reader",
            "upstream_name": "knowledge",
            "tool_scope": "list",
            "tools": "search_knowledge, get_doc",
        },
    )

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT g.id, g.tools FROM grants g
                 JOIN principals p ON p.id = g.principal_id
                WHERE p.username = 'reader'"""
        )
    assert set(row["tools"]) == {"search_knowledge", "get_doc"}

    await client.post(f"/ui/admin/grants/{row['id']}/delete", follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM grants") == 0


async def _create_upstream_id(client, name="wk"):
    await client.post(
        "/ui/admin/upstreams",
        data={"name": name, "url": "http://localhost:9000/mcp"},
    )
    pool = await db.pool()
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT id FROM upstreams WHERE name = $1", name)


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "data:text/html,<script>1</script>",
                                 "vbscript:msgbox(1)", "  javascript:alert(1)  ", "not a url"])
async def test_update_upstream_rejects_a_dangerous_public_url(client, bad):
    """public_url is rendered as an <a href> on the crawlable directory page,
    so a javascript:/data: scheme must be refused on save (#77) — not stored
    and rendered later as a one-click XSS."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    upstream_id = await _create_upstream_id(client)

    response = await client.post(
        f"/ui/admin/upstreams/{upstream_id}",
        data={"name": "wk", "public_url": bad},
        follow_redirects=False,
    )
    assert response.status_code == 200  # re-rendered detail page, not a redirect
    assert "must be an http" in response.text

    pool = await db.pool()
    async with pool.acquire() as conn:
        stored = await conn.fetchval("SELECT public_url FROM upstreams WHERE id = $1", upstream_id)
    assert stored is None, f"dangerous public_url was stored: {stored!r}"


async def test_update_upstream_accepts_an_https_public_url(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    upstream_id = await _create_upstream_id(client)

    response = await client.post(
        f"/ui/admin/upstreams/{upstream_id}",
        data={"name": "wk", "public_url": "https://example.com/wk"},
        follow_redirects=False,
    )
    assert response.status_code == 303  # saved -> redirect back to detail
    pool = await db.pool()
    async with pool.acquire() as conn:
        stored = await conn.fetchval("SELECT public_url FROM upstreams WHERE id = $1", upstream_id)
    assert stored == "https://example.com/wk"


# --- SSRF validation on upstream URLs (#62) --------------------------------
#
# Torii is a single-operator LAN gateway: upstreams ARE private-IP/loopback
# LAN services, so the DEFAULT guard rejects only link-local / cloud-metadata /
# unspecified targets and non-http(s) schemes; private + loopback + public are
# accepted. Strict mode (TORII_STRICT_UPSTREAM_URLS=1) additionally blocks
# private + loopback + reserved, for the future untrusted-upstream direction.


@pytest.mark.parametrize("bad", [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata (link-local)
    "http://169.254.10.10/x",                      # link-local generally
    "http://0.0.0.0:8080/mcp",                     # unspecified
    "file:///etc/passwd",                          # non-http scheme
    "ftp://example.com/x",                         # non-http scheme
])
async def test_registering_an_upstream_refuses_an_ssrf_url(client, bad):
    """A metadata/link-local target or a non-http scheme is refused at the
    write site by default — re-rendered form, not a 500, and no row proxy.py
    could later dereference."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    response = await client.post(
        "/ui/admin/upstreams",
        data={"name": "wk", "url": bad},
        follow_redirects=False,
    )
    assert response.status_code == 200  # re-rendered list page, not a redirect

    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM upstreams") == 0
        assert await conn.fetchval("SELECT count(*) FROM upstream_endpoints") == 0


@pytest.mark.parametrize("good", [
    "http://127.0.0.1/mcp",        # private LAN IP — a legitimate upstream
    "http://10.0.0.5:8300/mcp",      # private LAN IP
    "http://127.0.0.1:9/mcp",        # loopback — knowledge's shape
    "https://mcp.example.com/mcp",   # public host
])
async def test_registering_an_upstream_accepts_a_lan_or_public_target(client, good):
    """The whole model is LAN upstreams registered by private IP; the default
    guard must let them through."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    response = await client.post(
        "/ui/admin/upstreams",
        data={"name": "wk", "url": good},
        follow_redirects=False,
    )
    assert response.status_code == 303  # created -> redirect

    pool = await db.pool()
    async with pool.acquire() as conn:
        url = await conn.fetchval(
            """SELECT e.url FROM upstream_endpoints e
                 JOIN upstreams u ON u.id = e.upstream_id WHERE u.name = 'wk'"""
        )
    assert url == good


async def test_adding_an_endpoint_refuses_a_metadata_url(client):
    """The replica add path is the second write site and must guard the same
    way — otherwise the check is one URL swap from meaningless."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:8300/mcp")
    await _sign_in(client, secret)

    response = await client.post(
        f"/ui/admin/upstreams/{upstream_id}/endpoints",
        data={"url": "http://169.254.169.254/latest/meta-data/"},
        follow_redirects=False,
    )
    assert response.status_code == 200  # re-rendered detail page, not a redirect
    assert "may not point at" in response.text

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        ) == 1  # only the original, no metadata-IP replica added


def test_validate_upstream_url_default_posture():
    """The helper in isolation, default (LAN) posture."""
    from torii.upstreams import UpstreamUrlError, validate_upstream_url

    ok = validate_upstream_url("  https://mcp.example.com:8500/mcp  ")
    assert ok == "https://mcp.example.com:8500/mcp"  # trimmed, returned as-is

    # Accepted by default: private, loopback, public.
    for good in (
        "http://127.0.0.1/mcp", "http://10.0.0.5:8300/mcp",
        "http://172.16.9.9/mcp", "http://127.0.0.1:9/mcp",
        "http://[::1]:8080/mcp", "http://localhost:9000/mcp",
        "https://example.com/mcp",
    ):
        assert validate_upstream_url(good, strict=False) == good

    # Rejected in every mode: bad scheme, missing host, link-local/metadata,
    # unspecified.
    for bad in (
        "", "not a url", "ftp://example.com", "file:///etc/passwd",
        "http://169.254.169.254/", "http://169.254.10.10/",
        "http://[fe80::1]/", "http://0.0.0.0/", "http://[::]/",
        "http://[::ffff:169.254.169.254]/",  # IPv4-mapped metadata IP
    ):
        with pytest.raises(UpstreamUrlError):
            validate_upstream_url(bad, strict=False)


def test_validate_upstream_url_strict_posture():
    """Strict mode additionally blocks private + loopback + reserved."""
    from torii.upstreams import UpstreamUrlError, validate_upstream_url

    # Public still fine.
    assert validate_upstream_url("https://example.com/mcp", strict=True)

    for bad in (
        "http://127.0.0.1/mcp", "http://10.0.0.5:8300/mcp",
        "http://172.16.9.9/mcp", "http://127.0.0.1:9/mcp",
        "http://[::1]/", "http://[fc00::1]/", "http://localhost:9000/mcp",
        # And everything the default already blocks:
        "http://169.254.169.254/", "http://0.0.0.0/",
    ):
        with pytest.raises(UpstreamUrlError):
            validate_upstream_url(bad, strict=True)


async def test_strict_mode_refuses_a_private_upstream_at_the_write_site(client, monkeypatch):
    """With TORII_STRICT_UPSTREAM_URLS on, a private-IP upstream is refused at
    the UI write site — the marketplace-direction posture."""
    from torii import config as _config
    monkeypatch.setattr(_config, "STRICT_UPSTREAM_URLS", True)

    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    response = await client.post(
        "/ui/admin/upstreams",
        data={"name": "wk", "url": "http://127.0.0.1/mcp"},
        follow_redirects=False,
    )
    assert response.status_code == 200  # refused, re-rendered
    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM upstreams") == 0


async def test_grant_editor_refuses_bad_combinations(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    await client.post(
        "/ui/admin/upstreams",
        data={"name": "wk", "url": "http://localhost:9000/mcp"},
    )
    await client.post(
        "/ui/admin/principals", data={"username": "user", "kind": "human"}
    )

    # 'list' scope with no tools is invalid; the UI must not create the row.
    response = await client.post(
        "/ui/admin/grants",
        data={
            "subject_type": "principal",
            "subject_ref": "user",
            "upstream_name": "wk",
            "tool_scope": "list",
            "tools": "",
        },
    )
    assert response.status_code == 200
    assert "at least one tool" in response.text

    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM grants") == 0


async def test_toggle_upstream_flips_enabled(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    await client.post(
        "/ui/admin/upstreams",
        data={"name": "wk", "url": "http://localhost:9000/mcp"},
    )
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await conn.fetchval("SELECT id FROM upstreams WHERE name = 'wk'")
        assert await conn.fetchval("SELECT enabled FROM upstreams WHERE id = $1", upstream_id)

    await client.post(f"/ui/admin/upstreams/{upstream_id}/toggle", follow_redirects=False)
    async with pool.acquire() as conn:
        assert not await conn.fetchval("SELECT enabled FROM upstreams WHERE id = $1", upstream_id)


# --- config export ---------------------------------------------------------


async def test_config_export_carries_the_actionable_state(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    await client.post(
        "/ui/admin/upstreams",
        data={"name": "wk", "url": "http://localhost:9000/mcp"},
    )
    await client.post(
        "/ui/admin/principals", data={"username": "reader", "kind": "human"}
    )
    await client.post(
        "/ui/admin/grants",
        data={
            "subject_type": "principal",
            "subject_ref": "reader",
            "upstream_name": "wk",
            "tool_scope": "all",
        },
    )

    response = await client.get("/ui/admin/config.json")
    assert response.status_code == 200
    body = response.json()
    assert body["issuer"] == config.PUBLIC_BASE_URL
    assert any(p["username"] == "reader" for p in body["principals"])
    assert any(u["name"] == "wk" for u in body["upstreams"])
    assert any(
        g["upstream_name"] == "wk" and g["principal_username"] == "reader"
        for g in body["grants"]
    )


# --- connector URLs (both endpoint shapes) ---------------------------------


async def test_connectors_page_lists_a_direct_url_per_granted_server(client):
    """The page has to tell you the per-server URL, not just the aggregate —
    that's the whole point of the per-server endpoints existing."""
    principal_id, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "knowledge", display_name="Work Knowledge")
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, upstream_id,
        )
    await _sign_in(client, secret)

    response = await client.get("/ui/connectors")
    assert response.status_code == 200
    assert f"{config.PUBLIC_BASE_URL}/knowledge/mcp" in response.text
    assert f"{config.PUBLIC_BASE_URL}/mcp" in response.text
    # The friendly name shows, with the slug alongside it.
    assert "Work Knowledge" in response.text


async def test_connectors_page_advertises_nothing_you_cannot_use(client):
    """With no grants, don't hand out a per-server URL that would answer with
    an empty tool list — say so instead."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        await make_upstream(conn, "ungranted")
    await _sign_in(client, secret)

    response = await client.get("/ui/connectors")
    assert "no grants yet" in response.text.lower()
    assert f"{config.PUBLIC_BASE_URL}/ungranted/mcp" not in response.text


# --- overview stat tiles ---------------------------------------------------


async def test_overview_counts_real_tools_behind_an_all_grant(client):
    """An `all` grant carries no tool names, so counting only explicit ones
    reported "0+" for a caller who could reach everything. Ask the upstream."""
    import threading
    from wsgiref.simple_server import make_server

    def app(environ, start_response):
        import json as _json
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = _json.loads(environ["wsgi.input"].read(length) or b"{}")
        payload = {"jsonrpc": "2.0", "id": body.get("id"), "result": {"tools": [
            {"name": "web_search"}, {"name": "web_fetch"}, {"name": "third"},
        ]}}
        encoded = _json.dumps(payload).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(encoded)))])
        return [encoded]

    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    try:
        principal_id, secret = await _seed_admin()
        pool = await db.pool()
        async with pool.acquire() as conn:
            upstream_id = await make_upstream(conn, "finder", f"http://{host}:{port}/mcp")
            await conn.execute(
                """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
                   VALUES ('principal', $1, $2, 'all')""",
                principal_id, upstream_id,
            )
        await _sign_in(client, secret)

        response = await client.get("/ui")
        assert response.status_code == 200
        # Three real tools, not "0+".
        assert ">3</div>" in response.text
        assert "0+" not in response.text
    finally:
        server.shutdown()
        server.server_close()


async def test_overview_stat_tiles_render_values_not_dict_methods(client):
    """Regression: `counts.keys` in Jinja resolves to the dict METHOD, so the
    page rendered "<built-in method keys of dict object …>" where the key
    count belonged. Dict keys named after dict methods are a trap."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    response = await client.get("/ui")
    assert response.status_code == 200
    assert "built-in method" not in response.text
    assert "dict object at" not in response.text
    # With nothing granted and nothing minted, every tile is a real zero.
    assert response.text.count(">0</div>") >= 3


async def test_my_tools_shows_the_full_url_with_a_copy_control(client):
    """A bare `/knowledge/mcp` isn't pasteable — the page has to show the
    absolute URL, and offer to copy it."""
    principal_id, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "knowledge")
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, upstream_id,
        )
    await _sign_in(client, secret)

    response = await client.get("/ui/grants")
    assert response.status_code == 200
    full = f"{config.PUBLIC_BASE_URL}/knowledge/mcp"
    assert full in response.text
    # The copy affordance carries the same absolute URL, not a relative path.
    assert f'data-copy="{full}"' in response.text


async def test_copy_control_works_without_a_secure_context(client):
    """navigator.clipboard needs HTTPS; the dev stack is plain-HTTP LAN, so
    the handler must carry a fallback or the button silently does nothing."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    response = await client.get("/ui/grants")
    assert "isSecureContext" in response.text
    assert "execCommand" in response.text
    # And no external assets — the whole point of inlining it.
    assert "cdn" not in response.text.lower()


# --- self-provisioned connector credentials (Q14) --------------------------


async def test_user_can_create_a_connector_credential(client):
    """The GUI path: a confidential client with a STABLE id, so its limits
    survive removing and re-adding the connector in Claude."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    response = await client.post("/ui/connectors/provision", data={
        "client_name": "claude.ai", "label": "phone", "narrowed": "1",
    })
    assert response.status_code == 200
    assert "tor_cl_" in response.text

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT client_id, client_secret_hash, token_endpoint_auth_method,
                      registered_via, label, access_mode, principal_id
                 FROM oauth_clients WHERE label = 'phone'"""
        )
    # Confidential (a stolen refresh token can't be redeemed alone), bound to
    # its owner immediately, and stored hashed.
    assert row["token_endpoint_auth_method"] == "client_secret_post"
    assert row["client_secret_hash"] and "tor_cl_" not in row["client_secret_hash"]
    assert row["registered_via"] == "manual"
    assert row["access_mode"] == "narrowed"
    assert row["principal_id"] is not None


async def test_provisioned_secret_is_shown_once_and_stored_hashed(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    response = await client.post("/ui/connectors/provision", data={"client_name": "cli"})
    shown = _extract_secret(response.text)

    pool = await db.pool()
    async with pool.acquire() as conn:
        stored = await conn.fetchval("SELECT client_secret_hash FROM oauth_clients LIMIT 1")
    assert stored == credentials.hash_secret(shown)
    # A later page load must not repeat it.
    assert shown not in (await client.get("/ui/connectors")).text


async def test_user_can_limit_and_unlimit_their_own_connector(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval("SELECT id FROM principals WHERE username = $1", USERNAME)
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id)
               VALUES ('cl_mine', 'claude.ai', $1)""",
            principal_id,
        )
    await _sign_in(client, secret)

    await client.post("/ui/connectors/cl_mine/access_mode", follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = 'cl_mine'"
        ) == "narrowed"
        assert await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'client_access_mode_changed'"
        ) == 1

    await client.post("/ui/connectors/cl_mine/access_mode", follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = 'cl_mine'"
        ) == "inherit"


async def test_cannot_change_access_mode_of_someone_elses_connector(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        other = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'other') RETURNING id"
        )
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id)
               VALUES ('cl_theirs', 'claude.ai', $1)""",
            other,
        )
    await _sign_in(client, secret)

    response = await client.post("/ui/connectors/cl_theirs/access_mode")
    assert response.status_code == 403
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = 'cl_theirs'"
        ) == "inherit"


async def test_new_connectors_can_be_made_to_start_limited(client):
    """The principal-level default, and the reason it exists: a re-added
    connector is a new client, so 'start limited' is what makes narrowing
    durable."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    await client.post("/ui/account/narrow_new_clients", follow_redirects=False)
    pool = await db.pool()
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT narrow_new_clients FROM principals WHERE username = $1", USERNAME
        ) is True


# --- scoped keys from the UI (Q15) -----------------------------------------


async def _grant_server(principal_id, name):
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, name)
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, upstream_id,
        )
        return upstream_id


async def test_user_can_mint_a_key_scoped_to_one_server(client):
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _grant_server(principal_id, "finder")
    await _sign_in(client, secret)

    response = await client.post("/ui/keys", data={"name": "wk-only", "scope_to": "knowledge"})
    assert response.status_code == 200
    key_secret = _extract_secret(response.text)

    # The key reaches only that server, on EITHER endpoint shape — the URL was
    # never the boundary.
    for path in ("/mcp", "/knowledge/mcp", "/finder/mcp"):
        listed = await client.post(
            path, headers={"Authorization": f"Bearer {key_secret}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert listed.status_code == 200

    denied = await client.post(
        "/finder/mcp", headers={"Authorization": f"Bearer {key_secret}"},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "web_search", "arguments": {}}},
    )
    assert denied.json()["error"]["data"]["reason"] == "client_narrowed"


async def test_an_unscoped_key_still_inherits_everything(client):
    """Default unchanged: ticking nothing keeps the old behaviour."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _sign_in(client, secret)

    response = await client.post("/ui/keys", data={"name": "laptop"})
    key_secret = _extract_secret(response.text)

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT access_mode FROM api_keys WHERE key_hash = $1",
            credentials.hash_secret(key_secret),
        )
    assert row["access_mode"] == "inherit"


async def test_the_scope_picker_offers_only_reachable_servers(client):
    """Offering a server the owner can't reach would promise access that the
    resolver would then refuse — a confusing lie."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await make_upstream(conn, "not-mine")
    await _sign_in(client, secret)

    page = await client.get("/ui/keys")
    assert 'value="knowledge"' in page.text
    assert 'value="not-mine"' not in page.text


async def test_a_scope_for_an_unreachable_server_is_ignored(client):
    """Hand-posted form data must not create a grant that outruns the owner."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await make_upstream(conn, "not-mine")
    await _sign_in(client, secret)

    await client.post("/ui/keys", data={"name": "sneaky", "scope_to": "not-mine"})
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT u.name FROM grants g JOIN upstreams u ON u.id = g.upstream_id
                WHERE g.subject_type = 'key'"""
        )
    assert [r["name"] for r in rows] == []


# --- grant editor: discover tools, and say who plainly ----------------------


async def test_admin_can_discover_a_servers_tools(client):
    """Nobody remembers tool names six months later, so the editor asks the
    server. Descriptions and MCP's read-only hints come through too."""
    import threading
    from wsgiref.simple_server import make_server

    def app(environ, start_response):
        import json as _json
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = _json.loads(environ["wsgi.input"].read(length) or b"{}")
        payload = {"jsonrpc": "2.0", "id": body.get("id"), "result": {"tools": [
            {"name": "search_knowledge", "description": "Search the notes.",
             "annotations": {"readOnlyHint": True}},
            {"name": "run_sql", "description": "Execute SQL.",
             "annotations": {"readOnlyHint": False, "destructiveHint": True}},
        ]}}
        encoded = _json.dumps(payload).encode()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(encoded)))])
        return [encoded]

    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    try:
        _, secret = await _seed_admin()
        pool = await db.pool()
        async with pool.acquire() as conn:
            upstream_id = await make_upstream(conn, "wk", f"http://{host}:{port}/mcp")
        await _sign_in(client, secret)

        response = await client.get(f"/ui/admin/upstreams/{upstream_id}/tools.json")
        assert response.status_code == 200
        body = response.json()
        assert body["server"] == "wk"
        names = {t["name"]: t for t in body["tools"]}
        assert names["search_knowledge"]["description"] == "Search the notes."
        assert names["search_knowledge"]["read_only"] is True
        assert names["run_sql"]["destructive"] is True
        # Lookup by slug works too, which is what the form uses.
        assert (await client.get("/ui/admin/upstreams/wk/tools.json")).status_code == 200
    finally:
        server.shutdown()
        server.server_close()


async def test_tool_discovery_reports_an_unreachable_server(client):
    """An error the form can show, rather than an empty list that reads as
    'this server has no tools'."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "down", "http://127.0.0.1:1/mcp")
    await _sign_in(client, secret)
    response = await client.get(f"/ui/admin/upstreams/{upstream_id}/tools.json")
    assert response.status_code == 502
    assert "error" in response.json()


async def test_tool_discovery_is_admin_only(client):
    _, secret = await _seed_admin(is_admin=False)
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:1/mcp")
    await _sign_in(client, secret)
    assert (await client.get(f"/ui/admin/upstreams/{upstream_id}/tools.json")).status_code == 403


async def test_grant_form_accepts_one_combined_who_value(client):
    """The form asks "who gets it?" with real entities, so the operator never
    has to know what a "subject type" is."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'reader') RETURNING id"
        )
        await make_upstream(conn, "wk")
        key_id = await conn.fetchval(
            """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash, access_mode)
               VALUES ($1, 'scoped', 'tor_k', 'h1', 'narrowed') RETURNING id""",
            principal_id,
        )
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id, label)
               VALUES ('cl_phone', 'claude.ai', $1, 'phone')""",
            principal_id,
        )
        await conn.execute("INSERT INTO groups (name) VALUES ('family')")
    await _sign_in(client, secret)

    # A person, ticked tools.
    await client.post("/ui/admin/grants", data={
        "who": "principal:reader", "upstream_name": "wk",
        "tool_scope": "list", "tools": "get_doc",
    }, follow_redirects=False)
    # A connector limit.
    await client.post("/ui/admin/grants", data={
        "who": "client:cl_phone", "upstream_name": "wk", "tool_scope": "all",
    }, follow_redirects=False)
    # A key limit.
    await client.post("/ui/admin/grants", data={
        "who": f"key:{key_id}", "upstream_name": "wk", "tool_scope": "all",
    }, follow_redirects=False)
    # A group — the same dropdown, since a group is now a real entity.
    await client.post("/ui/admin/grants", data={
        "who": "group:family", "upstream_name": "wk", "tool_scope": "all",
    }, follow_redirects=False)

    async with pool.acquire() as conn:
        kinds = [r["subject_type"] for r in await conn.fetch(
            "SELECT subject_type FROM grants ORDER BY subject_type"
        )]
    assert kinds == ["client", "group", "key", "principal"]


async def test_scoping_a_credential_in_the_editor_marks_it_narrowed(client):
    """#60 write-path: narrowing is driven by access_mode, not by the presence of
    grant rows, so the admin editor must set the mode when it scopes a client or
    key. Both start at the 'inherit' default and must flip to 'narrowed'."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'reader') RETURNING id"
        )
        await make_upstream(conn, "wk")
        key_id = await conn.fetchval(
            """INSERT INTO api_keys (principal_id, name, key_prefix, key_hash)
               VALUES ($1, 'k', 'tor_k', 'h1') RETURNING id""",
            principal_id,
        )
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id, label)
               VALUES ('cl_phone', 'claude.ai', $1, 'phone')""",
            principal_id,
        )
        # Both default to 'inherit' — nothing has scoped them yet.
        assert await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = 'cl_phone'"
        ) == "inherit"
        assert await conn.fetchval(
            "SELECT access_mode FROM api_keys WHERE id = $1", key_id
        ) == "inherit"
    await _sign_in(client, secret)

    await client.post("/ui/admin/grants", data={
        "who": "client:cl_phone", "upstream_name": "wk", "tool_scope": "all",
    }, follow_redirects=False)
    await client.post("/ui/admin/grants", data={
        "who": f"key:{key_id}", "upstream_name": "wk", "tool_scope": "all",
    }, follow_redirects=False)

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = 'cl_phone'"
        ) == "narrowed"
        assert await conn.fetchval(
            "SELECT access_mode FROM api_keys WHERE id = $1", key_id
        ) == "narrowed"


async def test_grant_form_says_who_plainly_in_the_listing(client):
    """The listing labels the kind in words rather than as "subject_type"."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'reader') RETURNING id"
        )
        upstream_id = await make_upstream(conn, "wk")
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, upstream_id,
        )
    await _sign_in(client, secret)

    page = await client.get("/ui/admin/grants")
    assert "Who gets it?" in page.text
    assert ">person<" in page.text
    assert "subject_type" not in page.text.replace('name="subject_type"', "")


# --- admin: groups (#54) ---------------------------------------------------


async def test_non_admin_cannot_reach_the_groups_page(client):
    _, secret = await _seed_admin(is_admin=False)
    await _sign_in(client, secret)
    assert (await client.get("/ui/admin/groups")).status_code == 403
    assert (await client.post("/ui/admin/groups", data={"name": "sneaky"})).status_code == 403


async def test_admin_creates_a_group_adds_a_member_and_grants_to_it(client):
    """End to end, the way an operator does it: make a group, put someone in
    it, grant it a server — and the member's effective access changes without
    them signing in again."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        member_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'wife') RETURNING id"
        )
        await make_upstream(conn, "notebook")
    await _sign_in(client, secret)

    created = await client.post(
        "/ui/admin/groups",
        data={"name": "family", "description": "the household"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    group_id = created.headers["location"].rsplit("/", 1)[-1]

    await client.post(f"/ui/admin/groups/{group_id}/members",
                      data={"principal_id": str(member_id)}, follow_redirects=False)
    detail = await client.get(f"/ui/admin/groups/{group_id}")
    assert detail.status_code == 200
    assert "wife" in detail.text
    assert "family" in (await client.get("/ui/admin/groups")).text

    await client.post("/ui/admin/grants", data={
        "who": "group:family", "upstream_name": "notebook",
        "tool_scope": "list", "tools": "list_notes",
    }, follow_redirects=False)

    caller = rbac.Caller(principal_id=str(member_id), username="wife")
    async with pool.acquire() as conn:
        assert await rbac.effective_grants(conn, caller) == {
            "notebook": rbac.listed("list_notes")
        }

    # …and removing them denies on the next call, with no re-authentication.
    await client.post(f"/ui/admin/groups/{group_id}/members/{member_id}/delete",
                      follow_redirects=False)
    async with pool.acquire() as conn:
        assert await rbac.effective_grants(conn, caller) == {}
        events = [r["event"] for r in await conn.fetch(
            "SELECT event FROM audit_auth_events ORDER BY id"
        )]
    assert "group_created" in events
    assert "group_member_added" in events
    assert "group_member_removed" in events


async def test_granting_to_an_unknown_group_says_so(client):
    """The foreign key would refuse it anyway; the page must answer in a
    sentence rather than with a constraint dump."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        await make_upstream(conn, "wk")
    await _sign_in(client, secret)

    response = await client.post("/ui/admin/grants", data={
        "who": "group:famly", "upstream_name": "wk", "tool_scope": "all",
    }, follow_redirects=False)
    assert response.status_code == 200
    assert "No group named" in response.text
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM grants") == 0


async def test_deleting_a_group_removes_its_grants(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk")
        group_id = await conn.fetchval(
            "INSERT INTO groups (name) VALUES ('family') RETURNING id"
        )
        await conn.execute(
            """INSERT INTO grants (subject_type, group_name, upstream_id, tool_scope)
               VALUES ('group', 'family', $1, 'all')""",
            upstream_id,
        )
    await _sign_in(client, secret)

    await client.post(f"/ui/admin/groups/{group_id}/delete", follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM groups") == 0
        assert await conn.fetchval("SELECT count(*) FROM grants") == 0


async def test_a_duplicate_group_name_is_refused_politely(client):
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    await client.post("/ui/admin/groups", data={"name": "family"}, follow_redirects=False)
    # Case-insensitively duplicate — 'Family' and 'family' as two groups is a
    # support call waiting to happen.
    response = await client.post("/ui/admin/groups", data={"name": "Family"},
                                 follow_redirects=False)
    assert response.status_code == 200
    assert "already exists" in response.text


async def test_membership_is_editable_from_the_principal_page(client):
    """The natural place an operator looks. Same helper, same audit events."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        member_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'kid') RETURNING id"
        )
        group_id = await conn.fetchval(
            "INSERT INTO groups (name) VALUES ('family') RETURNING id"
        )
    await _sign_in(client, secret)

    await client.post(f"/ui/admin/principals/{member_id}/groups",
                      data={"group_id": str(group_id)}, follow_redirects=False)
    page = await client.get(f"/ui/admin/principals/{member_id}")
    assert "family" in page.text
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM group_members") == 1

    await client.post(f"/ui/admin/principals/{member_id}/groups/{group_id}/delete",
                      follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM group_members") == 0


async def test_my_tools_says_which_group_an_entitlement_came_from(client):
    """A group grant nobody can trace back to its group is a grant nobody can
    debug."""
    principal_id, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        direct = await make_upstream(conn, "wk")
        shared = await make_upstream(conn, "notebook")
        group_id = await conn.fetchval(
            "INSERT INTO groups (name) VALUES ('family') RETURNING id"
        )
        await conn.execute(
            "INSERT INTO group_members (group_id, principal_id) VALUES ($1, $2)",
            group_id, principal_id,
        )
        await conn.execute(
            """INSERT INTO grants (subject_type, principal_id, upstream_id, tool_scope)
               VALUES ('principal', $1, $2, 'all')""",
            principal_id, direct,
        )
        await conn.execute(
            """INSERT INTO grants (subject_type, group_name, upstream_id, tool_scope)
               VALUES ('group', 'family', $1, 'all')""",
            shared,
        )
    await _sign_in(client, secret)

    page = await client.get("/ui/grants")
    assert "notebook" in page.text
    assert "via group family" in page.text
    assert "direct" in page.text


async def test_user_can_rename_a_connector(client):
    """Without this, three claude.ai rows are indistinguishable."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        principal_id = await conn.fetchval("SELECT id FROM principals WHERE username = $1", USERNAME)
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id,
                                          first_seen_user_agent)
               VALUES ('cl_a', 'claude.ai', $1,
                       'Mozilla/5.0 (iPhone) Safari/604.1')""",
            principal_id,
        )
    await _sign_in(client, secret)

    page = await client.get("/ui/connectors")
    # The device hint disambiguates even before anyone renames it.
    assert "Safari on iPhone" in page.text

    await client.post("/ui/connectors/cl_a/rename", data={"label": "my phone"},
                      follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT label FROM oauth_clients WHERE client_id = 'cl_a'"
        ) == "my phone"
    assert "my phone" in (await client.get("/ui/connectors")).text


async def test_cannot_rename_someone_elses_connector(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        other = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'other') RETURNING id"
        )
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id, label)
               VALUES ('cl_theirs', 'claude.ai', $1, 'their phone')""",
            other,
        )
    await _sign_in(client, secret)

    assert (await client.post("/ui/connectors/cl_theirs/rename",
                              data={"label": "mine now"})).status_code == 403
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT label FROM oauth_clients WHERE client_id = 'cl_theirs'"
        ) == "their phone"


async def test_admin_client_list_shows_owner_and_device(client):
    """The complaint that started this: with several users you can't tell whose
    connector is whose when every row says "claude.ai"."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        wife = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'wife') RETURNING id"
        )
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id,
                                          first_seen_user_agent)
               VALUES ('cl_hers', 'claude.ai', $1,
                       'Mozilla/5.0 (iPhone) Safari/604.1')""",
            wife,
        )
    await _sign_in(client, secret)

    page = await client.get("/ui/admin/clients")
    # The name itself carries the owner, so an admin doesn't have to correlate
    # columns: "wife · claude.ai (Safari on iPhone)".
    assert "wife · claude.ai (Safari on iPhone)" in page.text
    # And an admin can rename it to something human.
    await client.post("/ui/admin/clients/cl_hers/rename", data={"label": "her phone"},
                      follow_redirects=False)
    page = await client.get("/ui/admin/clients")
    assert "wife · her phone" in page.text


async def test_admin_surfaces_name_every_connector_with_its_owner(client):
    """Two users, both with a self-registered claude.ai connector: every admin
    surface has to distinguish them without the admin cross-referencing ids."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        justin_id = await conn.fetchval("SELECT id FROM principals WHERE username = $1", USERNAME)
        wife_id = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'wife') RETURNING id"
        )
        for client_id, owner, agent in [
            ("cl_1", justin_id, "Mozilla/5.0 (Macintosh) Chrome/126.0 Safari/537.36"),
            ("cl_2", wife_id, "Mozilla/5.0 (iPhone) Safari/604.1"),
        ]:
            await conn.execute(
                """INSERT INTO oauth_clients (client_id, client_name, principal_id,
                                              first_seen_user_agent)
                   VALUES ($1, 'claude.ai', $2, $3)""",
                client_id, owner, agent,
            )
        await make_upstream(conn, "wk")
    await _sign_in(client, secret)

    for path in ("/ui/admin/clients", "/ui/admin/grants"):
        page = await client.get(path)
        assert f"{USERNAME} · claude.ai" in page.text, path
        assert "wife · claude.ai" in page.text, path


# --- self-service service identities (Q17) ---------------------------------


async def test_user_can_provision_a_service_identity(client):
    """The gap this closes: creating a service used to be admin-only, so a
    second human couldn't give their own script an identity."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _sign_in(client, secret)

    response = await client.post("/ui/services", data={
        "name": "Inventory Bot", "reaches": "knowledge",
    })
    assert response.status_code == 200
    key_secret = _extract_secret(response.text)
    assert key_secret.startswith("tor_")

    pool = await db.pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT p.username, p.kind, o.username AS owner
                 FROM principals p JOIN principals o ON o.id = p.owner_id
                WHERE p.kind = 'service'"""
        )
    # Namespaced under the owner, so two people can both have an inventory-bot.
    assert row["username"] == f"{USERNAME}/inventory-bot"
    assert row["owner"] == USERNAME

    # The key works, and reaches what was ticked.
    listed = await client.post(
        "/mcp", headers={"Authorization": f"Bearer {key_secret}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert listed.status_code == 200


async def test_a_service_cannot_be_given_more_than_its_owner(client):
    """Hand-posted form data must not manufacture access."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await make_upstream(conn, "not-mine")
    await _sign_in(client, secret)

    await client.post("/ui/services", data={"name": "greedy", "reaches": "not-mine"})
    async with pool.acquire() as conn:
        reaches = await conn.fetch(
            """SELECT u.name FROM grants g
                 JOIN upstreams u ON u.id = g.upstream_id
                 JOIN principals p ON p.id = g.principal_id
                WHERE p.kind = 'service'"""
        )
    assert [r["name"] for r in reaches] == []


async def test_a_service_identity_cannot_log_in(client):
    """It's keys-only by construction — there's no password to attack."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _sign_in(client, secret)
    await client.post("/ui/services", data={"name": "bot", "reaches": "knowledge"})

    attempt = await client.post(
        "/ui/login", data={"username": f"{USERNAME}/bot", "password": PASSWORD},
    )
    assert attempt.status_code == 401


async def test_replacing_all_service_keys_revokes_the_old_one(client):
    """The single-deployment case, now an explicit action rather than a side
    effect of adding a key (#39)."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _sign_in(client, secret)
    first = await client.post("/ui/services", data={"name": "bot", "reaches": "knowledge"})
    old_key = _extract_secret(first.text)

    pool = await db.pool()
    async with pool.acquire() as conn:
        service_id = await conn.fetchval("SELECT id FROM principals WHERE kind = 'service'")
    second = await client.post(f"/ui/services/{service_id}/key", data={"replace": "1"})
    new_key = _extract_secret(second.text)
    assert new_key != old_key

    for key, expected in ((old_key, 401), (new_key, 200)):
        response = await client.post(
            "/mcp", headers={"Authorization": f"Bearer {key}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert response.status_code == expected


async def test_cannot_touch_someone_elses_service(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        other = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'other') RETURNING id"
        )
        theirs = await conn.fetchval(
            """INSERT INTO principals (kind, username, owner_id)
               VALUES ('service', 'other/bot', $1) RETURNING id""",
            other,
        )
    await _sign_in(client, secret)

    assert (await client.post(f"/ui/services/{theirs}/key")).status_code == 403
    assert (await client.post(f"/ui/services/{theirs}/delete")).status_code == 403
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT 1 FROM principals WHERE id = $1", theirs)


async def test_admin_can_promote_a_service_to_independent(client):
    """Promotion needs an admin, because independent means it outlives the
    person who made it."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _sign_in(client, secret)
    await client.post("/ui/services", data={"name": "prod", "reaches": "knowledge"})

    pool = await db.pool()
    async with pool.acquire() as conn:
        service_id = await conn.fetchval("SELECT id FROM principals WHERE kind = 'service'")

    page = await client.get(f"/ui/admin/principals/{service_id}")
    assert "Promote to independent service" in page.text

    await client.post(f"/ui/admin/principals/{service_id}/detach_owner", follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT owner_id FROM principals WHERE id = $1", service_id
        ) is None
        assert await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'service_detached'"
        ) == 1


async def test_keys_and_services_pages_each_explain_when_to_use_the_other(client):
    """They overlap in access terms, so whichever page you land on has to say
    which one you actually want — otherwise the choice is a coin toss."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    keys_page = await client.get("/ui/keys")
    assert "/ui/services" in keys_page.text
    assert "isn't</em> you" in keys_page.text or "service identity" in keys_page.text

    services_page = await client.get("/ui/services")
    assert "/ui/keys" in services_page.text


async def test_a_service_can_hold_several_independently_revocable_keys(client):
    """#39: the same service deployed twice needs one key each, and revoking
    one must not take down the other deployment."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _sign_in(client, secret)
    created = await client.post("/ui/services", data={"name": "bot", "reaches": "knowledge"})
    first_key = _extract_secret(created.text)

    pool = await db.pool()
    async with pool.acquire() as conn:
        service_id = await conn.fetchval("SELECT id FROM principals WHERE kind = 'service'")

    added = await client.post(f"/ui/services/{service_id}/key", data={"name": "pi"})
    second_key = _extract_secret(added.text)
    assert second_key != first_key

    # Both work — adding one no longer revokes the other.
    for key in (first_key, second_key):
        response = await client.post(
            "/mcp", headers={"Authorization": f"Bearer {key}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert response.status_code == 200

    async with pool.acquire() as conn:
        pi_key_id = await conn.fetchval(
            "SELECT id FROM api_keys WHERE principal_id = $1 AND name = 'pi'", service_id
        )
    await client.post(f"/ui/services/{service_id}/key/{pi_key_id}/revoke", follow_redirects=False)

    # The revoked one is dead; the other deployment is untouched.
    dead = await client.post(
        "/mcp", headers={"Authorization": f"Bearer {second_key}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert dead.status_code == 401
    alive = await client.post(
        "/mcp", headers={"Authorization": f"Bearer {first_key}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert alive.status_code == 200


async def test_cannot_revoke_a_key_belonging_to_another_service(client):
    """Owning one service mustn't let you revoke a key of another — even one
    you also own."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _sign_in(client, secret)
    await client.post("/ui/services", data={"name": "alpha", "reaches": "knowledge"})
    await client.post("/ui/services", data={"name": "beta", "reaches": "knowledge"})

    pool = await db.pool()
    async with pool.acquire() as conn:
        alpha = await conn.fetchval("SELECT id FROM principals WHERE username LIKE '%/alpha'")
        beta = await conn.fetchval("SELECT id FROM principals WHERE username LIKE '%/beta'")
        beta_key = await conn.fetchval("SELECT id FROM api_keys WHERE principal_id = $1", beta)

    response = await client.post(f"/ui/services/{alpha}/key/{beta_key}/revoke")
    assert response.status_code == 403
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT revoked_at FROM api_keys WHERE id = $1", beta_key
        ) is None


# --- self-service connector scoping (Q21) ----------------------------------


async def test_user_can_say_what_a_limited_connector_reaches(client):
    """The gap this closes: you could mark a connector limited but had no way
    to grant it anything, so it was stuck reaching nothing unless an admin
    edited it from a different page."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _grant_server(principal_id, "finder")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id, access_mode)
               VALUES ('cl_phone', 'claude.ai', $1, 'narrowed')""",
            principal_id,
        )
    await _sign_in(client, secret)

    await client.post("/ui/connectors/cl_phone/scope",
                      data={"scope_to": "knowledge"}, follow_redirects=False)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT u.name, g.tool_scope FROM grants g
                 JOIN upstreams u ON u.id = g.upstream_id
                WHERE g.subject_type = 'client' AND g.client_id = 'cl_phone'"""
        )
    assert [(r["name"], r["tool_scope"]) for r in rows] == [("knowledge", "all")]

    # And it takes effect: the connector reaches that server and not the other.
    from torii import rbac
    async with pool.acquire() as conn:
        caller = rbac.Caller(principal_id=str(principal_id), client_id="cl_phone")
        assert set(await rbac.effective_grants(conn, caller)) == {"knowledge"}


async def test_scoping_can_pick_individual_tools(client):
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id)
               VALUES ('cl_phone', 'claude.ai', $1)""",
            principal_id,
        )
    await _sign_in(client, secret)

    await client.post("/ui/connectors/cl_phone/scope", data={
        "scope_to": "knowledge", "tools:knowledge": "get_doc",
    }, follow_redirects=False)

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT tool_scope, tools FROM grants WHERE client_id = 'cl_phone'"
        )
        # Setting a scope also marks it limited — picking servers and leaving
        # it inheriting everything is never what anyone meant.
        mode = await conn.fetchval(
            "SELECT access_mode FROM oauth_clients WHERE client_id = 'cl_phone'"
        )
    assert row["tool_scope"] == "list"
    assert list(row["tools"]) == ["get_doc"]
    assert mode == "narrowed"


async def test_scoping_replaces_rather_than_accumulates(client):
    """What the form shows has to be what the resolver sees."""
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    await _grant_server(principal_id, "finder")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id)
               VALUES ('cl_phone', 'claude.ai', $1)""",
            principal_id,
        )
    await _sign_in(client, secret)

    await client.post("/ui/connectors/cl_phone/scope",
                      data={"scope_to": "knowledge"}, follow_redirects=False)
    await client.post("/ui/connectors/cl_phone/scope",
                      data={"scope_to": "finder"}, follow_redirects=False)

    async with pool.acquire() as conn:
        names = [r["name"] for r in await conn.fetch(
            """SELECT u.name FROM grants g JOIN upstreams u ON u.id = g.upstream_id
                WHERE g.client_id = 'cl_phone'"""
        )]
    assert names == ["finder"]


async def test_scoping_cannot_exceed_the_owner(client):
    principal_id, secret = await _seed_admin()
    await _grant_server(principal_id, "knowledge")
    pool = await db.pool()
    async with pool.acquire() as conn:
        await make_upstream(conn, "not-mine")
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id)
               VALUES ('cl_phone', 'claude.ai', $1)""",
            principal_id,
        )
    await _sign_in(client, secret)

    await client.post("/ui/connectors/cl_phone/scope",
                      data={"scope_to": "not-mine"}, follow_redirects=False)
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM grants WHERE client_id = 'cl_phone'"
        ) == 0


async def test_cannot_scope_someone_elses_connector(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        other = await conn.fetchval(
            "INSERT INTO principals (kind, username) VALUES ('human', 'other') RETURNING id"
        )
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id)
               VALUES ('cl_theirs', 'claude.ai', $1)""",
            other,
        )
    await _sign_in(client, secret)
    assert (await client.post("/ui/connectors/cl_theirs/scope",
                              data={"scope_to": "x"})).status_code == 403


async def test_tool_picker_only_answers_for_servers_you_can_reach(client):
    """Otherwise it would advertise tools the user can't delegate, and every
    tick would be silently dropped."""
    principal_id, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        await make_upstream(conn, "not-mine")
    await _sign_in(client, secret)
    assert (await client.get("/ui/tools.json?server=not-mine")).status_code == 403


async def test_upstream_page_has_a_tools_section(client):
    """Clicking into a server should show what it offers — asked of the server,
    not remembered, so an added or removed tool needs no bookkeeping."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "knowledge")
    await _sign_in(client, secret)

    page = await client.get(f"/ui/admin/upstreams/{upstream_id}")
    assert page.status_code == 200
    assert ">Tools<" in page.text
    # It loads from the discovery endpoint rather than blocking the page on a
    # possibly-dead upstream.
    assert f"/ui/admin/upstreams/{upstream_id}/tools.json" in page.text
    assert 'id="tools-refresh"' in page.text
    # And it shows both call shapes, since that's the thing an admin needs.
    assert "knowledge__" in page.text
    assert "/knowledge/mcp" in page.text


# --- upstream endpoints (replicas, Q24) ------------------------------------


async def test_registering_a_server_creates_its_first_endpoint(client):
    """The create form stays single-URL; more replicas are added afterwards."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    await client.post("/ui/admin/upstreams", data={
        "name": "knowledge", "url": "http://127.0.0.1:8500/mcp", "timeout_seconds": "30",
    }, follow_redirects=False)

    pool = await db.pool()
    async with pool.acquire() as conn:
        urls = await conn.fetch(
            """SELECT e.url FROM upstream_endpoints e
                 JOIN upstreams u ON u.id = e.upstream_id WHERE u.name = 'knowledge'"""
        )
    assert [r["url"] for r in urls] == ["http://127.0.0.1:8500/mcp"]


async def test_admin_can_add_a_second_endpoint_and_see_it(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:8500/mcp")
    await _sign_in(client, secret)

    await client.post(
        f"/ui/admin/upstreams/{upstream_id}/endpoints",
        data={"url": "http://127.0.0.1:8501/mcp"},
        follow_redirects=False,
    )

    page = await client.get(f"/ui/admin/upstreams/{upstream_id}")
    assert "http://127.0.0.1:8500/mcp" in page.text
    assert "http://127.0.0.1:8501/mcp" in page.text


async def test_an_endpoint_can_be_taken_out_of_rotation(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:8500/mcp")
        endpoint_id = await conn.fetchval(
            "SELECT id FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        )
    await _sign_in(client, secret)

    await client.post(
        f"/ui/admin/upstreams/{upstream_id}/endpoints/{endpoint_id}/toggle",
        follow_redirects=False,
    )

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT enabled FROM upstream_endpoints WHERE id = $1", endpoint_id
        ) is False


async def test_the_last_endpoint_cannot_be_deleted(client):
    """Nothing in the schema can hold this without a trigger, so the UI does —
    the difference between "can't do that" and a server that silently stops
    answering."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:8500/mcp")
        endpoint_id = await conn.fetchval(
            "SELECT id FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        )
    await _sign_in(client, secret)

    page = await client.post(
        f"/ui/admin/upstreams/{upstream_id}/endpoints/{endpoint_id}/delete",
        follow_redirects=False,
    )

    assert "at least one endpoint" in page.text
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        ) == 1


async def test_a_second_endpoint_can_be_deleted(client):
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:8500/mcp")
        spare = await add_endpoint(conn, upstream_id, "http://127.0.0.1:8501/mcp")
    await _sign_in(client, secret)

    await client.post(
        f"/ui/admin/upstreams/{upstream_id}/endpoints/{spare}/delete", follow_redirects=False
    )

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        ) == 1


async def test_the_endpoint_routes_are_admin_only(client):
    """A new surface is a new chance to forget the gate."""
    _, secret = await _seed_admin(is_admin=False)
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:8500/mcp")
        endpoint_id = await conn.fetchval(
            "SELECT id FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        )
    await _sign_in(client, secret)

    for path in (
        f"/ui/admin/upstreams/{upstream_id}/endpoints",
        f"/ui/admin/upstreams/{upstream_id}/endpoints/{endpoint_id}/toggle",
        f"/ui/admin/upstreams/{upstream_id}/endpoints/{endpoint_id}/delete",
    ):
        response = await client.post(path, data={"url": "http://127.0.0.1:9/mcp"},
                                     follow_redirects=False)
        assert response.status_code == 403, path

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM upstream_endpoints WHERE upstream_id = $1", upstream_id
        ) == 1


async def test_a_health_check_records_every_replica(client):
    """A check that only reached whichever replica round-robin picked would say
    "ok" about a server that is half down."""
    _, secret = await _seed_admin()
    pool = await db.pool()
    async with pool.acquire() as conn:
        upstream_id = await make_upstream(conn, "wk", "http://127.0.0.1:1/mcp")
        await add_endpoint(conn, upstream_id, "http://127.0.0.1:2/mcp")
    await _sign_in(client, secret)

    page = await client.post(f"/ui/admin/upstreams/{upstream_id}/check", follow_redirects=False)

    assert "0/2 replicas ok" in page.text
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT last_health_ok, last_health_at FROM upstream_endpoints
                WHERE upstream_id = $1""",
            upstream_id,
        )
    assert len(rows) == 2
    assert all(r["last_health_at"] is not None and r["last_health_ok"] is False for r in rows)


# --- session revalidation: the stale-cookie hole (#61, #67) ----------------


async def test_a_session_minted_before_the_cutoff_is_logged_out(client):
    """The core of #61/#67: a signed cookie is no longer proof on its own. Once
    sessions_valid_after moves past the cookie's issued_at, the next request is
    redirected to login however valid the signature."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    assert (await client.get("/ui", follow_redirects=False)).status_code == 200

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE principals SET sessions_valid_after = now() + interval '1 hour'"
            " WHERE username = $1", USERNAME,
        )

    after = await client.get("/ui", follow_redirects=False)
    assert after.status_code == 302
    assert after.headers["location"] == "/ui/login"


async def test_disabling_a_signed_in_principal_logs_them_out(client):
    """#61: the disabled-admin PoC. A live admin cookie stops working the moment
    the principal is disabled — no waiting for the 12h TTL."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    assert (await client.get("/ui/admin/principals", follow_redirects=False)).status_code == 200

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE principals SET disabled_at = now() WHERE username = $1", USERNAME
        )

    after = await client.get("/ui/admin/principals", follow_redirects=False)
    assert after.status_code == 302
    assert after.headers["location"] == "/ui/login"


async def test_demoting_an_admin_drops_admin_access_on_the_next_request(client):
    """#61: is_admin is refreshed from the DB per request, so revoking admin
    takes hold immediately — the demoted user stays logged in but loses the
    admin pages rather than keeping them until the cookie expires."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)
    assert (await client.get("/ui/admin/principals", follow_redirects=False)).status_code == 200

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE principals SET is_admin = FALSE WHERE username = $1", USERNAME
        )

    # Still logged in...
    assert (await client.get("/ui/account", follow_redirects=False)).status_code == 200
    # ...but no longer an admin.
    assert (await client.get("/ui/admin/principals", follow_redirects=False)).status_code == 403


async def test_changing_password_revokes_tokens_and_other_sessions(client):
    """#67: a password change is the compromised-account response. It revokes
    the principal's tokens and moves the session cutoff, while keeping the
    browser that made the change signed in."""
    principal_id, secret = await _seed_admin()
    await _sign_in(client, secret)

    pool = await db.pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id, label)
               VALUES ('cl_x', 'claude.ai', $1, 'x')""", principal_id,
        )
        await conn.execute(
            """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at)
               VALUES ('refresh', 'h_refresh', $1, 'cl_x', now() + interval '30 days')""",
            principal_id,
        )

    new = "a-brand-new-password-just-as-long"
    resp = await client.post(
        "/ui/account/password",
        data={"current": PASSWORD, "password": new, "confirm": new},
        follow_redirects=False,
    )
    assert resp.status_code == 200

    # The browser that changed it stays signed in.
    assert (await client.get("/ui/account", follow_redirects=False)).status_code == 200

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT sessions_valid_after FROM principals WHERE id = $1", principal_id
        ) is not None
        assert await conn.fetchval(
            "SELECT revoked_at FROM tokens WHERE token_hash = 'h_refresh'"
        ) is not None
        assert await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'password_changed'"
        ) == 1


async def test_admin_reset_revokes_the_targets_tokens_and_sessions(client):
    """#67: an admin reset cuts off the target's old credentials the same way —
    their tokens die and their sessions are invalidated."""
    _, secret = await _seed_admin()
    await _sign_in(client, secret)

    pool = await db.pool()
    async with pool.acquire() as conn:
        target = await conn.fetchval(
            """INSERT INTO principals (kind, username) VALUES ('human', 'victim')
               RETURNING id"""
        )
        await conn.execute(
            """INSERT INTO auth_identities (principal_id, backend, password_hash)
               VALUES ($1, 'local', 'h')""", target,
        )
        await conn.execute(
            """INSERT INTO oauth_clients (client_id, client_name, principal_id, label)
               VALUES ('cl_v', 'claude.ai', $1, 'v')""", target,
        )
        await conn.execute(
            """INSERT INTO tokens (kind, token_hash, principal_id, client_id, expires_at)
               VALUES ('access', 'h_victim', $1, 'cl_v', now() + interval '1 hour')""",
            target,
        )

    resp = await client.post(
        f"/ui/admin/principals/{target}/reset_password", follow_redirects=False
    )
    assert resp.status_code == 200

    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT sessions_valid_after FROM principals WHERE id = $1", target
        ) is not None
        assert await conn.fetchval(
            "SELECT revoked_at FROM tokens WHERE token_hash = 'h_victim'"
        ) is not None
        assert await conn.fetchval(
            "SELECT count(*) FROM audit_auth_events WHERE event = 'password_reset'"
        ) == 1

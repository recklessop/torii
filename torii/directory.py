"""The public MCP directory (PRD Q12).

An unauthenticated, indexable listing of the servers an admin has chosen to
publish. Search engines, agents and humans can read what each server does and
how to connect; nobody gains access by reading it — default deny still
applies, so a listed server with no grant for you is readable-about and
uncallable.

What a listing publishes: name, description, tool names and their
descriptions, and the connection instructions. What it never publishes: the
LAN URL, the auth header, or anything about principals, grants, or audit.

Deliberately separate from `/ui`: this is the one surface on the whole gateway
meant to be crawled, so it carries `index, follow` (everything else is
`noindex`), it appears in robots.txt and sitemap.xml, and it emits
schema.org JSON-LD so an agent can parse it without scraping the HTML.

`/marketplace` is an alias. If paid listings ever land (the operator's idea, logged
in the PRD as a future phase), the URL is already claimed and nothing has to
be re-indexed.
"""

import asyncio
import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

from . import cache, config, db, proxy, web

log = logging.getLogger(__name__)

router = APIRouter()

# Tool lists come from the upstreams themselves, so they're cached briefly —
# a crawler shouldn't be able to hammer every backend by refreshing.
TOOLS_CACHE_PREFIX = "torii:dirtools:"
TOOLS_CACHE_TTL = 300

# The directory is unauthenticated and deliberately crawlable, so it is the one
# surface an anonymous visitor can drive at will. Two independent brakes keep
# that from becoming a denial of service (#63):
#   - a per-IP + global fixed-window rate limit, and
#   - a hard ceiling on any single upstream fetch, well below the upstream's own
#     (up to 300s) timeout, so a stalling backend can't pin a request open.
# Neither the fetch nor the rate check ever runs while a DB connection is held.
DIRECTORY_FETCH_TIMEOUT = 5.0
DIR_RL_PER_IP_LIMIT = 60
DIR_RL_GLOBAL_LIMIT = 600
DIR_RL_WINDOW_SECONDS = 60


async def _rate_limited(request: Request) -> bool:
    """True if this directory request should be turned away with a 429.

    Fixed-window, fails OPEN on a valkey outage (see `web.too_many_attempts`):
    the directory being briefly un-throttled is preferable to it going dark
    because the counter is down.
    """
    ip = web.client_ip(request) or "unknown"
    per_ip = await web.too_many_attempts(
        f"dir:{ip}", DIR_RL_PER_IP_LIMIT, DIR_RL_WINDOW_SECONDS
    )
    overall = await web.too_many_attempts(
        "dir:all", DIR_RL_GLOBAL_LIMIT, DIR_RL_WINDOW_SECONDS
    )
    return per_ip or overall


def _too_many(request: Request):
    return web.render(
        request,
        "pages/directory_missing.html",
        {"name": "", "robots": "noindex, follow",
         "message": "Too many requests — please slow down."},
        status_code=429,
    )


# --- JSON-LD -----------------------------------------------------------------


def _json_ld(obj: dict) -> str:
    """Serialise a dict for embedding in a `<script type="application/ld+json">`.

    `json.dumps` does NOT escape `<`, `>`, `&` or `/`, so a `</script>` reaching
    it from an upstream tool name or an admin `public_summary` would break out of
    the script element and execute as HTML (#59). Escape those characters (and
    the two Unicode line terminators JS treats as newlines) to their `\\uXXXX`
    forms — the standard JSON-LD-in-HTML defence. The result is still valid JSON,
    just inert as markup.
    """
    return (
        json.dumps(obj, indent=2)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


async def listed_servers(conn) -> list[dict]:
    rows = await conn.fetch(
        """SELECT name, display_name, description, public_summary, public_url, enabled
             FROM upstreams
            WHERE public_listed = TRUE
            ORDER BY name"""
    )
    return [
        {
            "name": r["name"],
            "title": r["display_name"] or r["name"],
            "summary": r["public_summary"] or r["description"] or "",
            "url": r["public_url"],
            "available": r["enabled"],
        }
        for r in rows
    ]


async def listed_server(conn, name: str) -> dict | None:
    row = await conn.fetchrow(
        """SELECT name, display_name, description, public_summary, public_url, enabled
             FROM upstreams
            WHERE name = $1 AND public_listed = TRUE""",
        name,
    )
    if row is None:
        return None
    return {
        "name": row["name"],
        "title": row["display_name"] or row["name"],
        "summary": row["public_summary"] or row["description"] or "",
        "url": row["public_url"],
        "available": row["enabled"],
        # Kept internal — used to fetch the tool list, never rendered. Built by
        # the one loader so the directory can't end up with its own idea of
        # which replicas are live.
        "_upstream": await proxy.load_upstream(conn, name),
    }


async def public_tools(upstream: proxy.Upstream) -> list[dict]:
    """Tool names and descriptions for a listed server, cached.

    Failure is not an error here: a backend being down shouldn't blank a
    directory page, so an empty list just means "not advertised right now".
    """
    key = TOOLS_CACHE_PREFIX + upstream.name
    try:
        cached = await cache.client().get(key)
        if cached:
            return json.loads(cached)
    except Exception:  # noqa: BLE001 — cache is an optimisation, not a source
        pass

    try:
        result = await asyncio.wait_for(
            proxy.call_upstream(upstream, "tools/list", {}),
            timeout=DIRECTORY_FETCH_TIMEOUT,
        )
    except (proxy.UpstreamError, asyncio.TimeoutError) as exc:
        log.info("directory: %s tool list unavailable (%s)", upstream.name, exc)
        return []

    tools = [
        {
            "name": tool.get("name", ""),
            "namespaced": f"{upstream.name}{'__'}{tool.get('name','')}",
            "description": (tool.get("description") or "").strip(),
        }
        for tool in (result.get("tools") or [])
        if tool.get("name")
    ]
    try:
        await cache.client().setex(key, TOOLS_CACHE_TTL, json.dumps(tools))
    except Exception:  # noqa: BLE001
        pass
    return tools


# --- HTML ------------------------------------------------------------------


@router.get("/directory")
async def directory(request: Request):
    if await _rate_limited(request):
        return _too_many(request)
    pool = await db.pool()
    async with pool.acquire() as conn:
        servers = await listed_servers(conn)
    return web.render(
        request,
        "pages/directory.html",
        {
            "servers": servers,
            "robots": "index, follow",
            "json_ld": _json_ld(_collection_json_ld(servers)),
        },
    )


@router.get("/marketplace")
async def marketplace_alias():
    """Alias, so the name is claimed if paid listings ever arrive."""
    return RedirectResponse("/directory", status_code=302)


@router.get("/directory/{name}")
async def directory_server(request: Request, name: str):
    if await _rate_limited(request):
        return _too_many(request)
    pool = await db.pool()
    async with pool.acquire() as conn:
        server = await listed_server(conn, name)
        if server is None:
            # Same answer for "not listed" and "doesn't exist": the directory
            # must not confirm the existence of private servers.
            return web.render(
                request,
                "pages/directory_missing.html",
                {"name": name, "robots": "noindex, follow"},
                status_code=404,
            )

    # The upstream fetch happens AFTER the DB connection is released (#63): a
    # slow or stalling backend must never hold a pool connection, or a handful
    # of anonymous requests could starve /ui, /mcp and /healthz of the same
    # 10-connection pool.
    tools = await public_tools(server["_upstream"]) if server["available"] else []

    return web.render(
        request,
        "pages/directory_server.html",
        {
            "server": server,
            "tools": tools,
            "robots": "index, follow",
            "json_ld": _json_ld(_server_json_ld(server, tools)),
        },
    )


# --- machine-readable ------------------------------------------------------


@router.get("/directory.json")
async def directory_json(request: Request):
    """For agents that would rather not parse HTML."""
    if await _rate_limited(request):
        return JSONResponse(
            {"error": "rate_limited"},
            status_code=429,
            headers={"Retry-After": str(DIR_RL_WINDOW_SECONDS)},
        )
    pool = await db.pool()
    # Resolve every listed server AND its upstream while the connection is held,
    # then release it BEFORE any upstream is contacted (#63). The old serial
    # loop did each backend's HTTP fetch inside one held connection, so a single
    # stalling upstream pinned it for the whole walk.
    async with pool.acquire() as conn:
        servers = await listed_servers(conn)
        resolved = []
        for entry in servers:
            server = await listed_server(conn, entry["name"])
            if server is None:
                continue
            resolved.append((entry, server))

    detailed = []
    for entry, server in resolved:
        tools = await public_tools(server["_upstream"]) if server["available"] else []
        detailed.append(
            {
                "name": entry["name"],
                "title": entry["title"],
                "summary": entry["summary"],
                "homepage": entry["url"],
                "available": entry["available"],
                # The URL to point a connector at for this server alone.
                "mcp_endpoint": f"{config.PUBLIC_BASE_URL}/{entry['name']}/mcp",
                "tool_prefix_on_aggregate": f"{entry['name']}__",
                "tools": tools,
            }
        )

    return JSONResponse(
        {
            "gateway": {
                "name": "torii",
                # Two shapes: the aggregate carries every granted server with
                # tools prefixed, the per-server one carries a single server
                # with bare tool names.
                "mcp_endpoint": f"{config.PUBLIC_BASE_URL}/mcp",
                "per_server_endpoint": f"{config.PUBLIC_BASE_URL}/{{server}}/mcp",
                "transport": "streamable-http",
                "authorization": {
                    "type": "oauth2.1",
                    "metadata": f"{config.PUBLIC_BASE_URL}/.well-known/oauth-authorization-server",
                    "resource_metadata": f"{config.PUBLIC_BASE_URL}/.well-known/oauth-protected-resource",
                    "dynamic_registration": True,
                    "static_keys": True,
                },
                "access": "Every tool requires an explicit grant. Listing here "
                          "describes a server; it does not grant access to it.",
            },
            "servers": detailed,
        },
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get("/robots.txt")
async def robots():
    """The directory is the only crawlable surface; everything else is off."""
    base = config.PUBLIC_BASE_URL
    body = "\n".join(
        [
            "User-agent: *",
            "Allow: /directory",
            "Allow: /directory.json",
            "Disallow: /ui",
            "Disallow: /mcp",
            "Disallow: /oauth",
            "Disallow: /authorize",
            "Disallow: /healthz",
            "",
            f"Sitemap: {base}/sitemap.xml",
            "",
        ]
    )
    return PlainTextResponse(body, headers={"Cache-Control": "public, max-age=3600"})


@router.get("/sitemap.xml")
async def sitemap():
    pool = await db.pool()
    async with pool.acquire() as conn:
        servers = await listed_servers(conn)

    base = config.PUBLIC_BASE_URL
    urls = [f"{base}/directory"] + [f"{base}/directory/{s['name']}" for s in servers]
    entries = "".join(f"<url><loc>{u}</loc></url>" for u in urls)
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{entries}</urlset>"
    )
    return PlainTextResponse(
        body, media_type="application/xml", headers={"Cache-Control": "public, max-age=3600"}
    )


# --- structured data -------------------------------------------------------


def _collection_json_ld(servers: list[dict]) -> dict:
    base = config.PUBLIC_BASE_URL
    return {
        "@context": "https://schema.org",
        "@type": "CollectionPage",
        "name": "MCP servers behind torii",
        "url": f"{base}/directory",
        "description": "Model Context Protocol servers published through the "
                       "torii gateway, with the tools each one offers.",
        "hasPart": [
            {
                "@type": "SoftwareApplication",
                "name": server.get("title") or server["name"],
                "applicationCategory": "DeveloperApplication",
                "description": server["summary"],
                "url": f"{base}/directory/{server['name']}",
            }
            for server in servers
        ],
    }


def _server_json_ld(server: dict, tools: list[dict]) -> dict:
    base = config.PUBLIC_BASE_URL
    return {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": server.get("title") or server["name"],
        "applicationCategory": "DeveloperApplication",
        "description": server["summary"],
        "url": f"{base}/directory/{server['name']}",
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        "featureList": [tool["namespaced"] for tool in tools],
        "potentialAction": {
            "@type": "ConsumeAction",
            "target": f"{base}/{server['name']}/mcp",
            "actionStatus": "PotentialActionStatus",
        },
    }

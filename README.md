# torii

[![CI](https://github.com/recklessop/torii/actions/workflows/ci.yml/badge.svg)](https://github.com/recklessop/torii/actions/workflows/ci.yml)
[![License: PolyForm NC 1.0.0](https://img.shields.io/badge/license-PolyForm%20NC%201.0.0-yellow.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)

**A self-owned gateway in front of your MCP servers.** torii is an OAuth 2.1
authorization server toward Claude clients (web, mobile, Office add-ins, Claude
Code, the API) and static bearer keys for everything else, with tool-level
RBAC, an audit trail, and a credential GUI. Your upstream MCP servers become
LAN-only services behind a single authenticated, authorized front door.

A *torii* is the shrine gate between the ordinary world and the ground behind
it: outside, every Claude surface; behind it, your MCP estate.

> **Status:** running in production for its author, pre-1.0, published
> source-available. The authorization model, OAuth server, proxy, and admin UI
> are built and tested (580+ tests).

## What it does

- **One front door for many MCP servers.** An aggregate `/mcp` endpoint and
  per-server `/<slug>/mcp` endpoints fan out to your upstreams. Tool names keep
  the `<server>__<tool>` namespacing, so migrating a client is a URL swap.
- **OAuth 2.1 authorization server.** RFC 8414 + RFC 9728 metadata, Dynamic
  Client Registration (RFC 7591), PKCE, refresh-token rotation and revocation —
  everything a claude.ai custom connector needs.
- **Tool-level RBAC, default deny.** Access is granted per tool, to a principal
  or a group, and narrowed per OAuth client. There is **one** authorization
  resolver and **no** admin-bypass path. The dangerous states (admin without
  2FA, wildcard grants, an empty tool list on a `list` grant) are
  unrepresentable in the database schema, not just checked in code.
- **Local credentials with TOTP.** bcrypt passwords, TOTP required for admins,
  WebAuthn passkeys, and `tor_`-prefixed API keys — all hashed at rest, shown
  once. An auth-backend seam is in place for a future external IdP.
- **Audit trail.** Every call and auth event, retained (default one year), with
  a viewer in the UI. No request/response payloads captured by default.
- **A credential and admin GUI**, plus a public MCP directory as the only
  crawlable surface.

## Quickstart (Docker)

```bash
git clone https://github.com/recklessop/torii.git && cd torii
cp .env.example .env
```

Fill in `.env` — at minimum a strong `POSTGRES_PASSWORD`, `VALKEY_PASSWORD`,
and `SESSION_SECRET`, and your public `PUBLIC_BASE_URL`:

```bash
# generate secrets
openssl rand -hex 24                                   # each password
python -c "import secrets; print(secrets.token_hex(32))"   # SESSION_SECRET
```

Then bring it up. The public compose builds from source and runs Postgres and
valkey on a private network (neither publishes a host port):

```bash
docker compose up -d
curl -s http://localhost:8400/healthz
```

Bootstrap the first admin:

```bash
docker compose exec torii python -m torii.cli bootstrap
```

`torii` listens on `:8400`. Put it behind a reverse proxy or tunnel that
terminates TLS and controls forwarding headers — see the security notes below.

## Run it locally (from source)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
docker compose up -d postgres valkey
export PUBLIC_BASE_URL=http://localhost:8400
export SESSION_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
python -m torii.server            # http://localhost:8400/healthz
pytest -q                         # see CONTRIBUTING.md for the DB env vars
```

## Configuration

All runtime state (principals, upstreams, grants, keys) lives in Postgres and
is managed in the UI. The process reads only a handful of environment
variables at boot — see `.env.example`. torii runs a **boot-time
configuration check** that prints each security-relevant setting's posture and
refuses to start on the worst combinations (for example, an `https`
`PUBLIC_BASE_URL` with no `SESSION_SECRET`).

Key ones:

| Variable | Purpose |
| --- | --- |
| `PUBLIC_BASE_URL` | Public origin; the OAuth issuer and WebAuthn origin. Must match the hostname clients use, byte-for-byte. |
| `SESSION_SECRET` | Signs the UI session cookie. **Set a stable value** or every restart logs everyone out — and an unset secret on an https origin is refused at boot. |
| `SESSION_HTTPS_ONLY` | Marks the session cookie `Secure`. Set `true` behind TLS. |
| `TORII_ENCRYPTION_KEY` | Fernet key encrypting upstream auth headers at rest. Saving an upstream credential is refused if unset. |
| `METRICS_TOKEN` | Bearer token for `/metrics`. Empty means the endpoint is off (404). |

## Security

torii is a security component. Before deploying, read **[SECURITY.md](SECURITY.md)**
for the honest posture — in particular:

- Run it **behind a proxy/tunnel you control**; it trusts forwarding headers
  for audit context and should not face the internet directly.
- Set `SESSION_SECRET`, `SESSION_HTTPS_ONLY=true`, and `TORII_ENCRYPTION_KEY`
  for a real deployment.
- Runtime dependencies are pinned and hashed in `requirements.lock`; CI runs
  `bandit`, `pip-audit`, and `gitleaks`.

Report vulnerabilities privately per the process in `SECURITY.md`.

## License

Released under **PolyForm Noncommercial 1.0.0** (see [LICENSE](LICENSE)). torii
is **source-available, not OSI open-source**: read, run, modify, and share it
for noncommercial purposes; commercial use requires a separate arrangement.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The one rule that matters most: every
caller-facing surface routes through the single RBAC resolver — never add a
second authorization path.

## Layout

| Path | What |
| --- | --- |
| `torii/rbac.py` | The authorization choke point: one resolver, default deny, no admin bypass |
| `torii/proxy.py` | `/mcp` aggregate + `/<slug>/mcp` per-server endpoints, fan-out, audit |
| `torii/oauth.py`, `routes_oauth.py` | OAuth 2.1 AS: metadata, DCR, PKCE, rotation, revocation |
| `torii/credentials.py` | Passwords, TOTP, `tor_` keys, tokens — all hashing |
| `torii/startup.py` | Boot-time configuration validation |
| `torii/config.py` | Environment wiring only; runtime config lives in Postgres |
| `torii/migrations/` | `*.sql`, applied in filename order on boot (advisory-locked) |

# Security policy

torii is a security gateway â an OAuth 2.1 authorization server and RBAC
choke point in front of a fleet of MCP servers. It is being published as
source-available software; this document is what a prospective operator or
security researcher should read before relying on it or reporting a flaw.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not as a public issue.

- Use this repository's **private vulnerability reporting**: the *Security* tab → *Report a vulnerability* (GitHub Security Advisories).
- Please include a description, affected version or commit, and a reproduction
  if you have one.
- Expect an acknowledgement within a few days. There is no bug-bounty program;
  this is a personal-infrastructure project published in the hope it is useful.

Do not open a public issue, PR, or discussion for an unfixed vulnerability.

## Supported versions

torii is pre-1.0 and evolves on `main`. Only the latest commit on `main`
receives security fixes; there are no maintained release branches yet. Pin to
a commit you have reviewed and follow `main` for fixes.

## Security posture (read this before deploying)

torii is built default-deny where it counts, but it is a piece of
infrastructure with real deployment requirements. An honest inventory:

### What is enforced

- **Authorization fails closed.** Access is resolved through a single RBAC
  resolver (`torii/rbac.py`) with default deny at tool granularity and no
  admin-bypass path. The dangerous states â admin without 2FA, wildcard
  grants, an empty tool list on a `list` grant â are unrepresentable in the
  schema (CHECK constraints and partial unique indexes), not merely checked in
  a handler.
- **Credentials at rest are hashed.** Passwords use bcrypt; API keys and OAuth
  tokens are stored hashed and shown exactly once. TOTP is required for admin.
- **Boot-time config validation (#80).** On startup torii prints each
  security-relevant setting's posture and **refuses to start** on the worst
  combinations â notably an `https` `PUBLIC_BASE_URL` with no `SESSION_SECRET`
  (which would make admin sessions forgeable). Override only with a conscious
  `TORII_ALLOW_INSECURE=1`.

### What fails open / requires operator care

- **Trusted-proxy requirement.** torii derives the client IP from the
  `CF-Connecting-IP` / `X-Forwarded-For` headers (`torii/web.py`). These are
  client-controllable if torii is exposed directly to the internet. This value
  is used as **audit context only, never as an authorization input** â but if
  you rely on IP in rate-limiting or logs, run torii **behind a reverse proxy
  or tunnel you control** that strips inbound forwarding headers. Do not
  publish the container port straight to the internet.
- **Upstream credential encryption can be downgraded.** Upstream auth headers
  are encrypted at rest with a Fernet key (`TORII_ENCRYPTION_KEY`). If the key
  is unset, saving an upstream credential is **refused** (#73) â it does not
  silently store plaintext. The one exception is the explicit, documented
  escape hatch `TORII_ALLOW_PLAINTEXT_UPSTREAM_SECRETS=1`, which stores those
  headers in plaintext. Do not set it in production.
- **`/metrics` is off unless a token is set.** It is opt-in
  (`METRICS_TOKEN`) because the series names include private upstream names.
  Scrape it over the LAN; never expose it publicly.
- **Rate limiting is a brake, not a quota.** The default per-minute tool-call
  limit is generous by design â it exists to contain a runaway or stolen
  credential, not to meter usage. Set per-credential limits where you need
  tighter control.
- **Session cookie `Secure` attribute** is derived from your config, not
  forced. Set `SESSION_HTTPS_ONLY=true` behind TLS; the boot check warns if
  your origin is `https` but this is off.

### Dependencies

Runtime dependencies are pinned and hashed in `requirements.lock` (generated
from the loose `requirements.txt` with `uv pip compile --generate-hashes`).
Build the image from the lockfile for a reproducible, tamper-evident
dependency set. CI runs `pip-audit`, `bandit`, and `gitleaks` on every push
(`.gitea/workflows/security.yml`).

## Licensing note

torii is released under the **PolyForm Noncommercial 1.0.0** license (see
`LICENSE`). It is source-available, **not** OSI open-source: you may read,
run, modify, and share it for noncommercial purposes. Commercial use requires
a separate arrangement. This affects who may deploy it and how, but does not
change the disclosure process above â security reports are welcome regardless.

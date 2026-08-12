"""Process-level wiring from the environment.

Everything an operator tunes at runtime — principals, upstreams, grants,
keys — lives in Postgres. This module is only what the process needs to
boot and where it lives on the network.
"""

import ipaddress
import os
import secrets


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# --- Storage ---------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://torii:torii@localhost:5432/torii"
)
VALKEY_URL = os.environ.get("VALKEY_URL", "redis://localhost:6379/0")

# --- Network ---------------------------------------------------------------

HOST = os.environ.get("TORII_HOST", "0.0.0.0")
PORT = _int("TORII_PORT", 8400)

# The issuer identity in OAuth metadata (RFC 8414 / RFC 9728) and the base
# for every absolute URL torii hands a client. MUST match the public
# hostname exactly — clients compare it byte-for-byte against the issuer
# in the metadata document.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", f"http://localhost:{PORT}").rstrip("/")

# --- Sessions (the /ui and authorize-page cookie) --------------------------

# Set this in deployment or every container restart logs everyone out.
SESSION_SECRET = os.environ.get("SESSION_SECRET", "") or secrets.token_hex(32)

# Mark the session cookie Secure. On behind the tunnel; off for plain-HTTP
# LAN access, or the login cookie is never set there.
SESSION_HTTPS_ONLY = _bool("SESSION_HTTPS_ONLY", False)

SESSION_TTL = _int("SESSION_TTL", 12 * 3600)

# --- Credential lifetimes (PRD FR2) ----------------------------------------

ACCESS_TOKEN_TTL = _int("ACCESS_TOKEN_TTL", 3600)             # 1 h
REFRESH_TOKEN_TTL = _int("REFRESH_TOKEN_TTL", 30 * 86400)     # 30 d, rotated
API_KEY_PREFIX = "tor_"

# Authorization codes are single-use and exchanged immediately; RFC 6749
# recommends a maximum of 10 minutes.
AUTH_CODE_TTL = _int("AUTH_CODE_TTL", 300)

# --- Login protection ------------------------------------------------------

LOGIN_MAX_ATTEMPTS = _int("LOGIN_MAX_ATTEMPTS", 5)
LOGIN_LOCKOUT_SECONDS = _int("LOGIN_LOCKOUT_SECONDS", 900)    # 15 min

# --- Trusted proxies (client-IP spoofing defence) --------------------------

# The forwarded client-IP headers (CF-Connecting-IP / X-Forwarded-For) are
# client-controllable, so they are trusted ONLY when the socket peer is a
# proxy we put there. Otherwise torii uses the socket IP and ignores the
# headers — a spoofed header can't move the login rate-limit bucket or forge
# an audit source.
#
# TRUSTED_PROXY is a comma-separated list of IPs / CIDRs (v4 or v6). The
# special value "*" trusts every peer (only sane when nothing but a real
# reverse proxy can ever reach the socket). Empty (the default) trusts none:
# behind the Cloudflare tunnel, set this to the cloudflared peer's address so
# CF-Connecting-IP is honoured again.
TRUSTED_PROXY = os.environ.get("TRUSTED_PROXY", "").strip()


def _trusted_networks(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in raw.split(","):
        part = part.strip()
        if not part or part == "*":
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            # A typo in the proxy list must not silently widen trust, and it
            # must not crash boot: drop the bad entry.
            continue
    return tuple(nets)


TRUST_ALL_PROXIES = TRUSTED_PROXY == "*"
TRUSTED_PROXY_NETWORKS = _trusted_networks(TRUSTED_PROXY)

# --- Auth backends (PRD Q9c: no external IdP at launch) --------------------

# The Authentik connector is P3+ scope. The seam exists now; this flag stays
# off until a connector is actually configured.
OIDC_ENABLED = _bool("OIDC_ENABLED", False)

# --- WebAuthn passkeys (PRD Q25) -------------------------------------------

# The Relying Party ID is the registrable domain passkeys are bound to. It
# derives from PUBLIC_BASE_URL's hostname; override only for edge cases
# (e.g. serving several subdomains of one parent). Changing it orphans every
# enrolled passkey — each is cryptographically bound to this value.
WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "")
WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "torii")

# --- Upstreams (PRD FR1) ---------------------------------------------------

# Per-upstream override lands with the upstream registry; this is the
# default ceiling so a wedged backend can never hang a client session.
UPSTREAM_TIMEOUT = _int("UPSTREAM_TIMEOUT", 30)

# --- Audit (PRD FR5, Q7) ---------------------------------------------------

AUDIT_RETENTION_DAYS = _int("AUDIT_RETENTION_DAYS", 365)

# --- Rate limits (PRD Q19) -------------------------------------------------

# Tool calls per minute when neither the credential nor the principal names a
# number. Generous by design: this is a runaway/stolen-credential brake, not a
# quota, and a limit that trips during normal use is one an operator disables.
DEFAULT_RATE_LIMIT_PER_MIN = _int("DEFAULT_RATE_LIMIT_PER_MIN", 120)

# --- Encryption ------------------------------------------------------------

# Fernet key protecting upstream auth headers at rest (Q18). Generate with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Losing it loses those credentials and nothing else — re-enter them in the UI.
ENCRYPTION_KEY = os.environ.get("TORII_ENCRYPTION_KEY", "")

# --- Metrics ---------------------------------------------------------------

# Bearer token for /metrics. EMPTY MEANS THE ENDPOINT IS OFF (404) — this is
# an internet-facing process and the series carry the names of private
# upstreams, so exposure has to be opt-in rather than default.
METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")

# --- Misc ------------------------------------------------------------------

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Upstream URL SSRF posture (#62). Torii's model is a single-operator LAN
# gateway: upstreams ARE private-IP LAN services (finder on 127.0.0.1,
# brain/vcs on 127.0.0.1, knowledge on loopback), so the default
# guard rejects only link-local / cloud-metadata / unspecified targets and
# ALLOWS private + loopback + public. Flip this on for the future
# untrusted-upstream / marketplace direction, where private + loopback +
# reserved ranges must ALSO be refused.
STRICT_UPSTREAM_URLS = _bool("TORII_STRICT_UPSTREAM_URLS", False)

# Interactive API docs are off by default: this process is internet-facing
# and its route table is not public information.
ENABLE_DOCS = _bool("ENABLE_DOCS", False)

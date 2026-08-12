"""Upstream URL validation — the SSRF guard for registered endpoints (#62).

An upstream URL is a fetch target: `proxy.py` issues server-side requests to
whatever string is stored, so an unvalidated value is a server-side request
forgery primitive. Left fully open, `http://169.254.169.254/…` (the cloud
metadata endpoint) is reachable by anyone who can write an upstream row.

The posture here fits torii's actual model: a **single-operator LAN gateway**.
Upstreams ARE private-IP LAN services — finder on `127.0.0.1:8300`,
brain/vcs on `127.0.0.1`, knowledge on loopback — so blanket-
blocking private/loopback ranges would break the legitimate act of registering
an upstream by IP. Two postures:

* **Default (always on):** require http/https with a host, and reject only the
  ranges that are never a legitimate upstream: IPv4 link-local `169.254.0.0/16`
  (covers the `169.254.169.254` metadata IP), IPv6 link-local `fe80::/10`, and
  the unspecified address (`0.0.0.0` / `::`). Private, loopback, and public
  targets are ALLOWED.

* **Strict (`TORII_STRICT_UPSTREAM_URLS=1`, default off):** ADDITIONALLY reject
  private (10/8, 172.16/12, 192.168/16), loopback (127/8, `::1`), and other
  reserved ranges. This is the posture for the future untrusted-upstream /
  marketplace direction (#20), not today's LAN model.

Hostnames are NOT resolved at write time in either mode — DNS is not consulted,
so a hostname that resolves inward is not caught here. A resolve-then-pin check
at request time is the follow-up the issue names for the day third-party URLs
are ever accepted.
"""

import ipaddress
from urllib.parse import urlparse

from . import config

# Hostnames that are loopback by convention rather than by being an IP literal,
# so `ipaddress` never sees them. Only relevant in strict mode (loopback is
# allowed by default), so they gate on the same flag below.
_LOOPBACK_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


class UpstreamUrlError(ValueError):
    """Invalid upstream URL. The message is safe to render on the form."""


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _always_blocked(ip) -> bool:
    """Ranges refused in EVERY mode: link-local (incl. cloud metadata) and the
    unspecified address. These are never a legitimate upstream target."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_link_local or ip.is_unspecified


def _strict_blocked(ip) -> bool:
    """Additional ranges refused only under TORII_STRICT_UPSTREAM_URLS: private,
    loopback, and other reserved/non-routable space."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast


def validate_upstream_url(raw: str, *, strict: bool | None = None) -> str:
    """Return the cleaned upstream URL, or raise UpstreamUrlError.

    `strict` defaults to `config.STRICT_UPSTREAM_URLS`; pass it explicitly in
    tests. Raises with a form-safe message so callers can re-render the form
    rather than 500.
    """
    if strict is None:
        strict = config.STRICT_UPSTREAM_URLS

    url = (raw or "").strip()
    if not url:
        raise UpstreamUrlError("A URL is required.")

    try:
        parsed = urlparse(url)
    except ValueError:
        raise UpstreamUrlError("That is not a valid URL.")

    if parsed.scheme not in ("http", "https"):
        raise UpstreamUrlError("Upstream URL must start with http:// or https://.")

    host = parsed.hostname
    if not host:
        raise UpstreamUrlError("Upstream URL must include a host.")

    if strict and host.lower() in _LOOPBACK_HOSTNAMES:
        raise UpstreamUrlError("Upstream URL may not point at localhost.")

    ip = _as_ip(host)
    if ip is not None:
        if _always_blocked(ip):
            raise UpstreamUrlError(
                "Upstream URL may not point at a link-local or metadata "
                "address (e.g. 169.254.169.254)."
            )
        if strict and _strict_blocked(ip):
            raise UpstreamUrlError(
                "Upstream URL may not point at a private, loopback, or "
                "reserved IP address (strict mode)."
            )

    return url

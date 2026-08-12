"""Boot-time configuration validation (#80).

One pass, run from the app lifespan before the server accepts traffic. It
prints each security-relevant setting's posture, WARNs on risky-but-
recoverable states, and hard-FAILS the combinations that would silently
expose an internet-facing gateway — chiefly an OAuth authorization server
whose session secret is unset (and therefore auto-generated and ephemeral)
while it answers on an https origin.

The defaults in `config.py` are convenient for a laptop and dangerous on the
public internet; nothing between the two used to say so out loud. This is
that voice. It reads the raw environment (not the already-parsed `config`
globals) so a presence check like "was SESSION_SECRET actually set?" is
honest — `config.SESSION_SECRET` is never empty, because it self-generates.

Escape hatch: `TORII_ALLOW_INSECURE=1` downgrades every hard failure to a
warning, for an operator who has read the posture and accepts it. It is not
set anywhere by default and never should be in production.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlparse

log = logging.getLogger("torii.startup")

_TRUTHY = ("1", "true", "yes", "on")

# Hosts that are never a real public origin.
_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}


class InsecureConfiguration(RuntimeError):
    """A boot-time configuration state unsafe enough to refuse to start."""


@dataclass
class ConfigReport:
    """The result of one validation pass, so callers (and tests) can inspect
    it without parsing log lines."""

    postures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    allow_insecure: bool = False

    @property
    def ok(self) -> bool:
        return not self.failures


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    return env.get(name, str(default)).strip().lower() in _TRUTHY


def _is_https(url: str) -> bool:
    return (urlparse(url).scheme or "").lower() == "https"


def _is_localhost(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in _LOCALHOST_HOSTS or host.endswith(".localhost")


def evaluate(env: Mapping[str, str]) -> ConfigReport:
    """Assess the environment. Pure: no logging, no raising, no process exit —
    it just returns what it found, which is what makes it testable."""
    report = ConfigReport(allow_insecure=_bool(env, "TORII_ALLOW_INSECURE", False))

    public_base_url = (env.get("PUBLIC_BASE_URL", "") or "").rstrip("/")
    https = _is_https(public_base_url)
    localhost = _is_localhost(public_base_url) or not public_base_url
    session_secret_set = bool(env.get("SESSION_SECRET", "").strip())
    encryption_key_set = bool(env.get("TORII_ENCRYPTION_KEY", "").strip())
    session_https_only = _bool(env, "SESSION_HTTPS_ONLY", False)
    metrics_on = bool(env.get("METRICS_TOKEN", "").strip())

    # --- PUBLIC_BASE_URL ---------------------------------------------------
    report.postures.append(
        f"PUBLIC_BASE_URL={public_base_url or '(unset -> http://localhost)'}"
        f" [{'https' if https else 'http'}]"
    )
    if localhost:
        report.warnings.append(
            "PUBLIC_BASE_URL is localhost/unset: this is the OAuth issuer and "
            "WebAuthn origin, compared byte-for-byte by every client. Real "
            "Claude surfaces (web, mobile, Office) cannot complete a flow "
            "against a localhost issuer. Fine for local dev; set it to the "
            "public https hostname before exposing the gateway."
        )

    # --- SESSION_SECRET ----------------------------------------------------
    report.postures.append(
        f"SESSION_SECRET={'set' if session_secret_set else 'UNSET (auto-generated, ephemeral)'}"
    )
    if not session_secret_set:
        message = (
            "SESSION_SECRET is unset. torii self-generates one per process, so "
            "every restart logs out every session — and whoever learns the "
            "value can forge an admin session past password+TOTP+passkey. "
            "Generate a stable one: python -c \"import secrets; "
            "print(secrets.token_hex(32))\"."
        )
        if https:
            # https origin == internet-facing == a forgeable admin session is
            # not survivable. This is the worst combination in the issue.
            report.failures.append(
                message + " Refusing to start with an https PUBLIC_BASE_URL and "
                "no SESSION_SECRET."
            )
        else:
            report.warnings.append(message)

    # --- SESSION_HTTPS_ONLY ------------------------------------------------
    report.postures.append(f"SESSION_HTTPS_ONLY={session_https_only}")
    if https and not session_https_only:
        report.warnings.append(
            "PUBLIC_BASE_URL is https but SESSION_HTTPS_ONLY is false: the "
            "session cookie is sent without the Secure attribute. Set "
            "SESSION_HTTPS_ONLY=true so the login cookie never rides plain HTTP."
        )
    if not https and session_https_only:
        report.warnings.append(
            "SESSION_HTTPS_ONLY is true but PUBLIC_BASE_URL is http: the "
            "Secure cookie will never be set, so login will appear to silently "
            "fail. Serve over https or set SESSION_HTTPS_ONLY=false."
        )

    # --- TORII_ENCRYPTION_KEY ---------------------------------------------
    report.postures.append(
        f"TORII_ENCRYPTION_KEY={'set' if encryption_key_set else 'UNSET'}"
    )
    if not encryption_key_set:
        report.warnings.append(
            "TORII_ENCRYPTION_KEY is unset: upstream credentials cannot be "
            "encrypted at rest, and saving one is refused (#73). Set a Fernet "
            "key before registering an upstream that needs an auth header: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\"."
        )

    # --- /metrics ----------------------------------------------------------
    report.postures.append(
        f"METRICS_TOKEN={'set (/metrics on)' if metrics_on else 'unset (/metrics off)'}"
    )

    return report


def validate(env: Mapping[str, str], *, raise_on_fail: bool = True) -> ConfigReport:
    """Run the pass, log every posture and finding, and (unless
    TORII_ALLOW_INSECURE is set) raise on the first hard failure.

    Returns the report so the lifespan — and tests — can inspect it."""
    report = evaluate(env)

    log.info("config posture:")
    for line in report.postures:
        log.info("  %s", line)
    for line in report.warnings:
        log.warning("config: %s", line)
    for line in report.failures:
        log.error("config: %s", line)

    if report.failures and raise_on_fail:
        if report.allow_insecure:
            log.error(
                "TORII_ALLOW_INSECURE is set: starting anyway with %d unsafe "
                "config failure(s) above. Do not do this in production.",
                len(report.failures),
            )
        else:
            raise InsecureConfiguration(
                "refusing to start: "
                + "; ".join(report.failures)
                + " (set TORII_ALLOW_INSECURE=1 to override, at your own risk)"
            )
    return report

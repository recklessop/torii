"""Login-surface hardening (#64, #65, #66).

Three separate bugs on the pre-auth path:

* #64 — a non-IP forwarded header reached the `::inet` bind and was swallowed,
  so a brute-force with a garbage `X-Forwarded-For` left NO audit/lockout row
  and 500'd OAuth completion.
* #65 — the forwarded header was trusted unconditionally, so anyone could
  rotate it to dodge the login rate limiter.
* #66 — distinct failure messages and a bcrypt-only-when-the-row-exists path
  let an attacker enumerate usernames and time real vs non-existent accounts.
"""

import pyotp
import pytest
from starlette.requests import Request

from torii import audit, auth_backends, config, credentials, routes_oauth, routes_ui, web

LOCAL = auth_backends.LOCAL


def _request(headers: dict[str, str] | None = None, client=("203.0.113.9", 55555)) -> Request:
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": client,
    }
    return Request(scope)


# --- #64: only real IPs survive; garbage never reaches ::inet ---------------


def test_garbage_forwarded_header_never_returns_non_ip(monkeypatch):
    # Trust the peer so the header is even considered.
    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", True)
    req = _request({"x-forwarded-for": "not-an-ip"})
    ip = web.client_ip(req)
    # Falls through the unparseable header to the (valid) socket IP.
    assert ip == "203.0.113.9"


def test_garbage_header_and_garbage_peer_returns_none(monkeypatch):
    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", True)
    req = _request({"cf-connecting-ip": ";drop"}, client=("garbage", 0))
    assert web.client_ip(req) is None


def test_valid_forwarded_ip_is_normalised(monkeypatch):
    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", True)
    req = _request({"x-forwarded-for": " 198.51.100.7 , 10.0.0.1 "})
    assert web.client_ip(req) == "198.51.100.7"


def test_parse_ip_rejects_non_ips():
    assert web._parse_ip("not-an-ip") is None
    assert web._parse_ip("") is None
    assert web._parse_ip(None) is None
    assert web._parse_ip("2001:db8::1") == "2001:db8::1"


# --- #65: forwarded headers honoured only from a trusted peer ---------------


def test_untrusted_peer_ignores_forwarded_header(monkeypatch):
    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", False)
    monkeypatch.setattr(config, "TRUSTED_PROXY_NETWORKS", ())
    req = _request({"cf-connecting-ip": "9.9.9.9"}, client=("203.0.113.9", 5))
    # The spoofable header is ignored; the socket IP is what buckets/audits.
    assert web.client_ip(req) == "203.0.113.9"


def test_trusted_peer_honours_forwarded_header(monkeypatch):
    import ipaddress

    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", False)
    monkeypatch.setattr(
        config, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("203.0.113.0/24"),)
    )
    req = _request({"cf-connecting-ip": "9.9.9.9"}, client=("203.0.113.9", 5))
    assert web.client_ip(req) == "9.9.9.9"


def test_peer_outside_the_trusted_range_is_not_trusted(monkeypatch):
    import ipaddress

    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", False)
    monkeypatch.setattr(
        config, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("10.0.0.0/8"),)
    )
    req = _request({"cf-connecting-ip": "9.9.9.9"}, client=("203.0.113.9", 5))
    assert web.client_ip(req) == "203.0.113.9"


def test_trusted_proxy_parsing_drops_bad_entries():
    nets = config._trusted_networks("10.0.0.0/8, junk, 127.0.0.1, *, ")
    rendered = {str(n) for n in nets}
    assert "10.0.0.0/8" in rendered
    assert "127.0.0.1/32" in rendered
    assert all("junk" not in r for r in rendered)


# --- #66: one generic message for every pre-auth failure --------------------

_PRE_AUTH_REASONS = [
    auth_backends.UNKNOWN_PRINCIPAL,
    auth_backends.BAD_PASSWORD,
    auth_backends.DISABLED,
    auth_backends.LOCKED,
    auth_backends.NO_LOCAL_CREDENTIALS,
]


def test_ui_login_message_is_identical_across_pre_auth_failures():
    messages = {routes_ui._login_error(r) for r in _PRE_AUTH_REASONS}
    assert len(messages) == 1, messages


def test_oauth_login_message_is_identical_across_pre_auth_failures():
    messages = {routes_oauth._login_error_text(r) for r in _PRE_AUTH_REASONS}
    assert len(messages) == 1, messages


# --- #64 end to end: a garbage header can't erase the audit trail ----------


async def test_malformed_forwarded_header_still_writes_a_login_failure(conn, monkeypatch):
    """The whole point of #64: a bad-credential login with a junk
    `X-Forwarded-For` must still land a login_failure row (and not raise), so
    brute force stays visible and lockout can fire."""
    monkeypatch.setattr(config, "TRUST_ALL_PROXIES", True)
    req = _request({"x-forwarded-for": "not-an-ip"}, client=("198.51.100.4", 40000))

    ip = web.client_ip(req)  # must be a real IP or None, never the junk string
    assert ip in ("198.51.100.4", None)

    await audit.record_auth_event(
        conn,
        event=audit.LOGIN_FAILURE,
        outcome="failure",
        principal_label="alice",
        backend="local",
        ip=ip,
        detail={"flow": "ui", "reason": auth_backends.BAD_PASSWORD},
    )
    count = await conn.fetchval(
        "SELECT count(*) FROM audit_auth_events WHERE event = $1 AND principal_label = $2",
        audit.LOGIN_FAILURE, "alice",
    )
    assert count == 1


def test_both_helpers_agree_and_totp_prompt_stays_distinct():
    generic = routes_ui._login_error(auth_backends.UNKNOWN_PRINCIPAL)
    assert routes_oauth._login_error_text(auth_backends.BAD_PASSWORD) == generic
    # The second-factor prompt is post-password: it reveals no account state
    # and must still tell the user to enter their code.
    totp = routes_ui._login_error(auth_backends.TOTP_REQUIRED)
    assert totp != generic
    assert routes_oauth._login_error_text(auth_backends.TOTP_REQUIRED) == totp

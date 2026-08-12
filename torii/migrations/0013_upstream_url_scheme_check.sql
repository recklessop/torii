-- Schema-level scheme guard on upstream endpoint URLs (SSRF, issue #62).
--
-- An upstream endpoint URL is a server-side fetch target: proxy.py issues
-- requests to whatever string is stored, so a `file://`, `ftp://`, `gopher://`
-- or a `javascript:` value is not merely wrong, it is an attack surface. The
-- primary guard is validate_upstream_url() at the two write sites in
-- routes_ui.py, which also rejects internal IP literals. This CHECK is the
-- belt to that handler's braces: the house rule here is schema-enforced
-- invariants over handler checks, so that no future code path — an import, a
-- migration, a bulk edit, a second write site someone forgets to route through
-- the validator — can land a non-http(s) URL the proxy would then dereference.
--
-- Scope is deliberately narrow: the scheme prefix only. Host-range validation
-- stays in the application layer (validate_upstream_url), because it needs
-- `ipaddress` parsing and per-family reasoning a CHECK cannot express cleanly,
-- AND because the host-range POSTURE is intentionally configurable: torii is a
-- single-operator LAN gateway, so the default guard rejects only link-local /
-- cloud-metadata / unspecified targets and ALLOWS private + loopback + public
-- (a LAN upstream registered by private IP is the normal case). Strict mode
-- (TORII_STRICT_UPSTREAM_URLS=1) additionally blocks private + loopback +
-- reserved, for the future untrusted-upstream direction. A column CHECK cannot
-- be flag-conditional, so it holds only the invariant that is true in EVERY
-- posture: the scheme is http or https. Resolve-then-pin — the real fix for
-- hostnames that resolve inward — belongs at request time, not write time.
--
-- Additive and safe on the live dev database: every existing endpoint row was
-- written as an http(s) URL, so the constraint validates without a rewrite.

ALTER TABLE upstream_endpoints
    ADD CONSTRAINT upstream_endpoints_url_is_http
    CHECK (url ~* '^https?://');

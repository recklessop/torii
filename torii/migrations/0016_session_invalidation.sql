-- Give sessions a server-side revocation point (#61, #67).
--
-- UI sessions are stateless signed cookies: _require_login read is_admin and
-- principal_id straight from the cookie and never re-read `principals`, so a
-- disabled or demoted admin kept full /ui access until the cookie expired, and
-- a password change revoked nothing. The MCP path never had this — rbac
-- re-reads disabled_at per call — but the UI skipped it.
--
-- `sessions_valid_after` is that revocation point: any session minted at or
-- before this instant is no longer valid. Disabling a principal and changing or
-- resetting a password stamp it to now(), so every cookie issued earlier stops
-- validating on its next request (SessionRevalidationMiddleware enforces it).
-- NULL means "no cutoff" — the default, so existing sessions keep working until
-- the first credential change.

ALTER TABLE principals ADD COLUMN sessions_valid_after TIMESTAMPTZ;

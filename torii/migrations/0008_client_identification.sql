-- Make a connector identifiable (PRD Q16).
--
-- Every claude.ai surface self-registers with the same client_name, so a
-- phone, a desktop and an Office add-in all render as "claude.ai" — and with
-- several humans, as several identical rows. The label column existed but
-- nothing ever set it.
--
-- Two fixes: record what the browser said when the connector was authorized,
-- and let a human rename it afterwards (UI, no schema needed for that).

ALTER TABLE oauth_clients
    ADD COLUMN first_seen_user_agent TEXT,
    ADD COLUMN first_seen_ip INET;

-- Captured at FIRST authorization only, so it describes where the connector
-- was set up rather than wherever it was last used. That's the fact that
-- distinguishes "my phone" from "my desktop"; the audit log already carries
-- per-event addresses if you need the history.

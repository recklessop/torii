-- TOTP is mandatory for admins, optional per principal for everyone else
-- (PRD Q11).
--
-- The CHECK is the point: an admin row can never carry totp_required = FALSE,
-- so "admins always have two-factor" is a property of the schema rather than
-- a rule some code path might forget. Turning a normal user into an admin
-- therefore has to raise their TOTP requirement in the same statement.

ALTER TABLE principals
    ADD COLUMN totp_required BOOLEAN NOT NULL DEFAULT FALSE;

-- Existing admins keep two-factor; existing non-admins are grandfathered as
-- not-required, and an operator opts them in per principal.
UPDATE principals SET totp_required = TRUE WHERE is_admin = TRUE;

-- Anyone who already enrolled keeps their requirement — un-requiring TOTP for
-- someone who has a working authenticator would be a silent downgrade.
UPDATE principals p SET totp_required = TRUE
 WHERE EXISTS (
    SELECT 1 FROM auth_identities i
     WHERE i.principal_id = p.id AND i.backend = 'local' AND i.totp_secret IS NOT NULL
 );

ALTER TABLE principals
    ADD CONSTRAINT admins_always_require_totp
        CHECK (is_admin = FALSE OR totp_required = TRUE);

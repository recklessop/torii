-- Passkeys (WebAuthn discoverable credentials) as a parallel sign-in path
-- (PRD Q25). One gesture on a platform authenticator replaces password+TOTP:
-- possession of the device plus its biometric IS the two factors that pair
-- approximates. The password+TOTP path is untouched — it remains the
-- fallback and recovery path, and the admins_always_require_totp CHECK from
-- 0002 is deliberately not revisited.
--
-- Stored per principal, several per person (laptop, phone, security key),
-- each named so it can be recognised and revoked individually. The
-- credential id and the COSE public key are stored as raw bytes: they are
-- what the authenticator actually signs over, and round-tripping them
-- through base64url in the database buys nothing but decode bugs.
--
-- Humans-only is schema-enforced WITHOUT a trigger via a composite foreign
-- key: principals gains UNIQUE (id, kind), and this table carries a
-- principal_kind column CHECKed to 'human' that must match the referenced
-- row. A service principal therefore cannot own a passkey no matter what a
-- future handler forgets — the same reasoning as admins_always_require_totp.
-- The one cost: principals.kind becomes un-updatable for a row holding
-- passkeys, and nothing in the codebase updates kind.
--
-- No revoked_at soft-delete: unlike an API key, a passkey row has no
-- audit-chain children. Removal is a DELETE; history lives in
-- audit_auth_events (passkey_enrolled / passkey_revoked).

ALTER TABLE principals
    ADD CONSTRAINT principals_id_kind_unique UNIQUE (id, kind);

CREATE TABLE webauthn_credentials (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id    UUID        NOT NULL,
    principal_kind  TEXT        NOT NULL DEFAULT 'human'
                                CHECK (principal_kind = 'human'),
    credential_id   BYTEA       NOT NULL UNIQUE,
    public_key      BYTEA       NOT NULL,          -- COSE, as attested
    -- Apple platform authenticators report 0 forever; the verifier only
    -- checks regression when either side is non-zero, so 0 -> 0 passes.
    -- BIGINT because the spec counter is uint32.
    sign_count      BIGINT      NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports      TEXT[]      NOT NULL DEFAULT '{}',
    aaguid          UUID,                          -- authenticator model, display only
    -- Sync state from the attestation flags (BE/BS). Display and audit
    -- context only — never an authorization input.
    backup_eligible BOOLEAN     NOT NULL DEFAULT FALSE,
    backed_up       BOOLEAN     NOT NULL DEFAULT FALSE,
    name            TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,

    CONSTRAINT webauthn_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT webauthn_belongs_to_a_human
        FOREIGN KEY (principal_id, principal_kind)
        REFERENCES principals (id, kind) ON DELETE CASCADE
);

CREATE INDEX webauthn_credentials_principal_idx
    ON webauthn_credentials (principal_id);

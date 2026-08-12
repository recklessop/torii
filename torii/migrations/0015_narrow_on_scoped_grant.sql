-- Make "a scoped credential is NARROWED" a schema invariant, not a handler
-- promise (#60).
--
-- Narrowing is driven by access_mode (see rbac.resolve/decide): a credential
-- that carries a client- or key-scoped grant MUST have access_mode='narrowed',
-- or the resolver would treat its grants as a no-op and hand it the owner's
-- full baseline. The write paths (create_grant, self-service scoping) set the
-- mode, and 0014 backfilled existing rows — but that is a handler guarantee,
-- and the house rule is that an invariant a future code path could break
-- belongs in the schema. This is cross-table (grants -> oauth_clients/api_keys),
-- which a CHECK constraint cannot express, so it is the one place a trigger
-- earns its keep: any INSERT of a client/key-scoped grant stamps the mode,
-- whatever path wrote it.
--
-- One-directional on purpose: scoping narrows, but deleting a credential's last
-- grant does NOT widen it back. A narrowed credential with no grants reaches
-- nothing, which is the safe reading of "the operator scoped this, then removed
-- everything" — never a silent return to the full baseline.

CREATE OR REPLACE FUNCTION narrow_scoped_credential() RETURNS trigger AS $$
BEGIN
    IF NEW.subject_type = 'client' THEN
        UPDATE oauth_clients
           SET access_mode = 'narrowed', updated_at = now()
         WHERE client_id = NEW.client_id
           AND access_mode <> 'narrowed';
    ELSIF NEW.subject_type = 'key' THEN
        UPDATE api_keys
           SET access_mode = 'narrowed'
         WHERE id = NEW.api_key_id
           AND access_mode <> 'narrowed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS grants_narrow_credential ON grants;
CREATE TRIGGER grants_narrow_credential
    AFTER INSERT ON grants
    FOR EACH ROW
    WHEN (NEW.subject_type IN ('client', 'key'))
    EXECUTE FUNCTION narrow_scoped_credential();

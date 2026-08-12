-- Scoped static keys (PRD Q15).
--
-- The question that prompted this: if a user has access to several servers,
-- can they mint a key that only reaches one of them — or do we just tell them
-- to use that server's URL?
--
-- Telling them to use the URL would be a lie. `/<slug>/mcp` is a naming
-- convenience, not a boundary (Q13): one authorization path serves both
-- endpoint shapes, so a key with baseline access can point at `/mcp` and
-- reach everything no matter which URL it was handed. Isolation has to live
-- in the grant.
--
-- So keys get the same treatment OAuth clients got in Q14: a grant subject of
-- their own, plus an explicit mode so "limited" survives having no grants yet.

ALTER TABLE grants
    ADD COLUMN api_key_id UUID REFERENCES api_keys (id) ON DELETE CASCADE;

-- Replace the exactly-one-subject rule to include the new subject type. Same
-- property as before: a grant with no subject, or two, stays unrepresentable.
ALTER TABLE grants DROP CONSTRAINT grant_subject_matches_type;

ALTER TABLE grants
    ADD CONSTRAINT grant_subject_matches_type CHECK (
        (subject_type = 'principal'
             AND principal_id IS NOT NULL AND client_id IS NULL
             AND group_name IS NULL AND api_key_id IS NULL)
     OR (subject_type = 'client'
             AND client_id IS NOT NULL AND principal_id IS NULL
             AND group_name IS NULL AND api_key_id IS NULL)
     OR (subject_type = 'group'
             AND group_name IS NOT NULL AND principal_id IS NULL
             AND client_id IS NULL AND api_key_id IS NULL)
     OR (subject_type = 'key'
             AND api_key_id IS NOT NULL AND principal_id IS NULL
             AND client_id IS NULL AND group_name IS NULL)
    );

ALTER TABLE grants DROP CONSTRAINT grants_subject_type_check;
ALTER TABLE grants
    ADD CONSTRAINT grants_subject_type_check
        CHECK (subject_type IN ('principal', 'client', 'group', 'key'));

CREATE UNIQUE INDEX grants_key_upstream_idx
    ON grants (api_key_id, upstream_id) WHERE subject_type = 'key';

-- Same two values, same meaning, as oauth_clients.access_mode:
--   'inherit'  — no key grants means the principal's baseline applies
--   'narrowed' — bounded by its own grants, so none means no access
ALTER TABLE api_keys
    ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'inherit'
        CHECK (access_mode IN ('inherit', 'narrowed'));

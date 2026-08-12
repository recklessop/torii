-- torii-local groups with local membership (#54).
--
-- Half of this was already here and dormant: `grants.subject_type = 'group'`
-- has existed since 0001, and the resolver has always unioned group grants
-- into the baseline. What was missing is MEMBERSHIP — `Caller.groups` only
-- ever carried IdP claims, and nothing populates those until the Authentik
-- connector lands (#17). So a group grant matched nobody, and `group_name`
-- was unvalidated free text: a typo was silently a group of zero.
--
-- Two tables and one foreign key close that. The join key stays `group_name`
-- rather than a new `grants.group_id` column, deliberately:
--
--   * `grants` keeps its exact shape, so `grant_subject_matches_type` and
--     `grants_group_upstream_idx` stay valid and untouched;
--   * renames cascade, and deleting a group takes its grants with it;
--   * "a grant pointing at a group that doesn't exist" becomes
--     unrepresentable — the schema-enforced-invariant rule, same pattern as
--     0002-0004.
--
-- Two keys for one subject would be exactly the second-authorization-path
-- smell this project exists to avoid.

CREATE TABLE groups (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE CHECK (length(btrim(name)) > 0),
    description TEXT,
    -- The Authentik seam (#17): the claim value that maps INTO this group.
    -- NULL means local-only — no IdP claim can ever satisfy it, because
    -- `NULL = ANY(...)` is never true. Nothing populates `Caller.groups`
    -- yet; this column is the mapping and nothing more.
    idp_claim   TEXT        UNIQUE CHECK (idp_claim IS NULL OR length(btrim(idp_claim)) > 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID        REFERENCES principals (id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 'Family' and 'family' as two groups is a support call waiting to happen:
-- an admin grants one and adds members to the other. The FK match itself
-- stays exact, so names are trimmed on input, never silently lowercased.
CREATE UNIQUE INDEX groups_name_ci_idx ON groups (lower(name));

CREATE TABLE group_members (
    group_id     UUID        NOT NULL REFERENCES groups (id)     ON DELETE CASCADE,
    principal_id UUID        NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by     UUID        REFERENCES principals (id) ON DELETE SET NULL,
    PRIMARY KEY (group_id, principal_id)
);

CREATE INDEX group_members_principal_idx ON group_members (principal_id);

-- Backfill BEFORE constraining. The dev database has real state, and any
-- free-text group grant written before this migration must end up owned by a
-- real row rather than rejected at ALTER time.
INSERT INTO groups (name, description)
SELECT DISTINCT g.group_name, 'Adopted from an existing grant when groups landed'
  FROM grants g
 WHERE g.subject_type = 'group' AND g.group_name IS NOT NULL
ON CONFLICT DO NOTHING;

ALTER TABLE grants
    ADD CONSTRAINT grants_group_name_fkey
        FOREIGN KEY (group_name) REFERENCES groups (name)
        ON UPDATE CASCADE ON DELETE CASCADE;

-- User-owned service principals (PRD Q17).
--
-- The gap: creating a service principal was admin-only, so a second human
-- couldn't provision a machine identity for their own script without asking
-- an operator every time.
--
-- The resolution keeps two things distinct, because they have opposite
-- security properties:
--
--   * A DELEGATED service (owner_id set) is a deputy of a person. Its access
--     is intersected with its owner's, so it can never escalate, and it stops
--     working when the owner is disabled. Safe to self-provision precisely
--     because of those two properties.
--   * An INDEPENDENT service (owner_id NULL) has its own grants and its own
--     lifecycle, and survives any person leaving. That needs authority beyond
--     one user, so it stays admin-created — an admin "detaches" a delegated
--     service to promote it.

ALTER TABLE principals
    ADD COLUMN owner_id UUID REFERENCES principals (id) ON DELETE CASCADE;

-- Only a service can be owned (a human answering to another human is a
-- different feature, and not one anybody asked for), and nothing may own
-- itself.
ALTER TABLE principals
    ADD CONSTRAINT only_services_have_owners
        CHECK (owner_id IS NULL OR kind = 'service'),
    ADD CONSTRAINT owner_is_not_self
        CHECK (owner_id IS NULL OR owner_id <> id);

CREATE INDEX principals_owner_idx ON principals (owner_id) WHERE owner_id IS NOT NULL;

-- ON DELETE CASCADE above is deliberate: deleting a human takes their
-- delegated services with them, which is the same reasoning as their keys and
-- connectors. Promote a service first if it should outlive them.

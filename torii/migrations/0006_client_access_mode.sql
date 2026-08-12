-- Make per-client narrowing durable (PRD Q14).
--
-- The hole: DCR mints a fresh client_id on every registration, and grants are
-- keyed on client_id. So removing and re-adding a narrowed connector produced
-- a NEW client with no client-scoped grants, which under the old resolver
-- meant "inherit the principal's full baseline". The stolen-phone protection
-- (Q8) silently evaporated on an action that feels routine.
--
-- Reusing a client row when client_name + redirect_uris match was rejected:
-- claude.ai's redirect_uri is identical for every user and DCR is
-- unauthenticated, so matching on it would let a stranger's registration bind
-- to an existing client row that already holds a principal and grants. That
-- swaps a silent-widening bug for an account-takeover path.
--
-- Instead: narrowing becomes an explicit MODE on the client, so "this client
-- is limited" survives having no grants yet, and a principal can opt to have
-- every newly registered client start limited.

ALTER TABLE oauth_clients
    ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'inherit'
        CHECK (access_mode IN ('inherit', 'narrowed'));

-- 'inherit'  — no client grants means the principal's baseline applies
--              (today's behaviour, and what a normal connector wants).
-- 'narrowed' — this client is limited to its own grants, FULL STOP. With no
--              grants that means no access, rather than everything. An empty
--              ceiling can't be expressed as a grant row (the schema forbids
--              a 'list' grant with no tools), which is exactly why this is a
--              column and not a magic row.

-- Existing clients that already carry narrowing keep behaving as they do, but
-- are marked so the intent is explicit rather than inferred from row counts.
UPDATE oauth_clients c SET access_mode = 'narrowed'
 WHERE EXISTS (SELECT 1 FROM grants g WHERE g.client_id = c.client_id);

-- Per-principal default, applied when a client first binds at authorization.
-- Off by default: turning it on makes every new connector start with an empty
-- tool list until its owner grants it something, which is safer but not
-- zero-touch, so it's a choice rather than an imposition.
ALTER TABLE principals
    ADD COLUMN narrow_new_clients BOOLEAN NOT NULL DEFAULT FALSE;

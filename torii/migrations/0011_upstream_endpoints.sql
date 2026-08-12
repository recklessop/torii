-- Several URLs per upstream (PRD Q24, issue #51).
--
-- An upstream was one row with one url, so torii could point at exactly one
-- copy of a server: a backend restart was a caller-visible outage and a second
-- replica was unrepresentable. Endpoints move to their own table, which also
-- gives per-replica health somewhere to live.
--
-- `upstreams.url` and the three `upstreams.last_health_*` columns are DROPPED
-- rather than kept as a "primary URL plus extras". Keeping them would be a
-- second source of truth for both routing and health — the same failure mode
-- Q24 rejected an operator-set "stateless" flag for — and it would make
-- "disable the primary replica" unrepresentable. The upstream-level health
-- pill becomes derived from the endpoint rows.
--
-- No "at least one endpoint" constraint: enforcing it needs a trigger, which
-- this codebase deliberately doesn't use. Zero enabled endpoints instead fails
-- closed and audited in the proxy (a clean UPSTREAM_UNAVAILABLE), and the UI
-- refuses to delete the last endpoint.

CREATE TABLE upstream_endpoints (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    upstream_id       UUID        NOT NULL REFERENCES upstreams (id) ON DELETE CASCADE,
    url               TEXT        NOT NULL,
    -- Selection is on `enabled` alone in this first pass. No outlier ejection,
    -- no circuit breaker: the retry walk absorbs a dead replica.
    enabled           BOOLEAN     NOT NULL DEFAULT TRUE,
    last_health_at    TIMESTAMPTZ,
    last_health_ok    BOOLEAN,
    last_health_error TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The same URL twice on one upstream is a typo, never a second replica.
    UNIQUE (upstream_id, url)
);

CREATE INDEX upstream_endpoints_upstream_idx ON upstream_endpoints (upstream_id);

-- Backfill BEFORE the drop: the dev database has real state.
INSERT INTO upstream_endpoints
        (upstream_id, url, last_health_at, last_health_ok, last_health_error, created_at)
    SELECT id, url, last_health_at, last_health_ok, last_health_error, created_at
      FROM upstreams;

ALTER TABLE upstreams
    DROP COLUMN url,
    DROP COLUMN last_health_at,
    DROP COLUMN last_health_ok,
    DROP COLUMN last_health_error;

-- Which replica served the call. Recorded on the ok AND the upstream_error
-- path — the failing replica is the one you most need named. ON DELETE SET
-- NULL, with the URL kept alongside, so history survives a replica being
-- removed exactly the way it survives an upstream being deleted.
ALTER TABLE audit_calls
    ADD COLUMN endpoint_id  UUID REFERENCES upstream_endpoints (id) ON DELETE SET NULL,
    ADD COLUMN endpoint_url TEXT;

-- Per-credential and per-principal rate limits (PRD Q19).
--
-- Section 7 lists this as the mitigation for a stolen static key: today a
-- leaked tor_ key can call as fast as the upstreams will answer. Login attempts
-- are already limited (per-IP window plus per-identity lockout); tool calls
-- were not.
--
-- NULL means "use the next level up", so precedence is key → principal →
-- DEFAULT_RATE_LIMIT_PER_MIN. That way raising the default lifts everyone who
-- hasn't been given a specific number, which is the behaviour an operator
-- expects from a default.

ALTER TABLE api_keys
    ADD COLUMN rate_limit_per_min INTEGER
        CHECK (rate_limit_per_min IS NULL OR rate_limit_per_min > 0);

ALTER TABLE principals
    ADD COLUMN rate_limit_per_min INTEGER
        CHECK (rate_limit_per_min IS NULL OR rate_limit_per_min > 0);

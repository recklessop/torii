-- torii initial schema (PRD sections 4, 5 FR2/FR3/FR5; CLAUDE.md P1 step 2).
--
-- Shape notes that the rest of the codebase depends on:
--   * Default deny is structural: access exists only as a row in `grants`.
--     There is no admin bypass column, by design (FR3). `principals.is_admin`
--     governs the /ui admin screens ONLY and is never consulted when
--     answering "may this caller call this tool".
--   * The auth-backend seam (Q9/Q9b/Q9c) is one table, `auth_identities`:
--     local credentials at launch, an OIDC identity row when the Authentik
--     connector lands in P3+. Both resolve to the same principal, so auth
--     method never changes authorization.
--   * Audit rows denormalize the labels they reference (principal_label,
--     upstream_name, tool_name) so a deleted principal or upstream never
--     erases history. FKs are ON DELETE SET NULL for the same reason.

-- ---------------------------------------------------------------- principals

CREATE TABLE principals (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          TEXT        NOT NULL CHECK (kind IN ('human', 'service')),
    username      TEXT        NOT NULL UNIQUE,
    display_name  TEXT,
    -- /ui admin access only. NOT an RBAC bypass (FR3).
    is_admin      BOOLEAN     NOT NULL DEFAULT FALSE,
    disabled_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Service principals authenticate with static keys only, never a login.
    CONSTRAINT service_principals_are_never_admins
        CHECK (kind = 'human' OR is_admin = FALSE)
);

CREATE INDEX principals_kind_idx ON principals (kind);

-- ----------------------------------------------------------- auth identities

CREATE TABLE auth_identities (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id     UUID        NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    backend          TEXT        NOT NULL CHECK (backend IN ('local', 'oidc')),

    -- local backend (bcrypt + TOTP)
    password_hash    TEXT,
    password_is_temp BOOLEAN     NOT NULL DEFAULT FALSE,
    totp_secret      TEXT,
    totp_enrolled_at TIMESTAMPTZ,
    failed_attempts  INTEGER     NOT NULL DEFAULT 0,
    locked_until     TIMESTAMPTZ,

    -- oidc backend (P3+; rows only exist once a connector is configured)
    provider         TEXT,
    subject          TEXT,
    email            TEXT,

    last_login_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT local_identity_has_password
        CHECK (backend <> 'local' OR password_hash IS NOT NULL),
    CONSTRAINT oidc_identity_has_provider_and_subject
        CHECK (backend <> 'oidc' OR (provider IS NOT NULL AND subject IS NOT NULL))
);

-- One local credential per principal; one principal per (provider, subject).
CREATE UNIQUE INDEX auth_identities_one_local_per_principal
    ON auth_identities (principal_id) WHERE backend = 'local';
CREATE UNIQUE INDEX auth_identities_oidc_subject
    ON auth_identities (provider, subject) WHERE backend = 'oidc';
CREATE INDEX auth_identities_principal_idx ON auth_identities (principal_id);

-- -------------------------------------------------------------- oauth clients

CREATE TABLE oauth_clients (
    client_id                TEXT        PRIMARY KEY,
    -- NULL for public clients (PKCE only) — the common claude.ai DCR case.
    client_secret_hash       TEXT,
    client_name              TEXT        NOT NULL,
    redirect_uris            TEXT[]      NOT NULL DEFAULT '{}',
    grant_types              TEXT[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    response_types           TEXT[]      NOT NULL DEFAULT '{code}',
    scope                    TEXT,
    token_endpoint_auth_method TEXT      NOT NULL DEFAULT 'none',
    registered_via           TEXT        NOT NULL DEFAULT 'dcr'
                                         CHECK (registered_via IN ('dcr', 'manual')),
    -- The human who completed an authorization with this client. NULL right
    -- after DCR: registration alone grants nothing (FR2), and an unbound
    -- client can hold no grants.
    principal_id             UUID        REFERENCES principals (id) ON DELETE CASCADE,
    -- Operator label, e.g. "phone" vs "desktop" vs "PPT add-in" — the thing
    -- per-client narrowing (Q8) is written against.
    label                    TEXT,
    last_seen_at             TIMESTAMPTZ,
    disabled_at              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX oauth_clients_principal_idx ON oauth_clients (principal_id);

-- -------------------------------------------------------------------- tokens

-- Access and refresh tokens, hashed. Rotation is a chain: the refresh token
-- issued in place of a used one points back at it via rotated_from, so a
-- replayed refresh is detectable.
CREATE TABLE tokens (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          TEXT        NOT NULL CHECK (kind IN ('access', 'refresh')),
    token_hash    TEXT        NOT NULL UNIQUE,
    principal_id  UUID        NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    client_id     TEXT        NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    scope         TEXT,
    -- RFC 8707 audience, when a client sends one.
    resource      TEXT,
    rotated_from  UUID        REFERENCES tokens (id) ON DELETE SET NULL,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    revoked_reason TEXT
);

CREATE INDEX tokens_principal_idx ON tokens (principal_id);
CREATE INDEX tokens_client_idx ON tokens (client_id);
CREATE INDEX tokens_expiry_idx ON tokens (expires_at) WHERE revoked_at IS NULL;

-- ------------------------------------------------------------------ api keys

-- Static bearer keys (tor_ prefix, shown once, hashed at rest). Same grant
-- evaluation path as OAuth tokens (FR2/FR3).
CREATE TABLE api_keys (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id  UUID        NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    name          TEXT        NOT NULL,
    -- Leading, non-secret fragment shown in the UI so a key is identifiable
    -- after its one-time reveal (e.g. "tor_a1b2c3").
    key_prefix    TEXT        NOT NULL,
    key_hash      TEXT        NOT NULL UNIQUE,
    rotated_from  UUID        REFERENCES api_keys (id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    UUID        REFERENCES principals (id) ON DELETE SET NULL,
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    revoked_reason TEXT
);

CREATE INDEX api_keys_principal_idx ON api_keys (principal_id);
CREATE INDEX api_keys_prefix_idx ON api_keys (key_prefix);

-- ----------------------------------------------------------------- upstreams

CREATE TABLE upstreams (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Namespace segment in <server>__<tool>; MetaMCP-compatible so client
    -- migration is a URL swap. Kept to what survives that concatenation.
    name              TEXT        NOT NULL UNIQUE
                                  CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    description       TEXT,
    url               TEXT        NOT NULL,
    -- Optional credential the gateway presents to the upstream. Write-only
    -- in the UI; gateway credentials are never forwarded upstream (section 7).
    auth_header_name  TEXT,
    auth_header_value TEXT,
    timeout_seconds   INTEGER     NOT NULL DEFAULT 30 CHECK (timeout_seconds BETWEEN 1 AND 300),
    enabled           BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Opt-in debug payload capture (FR5); off everywhere by default.
    capture_payloads  BOOLEAN     NOT NULL DEFAULT FALSE,
    last_health_at    TIMESTAMPTZ,
    last_health_ok    BOOLEAN,
    last_health_error TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -------------------------------------------------------------------- grants

-- The whole authorization model (FR3). Subject is a principal, ONE of that
-- principal's OAuth clients (narrowing, Q8), or an IdP group name (Q9).
-- Target is an upstream plus a tool scope: every tool on it, or a list.
CREATE TABLE grants (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type TEXT        NOT NULL CHECK (subject_type IN ('principal', 'client', 'group')),
    principal_id UUID        REFERENCES principals (id) ON DELETE CASCADE,
    client_id    TEXT        REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    group_name   TEXT,
    upstream_id  UUID        NOT NULL REFERENCES upstreams (id) ON DELETE CASCADE,
    tool_scope   TEXT        NOT NULL CHECK (tool_scope IN ('all', 'list')),
    tools        TEXT[]      NOT NULL DEFAULT '{}',
    note         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   UUID        REFERENCES principals (id) ON DELETE SET NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Exactly one subject column, matching subject_type. Keeps "a grant with
    -- no subject" and "a wildcard grant" unrepresentable (FR3: no wildcard
    -- principal or group).
    CONSTRAINT grant_subject_matches_type CHECK (
        (subject_type = 'principal'
             AND principal_id IS NOT NULL AND client_id IS NULL AND group_name IS NULL)
     OR (subject_type = 'client'
             AND client_id IS NOT NULL AND principal_id IS NULL AND group_name IS NULL)
     OR (subject_type = 'group'
             AND group_name IS NOT NULL AND principal_id IS NULL AND client_id IS NULL)
    ),
    -- 'list' means an explicit, non-empty tool list; 'all' carries no list.
    CONSTRAINT grant_tools_match_scope CHECK (
        (tool_scope = 'all'  AND cardinality(tools) = 0)
     OR (tool_scope = 'list' AND cardinality(tools) > 0)
    ),
    CONSTRAINT grant_group_name_not_blank
        CHECK (group_name IS NULL OR length(btrim(group_name)) > 0)
);

-- One grant row per (subject, upstream): the tool scope is edited in place
-- rather than accumulated, so what the UI shows is what the resolver sees.
CREATE UNIQUE INDEX grants_principal_upstream_idx
    ON grants (principal_id, upstream_id) WHERE subject_type = 'principal';
CREATE UNIQUE INDEX grants_client_upstream_idx
    ON grants (client_id, upstream_id) WHERE subject_type = 'client';
CREATE UNIQUE INDEX grants_group_upstream_idx
    ON grants (group_name, upstream_id) WHERE subject_type = 'group';
CREATE INDEX grants_upstream_idx ON grants (upstream_id);

-- --------------------------------------------------------------------- audit

-- Per-call record (FR5). No argument or result payloads by default.
CREATE TABLE audit_calls (
    id              BIGSERIAL   PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    principal_id    UUID        REFERENCES principals (id) ON DELETE SET NULL,
    principal_label TEXT,
    client_id       TEXT        REFERENCES oauth_clients (client_id) ON DELETE SET NULL,
    api_key_id      UUID        REFERENCES api_keys (id) ON DELETE SET NULL,
    upstream_id     UUID        REFERENCES upstreams (id) ON DELETE SET NULL,
    upstream_name   TEXT,
    tool_name       TEXT,
    method          TEXT        NOT NULL,
    outcome         TEXT        NOT NULL
                                CHECK (outcome IN ('ok', 'denied', 'error', 'upstream_error')),
    error_code      TEXT,
    latency_ms      INTEGER,
    request_id      TEXT,
    session_id      TEXT
);

CREATE INDEX audit_calls_ts_idx ON audit_calls (ts DESC);
CREATE INDEX audit_calls_principal_ts_idx ON audit_calls (principal_id, ts DESC);
CREATE INDEX audit_calls_outcome_ts_idx ON audit_calls (outcome, ts DESC);

-- Auth events (FR5): logins, failures, token issuance, revocations, DCR.
CREATE TABLE audit_auth_events (
    id              BIGSERIAL   PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    event           TEXT        NOT NULL,
    outcome         TEXT        NOT NULL CHECK (outcome IN ('ok', 'failure')),
    principal_id    UUID        REFERENCES principals (id) ON DELETE SET NULL,
    -- What the caller claimed to be, even when no principal matched.
    principal_label TEXT,
    client_id       TEXT        REFERENCES oauth_clients (client_id) ON DELETE SET NULL,
    api_key_id      UUID        REFERENCES api_keys (id) ON DELETE SET NULL,
    backend         TEXT,
    ip              INET,
    user_agent      TEXT,
    detail          JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_auth_events_ts_idx ON audit_auth_events (ts DESC);
CREATE INDEX audit_auth_events_event_ts_idx ON audit_auth_events (event, ts DESC);
CREATE INDEX audit_auth_events_principal_ts_idx ON audit_auth_events (principal_id, ts DESC);

-- Public directory of MCP servers hosted behind torii (PRD Q12).
--
-- Opt-in per upstream, default OFF: a server is private until an admin
-- deliberately publishes it. Listing publishes the name, description and tool
-- list — never the LAN URL and never the auth header — and grants nobody
-- access. A public listing plus default-deny means "you can read what this
-- does and how to connect" without "you can call it".

ALTER TABLE upstreams
    ADD COLUMN public_listed BOOLEAN NOT NULL DEFAULT FALSE;

-- Longer human/agent-facing copy for the directory page. Falls back to
-- `description` when unset, so listing a server needs no extra writing.
ALTER TABLE upstreams
    ADD COLUMN public_summary TEXT;

-- Homepage/docs link for a listed server, when it has one.
ALTER TABLE upstreams
    ADD COLUMN public_url TEXT;

CREATE INDEX upstreams_public_idx ON upstreams (public_listed)
    WHERE public_listed = TRUE;

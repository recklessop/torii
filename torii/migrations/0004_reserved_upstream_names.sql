-- Per-server MCP endpoints live at /<server>/mcp (PRD Q13), which puts
-- upstream names into the same URL namespace as torii's own routes. A server
-- called "ui" or "oauth" would shadow the gateway itself.
--
-- Enforced in the schema rather than in a form handler: the name is what
-- builds the URL, so an unroutable name must be unrepresentable, not merely
-- rejected by whichever code path happens to check.

ALTER TABLE upstreams
    ADD CONSTRAINT upstream_name_not_reserved
        CHECK (name NOT IN (
            'ui', 'mcp', 'oauth', 'authorize', 'healthz', 'directory',
            'marketplace', 'robots', 'sitemap', 'static', 'assets',
            'well-known', 'api', 'admin', 'login', 'logout', 'docs',
            'openapi', 'favicon'
        ));

-- An upstream's `name` is its SLUG: it's the `<server>` path segment in
-- /<server>/mcp and the prefix in <server>__<tool>, which is why it carries
-- the lowercase/dash CHECK and the reserved-word list.
--
-- That leaves nowhere to put a human label, so add one. Display names are
-- free text ("Work Knowledge", "BRAIN — Open Brain"); the slug stays the
-- machine-facing identifier. Grants reference upstream_id, so editing a slug
-- later never orphans a grant — it only changes the URL and the tool prefix
-- that clients see, which the UI warns about.

ALTER TABLE upstreams
    ADD COLUMN display_name TEXT;

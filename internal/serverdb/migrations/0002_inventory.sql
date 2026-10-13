-- 0002_inventory.sql
-- Host inventory model (spec 12): display name, environment and
-- criticality on hosts, plus key=value tags in their own table.
--
-- The 0001 tags/host_tags tables hold UI tag labels (name, color) and
-- are left untouched; spec 12 tags are key=value pairs (role=web) and
-- live in host_tag_kv. Endpoint order is the explicit priority column
-- of host_endpoints (0-based position set by the admin); nothing in the
-- inventory reorders it.

ALTER TABLE hosts ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN environment TEXT NOT NULL DEFAULT 'DEV';
ALTER TABLE hosts ADD COLUMN criticality TEXT NOT NULL DEFAULT 'LOW';

CREATE TABLE host_tag_kv (
    host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag_key   TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (host_id, tag_key)
);

CREATE INDEX idx_host_tag_kv_host ON host_tag_kv (host_id);

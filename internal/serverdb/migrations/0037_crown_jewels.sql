-- 0037_crown_jewels.sql
-- Crown jewels: the attack-path targets the maintainer marks (ADR 0011 D10,
-- Q7 decided 2026-11-09; plan VU-23).
--
-- A crown jewel is an attack-path node (internal/attackpath node ID, its
-- kind fixed by the ID prefix) with a role and an impact weight 1–10.
-- Roles name what the subject is (NOS executor host, firewall, Proxmox
-- node, NAS, Home Assistant host, other); the default weights by role
-- (executor host and firewall 10, the others 8) are suggestions the admin
-- confirms or changes in the UI. The weight stored here is always the one
-- the admin entered; nothing in NOS fills it from a role or a name.
-- Synthetic entries (internet, netbird) and unmanaged endpoints (unk:) are
-- never targets. At most 50 rows (attackpath.MaxTargets), enforced by
-- internal/attackpath/jewels in the write transaction.
--
-- crown_jewel_history: every mark, change and unmark with the admin, the
-- reason, the old and new role and weight and the suggested weight shown
-- for the role, so the audit trail survives in server.db beside the audit
-- log line the store writes. Rows are kept; they are bounded by admin
-- actions, not by managed hosts.

CREATE TABLE crown_jewels (
    node_id    TEXT PRIMARY KEY CHECK (
        length(CAST(node_id AS BLOB)) BETWEEN 1 AND 128
        AND (
            (substr(node_id, 1, 5) = 'host:'  AND length(node_id) > 5) OR
            (substr(node_id, 1, 4) = 'pve:'   AND length(node_id) > 4) OR
            (substr(node_id, 1, 6) = 'guest:' AND length(node_id) > 6) OR
            (substr(node_id, 1, 4) = 'ctr:'   AND length(node_id) > 4) OR
            (substr(node_id, 1, 4) = 'dev:'   AND length(node_id) > 4)
        )
    ),
    role       TEXT NOT NULL CHECK (role IN ('executor_host', 'firewall', 'pve_node', 'nas', 'home_assistant', 'other')),
    impact     INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 10),
    marked_by  TEXT NOT NULL CHECK (length(CAST(marked_by AS BLOB)) BETWEEN 1 AND 128),
    reason     TEXT NOT NULL DEFAULT '' CHECK (length(CAST(reason AS BLOB)) <= 512),
    marked_at  INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE crown_jewel_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id          TEXT NOT NULL CHECK (length(CAST(node_id AS BLOB)) BETWEEN 1 AND 128),
    action           TEXT NOT NULL CHECK (action IN ('marked', 'changed', 'unmarked')),
    old_role         TEXT CHECK (old_role IS NULL OR old_role IN ('executor_host', 'firewall', 'pve_node', 'nas', 'home_assistant', 'other')),
    old_impact       INTEGER CHECK (old_impact IS NULL OR old_impact BETWEEN 1 AND 10),
    new_role         TEXT CHECK (new_role IS NULL OR new_role IN ('executor_host', 'firewall', 'pve_node', 'nas', 'home_assistant', 'other')),
    new_impact       INTEGER CHECK (new_impact IS NULL OR new_impact BETWEEN 1 AND 10),
    suggested_impact INTEGER CHECK (suggested_impact IS NULL OR suggested_impact BETWEEN 1 AND 10),
    admin            TEXT NOT NULL CHECK (length(CAST(admin AS BLOB)) BETWEEN 1 AND 128),
    reason           TEXT NOT NULL DEFAULT '' CHECK (length(CAST(reason AS BLOB)) <= 512),
    at               INTEGER NOT NULL,
    CHECK ((action = 'marked') = (old_role IS NULL)),
    CHECK ((action = 'unmarked') = (new_role IS NULL)),
    CHECK ((old_role IS NULL) = (old_impact IS NULL)),
    CHECK ((new_role IS NULL) = (new_impact IS NULL))
);
CREATE INDEX idx_crown_jewel_history_at ON crown_jewel_history (id DESC);

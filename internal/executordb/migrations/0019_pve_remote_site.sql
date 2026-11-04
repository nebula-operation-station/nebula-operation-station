-- 0019_pve_remote_site.sql (ADR 0006 P2-01, node reboot): an admin-set
-- site marker on each PVE remote. 'onsite' and 'offsite' are set only by
-- the local admin (nebula pve remote set-site); '' means not set, which
-- the node reboot treats as unknown and refuses (fail closed): an offsite
-- node reboot is CRITICAL, manual and needs an agreed recovery path, so
-- NOS never offers it.
ALTER TABLE pve_remotes ADD COLUMN site TEXT NOT NULL DEFAULT ''
    CHECK (site IN ('', 'onsite', 'offsite'));

-- The append-only change trail gains the 'site' change type. SQLite cannot
-- alter a CHECK constraint, so the table is rebuilt with its rows and ids.
CREATE TABLE pve_remote_changes_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    remote_id   TEXT NOT NULL,
    change_type TEXT NOT NULL CHECK (change_type IN ('created', 're_added', 'endpoint_change', 'trust_repin', 'blocked', 'unblocked', 'credentials', 'removed', 'site')),
    detail      TEXT NOT NULL CHECK (length(detail) <= 512),
    actor       TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 64),
    at          INTEGER NOT NULL
);
INSERT INTO pve_remote_changes_new (id, remote_id, change_type, detail, actor, at)
    SELECT id, remote_id, change_type, detail, actor, at FROM pve_remote_changes;
DROP TABLE pve_remote_changes;
ALTER TABLE pve_remote_changes_new RENAME TO pve_remote_changes;
CREATE INDEX pve_remote_changes_remote_idx ON pve_remote_changes (remote_id, id);

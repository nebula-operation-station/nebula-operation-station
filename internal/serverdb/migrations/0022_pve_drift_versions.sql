-- Preserve immutable drift values and decisions under separate confirmation IDs.
CREATE TABLE pve_drift_hints_versioned (
    id              INTEGER PRIMARY KEY,
    remote_id       TEXT NOT NULL,
    vmid            INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    host_id         TEXT NOT NULL,
    field           TEXT NOT NULL CHECK (field IN ('ip', 'ram', 'node', 'state')),
    inventory_value TEXT NOT NULL,
    pve_value       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    resolved_at     TEXT NOT NULL DEFAULT '',
    resolution      TEXT NOT NULL DEFAULT '' CHECK (resolution IN ('', 'accepted', 'ignored')),
    resolved_by     TEXT NOT NULL DEFAULT '',
    superseded_at   TEXT NOT NULL DEFAULT ''
);
INSERT INTO pve_drift_hints_versioned
    SELECT *, '' FROM pve_drift_hints;
DROP TABLE pve_drift_hints;
ALTER TABLE pve_drift_hints_versioned RENAME TO pve_drift_hints;
CREATE INDEX idx_pve_drift_hints_remote ON pve_drift_hints (remote_id);
CREATE INDEX idx_pve_drift_hints_host ON pve_drift_hints (host_id);
CREATE UNIQUE INDEX idx_pve_drift_hints_open ON pve_drift_hints (host_id, field)
    WHERE resolved_at = '' AND superseded_at = '';

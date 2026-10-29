-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Retain incarnation high-water marks independently of prunable tombstones.
CREATE TABLE pve_guest_generations (
    remote_id TEXT NOT NULL,
    vmid INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (remote_id, vmid)
);
INSERT INTO pve_guest_generations (remote_id, vmid, generation)
    SELECT remote_id, vmid, MAX(generation) FROM pve_guests GROUP BY remote_id, vmid;

-- Only the current collection's bounded membership is retained per remote.
CREATE TABLE pve_guest_collections (
    remote_id TEXT PRIMARY KEY,
    collection_generation INTEGER NOT NULL,
    paged INTEGER NOT NULL
);
CREATE TABLE pve_guest_collection_seen (
    remote_id TEXT NOT NULL,
    vmid INTEGER NOT NULL,
    PRIMARY KEY (remote_id, vmid)
);

ALTER TABLE pve_nodes ADD COLUMN details_observed_at TEXT NOT NULL DEFAULT '';
ALTER TABLE pve_nodes ADD COLUMN details_checked_at TEXT NOT NULL DEFAULT '';
ALTER TABLE pve_nodes ADD COLUMN details_source TEXT NOT NULL DEFAULT '';
ALTER TABLE pve_nodes ADD COLUMN details_reason TEXT NOT NULL DEFAULT '';
UPDATE pve_nodes SET
    details_observed_at = CASE WHEN details_available = 1 THEN observed_at ELSE '' END,
    details_checked_at = observed_at,
    details_source = source;

CREATE INDEX idx_pve_backups_newest ON pve_backup_observations
    (remote_id, vmid, generation, started_unix DESC, source DESC, kind DESC, name DESC);

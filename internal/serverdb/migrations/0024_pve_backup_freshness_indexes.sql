-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Independent bounded range reads for freshness; historical evidence is retained.
CREATE INDEX idx_pve_backup_task_freshness ON pve_backup_observations
    (remote_id, vmid, generation, status,
     (CASE WHEN finished_unix = 0 THEN started_unix ELSE finished_unix END) DESC,
     source DESC, name DESC, started_unix DESC)
    WHERE kind = 'task';

-- Catalog confidence requires the current poll, rather than retained history.
CREATE INDEX idx_pve_backup_catalog_freshness ON pve_backup_observations
    (remote_id, vmid, generation, observed_at, collection_generation, status, verified,
     (CASE WHEN finished_unix = 0 THEN started_unix ELSE finished_unix END) DESC,
     source DESC, name DESC, started_unix DESC)
    WHERE kind = 'catalog';

-- Preserve legacy signed bytes and expiry in the single grant registry.
-- The marker keeps the compatibility schedule API restricted to legacy grants.
ALTER TABLE read_grants ADD COLUMN legacy_schedule INTEGER NOT NULL DEFAULT 0
    CHECK (legacy_schedule IN (0, 1));

INSERT INTO read_grants
    (id, digest, doc, approved_by, created_at, expires_at, revoked_at, legacy_schedule)
SELECT id, digest, doc, approved_by, created_at, expires_at, revoked_at, 1
FROM schedule_grants;

-- Carry forward the claims the legacy store retained, including action floors
-- and its latest observed clock. All future claims use the shared run log.
INSERT INTO read_run_log (grant_id, host_id, at)
SELECT grant_id, host_id, last_run FROM schedule_runs;

INSERT INTO read_action_last (action_id, host_id, last_run)
SELECT action_id, host_id, MAX(last_run) FROM schedule_runs
GROUP BY action_id, host_id
ON CONFLICT (action_id, host_id) DO UPDATE
SET last_run = MAX(read_action_last.last_run, excluded.last_run);

UPDATE read_clock SET high_water = MAX(high_water,
    COALESCE((SELECT MAX(last_run) FROM schedule_runs), 0)) WHERE id = 1;

DROP TABLE schedule_runs;
DROP TABLE schedule_grants;

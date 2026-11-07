-- 0020_runs_member.sql (ADR 0006 P2-03, container updates cu02): a durable
-- run of a batch member records its member ID and the frozen action ID, so
-- the run can be found by batch digest (runs.digest) and member ID after a
-- restart of either side, and its outcome reaches the batch rollout. Both
-- are '' for classic runs.
ALTER TABLE runs ADD COLUMN member_id TEXT NOT NULL DEFAULT '' CHECK (length(member_id) <= 128);
ALTER TABLE runs ADD COLUMN action_id TEXT NOT NULL DEFAULT '' CHECK (length(action_id) <= 128);
CREATE INDEX runs_member ON runs (digest, member_id) WHERE member_id != '';

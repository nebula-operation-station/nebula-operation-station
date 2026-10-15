-- 0009_stages.sql (M6): the stage plan of an execution (the document the
-- executor hashed into the approval; empty for a single-stage execution),
-- each host's stage (1-based) and what the rollout waits for, if anything
-- (shown in the UI and used to notify a waiting gate once).
ALTER TABLE executions ADD COLUMN stage_plan TEXT NOT NULL DEFAULT '' CHECK (length(stage_plan) <= 65536);
ALTER TABLE executions ADD COLUMN waiting TEXT NOT NULL DEFAULT '' CHECK (length(waiting) <= 300);
ALTER TABLE execution_hosts ADD COLUMN stage INTEGER NOT NULL DEFAULT 1 CHECK (stage BETWEEN 1 AND 20);

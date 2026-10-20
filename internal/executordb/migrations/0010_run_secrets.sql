-- 0010_run_secrets.sql (M7-3, review m73): which vault secret each slot of a
-- durable run uses (slot -> secret ID, never a value), so that the executor
-- can redact the values from the run's result and log when it collects
-- them, also after a restart. Empty for runs without secrets.
ALTER TABLE runs ADD COLUMN secret_refs TEXT NOT NULL DEFAULT '' CHECK (length(secret_refs) <= 4000);

-- 0012_runbook_secrets.sql: the secret slots of a runbook version (M7-3),
-- a JSON array of slot names. Planning maps each slot to a vault secret ID;
-- the executor resolves it and only the host sees the value.
ALTER TABLE runbook_versions ADD COLUMN secrets TEXT NOT NULL DEFAULT '[]' CHECK (length(secrets) <= 1000);

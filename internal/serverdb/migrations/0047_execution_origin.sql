-- 0047_execution_origin.sql
--
-- Origin of an execution (ADR 0016 D9; spec 07 v28-07-01). An execution
-- that the server attributes to an ops-agent suggestion holds
-- "suggestion:<note ID>.<step>" (the create request carried a valid
-- reference) or "suggestion-match:<note ID>" (a stored fix note holds a
-- step of the same action family on the same host). Every other execution
-- stores the empty string. The origin is server data only; it can raise the
-- approval class and nothing else.

ALTER TABLE executions ADD COLUMN origin TEXT NOT NULL DEFAULT ''
    CHECK (length(origin) <= 200);

-- 0008_execution_params.sql (M5): parameters of an execution (a JSON
-- object the server built from validated input; the executor keeps its own
-- canonical copy and hashes it).
ALTER TABLE executions ADD COLUMN params TEXT NOT NULL DEFAULT '{}';

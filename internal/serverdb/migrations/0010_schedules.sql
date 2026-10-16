-- 0010_schedules.sql: scheduled read-only checks. A schedule is the
-- server's view of a schedule grant (the executor holds and enforces the
-- grant itself, see docs/implementation/schedule-grants.md): which actions
-- run on which hosts how often, until when. Runs are stored as executions
-- created by "schedule".
CREATE TABLE schedules (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    digest      TEXT    NOT NULL CHECK (length(digest) = 64),
    state       TEXT    NOT NULL CHECK (state IN ('pending', 'active', 'revoked')),
    actions     TEXT    NOT NULL CHECK (length(actions) <= 4000),
    hosts       TEXT    NOT NULL CHECK (length(hosts) <= 20000),
    interval_s  INTEGER NOT NULL CHECK (interval_s BETWEEN 900 AND 604800),
    expires_at  INTEGER NOT NULL,
    options     BLOB,
    created_by  TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at  INTEGER NOT NULL,
    approved_at INTEGER
);

ALTER TABLE executions ADD COLUMN schedule_id TEXT NOT NULL DEFAULT '';
CREATE INDEX executions_schedule ON executions (schedule_id, action_id, created_at) WHERE schedule_id != '';

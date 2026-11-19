-- 0048_execution_rejected.sql (ADR 0007 amendment R1-R7, spec 07 v29-07-01):
-- allow the execution state 'rejected'. An operator rejects a pending
-- proposal (from the operations overview, or on the executor host with
-- `nebula reject`); the executor drops the permit and the server records the
-- rejection with a guarded update WHERE state = 'pending'. The CHECK on
-- executions.state must accept the new value.
--
-- This is the table rebuild of 0018_execution_expired.sql, with the column
-- list of the current schema (0047 added origin). Every existing row and
-- column is kept unchanged. The child table execution_hosts is rebuilt in
-- the same step so its foreign key never points at a dropped table.

CREATE TABLE executions_new (
    id              TEXT    PRIMARY KEY CHECK (length(id) = 36),
    digest          TEXT    NOT NULL DEFAULT '',
    action_id       TEXT    NOT NULL CHECK (length(action_id) BETWEEN 1 AND 100),
    module_version  TEXT    NOT NULL CHECK (length(module_version) BETWEEN 1 AND 40),
    artifact_sha256 TEXT    NOT NULL CHECK (length(artifact_sha256) = 64),
    risk            TEXT    NOT NULL,
    requirement     TEXT    NOT NULL DEFAULT '',
    state           TEXT    NOT NULL CHECK (state IN ('pending', 'approved', 'running', 'finished', 'failed', 'expired', 'rejected')),
    detail          TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    durable         INTEGER NOT NULL CHECK (durable IN (0, 1)),
    timeout_s       INTEGER NOT NULL,
    options         BLOB,
    approval_expiry INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    params          TEXT    NOT NULL DEFAULT '{}',
    stage_plan      TEXT    NOT NULL DEFAULT '' CHECK (length(stage_plan) <= 65536),
    waiting         TEXT    NOT NULL DEFAULT '' CHECK (length(waiting) <= 300),
    schedule_id     TEXT    NOT NULL DEFAULT '',
    origin          TEXT    NOT NULL DEFAULT '' CHECK (length(origin) <= 200)
);

INSERT INTO executions_new (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state, detail, durable, timeout_s, options, approval_expiry, created_by, created_at, finished_at, params, stage_plan, waiting, schedule_id, origin)
SELECT id, digest, action_id, module_version, artifact_sha256, risk, requirement, state, detail, durable, timeout_s, options, approval_expiry, created_by, created_at, finished_at, params, stage_plan, waiting, schedule_id, origin
FROM executions;

CREATE TABLE execution_hosts_new (
    execution_id   TEXT    NOT NULL REFERENCES executions_new (id),
    host_id        TEXT    NOT NULL,
    fingerprint    TEXT    NOT NULL,
    credential_ref TEXT    NOT NULL,
    endpoints      TEXT    NOT NULL,
    state          TEXT    NOT NULL CHECK (state IN ('waiting', 'running', 'finished')),
    class          TEXT    NOT NULL DEFAULT '',
    detail         TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    exit_code      INTEGER NOT NULL DEFAULT -1,
    result         BLOB,
    log            BLOB,
    log_truncated  INTEGER NOT NULL DEFAULT 0 CHECK (log_truncated IN (0, 1)),
    started_at     INTEGER,
    finished_at    INTEGER,
    stage          INTEGER NOT NULL DEFAULT 1 CHECK (stage BETWEEN 1 AND 20),
    PRIMARY KEY (execution_id, host_id)
) WITHOUT ROWID;

INSERT INTO execution_hosts_new (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, detail, exit_code, result, log, log_truncated, started_at, finished_at, stage)
SELECT execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, detail, exit_code, result, log, log_truncated, started_at, finished_at, stage
FROM execution_hosts;

DROP TABLE execution_hosts;
DROP TABLE executions;

ALTER TABLE executions_new RENAME TO executions;
ALTER TABLE execution_hosts_new RENAME TO execution_hosts;

CREATE INDEX executions_created ON executions (created_at);
CREATE INDEX executions_schedule ON executions (schedule_id, action_id, created_at) WHERE schedule_id != '';
CREATE INDEX idx_executions_action_id ON executions (action_id, id);

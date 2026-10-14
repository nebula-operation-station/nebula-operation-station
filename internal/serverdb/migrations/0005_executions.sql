-- 0005_executions.sql (M4): executions planned by the server and their
-- per-host outcomes. The executor decides and records what really ran;
-- this is the server's view for the UI. result and log are untrusted host
-- output (spec 09), rendered as text only.
CREATE TABLE executions (
    id              TEXT    PRIMARY KEY CHECK (length(id) = 36),
    digest          TEXT    NOT NULL DEFAULT '',
    action_id       TEXT    NOT NULL CHECK (length(action_id) BETWEEN 1 AND 100),
    module_version  TEXT    NOT NULL CHECK (length(module_version) BETWEEN 1 AND 40),
    artifact_sha256 TEXT    NOT NULL CHECK (length(artifact_sha256) = 64),
    risk            TEXT    NOT NULL,
    requirement     TEXT    NOT NULL DEFAULT '',
    state           TEXT    NOT NULL CHECK (state IN ('pending', 'approved', 'running', 'finished', 'failed')),
    detail          TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    durable         INTEGER NOT NULL CHECK (durable IN (0, 1)),
    timeout_s       INTEGER NOT NULL,
    options         BLOB,
    approval_expiry INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at      INTEGER NOT NULL,
    finished_at     INTEGER
);

CREATE INDEX executions_created ON executions (created_at);

CREATE TABLE execution_hosts (
    execution_id   TEXT    NOT NULL REFERENCES executions (id),
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
    PRIMARY KEY (execution_id, host_id)
) WITHOUT ROWID;

-- 0007_runs.sql (M4): durable runs (spec 07). A row is written when the
-- run is authorized and before anything is sent to the host, so that after
-- an executor restart the run is reconciled, never dispatched again.
-- Result and log are untrusted host output, kept until the server has
-- taken them (released).
CREATE TABLE runs (
    execution_id  TEXT    NOT NULL CHECK (length(execution_id) = 36),
    host_id       TEXT    NOT NULL CHECK (length(host_id) BETWEEN 1 AND 200),
    digest        TEXT    NOT NULL CHECK (length(digest) BETWEEN 1 AND 100),
    state         TEXT    NOT NULL CHECK (state IN ('dispatching', 'running', 'finished')),
    class         TEXT    NOT NULL DEFAULT '' CHECK (length(class) <= 40),
    detail        TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    exit_code     INTEGER NOT NULL DEFAULT -1,
    endpoints     TEXT    NOT NULL CHECK (length(endpoints) <= 8000),
    fingerprint   TEXT    NOT NULL CHECK (length(fingerprint) <= 100),
    timeout_s     INTEGER NOT NULL CHECK (timeout_s BETWEEN 1 AND 21600),
    endpoint      TEXT    NOT NULL DEFAULT '' CHECK (length(endpoint) <= 300),
    result        BLOB,
    log           BLOB,
    log_truncated INTEGER NOT NULL DEFAULT 0 CHECK (log_truncated IN (0, 1)),
    created_at    INTEGER NOT NULL,
    dispatched_at INTEGER,
    finished_at   INTEGER,
    released_at   INTEGER,
    PRIMARY KEY (execution_id, host_id)
);

CREATE INDEX runs_open ON runs (state) WHERE state != 'finished';

-- 0008_run_reboots.sql (M5): durable runs that asked the executor to wait
-- for a reboot (spec 11: the executor waits for SSH and a fresh boot; past
-- the deadline the result is host_not_returned). The job's own outcome is
-- kept here until then; the run stays open.
CREATE TABLE run_reboots (
    execution_id  TEXT    NOT NULL CHECK (length(execution_id) = 36),
    host_id       TEXT    NOT NULL CHECK (length(host_id) BETWEEN 1 AND 200),
    old_boot_id   TEXT    NOT NULL CHECK (length(old_boot_id) = 36),
    deadline      INTEGER NOT NULL,
    exit_code     INTEGER NOT NULL,
    result        BLOB,
    log           BLOB,
    log_truncated INTEGER NOT NULL DEFAULT 0 CHECK (log_truncated IN (0, 1)),
    PRIMARY KEY (execution_id, host_id)
);

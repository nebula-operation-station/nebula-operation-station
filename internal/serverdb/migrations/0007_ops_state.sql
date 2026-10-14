-- 0007_ops_state.sql (M5, spec 12): the last Ops State per host derived
-- from runs and update checks, so that transitions are notified once.
CREATE TABLE host_ops_state (
    host_id     TEXT    PRIMARY KEY CHECK (length(host_id) BETWEEN 1 AND 200),
    state       TEXT    NOT NULL CHECK (state IN ('READY', 'WARNING', 'UNREACHABLE', 'UNKNOWN')),
    reason      TEXT    NOT NULL CHECK (length(reason) <= 300),
    source      TEXT    NOT NULL CHECK (length(source) <= 100),
    observed_at INTEGER NOT NULL,
    changed_at  INTEGER NOT NULL
) WITHOUT ROWID;

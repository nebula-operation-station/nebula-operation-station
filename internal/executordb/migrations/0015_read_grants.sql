-- 0015_read_grants.sql: approved read grants (ADR 0007 "One standing
-- read-grant mechanism") and their durable run budgets. doc is the
-- canonical grant document the approval was bound to; digest its SHA-256.
CREATE TABLE read_grants (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    digest      TEXT    NOT NULL UNIQUE CHECK (length(digest) = 64),
    doc         BLOB    NOT NULL CHECK (length(doc) <= 262144),
    approved_by TEXT    NOT NULL CHECK (length(approved_by) <= 200),
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER
);

-- One row per reserved read run, stamped with the high-water time. The
-- per-target rolling-hour budget is this host's count of rows in the last
-- hour; the table is shared by every read grant, so overlapping grants
-- cannot multiply the ceiling.
CREATE TABLE read_run_log (
    grant_id TEXT    NOT NULL REFERENCES read_grants (id),
    host_id  TEXT    NOT NULL CHECK (length(host_id) <= 200),
    at       INTEGER NOT NULL
);
CREATE INDEX read_run_log_host_at ON read_run_log (host_id, at);

-- The last reservation of each action on each host (the 15-minute
-- per-action floor), shared by every read grant.
CREATE TABLE read_action_last (
    action_id TEXT    NOT NULL CHECK (length(action_id) <= 100),
    host_id   TEXT    NOT NULL CHECK (length(host_id) <= 200),
    last_run  INTEGER NOT NULL,
    PRIMARY KEY (action_id, host_id)
) WITHOUT ROWID;

-- High-water clock: the latest time the budget logic has seen. A
-- wall-clock rollback never moves it back, so budgets never refill by
-- rewinding the clock.
CREATE TABLE read_clock (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    high_water INTEGER NOT NULL
);
INSERT INTO read_clock (id, high_water) VALUES (1, 0);

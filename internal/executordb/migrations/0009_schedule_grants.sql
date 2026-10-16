-- 0009_schedule_grants.sql: approved schedule grants (standing permission
-- to run fixed LOW actions on fixed hosts on a schedule, see
-- docs/implementation/schedule-grants.md) and the last run of each action
-- on each host under a grant. doc is the canonical grant document the
-- approval was bound to; digest its SHA-256.
CREATE TABLE schedule_grants (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    digest      TEXT    NOT NULL UNIQUE CHECK (length(digest) = 64),
    doc         BLOB    NOT NULL CHECK (length(doc) <= 65536),
    approved_by TEXT    NOT NULL CHECK (length(approved_by) <= 200),
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER
);

CREATE TABLE schedule_runs (
    grant_id  TEXT    NOT NULL REFERENCES schedule_grants (id),
    action_id TEXT    NOT NULL CHECK (length(action_id) <= 100),
    host_id   TEXT    NOT NULL CHECK (length(host_id) <= 200),
    last_run  INTEGER NOT NULL,
    PRIMARY KEY (grant_id, action_id, host_id)
) WITHOUT ROWID;

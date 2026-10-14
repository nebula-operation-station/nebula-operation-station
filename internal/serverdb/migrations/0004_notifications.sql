-- 0004_notifications.sql (M3/M4): host key mismatches already notified
-- (spec 13: transitions only, never repeated). A row is the executor's
-- block of one host at one time; rows of hosts that are no longer blocked
-- are removed, so a later block notifies again.
CREATE TABLE notified_host_key_blocks (
    host_id     TEXT    NOT NULL CHECK (length(host_id) BETWEEN 1 AND 200),
    blocked_at  INTEGER NOT NULL,
    notified_at INTEGER NOT NULL,
    PRIMARY KEY (host_id, blocked_at)
) WITHOUT ROWID;

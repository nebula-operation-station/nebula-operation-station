-- 0004_notifications.sql (M3/M4): host key mismatches already notified
-- (spec 13: transitions only, never repeated, always sent). A row is the
-- delivery of the executor's block of one host at one time to one
-- provider; a provider that failed is retried until it accepts. Rows of
-- hosts that are no longer blocked are removed, so a later block notifies
-- again.
CREATE TABLE notified_host_key_blocks (
    host_id     TEXT    NOT NULL CHECK (length(host_id) BETWEEN 1 AND 200),
    blocked_at  INTEGER NOT NULL,
    provider    TEXT    NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    notified_at INTEGER NOT NULL,
    PRIMARY KEY (host_id, blocked_at, provider)
) WITHOUT ROWID;

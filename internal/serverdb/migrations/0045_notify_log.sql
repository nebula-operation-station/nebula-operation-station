-- 0045_notify_log.sql
--
-- Notification log (ADR 0016 D10). One row per notification event that was
-- sent, held back by the rate limit, held back by a mute, or failed. The
-- logic lives in internal/notifylog; these constraints enforce the sizes
-- that the Go code also enforces, so a row can never exceed them.
--
-- The table holds structured fields only. It never stores a provider token,
-- a provider target URL, or log text: reason is a closed code (CHECK below),
-- and the link is a NOS link (a plain path inside the NOS UI). Go drops
-- anything else before a row is written.
--
-- seq is AUTOINCREMENT so sequence numbers are never reused after a prune;
-- readers page with "seq < cursor" in descending order.
-- at is unix seconds, UTC. changed is a bit set of the fields that were
-- shortened or dropped on write (see notifylog.Field, bits 0 to 4).

CREATE TABLE notify_log (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    at            INTEGER NOT NULL,
    kind          TEXT NOT NULL CHECK (length(CAST(kind AS BLOB)) <= 64),
    host          TEXT NOT NULL CHECK (length(CAST(host AS BLOB)) <= 64),
    state         TEXT NOT NULL CHECK (length(CAST(state AS BLOB)) <= 64),
    reason        TEXT NOT NULL CHECK (reason IN ('', 'rate_limited', 'muted', 'provider_unreachable', 'provider_rejected', 'timeout', 'internal')),
    execution_id  TEXT NOT NULL CHECK (length(CAST(execution_id AS BLOB)) <= 128),
    link          TEXT NOT NULL CHECK (length(CAST(link AS BLOB)) <= 256),
    outcome       TEXT NOT NULL CHECK (outcome IN ('sent', 'held_rate_limit', 'held_muted', 'failed')),
    providers     INTEGER NOT NULL CHECK (providers BETWEEN 0 AND 16),
    changed       INTEGER NOT NULL DEFAULT 0 CHECK (changed BETWEEN 0 AND 31)
);

CREATE INDEX notify_log_at ON notify_log (at);

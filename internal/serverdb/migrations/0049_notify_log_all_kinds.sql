-- 0049_notify_log_all_kinds.sql
--
-- Widens the closed sets of the notification log (ADR 0016 D10) to every
-- event kind and state that internal/notify sends: execution, ops_state,
-- host_key_mismatch, test, executor_locked and integrity.reference_conflict,
-- and the states they report (waiting, partial, test, locked, conflict, and
-- other as the fallback for an unknown execution state). Migration 0045 is
-- not changed; it stays as the first definition of the table.
--
-- SQLite cannot ALTER a CHECK constraint, so the table is rebuilt the way the
-- SQLite documentation prescribes (see 0018_execution_expired.sql). Every row
-- keeps its seq, and the AUTOINCREMENT counter is carried over before the old
-- table is dropped, so a sequence number that was pruned away is never reused.
-- notify_log has no foreign keys and nothing references it.

CREATE TABLE notify_log_new (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    at            INTEGER NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('vuln.kev_new', 'vuln.critical_new', 'vuln.hermes_stale', 'vuln.feed_stale', 'vuln.feed_regressed', 'vuln.feed_mark_reset', 'integrity.nos_mismatch', 'integrity.host_change', 'integrity.scan_incomplete', 'integrity.baseline_tamper', 'integrity.reference_conflict', 'lease.expiring', 'lease.run_failed', 'digest', 'opsagent.suggestion_new', 'opsagent.settings_changed', 'execution', 'ops_state', 'host_key_mismatch', 'test', 'executor_locked')),
    host          TEXT NOT NULL CHECK (length(CAST(host AS BLOB)) <= 64),
    state         TEXT NOT NULL CHECK (state IN ('new', 'escalated', 'expiring', 'failed', 'stale', 'regressed', 'mismatch', 'incomplete', 'tamper', 'changed', 'reset', 'summary', 'waiting', 'partial', 'test', 'locked', 'conflict', 'other')),
    reason        TEXT NOT NULL CHECK (reason IN ('', 'rate_limited', 'muted', 'provider_unreachable', 'provider_rejected', 'timeout', 'internal')),
    execution_id  TEXT NOT NULL CHECK (length(CAST(execution_id AS BLOB)) <= 128),
    link          TEXT NOT NULL CHECK (length(CAST(link AS BLOB)) <= 256),
    outcome       TEXT NOT NULL CHECK (outcome IN ('sent', 'held_rate_limit', 'held_muted', 'failed')),
    providers     INTEGER NOT NULL CHECK (providers BETWEEN 0 AND 16),
    changed       INTEGER NOT NULL DEFAULT 0 CHECK (changed BETWEEN 0 AND 7)
);

-- Carry the sequence counter over: inserting the old counter as this
-- table's AUTOINCREMENT value keeps it when the newest rows were pruned.
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'notify_log_new', seq FROM sqlite_sequence WHERE name = 'notify_log';

INSERT INTO notify_log_new (seq, at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
SELECT seq, at, kind, host, state, reason, execution_id, link, outcome, providers, changed
FROM notify_log;

DROP TABLE notify_log;

ALTER TABLE notify_log_new RENAME TO notify_log;

CREATE INDEX notify_log_at ON notify_log (at);

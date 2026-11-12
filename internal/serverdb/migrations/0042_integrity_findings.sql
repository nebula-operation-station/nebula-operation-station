-- 0042_integrity_findings.sql
--
-- Integrity findings store (ADR 0015 D9; plan IG-03). A new store, not the
-- ADR 0011 vulnerability store: its observer is the NOS integrity check
-- (I1 and I2 runs), not Hermes.
--
-- The logic lives in internal/integritystore; these tables only hold its
-- rows and enforce the enums, sizes and links that must never be violated.
-- Findings are notes for the admin: nothing in this schema triggers an
-- action.
--
-- integrity_store_state: one row (id = 1). lock_counter is bumped at the
-- start of every write transaction so that writers take the database write
-- lock before they read.
--
-- integrity_runs: one row per check run of one subject. A run is
-- 'running', then 'complete' (closes findings it did not see) or
-- 'incomplete' (closes nothing), or 'aborted' (time limit). dropped counts
-- observations the run could not store (limits, invalid path). A run with
-- dropped > 0 can never close findings.
--
-- integrity_findings: keyed by (subject, class, path). path is the raw
-- bytes of the path as the host reported them; path_display is the escaped
-- text form computed by NOS and shown in the UI (never trusted from input).
-- old_record and new_record are bounded text. severity is derived from the
-- class by NOS (D9 table) and stored for sorting and filtering.

CREATE TABLE integrity_store_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    lock_counter  INTEGER NOT NULL DEFAULT 0 CHECK (lock_counter >= 0)
);
INSERT INTO integrity_store_state (id, lock_counter) VALUES (1, 0);

CREATE TABLE integrity_runs (
    id          TEXT PRIMARY KEY CHECK (length(id) = 32),
    subject     TEXT NOT NULL CHECK (subject = 'nos' OR (subject GLOB 'host/?*' AND length(subject) <= 70)),
    state       TEXT NOT NULL CHECK (state IN ('running', 'complete', 'incomplete', 'aborted')),
    dropped     INTEGER NOT NULL DEFAULT 0 CHECK (dropped >= 0),
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    CHECK ((state = 'running') = (ended_at IS NULL))
);
CREATE INDEX idx_integrity_runs_subject ON integrity_runs (subject, state);
CREATE INDEX idx_integrity_runs_ended ON integrity_runs (state, ended_at);

CREATE TABLE integrity_findings (
    subject          TEXT NOT NULL CHECK (subject = 'nos' OR (subject GLOB 'host/?*' AND length(subject) <= 70)),
    class            TEXT NOT NULL CHECK (class IN (
                         'pkg-file-mismatch', 'nos-unit-mismatch', 'critical-path-changed',
                         'critical-path-changed-in-job', 'setid-new', 'nos-key-missing',
                         'ssh-key-extra', 'mount-unexpected-critical',
                         'etc-changed', 'owner-mode-changed', 'baseline-digest-mismatch',
                         'changed-in-job-unverified', 'pkg-content-without-version',
                         'pkg-downgraded', 'mount-unexpected', 'reference-conflict',
                         'ssh-login-file-outside-roots',
                         'pkg-updated-outside-nos', 'scan-partial',
                         'expected-change')),
    severity         TEXT NOT NULL CHECK (severity IN ('info', 'medium', 'high', 'critical')),
    path             BLOB NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    path_display     TEXT NOT NULL CHECK (length(CAST(path_display AS BLOB)) BETWEEN 1 AND 16384),
    old_record       TEXT NOT NULL DEFAULT '' CHECK (length(CAST(old_record AS BLOB)) <= 2048),
    new_record       TEXT NOT NULL DEFAULT '' CHECK (length(CAST(new_record AS BLOB)) <= 2048),
    state            TEXT NOT NULL CHECK (state IN ('open', 'expected_pending', 'accepted', 'resolved')),
    first_seen_at    INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL,
    opened_run_id    TEXT NOT NULL CHECK (length(opened_run_id) = 32),
    last_run_id      TEXT NOT NULL CHECK (length(last_run_id) = 32),
    closed_run_id    TEXT CHECK (closed_run_id IS NULL OR length(closed_run_id) = 32),
    closed_at        INTEGER,
    state_run_id     TEXT CHECK (state_run_id IS NULL OR length(state_run_id) = 32),
    state_by         TEXT CHECK (state_by IS NULL OR length(CAST(state_by AS BLOB)) BETWEEN 1 AND 128),
    state_at         INTEGER NOT NULL,
    PRIMARY KEY (subject, class, path),
    CHECK ((state = 'resolved') = (closed_run_id IS NOT NULL)),
    CHECK ((state = 'resolved') = (closed_at IS NOT NULL)),
    CHECK (state <> 'accepted' OR state_by IS NOT NULL)
);
CREATE INDEX idx_integrity_findings_subject ON integrity_findings (subject, state);
CREATE INDEX idx_integrity_findings_closed ON integrity_findings (state, closed_at);

-- 0036_vuln_findings.sql
-- Vulnerability findings store (ADR 0011 D2, D5, D6; plan VU-07).
--
-- Hermes is the only writer of findings through runs; NOS computes every
-- finding_key (internal/vulnfinding) and owns state, closed_by,
-- nos_checked, the write ordering and the episode high-water marks. The
-- logic lives in internal/vulnstore; these tables only hold its rows and
-- enforce the enums, sizes and links that must never be violated.
--
-- vuln_runs: one row per Hermes run. run_seq is assigned by NOS at start,
-- strictly increasing (UNIQUE, never reused because runs are pruned only
-- 90 days after they ended and the next run_seq is taken from
-- vuln_store_state, not from MAX(run_seq)). A run is 'running', then
-- 'completed' or 'aborted' (6 h timeout, no closures).
--
-- vuln_run_sources: the feed sources a run named at start and NOS's
-- verdict on each (D5 run ordering): accepted, undated (content date kind
-- none: stale and raise-only), regressed (below the high-water mark),
-- invalid (dated beyond NOS's clock plus 10 minutes) or unknown (not on
-- NOS's fixed source list). Only pattern-checked IDs are stored.
--
-- vuln_source_marks: per listed source the newest content date and the
-- highest bundle sequence ever accepted at a run start. Rows are created
-- by NOS for listed IDs only, so their number is bounded by the list.
--
-- vuln_run_batches: idempotency of batches by (run_id, batch_seq) with the
-- SHA-256 of the accepted body. vuln_run_subjects: subjects the run fully
-- covered (D3 last_part). vuln_run_reported: finding keys the run reported
-- (not_affected = 1 for a reported not_affected record, a closure
-- request). vuln_run_rejected: keys with a rejected record in the run,
-- which blocks their closure in that run.
--
-- vuln_findings: one row per finding_key. Current values are the record
-- JSON (assessment text kept apart so retention can drop it); the episode
-- columns are the D5 high-water marks of the current episode, which only
-- rise until the finding closes and re-opens. state_run_seq is the run_seq
-- of the run that last wrote the finding; rev counts every write so a held
-- closure can tell whether the finding changed since the hold. Human states
-- (accepted_risk, false_positive) are set only by an admin and carry the
-- reason, approver, expiry and the D4 version basis they are bound to.
--
-- vuln_subject_watermarks: per subject the highest run_seq that completed
-- for it (coverage watermark) and when; also the staleness clock (D6).
--
-- vuln_held_closures: run closures NOS held for an admin (contradicted,
-- episode KEV or critical, guard tripped, classification failed); the
-- finding stays open until an admin confirms or discards the hold or a
-- newer complete run covers the subject.
--
-- Retention (D6, Q3): fixed findings 365 days, runs 90 days after they
-- ended (child rows cascade), assessment text of closed findings 90 days.
-- No feed data is stored, only per-finding scores and snapshot IDs.
--
-- Every value from Hermes is untrusted; internal/vulnfinding and
-- internal/vulnstore validate it before it reaches these tables.

CREATE TABLE vuln_store_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    next_run_seq  INTEGER NOT NULL CHECK (next_run_seq > 0),
    lock_counter  INTEGER NOT NULL DEFAULT 0
);
INSERT INTO vuln_store_state (id, next_run_seq) VALUES (1, 1);

CREATE TABLE vuln_runs (
    id                   TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    run_seq              INTEGER NOT NULL UNIQUE CHECK (run_seq > 0),
    token_id             TEXT NOT NULL CHECK (length(token_id) BETWEEN 1 AND 128),
    inventory_generation INTEGER NOT NULL CHECK (inventory_generation >= 0),
    matcher_version      TEXT NOT NULL CHECK (length(matcher_version) BETWEEN 1 AND 64),
    state                TEXT NOT NULL CHECK (state IN ('running', 'completed', 'aborted')),
    started_at           INTEGER NOT NULL,
    ended_at             INTEGER,
    batch_rejected       INTEGER NOT NULL DEFAULT 0 CHECK (batch_rejected IN (0, 1)),
    finding_count        INTEGER NOT NULL DEFAULT 0 CHECK (finding_count BETWEEN 0 AND 200000),
    superseded           INTEGER NOT NULL DEFAULT 0 CHECK (superseded >= 0),
    report               TEXT NOT NULL DEFAULT '{}' CHECK (length(report) <= 65536),
    CHECK ((state = 'running') = (ended_at IS NULL))
);
CREATE INDEX idx_vuln_runs_ended ON vuln_runs (state, ended_at);

CREATE TABLE vuln_run_sources (
    run_id       TEXT NOT NULL REFERENCES vuln_runs (id) ON DELETE CASCADE,
    source_id    TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    snapshot_id  TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
    integrity    TEXT NOT NULL CHECK (integrity IN ('signed', 'checksum', 'none')),
    date_kind    TEXT NOT NULL CHECK (length(date_kind) BETWEEN 1 AND 80),
    content_date INTEGER,
    sequence     INTEGER CHECK (sequence IS NULL OR sequence >= 0),
    status       TEXT NOT NULL CHECK (status IN ('accepted', 'undated', 'regressed', 'invalid', 'unknown')),
    stale        INTEGER NOT NULL CHECK (stale IN (0, 1)),
    PRIMARY KEY (run_id, source_id)
);

CREATE TABLE vuln_source_marks (
    source_id    TEXT PRIMARY KEY CHECK (length(source_id) BETWEEN 1 AND 64),
    content_date INTEGER,
    sequence     INTEGER CHECK (sequence IS NULL OR sequence >= 0),
    updated_at   INTEGER NOT NULL
);

CREATE TABLE vuln_run_batches (
    run_id      TEXT NOT NULL REFERENCES vuln_runs (id) ON DELETE CASCADE,
    batch_seq   INTEGER NOT NULL CHECK (batch_seq >= 0),
    body_sha256 BLOB NOT NULL CHECK (length(body_sha256) = 32),
    rejected    INTEGER NOT NULL CHECK (rejected IN (0, 1)),
    PRIMARY KEY (run_id, batch_seq)
);

CREATE TABLE vuln_run_subjects (
    run_id  TEXT NOT NULL REFERENCES vuln_runs (id) ON DELETE CASCADE,
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 200),
    PRIMARY KEY (run_id, subject)
);

CREATE TABLE vuln_run_reported (
    run_id       TEXT NOT NULL REFERENCES vuln_runs (id) ON DELETE CASCADE,
    finding_key  BLOB NOT NULL CHECK (length(finding_key) = 32),
    not_affected INTEGER NOT NULL CHECK (not_affected IN (0, 1)),
    PRIMARY KEY (run_id, finding_key)
);

CREATE TABLE vuln_run_rejected (
    run_id      TEXT NOT NULL REFERENCES vuln_runs (id) ON DELETE CASCADE,
    finding_key BLOB NOT NULL CHECK (length(finding_key) = 32),
    PRIMARY KEY (run_id, finding_key)
);

CREATE TABLE vuln_findings (
    finding_key            BLOB PRIMARY KEY CHECK (length(finding_key) = 32),
    subject                TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 200),
    subject_kind           TEXT NOT NULL CHECK (subject_kind IN ('host', 'image', 'device')),
    record                 TEXT NOT NULL CHECK (length(record) <= 131072),
    assessment             TEXT CHECK (assessment IS NULL OR length(CAST(assessment AS BLOB)) <= 4096),
    nos_checked            INTEGER NOT NULL CHECK (nos_checked IN (0, 1)),
    state                  TEXT NOT NULL CHECK (state IN ('open', 'fixed', 'accepted_risk', 'false_positive')),
    closed_by              TEXT CHECK (closed_by IS NULL OR closed_by IN ('nos_inventory', 'subject_removed', 'hermes_unconfirmed', 'admin_confirmed')),
    closed_note            TEXT NOT NULL DEFAULT '' CHECK (length(closed_note) <= 200),
    closed_at              INTEGER,
    state_run_seq          INTEGER NOT NULL CHECK (state_run_seq > 0),
    rev                    INTEGER NOT NULL DEFAULT 1 CHECK (rev > 0),
    episode                INTEGER NOT NULL DEFAULT 1 CHECK (episode > 0),
    episode_opened_at      INTEGER NOT NULL,
    episode_opened_run_seq INTEGER NOT NULL CHECK (episode_opened_run_seq > 0),
    episode_fixed_version  TEXT CHECK (episode_fixed_version IS NULL OR length(episode_fixed_version) <= 128),
    episode_kev_date       TEXT CHECK (episode_kev_date IS NULL OR length(episode_kev_date) = 10),
    episode_peak_tier      INTEGER NOT NULL CHECK (episode_peak_tier BETWEEN 0 AND 4),
    first_seen_at          INTEGER NOT NULL,
    last_seen_at           INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    human_by               TEXT CHECK (human_by IS NULL OR length(human_by) BETWEEN 1 AND 128),
    human_reason           TEXT CHECK (human_reason IS NULL OR length(CAST(human_reason AS BLOB)) <= 1024),
    human_category         TEXT CHECK (human_category IS NULL OR human_category IN ('backport_fixed', 'not_affected_config', 'component_not_used', 'vendor_disputed', 'other')),
    human_expires_at       INTEGER,
    human_basis_version    TEXT CHECK (human_basis_version IS NULL OR length(human_basis_version) <= 128),
    human_kev              INTEGER CHECK (human_kev IS NULL OR human_kev IN (0, 1)),
    human_at               INTEGER,
    CHECK ((state = 'fixed') = (closed_by IS NOT NULL)),
    CHECK ((state = 'fixed') = (closed_at IS NOT NULL)),
    CHECK ((state IN ('accepted_risk', 'false_positive')) = (human_by IS NOT NULL)),
    CHECK ((state = 'accepted_risk') = (human_expires_at IS NOT NULL)),
    CHECK ((state = 'false_positive') = (human_category IS NOT NULL))
);
CREATE INDEX idx_vuln_findings_subject ON vuln_findings (subject, state);
CREATE INDEX idx_vuln_findings_closed ON vuln_findings (state, closed_at);

CREATE TABLE vuln_subject_watermarks (
    subject      TEXT PRIMARY KEY CHECK (length(subject) BETWEEN 1 AND 200),
    run_seq      INTEGER NOT NULL CHECK (run_seq > 0),
    completed_at INTEGER NOT NULL
);

CREATE TABLE vuln_held_closures (
    run_id      TEXT NOT NULL REFERENCES vuln_runs (id) ON DELETE CASCADE,
    finding_key BLOB NOT NULL REFERENCES vuln_findings (finding_key) ON DELETE CASCADE,
    run_seq     INTEGER NOT NULL CHECK (run_seq > 0),
    subject     TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 200),
    reason      TEXT NOT NULL CHECK (reason IN ('contradicted', 'kev_or_critical', 'run_guard', 'window_guard', 'classify_failed')),
    finding_rev INTEGER NOT NULL CHECK (finding_rev > 0),
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (run_id, finding_key)
);
CREATE INDEX idx_vuln_held_subject ON vuln_held_closures (subject, run_seq);
CREATE INDEX idx_vuln_held_finding ON vuln_held_closures (finding_key);

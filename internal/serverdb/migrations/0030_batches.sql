-- 0030_batches.sql (ADR 0007 E13): server-side record of batch plans and
-- their per-member outcomes.
--
-- A batch is one reviewed plan of 1..100 expanded action-target members
-- (12 updates and 3 restarts are 15 member rows, never a wildcard). The
-- executor holds the approval and every member permit in memory only; the
-- server keeps the frozen plan for display and reconciliation, never a
-- resumable mutation right.
--
-- A batch is not a transaction. Each member has its own outcome; there is
-- no rollback column and no retry counter: a member that reached a final
-- outcome (success, failed, skipped, not_executed, unknown) never runs
-- again under this batch. A retry or a rollback is a new batch with a fresh
-- approval.

CREATE TABLE batches (
    id              TEXT    PRIMARY KEY CHECK (length(id) = 36),
    digest          TEXT    NOT NULL UNIQUE CHECK (length(digest) = 64),
    state           TEXT    NOT NULL CHECK (state IN ('pending', 'approved', 'refused', 'expired')),
    risk            TEXT    NOT NULL CHECK (risk IN ('LOW', 'MEDIUM', 'HIGH')),
    requirement     TEXT    NOT NULL DEFAULT '' CHECK (length(requirement) <= 20),
    member_count    INTEGER NOT NULL CHECK (member_count BETWEEN 1 AND 100),
    stage_count     INTEGER NOT NULL CHECK (stage_count BETWEEN 1 AND 20),
    canonical       BLOB    NOT NULL CHECK (length(canonical) BETWEEN 1 AND 1048576),
    options         BLOB,
    approval_expiry INTEGER NOT NULL DEFAULT 0,
    expiry          INTEGER NOT NULL,
    approved_by     TEXT    NOT NULL DEFAULT '' CHECK (length(approved_by) <= 64),
    detail          TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    created_by      TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at      INTEGER NOT NULL
);

CREATE INDEX batches_created ON batches (created_at);

-- The approved stage gates and thresholds (absolute counts; zero stops on
-- the first failed or unreachable member).
CREATE TABLE batch_stages (
    batch_id              TEXT    NOT NULL REFERENCES batches (id) ON DELETE CASCADE,
    stage                 INTEGER NOT NULL CHECK (stage BETWEEN 1 AND 20),
    stage_id              TEXT    NOT NULL CHECK (length(stage_id) BETWEEN 1 AND 64),
    gate                  TEXT    NOT NULL CHECK (gate IN ('manual', 'automatic')),
    failure_threshold     INTEGER NOT NULL CHECK (failure_threshold BETWEEN 0 AND 100),
    unreachable_threshold INTEGER NOT NULL CHECK (unreachable_threshold BETWEEN 0 AND 100),
    PRIMARY KEY (batch_id, stage)
) WITHOUT ROWID;

CREATE TABLE batch_members (
    batch_id        TEXT    NOT NULL REFERENCES batches (id) ON DELETE CASCADE,
    idx             INTEGER NOT NULL CHECK (idx BETWEEN 0 AND 99),
    member_id       TEXT    NOT NULL CHECK (length(member_id) BETWEEN 1 AND 64),
    execution_id    TEXT    NOT NULL UNIQUE CHECK (length(execution_id) = 36),
    stage           INTEGER NOT NULL CHECK (stage BETWEEN 1 AND 20),
    action_id       TEXT    NOT NULL CHECK (length(action_id) BETWEEN 1 AND 100),
    module_version  TEXT    NOT NULL CHECK (length(module_version) BETWEEN 1 AND 40),
    artifact_sha256 TEXT    NOT NULL CHECK (length(artifact_sha256) = 64),
    parameters_hash TEXT    NOT NULL CHECK (length(parameters_hash) = 64),
    params          TEXT    NOT NULL DEFAULT '{}' CHECK (length(params) <= 65536),
    risk            TEXT    NOT NULL CHECK (risk IN ('LOW', 'MEDIUM', 'HIGH')),
    host_id         TEXT    NOT NULL CHECK (length(host_id) BETWEEN 1 AND 63),
    fingerprint     TEXT    NOT NULL CHECK (length(fingerprint) <= 100),
    credential_ref  TEXT    NOT NULL CHECK (length(credential_ref) <= 64),
    container_id    TEXT    NOT NULL DEFAULT '' CHECK (length(container_id) IN (0, 64)),
    outcome         TEXT    NOT NULL DEFAULT 'planned'
                    CHECK (outcome IN ('planned', 'dispatched', 'success', 'failed', 'skipped', 'not_executed', 'unknown')),
    unreachable     INTEGER NOT NULL DEFAULT 0 CHECK (unreachable IN (0, 1)),
    detail          TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (batch_id, idx),
    UNIQUE (batch_id, member_id)
) WITHOUT ROWID;

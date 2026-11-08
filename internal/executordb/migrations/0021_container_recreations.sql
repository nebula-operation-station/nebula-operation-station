-- 0021_container_recreations.sql (ADR 0006 P2-04, container updates cu03):
-- one row per container update or rollback member run. The row is written
-- in state 'intent' before the job is dispatched and completed once from
-- the run's result (or left 'uncertain' when the run closed without one).
-- It keeps what a later rollback returns to through the rollback window:
-- the prior image per service (retained tag and reference), the
-- recreation definition and the phase 1 baseline. Rows are never deleted;
-- after the window they remain history. Nothing here is secret: the
-- binding and the definition hold identities and digests, no file content
-- and no environment.
CREATE TABLE container_recreations (
    execution_id          TEXT PRIMARY KEY CHECK (length(execution_id) = 36),
    batch_digest          TEXT NOT NULL CHECK (length(batch_digest) = 64),
    member_id             TEXT NOT NULL CHECK (length(member_id) BETWEEN 1 AND 128),
    kind                  TEXT NOT NULL CHECK (kind IN ('update', 'rollback')),
    rollback_of           TEXT NOT NULL DEFAULT '' CHECK (length(rollback_of) IN (0, 36)),
    host_id               TEXT NOT NULL CHECK (length(host_id) BETWEEN 1 AND 255),
    host_key              TEXT NOT NULL CHECK (length(host_key) <= 512),
    form                  TEXT NOT NULL CHECK (form IN ('compose', 'standalone')),
    unit                  TEXT NOT NULL CHECK (length(unit) <= 255),
    binding               TEXT NOT NULL CHECK (length(binding) BETWEEN 2 AND 131072),
    definition            TEXT NOT NULL CHECK (length(definition) BETWEEN 2 AND 131072),
    images                TEXT NOT NULL CHECK (length(images) BETWEEN 2 AND 131072),
    containers            TEXT NOT NULL DEFAULT '[]' CHECK (length(containers) BETWEEN 2 AND 262144),
    baseline              TEXT NOT NULL DEFAULT '' CHECK (length(baseline) <= 524288),
    verdict               TEXT NOT NULL DEFAULT '' CHECK (length(verdict) <= 65536),
    state                 TEXT NOT NULL CHECK (state IN ('intent', 'not_recreated', 'recreated', 'partial', 'uncertain', 'rolled_back')),
    window_expires_at     INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
);
CREATE INDEX container_recreations_host ON container_recreations (host_id, created_at);
CREATE INDEX container_recreations_state ON container_recreations (state);
CREATE INDEX container_recreations_member ON container_recreations (batch_digest, member_id);

-- A declared recovery plan per host and unit (Compose project or container
-- name): either a free-text reference without secrets or the explicit
-- declaration that the unit keeps no persistent data. Exactly one of the
-- two; never inferred. A rollback binds the digest of the current record.
CREATE TABLE container_recovery_plans (
    host_id     TEXT NOT NULL CHECK (length(host_id) BETWEEN 1 AND 255),
    unit        TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 255),
    kind        TEXT NOT NULL CHECK (kind IN ('plan', 'no_persistent_data')),
    reference   TEXT NOT NULL CHECK (length(reference) <= 2048),
    actor       TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 255),
    version     INTEGER NOT NULL CHECK (version >= 1),
    recorded_at INTEGER NOT NULL,
    CHECK ((kind = 'plan' AND length(reference) >= 1) OR (kind = 'no_persistent_data' AND reference = '')),
    PRIMARY KEY (host_id, unit)
);

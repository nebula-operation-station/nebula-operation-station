-- 0002_risk_floor.sql (H01): data the executor derives the minimum risk
-- class of a proposal from. Written only through admin RPCs (the `nebula`
-- CLI on the executor host), never by the server. Risk values are
-- canonical.Risk ranks: 1 LOW .. 4 CRITICAL.
--
-- Unlike 0001 these rows can LOWER the minimum risk below HIGH, so their
-- integrity matters. Losing them falls back to HIGH, which also lowers a
-- CRITICAL record to HIGH: back up executor.db.

-- Artifacts the admin has trusted for one action at a declared risk. The
-- executor hashed the bytes itself when the entry was made. A proposal whose
-- (artifact, action, version) is not listed has the minimum risk HIGH.
CREATE TABLE trusted_artifacts (
    artifact_sha256 BLOB    NOT NULL CHECK (length(artifact_sha256) = 32),
    action_id       TEXT    NOT NULL CHECK (length(action_id) BETWEEN 3 AND 129),
    module_version  TEXT    NOT NULL CHECK (length(module_version) BETWEEN 5 AND 20),
    risk            INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 4),
    label           TEXT    NOT NULL DEFAULT '' CHECK (length(label) <= 200),
    trusted_at      INTEGER NOT NULL,
    trusted_by      TEXT    NOT NULL,
    PRIMARY KEY (artifact_sha256, action_id, module_version)
) WITHOUT ROWID;

-- Host criticality as the executor knows it, bound to the host's pinned key.
-- host_id alone is a name the server chooses; a target counts only if both
-- its host_id and its key fingerprint match a row. Any other target is
-- unknown (HIGH for actions above LOW). A key belongs to one row only.
CREATE TABLE host_criticality (
    host_id              TEXT    PRIMARY KEY CHECK (length(host_id) BETWEEN 1 AND 63),
    host_key_fingerprint TEXT    NOT NULL UNIQUE CHECK (length(host_key_fingerprint) = 50),
    criticality          INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 4),
    updated_at           INTEGER NOT NULL,
    updated_by           TEXT    NOT NULL
) WITHOUT ROWID;

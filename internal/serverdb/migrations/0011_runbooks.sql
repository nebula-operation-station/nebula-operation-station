-- 0011_runbooks.sql: runbooks (spec 10), local single-action modules.
-- A version is immutable: saving a runbook adds version N+1, and every
-- execution keeps action ID (runbook.<slug>), version and artifact hash, so
-- it always refers to the exact bytes it ran. The triggers refuse any
-- change or removal of a stored version.
CREATE TABLE runbooks (
    slug       TEXT    PRIMARY KEY CHECK (length(slug) BETWEEN 1 AND 40),
    created_by TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at INTEGER NOT NULL
);

CREATE TABLE runbook_versions (
    slug            TEXT    NOT NULL REFERENCES runbooks (slug),
    version         INTEGER NOT NULL CHECK (version BETWEEN 1 AND 999999),
    title           TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
    description     TEXT    NOT NULL CHECK (length(description) <= 2000),
    risk            TEXT    NOT NULL CHECK (risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    durable         INTEGER NOT NULL CHECK (durable IN (0, 1)),
    timeout_s       INTEGER NOT NULL CHECK (timeout_s BETWEEN 10 AND 21600),
    params          TEXT    NOT NULL CHECK (length(params) <= 20000),
    body            BLOB    NOT NULL CHECK (length(body) BETWEEN 1 AND 262144),
    artifact        BLOB    NOT NULL,
    artifact_sha256 TEXT    NOT NULL CHECK (length(artifact_sha256) = 64),
    created_by      TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (slug, version)
);

CREATE TRIGGER runbook_versions_immutable BEFORE UPDATE ON runbook_versions
BEGIN
    SELECT RAISE(ABORT, 'runbook versions are immutable');
END;

CREATE TRIGGER runbook_versions_kept BEFORE DELETE ON runbook_versions
BEGIN
    SELECT RAISE(ABORT, 'runbook versions are kept');
END;

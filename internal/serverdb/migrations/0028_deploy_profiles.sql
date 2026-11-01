-- 0028_deploy_profiles.sql: deploy profiles (ADR 0008 section 1, PV-04).
-- A version is immutable: editing a profile saves version N+1, and every
-- deployment records the exact profile version and document digest it
-- planned from. The document is the canonical, secret-free JSON profile;
-- the triggers refuse any change or removal of a stored version.
CREATE TABLE deploy_profiles (
    slug       TEXT    PRIMARY KEY CHECK (length(slug) BETWEEN 1 AND 40),
    created_by TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at INTEGER NOT NULL
);

CREATE TABLE deploy_profile_versions (
    slug         TEXT    NOT NULL REFERENCES deploy_profiles (slug),
    version      INTEGER NOT NULL CHECK (version BETWEEN 1 AND 999999),
    title        TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
    description  TEXT    NOT NULL CHECK (length(description) <= 2000),
    doc          TEXT    NOT NULL CHECK (length(doc) BETWEEN 1 AND 16000),
    doc_sha256   TEXT    NOT NULL CHECK (length(doc_sha256) = 64),
    created_by   TEXT    NOT NULL CHECK (length(created_by) <= 64),
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (slug, version)
);

CREATE TRIGGER deploy_profile_versions_immutable BEFORE UPDATE ON deploy_profile_versions
BEGIN
    SELECT RAISE(ABORT, 'deploy profile versions are immutable');
END;

CREATE TRIGGER deploy_profile_versions_kept BEFORE DELETE ON deploy_profile_versions
BEGIN
    SELECT RAISE(ABORT, 'deploy profile versions are kept');
END;

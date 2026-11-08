-- 0022_container_definitions.sql (ADR 0006 P2-03, container updates cu05):
-- versioned operator definitions of standalone containers. The content is
-- secret (it holds env values) and lives only in the executor vault, one
-- vault secret per version, 'ctrdef.<definition_id>.<version>', written
-- once and never replaced. This table holds the metadata only: no content
-- and no digest of the content.
--
-- definition_id is a random UUID issued once per host and container name,
-- so it stays the same across recreates (a new container ID) and every
-- version of one container shares it. Rows are write-once; a version is
-- dropped, together with its vault secret, only while no container
-- recreation inside its rollback window references it.
CREATE TABLE container_definitions (
    host_id         TEXT NOT NULL CHECK (length(host_id) BETWEEN 1 AND 255),
    container_name  TEXT NOT NULL CHECK (length(container_name) BETWEEN 1 AND 128),
    definition_id   TEXT NOT NULL CHECK (length(definition_id) = 36),
    version         INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    vault_secret_id TEXT NOT NULL UNIQUE CHECK (length(vault_secret_id) <= 64
                        AND vault_secret_id = 'ctrdef.' || definition_id || '.' || CAST(version AS TEXT)),
    created_by      TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 255),
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (definition_id, version)
);
CREATE INDEX container_definitions_unit ON container_definitions (host_id, container_name, version);

-- Versions are written once: a stored version never changes.
CREATE TRIGGER container_definitions_write_once BEFORE UPDATE ON container_definitions
BEGIN
    SELECT RAISE(ABORT, 'container definitions are write-once');
END;

-- One definition_id per host and container name, and one host and
-- container name per definition_id.
CREATE TRIGGER container_definitions_one_id BEFORE INSERT ON container_definitions
WHEN EXISTS (SELECT 1 FROM container_definitions
             WHERE (definition_id = NEW.definition_id AND (host_id <> NEW.host_id OR container_name <> NEW.container_name))
                OR (host_id = NEW.host_id AND container_name = NEW.container_name AND definition_id <> NEW.definition_id))
BEGIN
    SELECT RAISE(ABORT, 'container definition identity mismatch');
END;

-- 0027_integrity_references.sql (ADR 0015 D2 "Offline installations",
-- D4 "Reference"; IG-03): the installed-files reference the executor
-- admitted into its own storage.
--
-- The executor admits release-manifest.json, its signature and
-- installed-files.json only after verifying the signature against its
-- durable root state and the list's SHA-256 against the manifest
-- (integrity.Admit). The exact bytes are copied here; later checks read
-- this copy, never the one under /usr/share. Exactly one row is active
-- per installation; superseded rows stay as history and are never
-- deleted or changed except for being superseded once.
--
-- The rollback rule (no lower release_version than the active one, no
-- second manifest for the same release_version) needs SemVer precedence
-- and is enforced by the store in the admitting transaction.
CREATE TABLE integrity_references (
    id              INTEGER PRIMARY KEY,
    release_version TEXT    NOT NULL CHECK (length(release_version) BETWEEN 1 AND 64),
    manifest        BLOB    NOT NULL CHECK (length(manifest) BETWEEN 1 AND 1048576),
    signature       BLOB    NOT NULL CHECK (length(signature) BETWEEN 1 AND 4096),
    list            BLOB    NOT NULL CHECK (length(list) BETWEEN 1 AND 4194304),
    manifest_sha256 TEXT    NOT NULL CHECK (length(manifest_sha256) = 64
                        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    list_sha256     TEXT    NOT NULL CHECK (length(list_sha256) = 64
                        AND list_sha256 NOT GLOB '*[^0-9a-f]*'),
    signed_by       TEXT    NOT NULL CHECK (length(signed_by) BETWEEN 1 AND 128),
    admitted_at     INTEGER NOT NULL,
    active          INTEGER NOT NULL CHECK (active IN (0, 1)),
    superseded_at   INTEGER,
    CHECK ((active = 1) = (superseded_at IS NULL))
);

-- Exactly one active reference per installation (this database).
CREATE UNIQUE INDEX integrity_references_one_active ON integrity_references (active) WHERE active = 1;

-- A new reference is always inserted as the active one.
CREATE TRIGGER integrity_references_insert_active
BEFORE INSERT ON integrity_references
WHEN NEW.active <> 1 OR NEW.superseded_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'integrity reference: a new reference must be the active one');
END;

-- Admitted bytes and metadata never change; the only update is
-- superseding the active row once.
CREATE TRIGGER integrity_references_immutable
BEFORE UPDATE ON integrity_references
WHEN NEW.id IS NOT OLD.id OR NEW.release_version IS NOT OLD.release_version
  OR NEW.manifest IS NOT OLD.manifest OR NEW.signature IS NOT OLD.signature
  OR NEW.list IS NOT OLD.list OR NEW.manifest_sha256 IS NOT OLD.manifest_sha256
  OR NEW.list_sha256 IS NOT OLD.list_sha256 OR NEW.signed_by IS NOT OLD.signed_by
  OR NEW.admitted_at IS NOT OLD.admitted_at
  OR NOT (OLD.active = 1 AND NEW.active = 0 AND NEW.superseded_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'integrity reference: admitted references are immutable');
END;

-- History is kept.
CREATE TRIGGER integrity_references_no_delete
BEFORE DELETE ON integrity_references
BEGIN
    SELECT RAISE(ABORT, 'integrity reference: admitted references are never deleted');
END;

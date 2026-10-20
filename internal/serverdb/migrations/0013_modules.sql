-- 0013_modules.sql: imported modules (M7-5, spec 10). A version is the
-- signed lock, its signature (if any) and its scripts; those never change.
-- state is the executor's verdict: verified (a trusted signer signed the
-- lock and the executor trusts its actions) or unverified (no signature,
-- an untrusted signer, or a signer change waiting for review); detail says
-- why. Only state, signer and detail may be updated (re-verification).
CREATE TABLE module_versions (
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 2 AND 31),
    version     TEXT    NOT NULL CHECK (length(version) BETWEEN 5 AND 20),
    lock        BLOB    NOT NULL CHECK (length(lock) <= 65536),
    lock_sha256 TEXT    NOT NULL CHECK (length(lock_sha256) = 64),
    signature   BLOB    NOT NULL CHECK (length(signature) <= 4096),
    scripts     BLOB    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('verified', 'unverified')),
    signer      TEXT    NOT NULL DEFAULT '' CHECK (length(signer) <= 200),
    detail      TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 400),
    imported_by TEXT    NOT NULL CHECK (length(imported_by) <= 64),
    imported_at INTEGER NOT NULL,
    PRIMARY KEY (name, version)
);

CREATE TRIGGER module_versions_immutable BEFORE UPDATE OF name, version, lock, lock_sha256, signature, scripts, imported_by, imported_at
ON module_versions
BEGIN
    SELECT RAISE(ABORT, 'module versions are immutable');
END;

CREATE TRIGGER module_versions_kept BEFORE DELETE ON module_versions
BEGIN
    SELECT RAISE(ABORT, 'module versions are kept');
END;

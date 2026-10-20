-- 0011_signers.sql (M7-5): trusted module signers and signed modules.
-- Written only through admin RPCs (the `nebula` CLI on the executor host)
-- and, for module registration, after the executor verified the signature
-- itself. Adding a signer is CRITICAL (spec 10).
CREATE TABLE trusted_signers (
    fingerprint TEXT    PRIMARY KEY CHECK (length(fingerprint) = 50),
    public_key  TEXT    NOT NULL CHECK (length(public_key) <= 200),
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    added_at    INTEGER NOT NULL,
    added_by    TEXT    NOT NULL
) WITHOUT ROWID;

-- The signer of each module name: an update signed by another signer is
-- refused until an admin confirms it (spec 10: manual review).
CREATE TABLE module_signers (
    name         TEXT    PRIMARY KEY CHECK (length(name) BETWEEN 2 AND 31),
    fingerprint  TEXT    NOT NULL CHECK (length(fingerprint) = 50),
    confirmed_by TEXT    NOT NULL,
    updated_at   INTEGER NOT NULL
) WITHOUT ROWID;

-- Registered module versions; a version's lock never changes.
CREATE TABLE module_versions (
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 2 AND 31),
    version     TEXT    NOT NULL CHECK (length(version) BETWEEN 5 AND 20),
    lock_sha256 TEXT    NOT NULL CHECK (length(lock_sha256) = 64),
    fingerprint TEXT    NOT NULL CHECK (length(fingerprint) = 50),
    registered_at INTEGER NOT NULL,
    PRIMARY KEY (name, version)
) WITHOUT ROWID;

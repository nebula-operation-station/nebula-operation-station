-- 0006_vault.sql (M2): the secret vault for everything that is not an SSH
-- key (spec 06). Only ciphertext is stored: the master key is wrapped with
-- a key derived from the vault passphrase (Argon2id, parameters below),
-- and each secret has its own data key wrapped with the master key. The
-- secret's ID and version are associated data of both encryptions, so a
-- blob copied to another record or version does not decrypt.
CREATE TABLE vault_meta (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    format         INTEGER NOT NULL CHECK (format = 1),
    kdf_time       INTEGER NOT NULL CHECK (kdf_time BETWEEN 1 AND 64),
    kdf_memory_kib INTEGER NOT NULL CHECK (kdf_memory_kib BETWEEN 8 AND 4194304),
    kdf_threads    INTEGER NOT NULL CHECK (kdf_threads BETWEEN 1 AND 255),
    salt           BLOB    NOT NULL CHECK (length(salt) = 16),
    wrapped_master BLOB    NOT NULL CHECK (length(wrapped_master) = 72),
    created_at     INTEGER NOT NULL,
    created_by     TEXT    NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200)
);

CREATE TABLE vault_secrets (
    id          TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    version     INTEGER NOT NULL CHECK (version >= 1),
    wrapped_dek BLOB    NOT NULL CHECK (length(wrapped_dek) = 72),
    sealed      BLOB    NOT NULL CHECK (length(sealed) BETWEEN 40 AND 65600),
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 200)
);

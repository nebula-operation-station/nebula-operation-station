-- 0003_webauthn_credentials.sql (H03): WebAuthn credentials registered on
-- the executor. Public keys only; they never leave the executor except as
-- IDs in WebAuthn options. Signature counters stay in webauthn_counters.
--
-- Like 0002 these rows grant capability (a credential can approve permits),
-- so their integrity matters. Losing them only removes capability.
CREATE TABLE webauthn_credentials (
    credential_id      BLOB    PRIMARY KEY CHECK (length(credential_id) BETWEEN 1 AND 1023),
    public_key         BLOB    NOT NULL CHECK (length(public_key) BETWEEN 1 AND 2048),
    user_handle        BLOB    NOT NULL CHECK (length(user_handle) BETWEEN 0 AND 64),
    user_name          TEXT    NOT NULL CHECK (length(user_name) BETWEEN 1 AND 64),
    label              TEXT    NOT NULL DEFAULT '' CHECK (length(label) <= 200),
    aaguid             BLOB    NOT NULL CHECK (length(aaguid) IN (0, 16)),
    attestation_format TEXT    NOT NULL CHECK (length(attestation_format) <= 32),
    created_at         INTEGER NOT NULL,
    created_by         TEXT    NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200)
) WITHOUT ROWID;

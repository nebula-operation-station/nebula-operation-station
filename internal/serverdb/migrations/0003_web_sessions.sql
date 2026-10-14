-- 0003_web_sessions.sql (M2): web sessions after a WebAuthn login that the
-- executor verified. Only the SHA-256 of the session token is stored, so a
-- copy of this database does not yield a usable cookie. Times are Unix
-- seconds (compared in SQL), unlike the RFC 3339 text elsewhere.
CREATE TABLE web_sessions (
    token_hash    BLOB    PRIMARY KEY CHECK (length(token_hash) = 32),
    credential_id TEXT    NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1400),
    user_name     TEXT    NOT NULL CHECK (length(user_name) <= 64),
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX web_sessions_expires ON web_sessions (expires_at);

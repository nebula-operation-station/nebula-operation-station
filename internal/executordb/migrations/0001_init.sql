-- 0001_init.sql: executor state that must survive a restart.
--
-- Permits and the privileged session are deliberately NOT stored: a restart
-- revokes them (safe default). What is stored can only make the executor
-- stricter after a restart, never more permissive.

-- Spent execution IDs. An ID is bound to one request digest when its
-- permit is created and stays bound, so it can neither be revived nor
-- re-bound to other content after a restart. Rows are pruned only long
-- after the request expired (see RetainSpentExecutions).
CREATE TABLE execution_ids (
    execution_id TEXT    PRIMARY KEY CHECK (length(execution_id) BETWEEN 1 AND 64),
    digest       BLOB    NOT NULL CHECK (length(digest) = 32),
    expires_at   INTEGER NOT NULL,
    bound_at     INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_execution_ids_expires ON execution_ids (expires_at);

-- WebAuthn signature counters (WebAuthn §6.1.1). The stored value only
-- ever grows.
CREATE TABLE webauthn_counters (
    credential_id BLOB    PRIMARY KEY CHECK (length(credential_id) BETWEEN 1 AND 1023),
    sign_count    INTEGER NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    updated_at    INTEGER NOT NULL
) WITHOUT ROWID;

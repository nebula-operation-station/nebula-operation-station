-- 0005_totp_recovery.sql (M2): TOTP for account recovery (spec 05) and the
-- recovery state. Set up only through admin RPCs (the `nebula` CLI on the
-- executor host). The secret is stored as is: executor.db is private to
-- the executor user (0600); the vault (Milestone 2) will encrypt it.
--
-- last_step makes every code single-use. recovery_state is set by a
-- recovery login and cleared when a new WebAuthn credential is registered;
-- while it is set, no privileged session or browser approval is possible.
CREATE TABLE totp (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    secret     BLOB    NOT NULL CHECK (length(secret) = 20),
    activated  INTEGER NOT NULL DEFAULT 0 CHECK (activated IN (0, 1)),
    last_step  INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    created_by TEXT    NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200)
);

CREATE TABLE recovery_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    pending_since INTEGER NOT NULL
);

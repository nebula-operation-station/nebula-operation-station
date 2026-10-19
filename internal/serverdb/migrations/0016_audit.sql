-- 0016_audit.sql (M10-1): the server's own audit lines (the web `audit`
-- log lines), for the History page. The hash chain is optional
-- (audit_hash_chain in server.json): the server cannot sign its lines in a
-- way a compromised server could not repeat, so the chain only shows
-- accidental or offline changes. Executor events are signed and live in
-- executor.db.
CREATE TABLE audit_log (
    seq       INTEGER PRIMARY KEY CHECK (seq >= 1),
    at        INTEGER NOT NULL,
    kind      TEXT    NOT NULL CHECK (length(kind) <= 64),
    user_name TEXT    NOT NULL DEFAULT '' CHECK (length(user_name) <= 64),
    body      TEXT    NOT NULL CHECK (length(body) <= 65536),
    prev_hash BLOB,
    hash      BLOB
);
CREATE INDEX audit_log_kind ON audit_log (kind, seq);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'the audit log is append-only');
END;

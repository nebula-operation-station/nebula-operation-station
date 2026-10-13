-- 0004_host_keys.sql (H05): the SSH host key pinned per host, and how the
-- executor logs in there. Written only through admin RPCs (the `nebula` CLI
-- on the executor host) after the admin confirmed the fingerprint, never by
-- the server.
--
-- Every endpoint of a host must present exactly this key. A key belongs to
-- one host only: cloned machines with the same host key must be re-keyed.
-- blocked_* is set on the first host key mismatch and stops every further
-- connection to the host until the admin re-pins it.
CREATE TABLE host_keys (
    host_id             TEXT    PRIMARY KEY CHECK (length(host_id) BETWEEN 1 AND 63),
    public_key          BLOB    NOT NULL CHECK (length(public_key) BETWEEN 1 AND 2048),
    fingerprint         TEXT    NOT NULL UNIQUE CHECK (length(fingerprint) = 50),
    ssh_user            TEXT    NOT NULL CHECK (length(ssh_user) BETWEEN 1 AND 32),
    credential_ref      TEXT    NOT NULL CHECK (length(credential_ref) BETWEEN 1 AND 64),
    source              TEXT    NOT NULL CHECK (source IN ('probe', 'known_hosts')),
    pinned_at           INTEGER NOT NULL,
    pinned_by           TEXT    NOT NULL CHECK (length(pinned_by) BETWEEN 1 AND 200),
    blocked_at          INTEGER,
    blocked_fingerprint TEXT    CHECK (blocked_fingerprint IS NULL OR length(blocked_fingerprint) <= 64),
    blocked_endpoint    TEXT    CHECK (blocked_endpoint IS NULL OR length(blocked_endpoint) <= 300)
) WITHOUT ROWID;

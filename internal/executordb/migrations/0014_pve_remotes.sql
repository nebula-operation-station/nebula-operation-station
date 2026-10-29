-- 0014_pve_remotes.sql (ADR 0006, P1-04): the executor's durable registry
-- of PVE remotes. The executor alone owns the authoritative endpoints,
-- trust pins, generations and tombstones; server tables are presentation
-- copies only (spec 03). Only opaque vault references and versions are
-- stored here, never secret values (spec 06).
--
-- A removed remote keeps its row as a tombstone: the remote_id and its
-- trust identity stay reserved, so an id can never be reused under a
-- different trust identity without an explicit re-add, and a trust
-- identity can never be registered for a second remote id (the UNIQUE
-- index below is the database-level guard).
CREATE TABLE pve_remotes (
    remote_id                 TEXT PRIMARY KEY CHECK (length(remote_id) BETWEEN 1 AND 64),
    name                      TEXT NOT NULL CHECK (length(name) <= 255),
    kind                      TEXT NOT NULL CHECK (kind IN ('cluster', 'standalone')),
    trust_pin_kind            TEXT NOT NULL CHECK (trust_pin_kind IN ('ca', 'leaf')),
    trust_pin                 TEXT NOT NULL CHECK (length(trust_pin) = 64),
    trust_generation          INTEGER NOT NULL CHECK (trust_generation BETWEEN 1 AND 281474976710655),
    state                     TEXT NOT NULL CHECK (state IN ('active', 'blocked', 'removed')),
    read_credential_ref       TEXT NOT NULL CHECK (length(read_credential_ref) <= 64),
    read_credential_version   INTEGER NOT NULL CHECK (read_credential_version BETWEEN 0 AND 9223372036854775807),
    action_credential_ref     TEXT NOT NULL CHECK (length(action_credential_ref) <= 64),
    action_credential_version INTEGER NOT NULL CHECK (action_credential_version BETWEEN 0 AND 9223372036854775807),
    blocked_at                INTEGER,
    blocked_by                TEXT CHECK (length(blocked_by) <= 64),
    blocked_reason            TEXT CHECK (length(blocked_reason) <= 512),
    removed_at                INTEGER,
    created_at                INTEGER NOT NULL,
    updated_at                INTEGER NOT NULL,
    updated_by                TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 64)
);

-- The current trust identity of every remote, including tombstones.
CREATE UNIQUE INDEX pve_remote_trust_pin_idx ON pve_remotes (trust_pin);

-- Ordered node API endpoints of a remote (failover order).
CREATE TABLE pve_remote_endpoints (
    remote_id TEXT NOT NULL REFERENCES pve_remotes(remote_id),
    seq       INTEGER NOT NULL CHECK (seq BETWEEN 1 AND 64),
    host      TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    port      INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    PRIMARY KEY (remote_id, seq)
);

-- Append-only audit trail of trust, endpoint, credential and state
-- changes. Detail is structured, nonsecret text; secrets never appear
-- here.
CREATE TABLE pve_remote_changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    remote_id   TEXT NOT NULL,
    change_type TEXT NOT NULL CHECK (change_type IN ('created', 're_added', 'endpoint_change', 'trust_repin', 'blocked', 'unblocked', 'credentials', 'removed')),
    detail      TEXT NOT NULL CHECK (length(detail) <= 512),
    actor       TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 64),
    at          INTEGER NOT NULL
);

CREATE INDEX pve_remote_changes_remote_idx ON pve_remote_changes (remote_id, id);

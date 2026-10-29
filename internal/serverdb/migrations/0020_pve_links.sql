-- 0020_pve_links.sql
-- PVE guest <-> managed host linking, staging and drift hints (ADR 0006,
-- ticket P1-12).
--
-- * pve_host_links holds explicit, reviewed links. A link is created only
--   by an explicit import/confirm call, never automatically. It is keyed
--   by the guest incarnation (remote_id, vmid, generation): a reused VMID
--   (new generation) never inherits a link. Unlinking is a tombstone
--   (unlinked_at), keeping the explicit link history (ADR 0006).
-- * pve_staging is the staging list of unmanaged guests (like
--   discovery_staging): NEW / EXISTING / POSSIBLE / CONFLICT, with the
--   computed candidates. Nothing becomes a managed host until an explicit
--   import ("add to managed hosts").
-- * pve_drift_hints are read-only drift records (inventory vs PVE: ip,
--   ram, node, state) with an explicit accept/ignore decision. Accepting
--   updates display fields only, never SSH endpoints, keys or criticality.
-- * Conflicts (one MAC on two guests, one IP on two hosts) are flagged in
--   these rows' data, never resolved silently.

CREATE TABLE pve_host_links (
    id            INTEGER PRIMARY KEY,
    remote_id     TEXT NOT NULL,
    vmid          INTEGER NOT NULL,
    generation    INTEGER NOT NULL,
    host_id       TEXT NOT NULL,
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    unlinked_at   TEXT NOT NULL DEFAULT '',
    unlink_reason TEXT NOT NULL DEFAULT ''
    -- At most one active link (unlinked_at = '') per incarnation and one
    -- active link per host are enforced transactionally in
    -- pveinventory.CreateLink; the table keeps the full explicit link
    -- history (tombstones are never deleted).
);
CREATE INDEX idx_pve_host_links_incarnation ON pve_host_links (remote_id, vmid, generation);
CREATE INDEX idx_pve_host_links_host ON pve_host_links (host_id);
CREATE INDEX idx_pve_host_links_unlinked_at ON pve_host_links (unlinked_at);

CREATE TABLE pve_staging (
    remote_id       TEXT NOT NULL,
    vmid            INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    kind            TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL DEFAULT '',
    node            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT '',
    hostname        TEXT NOT NULL DEFAULT '',
    macs_json       TEXT NOT NULL DEFAULT '[]',
    ips_json        TEXT NOT NULL DEFAULT '[]',
    state           TEXT NOT NULL CHECK (state IN ('NEW', 'EXISTING', 'POSSIBLE', 'CONFLICT')),
    candidates_json TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    imported_at     TEXT NOT NULL DEFAULT '',
    imported_by     TEXT NOT NULL DEFAULT '',
    imported_asset  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (remote_id, vmid, generation)
);
CREATE INDEX idx_pve_staging_remote ON pve_staging (remote_id);

CREATE TABLE pve_drift_hints (
    id            INTEGER PRIMARY KEY,
    remote_id     TEXT NOT NULL,
    vmid          INTEGER NOT NULL,
    generation    INTEGER NOT NULL,
    host_id       TEXT NOT NULL,
    field         TEXT NOT NULL CHECK (field IN ('ip', 'ram', 'node', 'state')),
    pve_value     TEXT NOT NULL,
    host_value    TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'accepted', 'ignored')),
    decided_by    TEXT NOT NULL DEFAULT '',
    decided_at    TEXT NOT NULL DEFAULT '',
    UNIQUE (remote_id, vmid, generation, host_id, field, pve_value, host_value)
);
CREATE INDEX idx_pve_drift_hints_remote ON pve_drift_hints (remote_id);
CREATE INDEX idx_pve_drift_hints_host ON pve_drift_hints (host_id);

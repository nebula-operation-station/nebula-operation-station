-- 0034_net_guest_nics.sql
-- Provider-reported guest NICs for the traffic map (ADR 0009 D1 tier 2,
-- TM14).
--
-- These rows are the pve-collector's claim about a remote's guest
-- configuration (bridge, VLAN tag, MAC per guest netN), imported from the
-- spool by the server. They are kept apart from the observed tiers on
-- purpose: they never create or change net_endpoints, carry no address
-- and are matched to observed endpoints only by MAC, at read time, on the
-- server. Their source is always "provider".
--
-- net_guest_nic_snapshots has one row per remote with the observation
-- time of the remote's latest imported snapshot; an older snapshot is
-- refused, so a replay cannot roll a remote back. net_guest_nics holds
-- that snapshot's NICs, replaced as a whole on every import, and cascades
-- with its snapshot row.
--
-- Bounds (internal/trafficstore): the number of remotes, the NICs per
-- remote and the NICs in total are capped; the total is kept by triggers
-- in traffic_counts under name 'guest_nics' (reporter '' is the total).
-- Retention: Prune removes snapshots (and with them their NICs) whose
-- observation time lies before now-retention.

CREATE TABLE net_guest_nic_snapshots (
    remote      TEXT PRIMARY KEY,
    observed_at INTEGER NOT NULL,
    imported_at INTEGER NOT NULL
);
CREATE INDEX idx_net_guest_nic_snapshots_observed ON net_guest_nic_snapshots (observed_at);

CREATE TABLE net_guest_nics (
    remote    TEXT NOT NULL REFERENCES net_guest_nic_snapshots(remote) ON DELETE CASCADE,
    vmid      INTEGER NOT NULL,
    nic_index INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    bridge    TEXT NOT NULL DEFAULT '',
    vlan      INTEGER NOT NULL DEFAULT 0,
    mac       TEXT NOT NULL,
    PRIMARY KEY (remote, vmid, nic_index)
);
-- Endpoint matching joins by MAC; a MAC may be reported by several
-- remotes (cloned guests), so the index is not unique.
CREATE INDEX idx_net_guest_nics_mac ON net_guest_nics (mac);

CREATE TRIGGER net_guest_nics_count_insert AFTER INSERT ON net_guest_nics
BEGIN
    INSERT OR IGNORE INTO traffic_counts (name, reporter, n) VALUES ('guest_nics', '', 0);
    UPDATE traffic_counts SET n = n + 1 WHERE name = 'guest_nics' AND reporter = '';
END;

CREATE TRIGGER net_guest_nics_count_delete AFTER DELETE ON net_guest_nics
BEGIN
    UPDATE traffic_counts SET n = n - 1 WHERE name = 'guest_nics' AND reporter = '';
END;

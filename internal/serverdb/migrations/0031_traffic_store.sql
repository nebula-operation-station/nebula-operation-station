-- 0031_traffic_store.sql
-- Traffic store: observed endpoints and hourly flow buckets (ADR 0009,
-- TM11; decisions D2, D3, D7).
--
-- net_endpoints is the deduplicated set of endpoints observed on the
-- network: one row per MAC, or per first-seen address when no MAC is
-- known. The identity is store-assigned ("mac:<mac>" or
-- "addr:<address>"). Addresses accumulate in net_endpoint_addresses.
-- The row carries the VLAN, the vendor OUI, the hostname, first/last
-- seen, the source tier, the reporter, and the link to the matching IPAM
-- asset or managed host.
--
-- flow_buckets holds one row per (hour, flow key, reporter): the bytes
-- and connection counts that one reporter attributed to one flow in one
-- hour. Bytes and connections accumulate on upsert (a report interval
-- can contribute several parts to one hour); queries merge the rows of a
-- flow per hour, preferring the server end's report (internal/flowagg
-- semantics).
--
-- Retention (D3): rows older than the retention (default 21 days,
-- configurable lower only) are removed by Prune, which the store runs at
-- most once per clock hour on writes and which the server schedule
-- invokes hourly.
--
-- Caps (D7): internal/trafficstore bounds the total rows and the rows
-- per reporter; a reporter that reaches its cap is refused, other
-- reporters' data is never evicted.
--
-- Every value comes from a managed host and is untrusted input; it is
-- validated against explicit limits in internal/trafficstore before it
-- reaches the database. No credential material or raw host output lives
-- here.

CREATE TABLE net_endpoints (
    id            TEXT PRIMARY KEY,
    mac           TEXT NOT NULL DEFAULT '',
    vlan          INTEGER NOT NULL DEFAULT 0,
    oui           TEXT NOT NULL DEFAULT '',
    hostname      TEXT NOT NULL DEFAULT '',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    tier          TEXT NOT NULL DEFAULT '',
    reporter      TEXT NOT NULL DEFAULT '',
    ipam_asset_id TEXT NOT NULL DEFAULT '',
    host_id       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_net_endpoints_mac ON net_endpoints (mac);
CREATE INDEX idx_net_endpoints_reporter ON net_endpoints (reporter);
CREATE INDEX idx_net_endpoints_last_seen ON net_endpoints (last_seen);
CREATE INDEX idx_net_endpoints_ipam_asset ON net_endpoints (ipam_asset_id);
CREATE INDEX idx_net_endpoints_host ON net_endpoints (host_id);

CREATE TABLE net_endpoint_addresses (
    endpoint_id TEXT NOT NULL REFERENCES net_endpoints(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    PRIMARY KEY (endpoint_id, address)
);
CREATE INDEX idx_net_endpoint_addresses_address ON net_endpoint_addresses (address);

CREATE TABLE flow_buckets (
    hour            INTEGER NOT NULL,
    a               TEXT NOT NULL,
    b               TEXT NOT NULL,
    proto           INTEGER NOT NULL,
    server_port     INTEGER NOT NULL,
    server_side     INTEGER NOT NULL,
    tier            TEXT NOT NULL,
    bytes_ab        INTEGER NOT NULL DEFAULT 0,
    bytes_ba        INTEGER NOT NULL DEFAULT 0,
    connections     INTEGER NOT NULL DEFAULT 0,
    lower_bound     INTEGER NOT NULL DEFAULT 0,
    reporter        TEXT NOT NULL,
    server_reported INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, a, b, proto, server_port, server_side, tier, reporter)
);
-- Top-5 / overview queries scan by endpoint and hour range.
CREATE INDEX idx_flow_buckets_a_hour ON flow_buckets (a, hour);
CREATE INDEX idx_flow_buckets_b_hour ON flow_buckets (b, hour);
-- Pruning scans by hour.
CREATE INDEX idx_flow_buckets_hour ON flow_buckets (hour);
-- Per-reporter cap counting.
CREATE INDEX idx_flow_buckets_reporter ON flow_buckets (reporter);

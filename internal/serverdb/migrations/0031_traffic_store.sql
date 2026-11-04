-- 0031_traffic_store.sql
-- Traffic store: observed endpoints and hourly flow buckets (ADR 0009,
-- TM11; decisions D2, D3, D7).
--
-- net_endpoints is the deduplicated set of endpoints observed on the
-- network: at most one row per MAC (unique index), otherwise one row per
-- address-only observation. The id is an opaque, store-assigned value
-- that never changes. Only server-derived values live here: the MAC, its
-- OUI (derived from the MAC), last_seen (the latest of all reporters,
-- for prune), the authoritative owner and the IPAM/host links. owner is
-- the managed host that has the endpoint's MAC on its own interface (or,
-- without a MAC, all its addresses) according to the server's own
-- records, '' when no such host reported it; it is never taken from a
-- report. ipam_asset_id and host_id are set by server-side matching
-- only.
--
-- net_endpoint_reporters is the seen-by set: one row per (endpoint,
-- reporter) with everything that reporter claimed (tier, VLAN, hostname,
-- OUI without MAC) and its first/last seen. first_ingest is the server's
-- time of the reporter's first report for the endpoint; first_seen is
-- clamped to it minus a bounded lead, so a reporter cannot claim the
-- epoch. Reads prefer the owner's row and flag conflicts between
-- reporters when there is no owner. Per-host caps count these rows, so
-- one reporter's activity never shifts another reporter's count.
-- net_endpoint_addresses attributes every address to the reporter that
-- saw it; the per-endpoint address cap applies per (endpoint, reporter),
-- so another reporter cannot fill the owner's address slots. Rows
-- cascade: endpoint -> reporters -> addresses.
--
-- flow_buckets holds at most one row per (hour, flow key, reporting
-- side): server_reported = 1 is the server end's report, 0 the client
-- end's. The first reporter of a side holds it; a different reporter is
-- refused as a conflict (internal/flowagg semantics), so the same bytes
-- are never taken from two hosts and an unrelated host cannot override a
-- side it does not own. The store also refuses observations whose claimed
-- end is not one of the reporter's own addresses ("foreign").
--
-- traffic_counts holds the row counts the caps are checked against,
-- maintained by triggers so inserts, prune and cascades keep them exact
-- without COUNT(*) scans: name 'buckets' / 'endpoints' with reporter ''
-- is the total, name 'buckets' / 'endpoint_seen' with a reporter is that
-- reporter's count (reporter names are never empty).
--
-- traffic_store_lock has one row; every write transaction updates it
-- first, so the transaction holds the write lock before it reads the
-- caps (a serialized write instead of a failed snapshot upgrade).
--
-- Retention (D3): Prune removes rows older than the retention (default
-- 21 days, configurable lower only), at most once per clock hour on
-- writes and hourly from the server schedule.
--
-- Every value comes from a managed host and is untrusted input; it is
-- validated against explicit limits in internal/trafficstore before it
-- reaches the database. No credential material or raw host output lives
-- here.

CREATE TABLE net_endpoints (
    id            TEXT PRIMARY KEY,
    mac           TEXT NOT NULL DEFAULT '',
    oui           TEXT NOT NULL DEFAULT '',
    last_seen     INTEGER NOT NULL,
    owner         TEXT NOT NULL DEFAULT '',
    ipam_asset_id TEXT NOT NULL DEFAULT '',
    host_id       TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_net_endpoints_mac ON net_endpoints (mac) WHERE mac != '';
CREATE INDEX idx_net_endpoints_last_seen ON net_endpoints (last_seen);
CREATE INDEX idx_net_endpoints_owner ON net_endpoints (owner) WHERE owner != '';
CREATE INDEX idx_net_endpoints_ipam_asset ON net_endpoints (ipam_asset_id);
CREATE INDEX idx_net_endpoints_host ON net_endpoints (host_id);

CREATE TABLE net_endpoint_reporters (
    endpoint_id  TEXT NOT NULL REFERENCES net_endpoints(id) ON DELETE CASCADE,
    reporter     TEXT NOT NULL,
    tier         TEXT NOT NULL,
    vlan         INTEGER NOT NULL DEFAULT 0,
    oui          TEXT NOT NULL DEFAULT '',
    hostname     TEXT NOT NULL DEFAULT '',
    first_seen   INTEGER NOT NULL,
    first_ingest INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    PRIMARY KEY (endpoint_id, reporter)
);
CREATE INDEX idx_net_endpoint_reporters_last_seen ON net_endpoint_reporters (last_seen);

CREATE TABLE net_endpoint_addresses (
    endpoint_id TEXT NOT NULL,
    reporter    TEXT NOT NULL,
    address     TEXT NOT NULL,
    PRIMARY KEY (endpoint_id, reporter, address),
    FOREIGN KEY (endpoint_id, reporter)
        REFERENCES net_endpoint_reporters (endpoint_id, reporter) ON DELETE CASCADE
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
    server_reported INTEGER NOT NULL,
    reporter        TEXT NOT NULL,
    bytes_ab        INTEGER NOT NULL DEFAULT 0,
    bytes_ba        INTEGER NOT NULL DEFAULT 0,
    connections     INTEGER NOT NULL DEFAULT 0,
    lower_bound     INTEGER NOT NULL DEFAULT 0,
    -- ab_key orders (a, b) as netip.Addr.Compare does (family byte, then
    -- the 16-byte address of a, then of b), so SQL tie breaks match
    -- internal/flowagg's key order; text order of a/b does not.
    ab_key          BLOB NOT NULL DEFAULT x'',
    -- The leading hour column also serves Prune (hour <= ?).
    PRIMARY KEY (hour, a, b, proto, server_port, server_side, tier, server_reported)
);
-- Top-5 / overview queries scan by endpoint and hour range.
CREATE INDEX idx_flow_buckets_a_hour ON flow_buckets (a, hour);
CREATE INDEX idx_flow_buckets_b_hour ON flow_buckets (b, hour);

CREATE TABLE traffic_counts (
    name     TEXT NOT NULL,
    reporter TEXT NOT NULL,
    n        INTEGER NOT NULL,
    PRIMARY KEY (name, reporter)
);

CREATE TRIGGER flow_buckets_count_insert AFTER INSERT ON flow_buckets
BEGIN
    INSERT OR IGNORE INTO traffic_counts (name, reporter, n) VALUES ('buckets', '', 0);
    INSERT OR IGNORE INTO traffic_counts (name, reporter, n) VALUES ('buckets', NEW.reporter, 0);
    UPDATE traffic_counts SET n = n + 1
        WHERE name = 'buckets' AND reporter IN ('', NEW.reporter);
END;

CREATE TRIGGER flow_buckets_count_delete AFTER DELETE ON flow_buckets
BEGIN
    UPDATE traffic_counts SET n = n - 1
        WHERE name = 'buckets' AND reporter IN ('', OLD.reporter);
    DELETE FROM traffic_counts
        WHERE name = 'buckets' AND reporter = OLD.reporter AND reporter != '' AND n <= 0;
END;

CREATE TRIGGER net_endpoints_count_insert AFTER INSERT ON net_endpoints
BEGIN
    INSERT OR IGNORE INTO traffic_counts (name, reporter, n) VALUES ('endpoints', '', 0);
    UPDATE traffic_counts SET n = n + 1 WHERE name = 'endpoints' AND reporter = '';
END;

CREATE TRIGGER net_endpoints_count_delete AFTER DELETE ON net_endpoints
BEGIN
    UPDATE traffic_counts SET n = n - 1 WHERE name = 'endpoints' AND reporter = '';
END;

CREATE TRIGGER net_endpoint_reporters_count_insert AFTER INSERT ON net_endpoint_reporters
BEGIN
    INSERT OR IGNORE INTO traffic_counts (name, reporter, n) VALUES ('endpoint_seen', NEW.reporter, 0);
    UPDATE traffic_counts SET n = n + 1 WHERE name = 'endpoint_seen' AND reporter = NEW.reporter;
END;

CREATE TRIGGER net_endpoint_reporters_count_delete AFTER DELETE ON net_endpoint_reporters
BEGIN
    UPDATE traffic_counts SET n = n - 1 WHERE name = 'endpoint_seen' AND reporter = OLD.reporter;
    DELETE FROM traffic_counts WHERE name = 'endpoint_seen' AND reporter = OLD.reporter AND n <= 0;
END;

CREATE TABLE traffic_store_lock (
    id INTEGER PRIMARY KEY CHECK (id = 1)
);
INSERT INTO traffic_store_lock (id) VALUES (1);

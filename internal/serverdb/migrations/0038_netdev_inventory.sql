-- 0038_netdev_inventory.sql
-- Network device inventory store (ADR 0010 D4, Q11; plan ND-16 part 1).
--
-- Presentation copies of what the executor read from managed switches and
-- firewalls (internal/netdevcontract observations). Every string is device
-- text: untrusted, validated by internal/netdevcontract before it is
-- stored, stored verbatim and rendered as text only. The logic lives in
-- internal/netdevinventory; these tables hold its rows and enforce the
-- enums and sizes that must never be violated.
--
-- netdev_devices_seen: one row per device the server has learned of,
-- keyed by the executor's immutable device_id. last_seen is the newest
-- observed_at of any stored dataset; state turns 'stale' after three
-- missed poll intervals. Rows are never deleted by the inventory.
--
-- netdev_datasets: one row per stored dataset of one (device, read). A
-- read is replaced atomically: the new dataset and all its typed rows are
-- written in one transaction and become current (current = 1) while the
-- previous one is kept as history (current = 0) until retention removes
-- it. At most one current dataset per (device, read). state is 'fresh'
-- for a complete read, 'partial' for a list cut at its parse limit
-- (incomplete = 1) and 'stale' once the read is three poll intervals old.
-- payload_sha256 is the SHA-256 of the normalized payload; an identical
-- re-read only advances observed_at.
--
-- Typed row tables (one row per entry, keyed by dataset and row_key, the
-- entry's natural key within its read):
--   seq     position in the read (rule order), NULL for a carried row;
--   seen_at NULL for a row present in the read; for a row carried over
--           from the previous dataset, when it was last seen;
--   absent  1 when a complete read no longer contained the row. A row a
--           partial read did not cover is carried with absent = 0.
-- Rows missing from a read are therefore never silently dropped; they stay
-- visible as absent until their retention window has passed.
--
-- Times are INTEGER microseconds since the Unix epoch (UTC). List columns
-- (members, tags, VLAN lists, addresses, capabilities) are JSON arrays.

CREATE TABLE netdev_devices_seen (
    device_id        TEXT PRIMARY KEY CHECK (length(CAST(device_id AS BLOB)) BETWEEN 1 AND 64),
    family           TEXT NOT NULL CHECK (family IN ('cbs', 'panos')),
    label            TEXT NOT NULL DEFAULT '' CHECK (length(CAST(label AS BLOB)) <= 255),
    trust_generation INTEGER NOT NULL CHECK (trust_generation >= 1),
    last_seen        INTEGER,
    state            TEXT NOT NULL DEFAULT 'fresh' CHECK (state IN ('fresh', 'stale')),
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE TABLE netdev_datasets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      TEXT NOT NULL REFERENCES netdev_devices_seen (device_id),
    read           TEXT NOT NULL CHECK (read IN ('facts', 'ports', 'vlans', 'mac_table',
                       'lldp_neighbors', 'firewall_policy', 'hit_counts')),
    observed_at    INTEGER NOT NULL,
    stored_at      INTEGER NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('fresh', 'stale', 'partial')),
    incomplete     INTEGER NOT NULL CHECK (incomplete IN (0, 1)),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
    row_count      INTEGER NOT NULL CHECK (row_count >= 0),
    current        INTEGER NOT NULL CHECK (current IN (0, 1)),
    CHECK (incomplete = 0 OR state <> 'fresh'),
    CHECK (incomplete = 1 OR state <> 'partial')
);
CREATE UNIQUE INDEX idx_netdev_datasets_current ON netdev_datasets (device_id, read) WHERE current = 1;
CREATE INDEX idx_netdev_datasets_history ON netdev_datasets (device_id, read, observed_at);

CREATE TABLE netdev_facts (
    dataset_id           INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key              TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq                  INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at              INTEGER,
    absent               INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    model                TEXT NOT NULL CHECK (length(CAST(model AS BLOB)) BETWEEN 1 AND 255),
    firmware_version     TEXT NOT NULL CHECK (length(CAST(firmware_version AS BLOB)) BETWEEN 1 AND 255),
    serial               TEXT NOT NULL DEFAULT '' CHECK (length(CAST(serial AS BLOB)) <= 255),
    hostname             TEXT NOT NULL DEFAULT '' CHECK (length(CAST(hostname AS BLOB)) <= 255),
    uptime_seconds       INTEGER CHECK (uptime_seconds IS NULL OR uptime_seconds >= 0),
    management_addresses TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(management_addresses)),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL)
);

CREATE TABLE netdev_vlans (
    dataset_id INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key    TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq        INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at    INTEGER,
    absent     INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    vlan_id    INTEGER NOT NULL CHECK (vlan_id BETWEEN 1 AND 4094),
    name       TEXT NOT NULL DEFAULT '' CHECK (length(CAST(name AS BLOB)) <= 255),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL)
);

-- netdev_interfaces holds CBS switch ports (kind 'port', read 'ports') and
-- PAN-OS interfaces (kind 'firewall', read 'firewall_policy').
CREATE TABLE netdev_interfaces (
    dataset_id    INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key       TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq           INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at       INTEGER,
    absent        INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    kind          TEXT NOT NULL CHECK (kind IN ('port', 'firewall')),
    name          TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 64),
    admin_state   TEXT CHECK (admin_state IS NULL OR admin_state IN ('up', 'down', 'unknown')),
    oper_state    TEXT CHECK (oper_state IS NULL OR oper_state IN ('up', 'down', 'unknown')),
    speed_mbps    INTEGER CHECK (speed_mbps IS NULL OR speed_mbps BETWEEN 0 AND 1000000),
    mode          TEXT CHECK (mode IS NULL OR mode IN ('access', 'trunk', 'general', 'unknown')),
    access_vlan   INTEGER CHECK (access_vlan IS NULL OR access_vlan BETWEEN 1 AND 4094),
    native_vlan   INTEGER CHECK (native_vlan IS NULL OR native_vlan BETWEEN 1 AND 4094),
    allowed_vlans TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_vlans)),
    description   TEXT NOT NULL DEFAULT '' CHECK (length(CAST(description AS BLOB)) <= 255),
    vlan_tag      INTEGER CHECK (vlan_tag IS NULL OR vlan_tag BETWEEN 1 AND 4094),
    addresses     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(addresses)),
    zone          TEXT NOT NULL DEFAULT '' CHECK (length(CAST(zone AS BLOB)) <= 63),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL),
    CHECK (kind = 'firewall' OR (admin_state IS NOT NULL AND oper_state IS NOT NULL AND mode IS NOT NULL))
);

CREATE TABLE netdev_mac_entries (
    dataset_id INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key    TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq        INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at    INTEGER,
    absent     INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    vlan       INTEGER NOT NULL CHECK (vlan BETWEEN 1 AND 4094),
    mac        TEXT NOT NULL CHECK (length(mac) = 17),
    port       TEXT NOT NULL DEFAULT '' CHECK (length(CAST(port AS BLOB)) <= 64),
    type       TEXT NOT NULL CHECK (type IN ('dynamic', 'static', 'other')),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL)
);

CREATE TABLE netdev_lldp_neighbors (
    dataset_id         INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key            TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq                INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at            INTEGER,
    absent             INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    local_port         TEXT NOT NULL CHECK (length(CAST(local_port AS BLOB)) BETWEEN 1 AND 64),
    chassis_id         TEXT NOT NULL CHECK (length(CAST(chassis_id AS BLOB)) BETWEEN 1 AND 255),
    port_id            TEXT NOT NULL CHECK (length(CAST(port_id AS BLOB)) BETWEEN 1 AND 255),
    system_name        TEXT NOT NULL DEFAULT '' CHECK (length(CAST(system_name AS BLOB)) <= 255),
    management_address TEXT NOT NULL DEFAULT '' CHECK (length(CAST(management_address AS BLOB)) <= 64),
    capabilities       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(capabilities)),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL)
);

CREATE TABLE netdev_fw_rules (
    dataset_id   INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key      TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq          INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at      INTEGER,
    absent       INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    name         TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 63),
    uuid         TEXT NOT NULL DEFAULT '' CHECK (length(uuid) IN (0, 36)),
    from_zones   TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(from_zones)),
    to_zones     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(to_zones)),
    sources      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(sources)),
    destinations TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(destinations)),
    source_users TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(source_users)),
    applications TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(applications)),
    services     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(services)),
    categories   TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(categories)),
    action       TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both')),
    disabled     INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    description  TEXT NOT NULL DEFAULT '' CHECK (length(CAST(description AS BLOB)) <= 1024),
    tags         TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags)),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL)
);

CREATE TABLE netdev_nat_rules (
    dataset_id              INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key                 TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq                     INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at                 INTEGER,
    absent                  INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    name                    TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 63),
    uuid                    TEXT NOT NULL DEFAULT '' CHECK (length(uuid) IN (0, 36)),
    from_zones              TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(from_zones)),
    to_zones                TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(to_zones)),
    sources                 TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(sources)),
    destinations            TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(destinations)),
    service                 TEXT NOT NULL DEFAULT '' CHECK (length(CAST(service AS BLOB)) <= 255),
    source_translation      TEXT NOT NULL DEFAULT '' CHECK (length(CAST(source_translation AS BLOB)) <= 1024),
    destination_translation TEXT NOT NULL DEFAULT '' CHECK (length(CAST(destination_translation AS BLOB)) <= 1024),
    disabled                INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    description             TEXT NOT NULL DEFAULT '' CHECK (length(CAST(description AS BLOB)) <= 1024),
    tags                    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags)),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL)
);

-- netdev_objects holds the PAN-OS address and service objects, address and
-- service groups and zones of a firewall_policy dataset.
CREATE TABLE netdev_objects (
    dataset_id     INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key        TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq            INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at        INTEGER,
    absent         INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    kind           TEXT NOT NULL CHECK (kind IN ('address', 'address_group', 'service', 'service_group', 'zone')),
    name           TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 63),
    address_type   TEXT CHECK (address_type IS NULL OR address_type IN ('ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn')),
    value          TEXT NOT NULL DEFAULT '' CHECK (length(CAST(value AS BLOB)) <= 255),
    protocol       TEXT NOT NULL DEFAULT '' CHECK (protocol IN ('', 'tcp', 'udp', 'sctp')),
    port           TEXT NOT NULL DEFAULT '' CHECK (length(CAST(port AS BLOB)) <= 255),
    source_port    TEXT NOT NULL DEFAULT '' CHECK (length(CAST(source_port AS BLOB)) <= 255),
    static_members TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(static_members)),
    dynamic_filter TEXT NOT NULL DEFAULT '' CHECK (length(CAST(dynamic_filter AS BLOB)) <= 2048),
    interfaces     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(interfaces)),
    description    TEXT NOT NULL DEFAULT '' CHECK (length(CAST(description AS BLOB)) <= 1024),
    tags           TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags)),
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL),
    CHECK ((kind = 'address') = (address_type IS NOT NULL))
);

CREATE TABLE netdev_rule_hits (
    dataset_id INTEGER NOT NULL REFERENCES netdev_datasets (id) ON DELETE CASCADE,
    row_key    TEXT NOT NULL CHECK (length(CAST(row_key AS BLOB)) BETWEEN 1 AND 1024),
    seq        INTEGER CHECK (seq IS NULL OR seq >= 0),
    seen_at    INTEGER,
    absent     INTEGER NOT NULL DEFAULT 0 CHECK (absent IN (0, 1)),
    rule_name  TEXT NOT NULL CHECK (length(CAST(rule_name AS BLOB)) BETWEEN 1 AND 63),
    hits       INTEGER NOT NULL CHECK (hits >= 0),
    first_hit  INTEGER,
    last_hit   INTEGER,
    reset_at   INTEGER,
    PRIMARY KEY (dataset_id, row_key),
    CHECK ((seq IS NULL) = (seen_at IS NOT NULL)),
    CHECK (absent = 0 OR seen_at IS NOT NULL)
);

-- netdev_config_versions: redacted configuration versions (ADR 0010 D4
-- "Config versions, diff and drift"). Written by ND-17
-- (internal/netdevinventory/configs.go); created here so ND-16 retention
-- covers it. One row per distinct raw_digest per (device, config); an
-- identical read only advances last_seen. baseline marks the mirrored
-- executor-approved baseline, change_bound_at the time of the newest
-- change the version is bound to. Q11: kept 400 days, at most 1,000 per
-- device; the baseline, versions bound to a change in the last 400 days
-- and the newest version per (device, config) are never pruned.
CREATE TABLE netdev_config_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL REFERENCES netdev_devices_seen (device_id),
    config          TEXT NOT NULL CHECK (config IN ('running', 'startup')),
    raw_digest      TEXT NOT NULL CHECK (length(raw_digest) = 64 AND raw_digest NOT GLOB '*[^0-9a-f]*'),
    redacted_digest TEXT NOT NULL CHECK (length(redacted_digest) = 64 AND redacted_digest NOT GLOB '*[^0-9a-f]*'),
    redacted_text   TEXT NOT NULL CHECK (length(CAST(redacted_text AS BLOB)) BETWEEN 1 AND 8388608),
    lease_id        TEXT NOT NULL DEFAULT '' CHECK (length(CAST(lease_id AS BLOB)) <= 128),
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL CHECK (last_seen >= first_seen),
    baseline        INTEGER NOT NULL DEFAULT 0 CHECK (baseline IN (0, 1)),
    change_bound_at INTEGER,
    UNIQUE (device_id, config, raw_digest)
);
CREATE INDEX idx_netdev_config_versions_seen ON netdev_config_versions (device_id, last_seen);

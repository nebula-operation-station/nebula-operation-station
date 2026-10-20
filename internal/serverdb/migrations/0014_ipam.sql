-- 0014_ipam.sql: network assets and IPAM-light (M9-1, spec 12). Address
-- status is computed from these rows, never stored. Addresses are stored
-- in their canonical text form (net/netip), networks as canonical
-- prefixes (masked).
CREATE TABLE assets (
    id         TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 63),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    kind       TEXT    NOT NULL CHECK (kind IN ('server', 'nas', 'firewall', 'switch', 'printer', 'iot', 'unknown')),
    hostname   TEXT    NOT NULL DEFAULT '' CHECK (length(hostname) <= 253),
    mac        TEXT    NOT NULL DEFAULT '' CHECK (mac = '' OR length(mac) = 17),
    notes      TEXT    NOT NULL DEFAULT '' CHECK (length(notes) <= 2000),
    host_id    TEXT    NOT NULL DEFAULT '' CHECK (length(host_id) <= 63),
    updated_at INTEGER NOT NULL
);

CREATE TABLE asset_addresses (
    asset_id TEXT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    address  TEXT NOT NULL CHECK (length(address) BETWEEN 2 AND 45),
    PRIMARY KEY (asset_id, address)
);
CREATE INDEX asset_addresses_address ON asset_addresses (address);

CREATE TABLE networks (
    id      TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 63),
    name    TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    prefix  TEXT    NOT NULL UNIQUE CHECK (length(prefix) BETWEEN 4 AND 49),
    vlan    INTEGER NOT NULL DEFAULT 0 CHECK (vlan BETWEEN 0 AND 4094),
    gateway TEXT    NOT NULL DEFAULT '' CHECK (length(gateway) <= 45),
    notes   TEXT    NOT NULL DEFAULT '' CHECK (length(notes) <= 2000)
);

CREATE TABLE pools (
    network_id TEXT NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    first      TEXT NOT NULL CHECK (length(first) BETWEEN 2 AND 45),
    last       TEXT NOT NULL CHECK (length(last) BETWEEN 2 AND 45),
    PRIMARY KEY (network_id, name)
);

-- Reservations and exclusions of single addresses.
CREATE TABLE ip_entries (
    address TEXT NOT NULL PRIMARY KEY CHECK (length(address) BETWEEN 2 AND 45),
    kind    TEXT NOT NULL CHECK (kind IN ('reserved', 'excluded')),
    note    TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 200),
    by_user TEXT NOT NULL CHECK (length(by_user) <= 64),
    at      INTEGER NOT NULL
);

-- What discovery saw (M9-2 fills it); one row per address, the latest.
CREATE TABLE discovered_addresses (
    address  TEXT    NOT NULL PRIMARY KEY CHECK (length(address) BETWEEN 2 AND 45),
    mac      TEXT    NOT NULL DEFAULT '' CHECK (mac = '' OR length(mac) = 17),
    hostname TEXT    NOT NULL DEFAULT '' CHECK (length(hostname) <= 253),
    seen_at  INTEGER NOT NULL
);

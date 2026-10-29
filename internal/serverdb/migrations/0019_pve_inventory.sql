-- 0019_pve_inventory.sql
-- PVE inventory store (ADR 0006, ticket P1-11): server-side presentation
-- copies of the normalized Proxmox VE observations the collector spools.
--
-- Identity rules:
--   * Every remote child carries remote_id.
--   * Nodes are keyed by (remote_id, node).
--   * Guests are keyed by (remote_id, vmid, generation) -- never vmid
--     alone. generation is the local guest incarnation: a VMID reused
--     after deletion is a new generation, and the old incarnation is
--     tombstoned (kept, not deleted).
--   * The executor owns authoritative identity; these tables are
--     presentation copies only.
--
-- Dataset state: every dataset row carries observed_at, source, a state
-- (available | unavailable | partial) and, for unavailable, a reason.
-- "partial" means the enumeration was incomplete, so unseen objects must
-- not be treated as deleted. Stale data is kept with its age and is only
-- removed by explicit retention (tombstones and task metadata are pruned
-- after 30 days).
--
-- No credential material, raw API responses, task logs or command output
-- live here.

CREATE TABLE pve_remotes (
    remote_id                  TEXT PRIMARY KEY,
    name                       TEXT NOT NULL DEFAULT '',
    kind                       TEXT NOT NULL DEFAULT '',
    trust_generation           INTEGER NOT NULL DEFAULT 0,
    first_observed_at          TEXT NOT NULL,
    last_observed_at           TEXT NOT NULL,
    last_source                TEXT NOT NULL DEFAULT '',
    last_collection_generation INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE pve_nodes (
    remote_id               TEXT NOT NULL,
    node                    TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT '',
    uptime_seconds          INTEGER NOT NULL DEFAULT 0,
    cpu_count               INTEGER NOT NULL DEFAULT 0,
    ram_total_bytes         INTEGER NOT NULL DEFAULT 0,
    ram_used_bytes          INTEGER NOT NULL DEFAULT 0,
    pve_version             TEXT NOT NULL DEFAULT '',
    kernel_version          TEXT NOT NULL DEFAULT '',
    details_available       INTEGER NOT NULL DEFAULT 0,
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, node)
);
CREATE INDEX idx_pve_nodes_remote ON pve_nodes (remote_id);

CREATE TABLE pve_guests (
    remote_id               TEXT NOT NULL,
    vmid                    INTEGER NOT NULL,
    generation              INTEGER NOT NULL,
    kind                    TEXT NOT NULL DEFAULT '',
    node                    TEXT NOT NULL DEFAULT '',
    name                    TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT '',
    uuid                    TEXT NOT NULL DEFAULT '',
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    tombstoned              INTEGER NOT NULL DEFAULT 0,
    tombstoned_at           TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (remote_id, vmid, generation)
);
CREATE INDEX idx_pve_guests_remote_active ON pve_guests (remote_id, tombstoned);
CREATE INDEX idx_pve_guests_remote_vmid ON pve_guests (remote_id, vmid);
CREATE INDEX idx_pve_guests_tombstoned_at ON pve_guests (tombstoned_at);

CREATE TABLE pve_guest_configs (
    remote_id               TEXT NOT NULL,
    vmid                    INTEGER NOT NULL,
    generation              INTEGER NOT NULL,
    cpu_count               INTEGER NOT NULL DEFAULT 0,
    ram_bytes               INTEGER NOT NULL DEFAULT 0,
    disks_json              TEXT NOT NULL DEFAULT '[]',
    boot_order_json         TEXT NOT NULL DEFAULT '[]',
    hostpci_json            TEXT NOT NULL DEFAULT '[]',
    cloud_init_ip_json      TEXT NOT NULL DEFAULT '',
    tags_json               TEXT NOT NULL DEFAULT '[]',
    pool                    TEXT NOT NULL DEFAULT '',
    cap_snapshots           TEXT NOT NULL DEFAULT '',
    cap_live_migration      TEXT NOT NULL DEFAULT '',
    cap_ram_snapshots       TEXT NOT NULL DEFAULT '',
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, vmid, generation)
);

CREATE TABLE pve_interfaces (
    remote_id               TEXT NOT NULL,
    vmid                    INTEGER NOT NULL,
    generation              INTEGER NOT NULL,
    name                    TEXT NOT NULL,
    mac                     TEXT NOT NULL DEFAULT '',
    bridge                  TEXT NOT NULL DEFAULT '',
    vlan                    INTEGER NOT NULL DEFAULT 0,
    ips_json                TEXT NOT NULL DEFAULT '[]',
    source                  TEXT NOT NULL DEFAULT '',
    observed_at             TEXT NOT NULL,
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, vmid, generation, name)
);

CREATE TABLE pve_snapshots (
    remote_id               TEXT NOT NULL,
    vmid                    INTEGER NOT NULL,
    generation              INTEGER NOT NULL,
    name                    TEXT NOT NULL,
    time_unix               INTEGER NOT NULL DEFAULT 0,
    parent                  TEXT NOT NULL DEFAULT '',
    has_ram                 INTEGER NOT NULL DEFAULT 0,
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, vmid, generation, name)
);

CREATE TABLE pve_backup_observations (
    remote_id               TEXT NOT NULL,
    vmid                    INTEGER NOT NULL,
    generation              INTEGER NOT NULL,
    source                  TEXT NOT NULL,
    kind                    TEXT NOT NULL,
    name                    TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT '',
    started_unix            INTEGER NOT NULL DEFAULT 0,
    finished_unix           INTEGER NOT NULL DEFAULT 0,
    verified                TEXT NOT NULL DEFAULT '',
    observed_at             TEXT NOT NULL,
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, vmid, generation, source, kind, name, started_unix)
);

CREATE TABLE pve_storages (
    remote_id               TEXT NOT NULL,
    name                    TEXT NOT NULL,
    type                    TEXT NOT NULL DEFAULT '',
    format                  TEXT NOT NULL DEFAULT '',
    content_json            TEXT NOT NULL DEFAULT '[]',
    active                  INTEGER NOT NULL DEFAULT 0,
    size_bytes              INTEGER NOT NULL DEFAULT 0,
    free_bytes              INTEGER NOT NULL DEFAULT 0,
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, name)
);

CREATE TABLE pve_cluster_status (
    remote_id               TEXT PRIMARY KEY,
    quorum                  TEXT NOT NULL DEFAULT '',
    nodes_json              TEXT NOT NULL DEFAULT '[]',
    ha_resources_json       TEXT NOT NULL DEFAULT '[]',
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE pve_tasks (
    remote_id               TEXT NOT NULL,
    node                    TEXT NOT NULL,
    actor                   TEXT NOT NULL DEFAULT '',
    type                    TEXT NOT NULL DEFAULT '',
    target                  TEXT NOT NULL DEFAULT '',
    started_unix            INTEGER NOT NULL,
    exit_status             TEXT NOT NULL DEFAULT '',
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, node, started_unix, actor, type, target)
);
CREATE INDEX idx_pve_tasks_remote_started ON pve_tasks (remote_id, started_unix);

-- Current state of each top-level dataset for a remote: one row per
-- (remote_id, dataset). dataset is one of nodes, guests, storages,
-- cluster, tasks.
CREATE TABLE pve_dataset_status (
    remote_id               TEXT NOT NULL,
    dataset                 TEXT NOT NULL,
    state                   TEXT NOT NULL,
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, dataset)
);

-- Current state of each per-guest sub-dataset for one incarnation: one
-- row per (remote_id, vmid, generation, dataset). dataset is one of
-- config, interfaces, snapshots, backups.
CREATE TABLE pve_guest_dataset_status (
    remote_id               TEXT NOT NULL,
    vmid                    INTEGER NOT NULL,
    generation              INTEGER NOT NULL,
    dataset                 TEXT NOT NULL,
    state                   TEXT NOT NULL,
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, vmid, generation, dataset)
);

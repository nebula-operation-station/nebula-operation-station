-- 0052_vuln_inventory.sql
-- Versioned per-host package inventory store (ADR 0011 D3, "New data the
-- export needs"). Only additive: no existing table is changed. The Go side
-- is internal/vulninventory, which validates every row before it is written
-- and never updates a row; these CHECKs only hold the invariants that must
-- never be violated.
--
-- vuln_inventory_reads: one row per NOS read of a host's installed source
-- packages (package.list_installed). A read is immutable: a new read is a
-- new row, even when it is identical to the one before. complete is the D3
-- completeness flag (0 or 1). read_at is Unix seconds; "newest" means the
-- highest read_at, then the highest id. body is the canonical JSON of the
-- components (sorted by source), the only place package names live; the
-- counters are derived from it when the row is written. There is no column
-- for an address, host name, label or log (ADR 0011 D3).
--
-- Byte limits of the text columns use length(CAST(... AS BLOB)) because
-- length() on TEXT counts characters; the same limits are named constants
-- in internal/vulninventory.
--
-- vuln_inventory_snapshots and vuln_inventory_snapshot_reads: the export
-- snapshot (vuln-inventory-v1) that pins the reads a page series serves. The
-- snapshot rows are used by a later step (iv04); the store only reads them
-- to decide what Prune may delete. A read a snapshot points to is never
-- deleted (the foreign key is RESTRICT).

CREATE TABLE vuln_inventory_reads (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id        TEXT NOT NULL CHECK (length(CAST(host_id AS BLOB)) BETWEEN 1 AND 128),
    execution_id   TEXT NOT NULL CHECK (length(CAST(execution_id AS BLOB)) BETWEEN 1 AND 64),
    read_at        INTEGER NOT NULL CHECK (read_at > 0),
    complete       INTEGER NOT NULL CHECK (complete IN (0, 1)),
    reason         TEXT NOT NULL CHECK (length(CAST(reason AS BLOB)) <= 128),
    dropped        INTEGER NOT NULL DEFAULT 0 CHECK (dropped >= 0),
    ecosystem      TEXT NOT NULL CHECK (length(CAST(ecosystem AS BLOB)) <= 64),
    kernel_release TEXT NOT NULL CHECK (length(CAST(kernel_release AS BLOB)) <= 128),
    kernel_state   TEXT NOT NULL CHECK (length(CAST(kernel_state AS BLOB)) <= 32),
    kernel_source  TEXT NOT NULL CHECK (length(CAST(kernel_source AS BLOB)) <= 64),
    kernel_version TEXT NOT NULL CHECK (length(CAST(kernel_version AS BLOB)) <= 256),
    binaries       INTEGER NOT NULL CHECK (binaries >= 0),
    sources        INTEGER NOT NULL CHECK (sources >= 0),
    body           BLOB NOT NULL
);

CREATE INDEX vuln_inventory_reads_host ON vuln_inventory_reads (host_id, id);

CREATE TABLE vuln_inventory_snapshots (
    id          TEXT PRIMARY KEY CHECK (length(CAST(id AS BLOB)) BETWEEN 1 AND 64),
    generation  INTEGER NOT NULL UNIQUE CHECK (generation >= 0),
    taken_at    INTEGER NOT NULL
);

CREATE TABLE vuln_inventory_snapshot_reads (
    snapshot_id TEXT NOT NULL REFERENCES vuln_inventory_snapshots (id) ON DELETE CASCADE,
    read_id     INTEGER NOT NULL REFERENCES vuln_inventory_reads (id) ON DELETE RESTRICT,
    PRIMARY KEY (snapshot_id, read_id)
);

CREATE INDEX vuln_inventory_snapshot_reads_read ON vuln_inventory_snapshot_reads (read_id);

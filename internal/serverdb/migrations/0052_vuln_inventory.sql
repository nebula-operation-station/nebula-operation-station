-- 0052_vuln_inventory.sql
-- Versioned per-host package inventory store (ADR 0011 D3, "New data the
-- export needs"). Only additive: no existing table is changed. The Go side
-- is internal/vulninventory, which validates every row before it is written
-- and never updates a row; these CHECKs and triggers only hold the invariants
-- that must never be violated.
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
-- in internal/vulninventory, and that package's tests check each CHECK
-- number against its constant.
--
-- vuln_inventory_snapshots and vuln_inventory_snapshot_reads: the export
-- snapshot (vuln-inventory-v1) that pins the reads a page series serves. The
-- snapshot rows are used by a later step (iv04).

CREATE TABLE vuln_inventory_reads (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id        TEXT NOT NULL CHECK (length(CAST(host_id AS BLOB)) BETWEEN 1 AND 128),
    execution_id   TEXT NOT NULL CHECK (length(CAST(execution_id AS BLOB)) BETWEEN 1 AND 64),
    read_at        INTEGER NOT NULL CHECK (read_at > 0),
    complete       INTEGER NOT NULL CHECK (complete IN (0, 1)),
    reason         TEXT NOT NULL CHECK (length(CAST(reason AS BLOB)) <= 128),
    dropped        INTEGER NOT NULL DEFAULT 0 CHECK (dropped BETWEEN 0 AND 40000),
    ecosystem      TEXT NOT NULL CHECK (length(CAST(ecosystem AS BLOB)) <= 64),
    kernel_release TEXT NOT NULL CHECK (length(CAST(kernel_release AS BLOB)) <= 128),
    kernel_state   TEXT NOT NULL CHECK (length(CAST(kernel_state AS BLOB)) <= 32),
    kernel_source  TEXT NOT NULL CHECK (length(CAST(kernel_source AS BLOB)) <= 64),
    kernel_version TEXT NOT NULL CHECK (length(CAST(kernel_version AS BLOB)) <= 256),
    binaries       INTEGER NOT NULL CHECK (binaries BETWEEN 0 AND 20000),
    sources        INTEGER NOT NULL CHECK (sources BETWEEN 0 AND 20000),
    -- 12540002 = MaxBodyBytes in internal/vulninventory (store.go).
    body           BLOB NOT NULL CHECK (length(body) BETWEEN 2 AND 12540002)
);

-- The read path: the newest read of a host, and the newest complete read of a
-- host. Both are a seek to the first entry of the index, with no sort. The
-- Go tests check the query plans (EXPLAIN QUERY PLAN).
CREATE INDEX vuln_inventory_reads_host_read ON vuln_inventory_reads (host_id, read_at DESC, id DESC);
CREATE INDEX vuln_inventory_reads_host_complete ON vuln_inventory_reads (host_id, complete, read_at DESC, id DESC);

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

-- A read is immutable at the database level too: the Go store only inserts,
-- and this trigger makes any UPDATE fail.
CREATE TRIGGER vuln_inventory_reads_immutable BEFORE UPDATE ON vuln_inventory_reads
BEGIN
    SELECT RAISE(ABORT, 'vuln_inventory_reads: a read is immutable');
END;

-- INSERT OR REPLACE removes the old row of a clashing id without firing a
-- DELETE trigger, so the rule below is not enough on its own. This trigger
-- refuses any insert whose id is already in use, so no stored read can be
-- swapped out.
CREATE TRIGGER vuln_inventory_reads_no_reuse_id BEFORE INSERT ON vuln_inventory_reads
WHEN NEW.id IS NOT NULL AND EXISTS (SELECT 1 FROM vuln_inventory_reads WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'vuln_inventory_reads: an id in use cannot be reused');
END;

-- Deletion rule. A read is deleted only if no snapshot pins it and it is
-- neither the newest read nor the last complete read of its host (ADR 0011
-- D5, D6). The check runs per row against the rows as they were before the
-- statement, so a multi-row DELETE that reaches a protected row is refused as a
-- whole. Which other reads may go (retention, decision E1) is not decided here.
CREATE TRIGGER vuln_inventory_reads_protected BEFORE DELETE ON vuln_inventory_reads
WHEN EXISTS (SELECT 1 FROM vuln_inventory_snapshot_reads WHERE read_id = OLD.id)
    OR OLD.id = (SELECT n.id FROM vuln_inventory_reads AS n WHERE n.host_id = OLD.host_id
        ORDER BY n.read_at DESC, n.id DESC LIMIT 1)
    OR OLD.id = (SELECT n.id FROM vuln_inventory_reads AS n WHERE n.host_id = OLD.host_id AND n.complete = 1
        ORDER BY n.read_at DESC, n.id DESC LIMIT 1)
BEGIN
    SELECT RAISE(ABORT, 'vuln_inventory_reads: a pinned, newest or last complete read cannot be deleted');
END;

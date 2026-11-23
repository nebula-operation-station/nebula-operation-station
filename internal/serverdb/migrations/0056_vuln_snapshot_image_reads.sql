-- 0056_vuln_snapshot_image_reads.sql
-- Pins image reads in inventory snapshots (ADR 0011 amendment 2026-11-23,
-- img01). Only additive: no existing table is changed. The Go side is
-- internal/vulninventory (snapshot.go, images.go).
--
-- vuln_inventory_snapshot_image_reads: the image reads a snapshot pins, one
-- row per (snapshot, image read). A snapshot pins the newest image read of
-- each (host, digest) of its hosts. Deleting a snapshot removes its pins
-- (CASCADE). An image read that a snapshot pins cannot be deleted
-- (RESTRICT); PutImage keeps pinned reads and PruneSnapshots deletes an
-- image read only after no snapshot pins it.

CREATE TABLE vuln_inventory_snapshot_image_reads (
    snapshot_id   TEXT NOT NULL REFERENCES vuln_inventory_snapshots (id) ON DELETE CASCADE,
    image_read_id INTEGER NOT NULL REFERENCES vuln_image_reads (id) ON DELETE RESTRICT,
    PRIMARY KEY (snapshot_id, image_read_id)
);

-- The RESTRICT check and the prune look up the snapshots that pin one read.
CREATE INDEX vuln_inventory_snapshot_image_reads_read ON vuln_inventory_snapshot_image_reads (image_read_id);

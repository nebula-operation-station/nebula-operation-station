-- 0053_vuln_image_inventory.sql
-- Image package inventory store (ADR 0011 D3, image.packages; decision E4):
-- the package list of one local container image, read by image.packages.
-- Only additive: no existing table is changed. The Go side is
-- internal/vulninventory (images.go), which validates every row before it is
-- written. It keeps at most ImageReadsKept reads per image on one host: after
-- an insert the older reads of that host and digest are deleted in the same
-- transaction, so the table never holds a fourth read of an image on a host.
-- That retention is the only delete; nothing else removes a row.
--
-- vuln_image_reads: one row per successful image.packages read. digest is the
-- platform digest the read was pinned to (sha256:<64 hex>) and host_id the
-- host it was read on; together they are the image key. repository is a name
-- the host's inspect result gave that image, without its digest; it is not
-- part of the key. "Newest" means the highest read_at, then the highest id.
-- A read is immutable (trigger below). body is the canonical JSON of the
-- packages, the only place package names live.
-- There is no column for an address, host name, label or log.
--
-- Byte limits use length(CAST(... AS BLOB)); the same limits are named
-- constants in internal/vulninventory (images.go), and the tests there check
-- each CHECK number against its constant.

CREATE TABLE vuln_image_reads (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    repository   TEXT NOT NULL CHECK (length(CAST(repository AS BLOB)) BETWEEN 1 AND 255),
    digest       TEXT NOT NULL CHECK (length(digest) = 71 AND substr(digest, 1, 7) = 'sha256:' AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'),
    host_id      TEXT NOT NULL CHECK (length(CAST(host_id AS BLOB)) BETWEEN 1 AND 128),
    execution_id TEXT NOT NULL CHECK (length(CAST(execution_id AS BLOB)) BETWEEN 1 AND 64),
    read_at      INTEGER NOT NULL CHECK (read_at > 0),
    complete     INTEGER NOT NULL CHECK (complete IN (0, 1)),
    reason       TEXT NOT NULL CHECK (length(CAST(reason AS BLOB)) <= 128),
    os_family    TEXT NOT NULL CHECK (length(CAST(os_family AS BLOB)) <= 64),
    os_name      TEXT NOT NULL CHECK (length(CAST(os_name AS BLOB)) <= 128),
    packages     INTEGER NOT NULL CHECK (packages BETWEEN 0 AND 5000),
    -- 3240002 = MaxImageBodyBytes in internal/vulninventory (images.go).
    body         BLOB NOT NULL CHECK (length(body) BETWEEN 2 AND 3240002)
);

-- The read path and the retention: the newest reads of one image on one host.
CREATE INDEX vuln_image_reads_host_digest_read ON vuln_image_reads (host_id, digest, read_at DESC, id DESC);

-- A read is immutable: the Go store only inserts and deletes by retention.
CREATE TRIGGER vuln_image_reads_immutable BEFORE UPDATE ON vuln_image_reads
BEGIN
    SELECT RAISE(ABORT, 'vuln_image_reads: a read is immutable');
END;

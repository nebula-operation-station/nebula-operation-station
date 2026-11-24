-- 0057_netdev_devices_origin.sql
-- Where a device row came from (ND-16 variant 1, review round 1 of PR #814).
--
-- Additive only: four columns on netdev_devices_seen, no existing row is
-- changed. Rows written before this migration have origin 'unreported' and
-- no spool reference, which is the truth: no spool record wrote them.
--
-- origin: 'collector_reported' once a device metadata record the collector
--   spooled wrote the row; 'unreported' otherwise. It never goes back.
--   "Collector reported" is not "confirmed": the confirmed asset link is
--   netdev_asset_links (0040), a separate admin act.
-- spool_name, spool_sha256: the spool record the row was last written from
--   (file name and SHA-256 of its bytes as lowercase hex).
-- reported_at: when that record was accepted (INTEGER microseconds UTC).
--   It is kept apart from last_seen, which stays the newest dataset
--   observation. A metadata report never moves last_seen or state.
--
-- The CHECK on reported_at ties the three together: a collector-reported
-- row always names its spool record and report time, and no other row does.

ALTER TABLE netdev_devices_seen ADD COLUMN origin TEXT NOT NULL DEFAULT 'unreported'
    CHECK (origin IN ('unreported', 'collector_reported'));
ALTER TABLE netdev_devices_seen ADD COLUMN spool_name TEXT
    CHECK (spool_name IS NULL OR length(CAST(spool_name AS BLOB)) BETWEEN 1 AND 255);
ALTER TABLE netdev_devices_seen ADD COLUMN spool_sha256 TEXT
    CHECK (spool_sha256 IS NULL OR (length(spool_sha256) = 64 AND spool_sha256 NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE netdev_devices_seen ADD COLUMN reported_at INTEGER
    CHECK (reported_at IS NULL OR reported_at >= 0)
    CHECK ((origin = 'collector_reported') = (reported_at IS NOT NULL
        AND spool_name IS NOT NULL AND spool_sha256 IS NOT NULL));

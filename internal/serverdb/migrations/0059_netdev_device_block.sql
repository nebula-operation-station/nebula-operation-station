-- The collector's block state of a device row (A1-3 round 2, PR #878).
--
-- Additive only: two columns on netdev_devices_seen, no existing row is
-- changed, no table rebuild. Rows written before this migration are not
-- blocked, which is what the device list showed for them.
--
-- blocked: 1 once the newest device metadata record the collector spooled
--   reports the device as blocked; 0 otherwise. A newer unblocked record sets
--   it back to 0. The importer keeps every dataset of a blocked device instead
--   of importing it, and reads this column at start so the block survives a
--   restart.
-- block_reason: the reason the collector gave, untrusted text from the
--   record, at most 256 bytes. NULL when the row is not blocked.

ALTER TABLE netdev_devices_seen ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0
    CHECK (blocked IN (0, 1));
ALTER TABLE netdev_devices_seen ADD COLUMN block_reason TEXT
    CHECK (block_reason IS NULL OR length(CAST(block_reason AS BLOB)) <= 256)
    CHECK ((blocked = 0 AND block_reason IS NULL) OR (blocked = 1 AND block_reason IS NOT NULL));

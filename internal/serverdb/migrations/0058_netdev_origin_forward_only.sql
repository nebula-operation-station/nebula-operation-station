-- 0058_netdev_origin_forward_only.sql
-- Enforce "origin never goes back" on netdev_devices_seen (review nx08f3,
-- item 4 of PR #814 follow-up). Migration 0057 states the rule in a comment
-- only: a direct UPDATE could still set origin back to 'unreported' and NULL
-- the spool columns. This trigger refuses that write.
--
-- Additive only: one trigger, no table rebuild, no existing row changed.
-- 0057 is not edited. The CHECK constraints of 0057 still tie origin to
-- spool_name, spool_sha256 and reported_at for every row.

CREATE TRIGGER netdev_devices_seen_origin_forward_only
BEFORE UPDATE OF origin ON netdev_devices_seen
WHEN OLD.origin = 'collector_reported' AND NEW.origin <> 'collector_reported'
BEGIN
    SELECT RAISE(ABORT, 'netdev_devices_seen: origin never goes back from collector_reported');
END;

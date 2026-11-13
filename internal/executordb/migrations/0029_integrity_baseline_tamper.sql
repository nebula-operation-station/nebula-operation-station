-- 0029_integrity_baseline_tamper.sql (ADR 0015 D7 "Server compromise",
-- D9 `integrity.baseline_tamper`; IG-06): the executor-side record of an
-- I2 baseline digest mismatch.
--
-- When the executor recomputes the digest of the server's baseline list
-- and it differs from the executor-held approved digest, the finding is
-- kept here, in executor-owned storage, so a compromised server that
-- drops the comparison result cannot make it disappear. One row per host:
-- a repeated mismatch only counts (count, last_seen, latest digests), so a
-- caller cannot grow the table or the audit log without bound.
--
-- Rows are never deleted and first_seen never changes; count only grows.
-- Closing a finding is a later executor-local admin step, not part of this
-- table's writers.
CREATE TABLE integrity_baseline_tamper (
    host_id          TEXT    PRIMARY KEY CHECK (length(host_id) BETWEEN 1 AND 255),
    -- The executor-held approved digest at the latest mismatch.
    approved_digest  TEXT    NOT NULL CHECK (length(approved_digest) = 64
                         AND approved_digest NOT GLOB '*[^0-9a-f]*'),
    -- The digest the executor recomputed from the server's list at the
    -- latest mismatch.
    presented_digest TEXT    NOT NULL CHECK (length(presented_digest) = 64
                         AND presented_digest NOT GLOB '*[^0-9a-f]*'),
    first_seen       INTEGER NOT NULL,
    last_seen        INTEGER NOT NULL,
    count            INTEGER NOT NULL CHECK (count >= 1),
    -- When the finding was last written to the audit log (rate limit).
    last_audited     INTEGER NOT NULL,
    CHECK (approved_digest <> presented_digest)
);

CREATE TRIGGER integrity_baseline_tamper_update
BEFORE UPDATE ON integrity_baseline_tamper
WHEN NEW.host_id IS NOT OLD.host_id OR NEW.first_seen IS NOT OLD.first_seen
  OR NEW.count < OLD.count OR NEW.last_seen < OLD.last_seen
BEGIN
    SELECT RAISE(ABORT, 'integrity baseline tamper: findings only grow');
END;

CREATE TRIGGER integrity_baseline_tamper_no_delete
BEFORE DELETE ON integrity_baseline_tamper
BEGIN
    SELECT RAISE(ABORT, 'integrity baseline tamper: findings are never deleted silently');
END;

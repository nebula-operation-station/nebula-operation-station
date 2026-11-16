-- 0028_integrity_baseline_digests.sql (ADR 0015 D7 item 2, D9
-- `integrity.baseline_tamper`; IG-06): the approved I2 baseline digest of
-- every managed host, held by the executor as tamper evidence.
--
-- The full baseline list lives only in the server database; this table
-- holds its digest (lowercase hex SHA-256), so a compromised server that
-- rewrites the list cannot make it match. Only the executor writes here,
-- and only when a baseline approval stores a new digest; there is no RPC
-- that sets a digest. A server-supplied digest is at most compared with
-- the active one, and a mismatch is a finding, never a correction.
--
-- Exactly one row is active per host. An approval supersedes the active
-- row once and inserts the new one, which names the digest it was built
-- on (previous_digest); the initial approval has no previous digest and is
-- possible only while the host has no digest at all. Rows are never
-- deleted or otherwise changed, so the history of every approval stays.
CREATE TABLE integrity_baseline_digests (
    id              INTEGER PRIMARY KEY,
    host_id         TEXT    NOT NULL CHECK (length(host_id) BETWEEN 1 AND 255),
    digest          TEXT    NOT NULL CHECK (length(digest) = 64
                        AND digest NOT GLOB '*[^0-9a-f]*'),
    previous_digest TEXT             CHECK (previous_digest IS NULL OR (length(previous_digest) = 64
                        AND previous_digest NOT GLOB '*[^0-9a-f]*')),
    -- initial: `nebula integrity approve --initial` (executor-local CLI);
    -- cli: `nebula integrity approve`; browser: user-verified assertion
    -- for a proposal without critical-class changes.
    approval_kind   TEXT    NOT NULL CHECK (approval_kind IN ('initial', 'cli', 'browser')),
    approved_at     INTEGER NOT NULL,
    active          INTEGER NOT NULL CHECK (active IN (0, 1)),
    superseded_at   INTEGER,
    CHECK ((active = 1) = (superseded_at IS NULL)),
    CHECK ((approval_kind = 'initial') = (previous_digest IS NULL))
);

-- Exactly one active digest per host.
CREATE UNIQUE INDEX integrity_baseline_digests_one_active
    ON integrity_baseline_digests (host_id) WHERE active = 1;

-- A new digest is always inserted as the active one; an initial digest
-- only for a host without any digest, a later one only on top of the
-- host's active digest.
CREATE TRIGGER integrity_baseline_digests_insert
BEFORE INSERT ON integrity_baseline_digests
WHEN NEW.active <> 1 OR NEW.superseded_at IS NOT NULL
  OR (NEW.approval_kind = 'initial'
      AND EXISTS (SELECT 1 FROM integrity_baseline_digests WHERE host_id = NEW.host_id))
  OR (NEW.approval_kind <> 'initial'
      AND NOT EXISTS (SELECT 1 FROM integrity_baseline_digests
                      WHERE host_id = NEW.host_id AND active = 0
                        AND digest = NEW.previous_digest
                        AND id = (SELECT max(id) FROM integrity_baseline_digests
                                  WHERE host_id = NEW.host_id)))
BEGIN
    SELECT RAISE(ABORT, 'integrity baseline digest: not built on the approved digest');
END;

-- Approved digests never change; the only update is superseding the
-- active row once.
CREATE TRIGGER integrity_baseline_digests_immutable
BEFORE UPDATE ON integrity_baseline_digests
WHEN NEW.id IS NOT OLD.id OR NEW.host_id IS NOT OLD.host_id
  OR NEW.digest IS NOT OLD.digest OR NEW.previous_digest IS NOT OLD.previous_digest
  OR NEW.approval_kind IS NOT OLD.approval_kind OR NEW.approved_at IS NOT OLD.approved_at
  OR NOT (OLD.active = 1 AND NEW.active = 0 AND NEW.superseded_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'integrity baseline digest: approved digests are immutable');
END;

-- History is kept.
CREATE TRIGGER integrity_baseline_digests_no_delete
BEFORE DELETE ON integrity_baseline_digests
BEGIN
    SELECT RAISE(ABORT, 'integrity baseline digest: approved digests are never deleted');
END;

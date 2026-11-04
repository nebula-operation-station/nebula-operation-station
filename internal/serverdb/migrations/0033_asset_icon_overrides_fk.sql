-- Per-asset icon overrides follow their asset (TM13b, follow-up of
-- 0032). asset_icon_overrides.asset_id now references assets (id) with
-- ON DELETE CASCADE, so deleting an asset removes its override and a
-- later asset with the same ID does not inherit it. The icon history
-- (software_icon_history) is kept; it only holds hashes.
--
-- rollback_of -1 marks the end of an asset's life in its history:
-- internal/softwarecat refuses to roll back that row or any older one,
-- so a later asset with the same ID cannot get the old asset's icon
-- back through a rollback. The trigger asset_icon_override_on_asset_delete
-- writes that marker (changed_by "system", icon_sha NULL, prev_sha the
-- removed override or NULL) in the deletion transaction for every
-- deleted asset that has icon history, also when its override was
-- already cleared: rolling back an old "clear" would otherwise put the
-- old asset's icon on a new asset with the same ID. Only a removed
-- live override is also audited, as asset_icon_clear (actor "system").
-- A delete of an asset without icon history, or one whose newest
-- history row already is the marker, records nothing.
--
-- SQLite cannot add a foreign key to an existing table, so the table is
-- rebuilt. Existing data is brought to the same state first: overrides
-- of assets that no longer exist are dropped and recorded like a
-- delete, and every other asset in the history that no longer exists
-- gets the marker (not audited; nothing is removed). This migration
-- cannot see deletions of assets that exist again by now (deleted and
-- recreated with the same ID before the upgrade): their override and
-- history are kept as they are and treated as the current asset's.
--
-- Timestamps are Unix nanoseconds, like the ones internal/softwarecat
-- writes, but taken from SQLite's clock, not the store's injected one;
-- history and audit order is by id, which is always correct.

INSERT INTO software_icon_history (subject_kind, subject_id, icon_sha, prev_sha, rollback_of, changed_by, changed_at)
    SELECT 'asset', o.asset_id, NULL, o.icon_sha, -1, 'system',
           CAST(unixepoch('subsec') * 1000000000 AS INTEGER)
    FROM asset_icon_overrides o
    WHERE NOT EXISTS (SELECT 1 FROM assets a WHERE a.id = o.asset_id)
    ORDER BY o.asset_id;

INSERT INTO software_catalog_audit (at, actor, action, subject, detail)
    SELECT CAST(unixepoch('subsec') * 1000000000 AS INTEGER), 'system', 'asset_icon_clear', o.asset_id,
           o.icon_sha || ' -> none (asset deleted)'
    FROM asset_icon_overrides o
    WHERE NOT EXISTS (SELECT 1 FROM assets a WHERE a.id = o.asset_id)
    ORDER BY o.asset_id;

-- Runs after the orphan overrides are marked, so those are skipped.
INSERT INTO software_icon_history (subject_kind, subject_id, icon_sha, prev_sha, rollback_of, changed_by, changed_at)
    SELECT 'asset', g.subject_id, NULL, NULL, -1, 'system',
           CAST(unixepoch('subsec') * 1000000000 AS INTEGER)
    FROM (SELECT DISTINCT subject_id FROM software_icon_history WHERE subject_kind = 'asset') g
    WHERE NOT EXISTS (SELECT 1 FROM assets a WHERE a.id = g.subject_id)
      AND (SELECT h.rollback_of FROM software_icon_history h
           WHERE h.subject_kind = 'asset' AND h.subject_id = g.subject_id
           ORDER BY h.id DESC LIMIT 1) <> -1
    ORDER BY g.subject_id;

CREATE TABLE asset_icon_overrides_fk (
    asset_id   TEXT PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 63)
               REFERENCES assets (id) ON DELETE CASCADE,
    icon_sha   TEXT NOT NULL REFERENCES software_icons (sha),
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 64),
    updated_at INTEGER NOT NULL
);

INSERT INTO asset_icon_overrides_fk (asset_id, icon_sha, updated_by, updated_at)
    SELECT o.asset_id, o.icon_sha, o.updated_by, o.updated_at
    FROM asset_icon_overrides o
    WHERE EXISTS (SELECT 1 FROM assets a WHERE a.id = o.asset_id);

DROP TABLE asset_icon_overrides;
ALTER TABLE asset_icon_overrides_fk RENAME TO asset_icon_overrides;

-- BEFORE DELETE: the cascade removes the override as part of the
-- delete, so an AFTER trigger would no longer see it.
CREATE TRIGGER asset_icon_override_on_asset_delete
BEFORE DELETE ON assets
WHEN EXISTS (SELECT 1 FROM asset_icon_overrides WHERE asset_id = OLD.id)
  OR COALESCE((SELECT h.rollback_of FROM software_icon_history h
               WHERE h.subject_kind = 'asset' AND h.subject_id = OLD.id
               ORDER BY h.id DESC LIMIT 1), -1) <> -1
BEGIN
    INSERT INTO software_icon_history (subject_kind, subject_id, icon_sha, prev_sha, rollback_of, changed_by, changed_at)
        VALUES ('asset', OLD.id, NULL,
                (SELECT o.icon_sha FROM asset_icon_overrides o WHERE o.asset_id = OLD.id),
                -1, 'system', CAST(unixepoch('subsec') * 1000000000 AS INTEGER));
    INSERT INTO software_catalog_audit (at, actor, action, subject, detail)
        SELECT CAST(unixepoch('subsec') * 1000000000 AS INTEGER), 'system', 'asset_icon_clear', OLD.id,
               o.icon_sha || ' -> none (asset deleted)'
        FROM asset_icon_overrides o WHERE o.asset_id = OLD.id;
END;

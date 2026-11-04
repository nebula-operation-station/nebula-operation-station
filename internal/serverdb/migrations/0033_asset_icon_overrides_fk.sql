-- Per-asset icon overrides follow their asset (TM13b, follow-up of
-- 0032). asset_icon_overrides.asset_id now references assets (id) with
-- ON DELETE CASCADE, so deleting an asset removes its override and a
-- later asset with the same ID does not inherit it. The icon history
-- (software_icon_history) is kept; it only holds hashes.
--
-- Removing an override this way is an icon change like any other: the
-- trigger asset_icon_override_on_asset_delete records it in the
-- deletion transaction as an asset_icon_clear audit row (actor
-- "system") and a history row (changed_by "system", rollback_of -1).
-- rollback_of -1 marks the end of an asset's life in its history:
-- internal/softwarecat refuses to roll back that row or any older one,
-- so a later asset with the same ID cannot get the old asset's icon
-- back through a rollback.
--
-- SQLite cannot add a foreign key to an existing table, so the table is
-- rebuilt. Overrides of assets that no longer exist are dropped and
-- recorded the same way.
--
-- Timestamps are Unix nanoseconds, like the ones internal/softwarecat
-- writes.

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
BEGIN
    INSERT INTO software_icon_history (subject_kind, subject_id, icon_sha, prev_sha, rollback_of, changed_by, changed_at)
        SELECT 'asset', OLD.id, NULL, o.icon_sha, -1, 'system',
               CAST(unixepoch('subsec') * 1000000000 AS INTEGER)
        FROM asset_icon_overrides o WHERE o.asset_id = OLD.id;
    INSERT INTO software_catalog_audit (at, actor, action, subject, detail)
        SELECT CAST(unixepoch('subsec') * 1000000000 AS INTEGER), 'system', 'asset_icon_clear', OLD.id,
               o.icon_sha || ' -> none (asset deleted)'
        FROM asset_icon_overrides o WHERE o.asset_id = OLD.id;
END;

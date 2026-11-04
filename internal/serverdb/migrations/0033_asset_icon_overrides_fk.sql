-- Per-asset icon overrides follow their asset (TM13b, follow-up of
-- 0032). asset_icon_overrides.asset_id now references assets (id) with
-- ON DELETE CASCADE, so deleting an asset removes its override and a
-- later asset with the same ID does not inherit it. The icon history
-- (software_icon_history) is kept; it only holds hashes.
--
-- SQLite cannot add a foreign key to an existing table, so the table is
-- rebuilt. Overrides of assets that no longer exist are dropped.

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

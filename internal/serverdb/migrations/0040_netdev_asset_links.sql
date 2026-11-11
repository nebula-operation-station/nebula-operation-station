-- 0040_netdev_asset_links.sql
-- Confirmed network device ↔ IPAM asset links (ADR 0010 D4 "Device as an
-- asset"; plan ND-18 part 2).
--
-- A row exists only because an admin confirmed it on the device page
-- (internal/ipam ConfirmDeviceLink). Nothing writes it automatically: a
-- MAC match between a switch MAC table and an asset is a suggestion only.
--
-- One asset per device and one device per asset. confirmed_by is the web
-- user who confirmed, confirmed_at INTEGER seconds since the Unix epoch.
--
-- Both sides cascade: deleting the asset or the device removes the link,
-- so a later asset or device with the same ID never inherits an earlier
-- confirmation (no stale link can point at a different asset).

CREATE TABLE netdev_asset_links (
    device_id    TEXT    PRIMARY KEY REFERENCES netdev_devices_seen (device_id) ON DELETE CASCADE,
    asset_id     TEXT    NOT NULL UNIQUE REFERENCES assets (id) ON DELETE CASCADE,
    confirmed_by TEXT    NOT NULL CHECK (length(confirmed_by) BETWEEN 1 AND 64),
    confirmed_at INTEGER NOT NULL
);

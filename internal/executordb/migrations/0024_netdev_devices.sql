-- 0024_netdev_devices.sql (ADR 0010 D1/D3, ND-10): the executor's durable
-- registry of managed network devices (CBS switches, PAN-OS firewalls).
-- The executor alone owns the endpoint, trust pin, trust generation, block
-- state and vault references; server tables are presentation copies only.
--
-- No secret is stored here. credential_ref, digest_key_ref and
-- fingerprint_key_ref are opaque vault references; the device credentials
-- and the per-device HMAC keys live in the executor vault (ADR 0010 D2).
--
-- endpoint_ip is always an IP literal (no zone); names are labels and are
-- never resolved when dialling.
--
-- A removed device keeps its row with tombstoned_at set and its id is
-- recorded in netdev_tombstones; triggers below make both permanent, so a
-- tombstoned id can never be reused. The trust identity (family, pin_kind,
-- pin_value) is unique among live devices.
CREATE TABLE netdev_devices (
    id                  TEXT PRIMARY KEY CHECK (
                            length(id) BETWEEN 1 AND 64
                            AND id NOT GLOB '*[^a-z0-9-]*'
                            AND id NOT GLOB '-*'
                            AND id NOT GLOB '*-'),
    family              TEXT NOT NULL CHECK (family IN ('cbs', 'panos')),
    label               TEXT NOT NULL DEFAULT '' CHECK (length(label) <= 255),
    endpoint_ip         TEXT NOT NULL CHECK (
                            length(endpoint_ip) BETWEEN 2 AND 39
                            AND endpoint_ip NOT GLOB '*[^0-9a-f.:]*'),
    port                INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    pin_kind            TEXT NOT NULL CHECK (pin_kind IN ('ssh-host-key', 'tls-leaf', 'tls-ca')),
    pin_value           TEXT NOT NULL CHECK (
                            length(pin_value) = 64
                            AND pin_value NOT GLOB '*[^0-9a-f]*'),
    trust_generation    INTEGER NOT NULL DEFAULT 1 CHECK (trust_generation BETWEEN 1 AND 281474976710655),
    blocked             INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    block_reason        TEXT CHECK (length(block_reason) BETWEEN 1 AND 512),
    credential_ref      TEXT CHECK (
                            length(credential_ref) BETWEEN 1 AND 64
                            AND credential_ref GLOB '[a-z0-9]*'
                            AND credential_ref NOT GLOB '*[^a-z0-9_-]*'),
    digest_key_ref      TEXT NOT NULL CHECK (
                            length(digest_key_ref) BETWEEN 1 AND 64
                            AND digest_key_ref GLOB '[a-z0-9]*'
                            AND digest_key_ref NOT GLOB '*[^a-z0-9_-]*'),
    fingerprint_key_ref TEXT NOT NULL CHECK (
                            length(fingerprint_key_ref) BETWEEN 1 AND 64
                            AND fingerprint_key_ref GLOB '[a-z0-9]*'
                            AND fingerprint_key_ref NOT GLOB '*[^a-z0-9_-]*'),
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    tombstoned_at       INTEGER,
    -- A CBS switch is pinned by its SSH host key, a PAN-OS firewall by its
    -- TLS leaf or issuing CA (ADR 0010 D1).
    CHECK ((family = 'cbs' AND pin_kind = 'ssh-host-key')
        OR (family = 'panos' AND pin_kind IN ('tls-leaf', 'tls-ca'))),
    -- A block always carries its reason; an unblocked device has none.
    CHECK ((blocked = 1) = (block_reason IS NOT NULL)),
    -- The two per-device keys are independent vault entries.
    CHECK (digest_key_ref <> fingerprint_key_ref)
);

-- The trust identity of every live device is unique.
CREATE UNIQUE INDEX netdev_devices_trust_identity_idx
    ON netdev_devices (family, pin_kind, pin_value)
    WHERE tombstoned_at IS NULL;

-- Every device id that was ever tombstoned. Rows are never deleted.
CREATE TABLE netdev_tombstones (
    id            TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    tombstoned_at INTEGER NOT NULL
);

-- A tombstoned id can never be registered again.
CREATE TRIGGER netdev_devices_no_tombstoned_id
BEFORE INSERT ON netdev_devices
WHEN EXISTS (SELECT 1 FROM netdev_tombstones WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'netdev device id is tombstoned');
END;

-- A tombstoned device row is frozen: no update can revive or change it.
CREATE TRIGGER netdev_devices_tombstone_frozen
BEFORE UPDATE ON netdev_devices
WHEN OLD.tombstoned_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'netdev device is tombstoned');
END;

-- Device rows are never deleted; removal is a tombstone.
CREATE TRIGGER netdev_devices_no_delete
BEFORE DELETE ON netdev_devices
BEGIN
    SELECT RAISE(ABORT, 'netdev devices are tombstoned, never deleted');
END;

-- Tombstones are permanent.
CREATE TRIGGER netdev_tombstones_no_update
BEFORE UPDATE ON netdev_tombstones
BEGIN
    SELECT RAISE(ABORT, 'netdev tombstones are permanent');
END;

CREATE TRIGGER netdev_tombstones_no_delete
BEFORE DELETE ON netdev_tombstones
BEGIN
    SELECT RAISE(ABORT, 'netdev tombstones are permanent');
END;

-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Storages are reported per node (storwire): node-local stores with the
-- same ID on different nodes are distinct rows, and PVE's shared flag is
-- stored instead of guessed from the storage type. The key gains the
-- node. Earlier rows carry no node and are dropped; the 5-minute storage
-- read repopulates the table.

DROP TABLE pve_storages;

CREATE TABLE pve_storages (
    remote_id               TEXT NOT NULL,
    node                    TEXT NOT NULL,
    name                    TEXT NOT NULL,
    type                    TEXT NOT NULL DEFAULT '',
    format                  TEXT NOT NULL DEFAULT '',
    content_json            TEXT NOT NULL DEFAULT '[]',
    active                  INTEGER NOT NULL DEFAULT 0,
    shared                  INTEGER NOT NULL DEFAULT 0 CHECK (shared IN (0, 1)),
    size_bytes              INTEGER NOT NULL DEFAULT 0,
    free_bytes              INTEGER NOT NULL DEFAULT 0,
    observed_at             TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT '',
    state                   TEXT NOT NULL,
    reason                  TEXT NOT NULL DEFAULT '',
    collection_generation   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (remote_id, node, name)
);

-- SPDX-License-Identifier: AGPL-3.0-or-later
-- 0025_pve_service_placements.sql
-- Explicit service placements (ADR 0006, ticket P1-27).
--
-- A service has exactly one explicit placement: a managed host, a PVE guest
-- incarnation, or a Docker container on a managed host. A placement is
-- created only by an explicit reviewed call, never inferred from names,
-- processes or Compose labels. It carries source and time. The optional
-- health-check configuration (protocol, approved destination, port) is
-- stored with the placement; a service without a configured check stays
-- unknown (unknown is never rendered as healthy or off).
--
-- Removing a placement is a tombstone (removed_at), keeping the explicit
-- placement history. A placement pointing at a tombstoned guest
-- incarnation is tombstoned by the VMID-reuse sweep, like host links.

CREATE TABLE pve_service_placements (
    id                INTEGER PRIMARY KEY,
    service_name      TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('host', 'guest', 'container')),
    host_id           TEXT NOT NULL DEFAULT '',
    remote_id         TEXT NOT NULL DEFAULT '',
    vmid              INTEGER NOT NULL DEFAULT 0,
    generation        INTEGER NOT NULL DEFAULT 0,
    container_id      TEXT NOT NULL DEFAULT '',
    check_protocol    TEXT NOT NULL DEFAULT '' CHECK (check_protocol IN ('', 'http', 'https', 'tcp')),
    check_destination TEXT NOT NULL DEFAULT '',
    check_port        INTEGER NOT NULL DEFAULT 0,
    check_internal    INTEGER NOT NULL DEFAULT 0 CHECK (check_internal IN (0, 1)),
    source            TEXT NOT NULL,
    recorded_by       TEXT NOT NULL,
    recorded_at       TEXT NOT NULL,
    removed_at        TEXT NOT NULL DEFAULT '',
    removed_by        TEXT NOT NULL DEFAULT '',
    remove_reason     TEXT NOT NULL DEFAULT '',
    CHECK ((check_protocol = '' AND check_destination = '' AND check_port = 0 AND check_internal = 0)
        OR (check_protocol IN ('http', 'https', 'tcp') AND length(check_destination) BETWEEN 1 AND 253 AND check_port BETWEEN 1 AND 65535)),
    CHECK ((kind = 'host' AND host_id <> '' AND remote_id = '' AND vmid = 0 AND generation = 0 AND container_id = '')
        OR (kind = 'guest' AND host_id = '' AND remote_id <> '' AND vmid > 0 AND generation > 0 AND container_id = '')
        OR (kind = 'container' AND host_id <> '' AND remote_id = '' AND vmid = 0 AND generation = 0
            AND length(container_id) = 64 AND container_id NOT GLOB '*[^0-9a-f]*'))
    -- At most one active placement (removed_at = '') per service is
    -- enforced transactionally in pveinventory.SetServicePlacement; the
    -- table keeps the full explicit placement history (tombstones are
    -- never deleted).
);
CREATE UNIQUE INDEX uq_pve_service_placements_active ON pve_service_placements (service_name) WHERE removed_at = '';
CREATE INDEX idx_pve_service_placements_kind ON pve_service_placements (kind);
CREATE INDEX idx_pve_service_placements_host ON pve_service_placements (host_id);
CREATE INDEX idx_pve_service_placements_incarnation ON pve_service_placements (remote_id, vmid, generation);
CREATE INDEX idx_pve_service_placements_removed_at ON pve_service_placements (removed_at);

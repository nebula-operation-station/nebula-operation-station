-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Host names can be reused after deletion. Tombstone placements in the
-- deletion transaction so a new host cannot inherit placement or approval.

CREATE TRIGGER tombstone_service_placements_on_host_delete
AFTER DELETE ON hosts
BEGIN
    UPDATE pve_service_placements
    SET removed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        removed_by = 'system',
        remove_reason = 'host-deleted'
    WHERE kind IN ('host', 'container')
      AND host_id = OLD.name
      AND removed_at = '';
END;

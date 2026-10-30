// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// The schedule API is a compatibility view of the shared read-grant registry.
// Legacy signed documents retain their exact bytes and absolute expiry.

// SaveScheduleGrant stores a legacy approval in the shared grant registry.
func (db *DB) SaveScheduleGrant(g permit.StoredGrant) error {
	return db.saveReadGrant(g, true)
}

// ScheduleGrant returns one legacy schedule grant.
func (db *DB) ScheduleGrant(id string) (permit.StoredGrant, bool, error) {
	g, err := scanReadGrant(db.sql.QueryRow(`SELECT id, digest, doc, approved_by, created_at, expires_at, revoked_at FROM read_grants WHERE id = ? AND legacy_schedule = 1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return permit.StoredGrant{}, false, nil
	}
	if err != nil {
		return permit.StoredGrant{}, false, fmt.Errorf("executordb: schedule grant: %w", err)
	}
	return g, true, nil
}

// ScheduleGrants returns every legacy schedule grant, newest first.
func (db *DB) ScheduleGrants() ([]permit.StoredGrant, error) {
	rows, err := db.sql.Query(`SELECT id, digest, doc, approved_by, created_at, expires_at, revoked_at FROM read_grants WHERE legacy_schedule = 1 ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: schedule grants: %w", err)
	}
	defer rows.Close()
	var out []permit.StoredGrant
	for rows.Next() {
		g, err := scanReadGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("executordb: schedule grants: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeScheduleGrant revokes a legacy approval in the shared registry.
func (db *DB) RevokeScheduleGrant(id string, at time.Time) (bool, error) {
	res, err := db.sql.Exec(`UPDATE read_grants SET revoked_at = ? WHERE id = ? AND legacy_schedule = 1 AND revoked_at IS NULL`, at.Unix(), id)
	if err != nil {
		return false, fmt.Errorf("executordb: revoke schedule grant: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ClaimScheduleRun reserves a legacy run against the shared target ceiling
// and action floor, atomically with the grant's revocation and expiry check.
func (db *DB) ClaimScheduleRun(grantID, actionID, hostID string, now time.Time, minInterval time.Duration) (bool, error) {
	return db.ReserveReadRun(grantID, actionID, hostID, now, permit.GlobalRunBudget, minInterval)
}

var _ permit.ScheduleStore = (*DB)(nil)

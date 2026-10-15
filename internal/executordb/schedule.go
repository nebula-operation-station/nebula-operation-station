// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// Schedule grants (docs/implementation/schedule-grants.md); DB implements
// permit.ScheduleStore.

func scanGrant(row interface{ Scan(...any) error }) (permit.StoredGrant, error) {
	var g permit.StoredGrant
	var created, expires int64
	var revoked sql.NullInt64
	if err := row.Scan(&g.ID, &g.Digest, &g.Doc, &g.ApprovedBy, &created, &expires, &revoked); err != nil {
		return permit.StoredGrant{}, err
	}
	g.CreatedAt, g.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	if revoked.Valid {
		g.RevokedAt = time.Unix(revoked.Int64, 0)
	}
	return g, nil
}

// SaveScheduleGrant stores an approved grant.
func (db *DB) SaveScheduleGrant(g permit.StoredGrant) error {
	_, err := db.sql.Exec(`INSERT INTO schedule_grants (id, digest, doc, approved_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		g.ID, g.Digest, g.Doc, g.ApprovedBy, g.CreatedAt.Unix(), g.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("executordb: save schedule grant: %w", err)
	}
	return nil
}

// ScheduleGrant returns one grant.
func (db *DB) ScheduleGrant(id string) (permit.StoredGrant, bool, error) {
	g, err := scanGrant(db.sql.QueryRow(`SELECT id, digest, doc, approved_by, created_at, expires_at, revoked_at FROM schedule_grants WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return permit.StoredGrant{}, false, nil
	}
	if err != nil {
		return permit.StoredGrant{}, false, fmt.Errorf("executordb: schedule grant: %w", err)
	}
	return g, true, nil
}

// ScheduleGrants returns every grant, newest first.
func (db *DB) ScheduleGrants() ([]permit.StoredGrant, error) {
	rows, err := db.sql.Query(`SELECT id, digest, doc, approved_by, created_at, expires_at, revoked_at FROM schedule_grants ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: schedule grants: %w", err)
	}
	defer rows.Close()
	var out []permit.StoredGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("executordb: schedule grants: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeScheduleGrant marks an active grant revoked.
func (db *DB) RevokeScheduleGrant(id string, at time.Time) (bool, error) {
	res, err := db.sql.Exec(`UPDATE schedule_grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, at.Unix(), id)
	if err != nil {
		return false, fmt.Errorf("executordb: revoke schedule grant: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ClaimScheduleRun records a run at now if the last run of this action on
// this host under the grant is at least minInterval ago. One statement, so
// two concurrent claims cannot both succeed.
func (db *DB) ClaimScheduleRun(grantID, actionID, hostID string, now time.Time, minInterval time.Duration) (bool, error) {
	res, err := db.sql.Exec(`INSERT INTO schedule_runs (grant_id, action_id, host_id, last_run) VALUES (?, ?, ?, ?)
		ON CONFLICT (grant_id, action_id, host_id) DO UPDATE SET last_run = excluded.last_run
		WHERE schedule_runs.last_run <= ?`, grantID, actionID, hostID, now.Unix(), now.Add(-minInterval).Unix())
	if err != nil {
		return false, fmt.Errorf("executordb: claim schedule run: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

var _ permit.ScheduleStore = (*DB)(nil)

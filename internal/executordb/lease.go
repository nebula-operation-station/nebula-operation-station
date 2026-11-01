// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Read grants (ADR 0007 "One standing read-grant mechanism"); DB
// implements permit.ReadGrantStore.

func scanReadGrant(row interface{ Scan(...any) error }) (permit.StoredReadGrant, error) {
	var g permit.StoredReadGrant
	var created, expires int64
	var revoked sql.NullInt64
	if err := row.Scan(&g.ID, &g.Digest, &g.Doc, &g.ApprovedBy, &created, &expires, &revoked); err != nil {
		return permit.StoredReadGrant{}, err
	}
	g.CreatedAt, g.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	if revoked.Valid {
		g.RevokedAt = time.Unix(revoked.Int64, 0)
	}
	return g, nil
}

// SaveReadGrant stores an approved read grant.
func (db *DB) SaveReadGrant(g permit.StoredReadGrant) error {
	return db.saveReadGrant(g, false)
}

func (db *DB) saveReadGrant(g permit.StoredReadGrant, legacy bool) error {
	res, err := db.sql.Exec(`INSERT INTO read_grants (id, digest, doc, approved_by, created_at, expires_at, legacy_schedule)
		SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM recovery_state)`,
		g.ID, g.Digest, g.Doc, g.ApprovedBy, g.CreatedAt.Unix(), g.ExpiresAt.Unix(), legacy)
	if err != nil {
		return fmt.Errorf("executordb: save read grant: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("executordb: save read grant: %w", err)
	} else if n == 0 {
		return permit.ErrReadGrantInactive
	}
	return nil
}

// ReadGrantClock durably observes now and returns the nondecreasing read
// clock, including observations that are denied before a reservation.
func (db *DB) ReadGrantClock(now time.Time) (time.Time, error) {
	var effective int64
	err := db.sql.QueryRow(`INSERT INTO read_clock (id, high_water) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET high_water = MAX(read_clock.high_water, excluded.high_water)
		RETURNING high_water`, now.Unix()).Scan(&effective)
	if err != nil {
		return time.Time{}, fmt.Errorf("executordb: read grant clock: %w", err)
	}
	return time.Unix(effective, 0), nil
}

// ReadGrant returns one read grant.
func (db *DB) ReadGrant(id string) (permit.StoredReadGrant, bool, error) {
	g, err := scanReadGrant(db.sql.QueryRow(`SELECT id, digest, doc, approved_by, created_at, expires_at, revoked_at FROM read_grants WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return permit.StoredReadGrant{}, false, nil
	}
	if err != nil {
		return permit.StoredReadGrant{}, false, fmt.Errorf("executordb: read grant: %w", err)
	}
	return g, true, nil
}

// ReadGrants returns every read grant, newest first.
func (db *DB) ReadGrants() ([]permit.StoredReadGrant, error) {
	rows, err := db.sql.Query(`SELECT id, digest, doc, approved_by, created_at, expires_at, revoked_at FROM read_grants ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: read grants: %w", err)
	}
	defer rows.Close()
	var out []permit.StoredReadGrant
	for rows.Next() {
		g, err := scanReadGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("executordb: read grants: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeReadGrant marks an active read grant revoked.
func (db *DB) RevokeReadGrant(id string, at time.Time) (bool, error) {
	res, err := db.sql.Exec(`UPDATE read_grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, at.Unix(), id)
	if err != nil {
		return false, fmt.Errorf("executordb: revoke read grant: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// readActionLastRetention is how long an interval row is kept: the
// longest interval any read grant may approve (schedgrant.MaxInterval).
const readActionLastRetention = schedgrant.MaxInterval

// ReserveReadRun atomically reserves one run of actionID on hostID under
// grantID at now, in one transaction, so two concurrent reservations
// cannot both succeed. It succeeds only while (a) the target's
// reservations in the last hour are below the per-target ceiling budget,
// and (b) the last reservation of actionID on hostID is at least
// minInterval ago (the 15-minute per-action floor). Both counters are
// shared across grants, so overlapping grants cannot multiply the
// per-target ceiling, and they are durable across restart. The window is
// anchored to the latest time the store has seen (the high-water clock),
// so a wall-clock rollback never moves it backward or refills a budget.
// Grant activity is rechecked in that same transaction, serialized with
// revocation; a missing, revoked or expired grant returns ErrReadGrantInactive.
func (db *DB) ReserveReadRun(grantID, actionID, hostID string, now time.Time, budget int, minInterval time.Duration) (bool, error) {
	if budget < 1 {
		return false, fmt.Errorf("executordb: reserve read run: budget %d below 1", budget)
	}
	if minInterval > readActionLastRetention {
		return false, fmt.Errorf("executordb: reserve read run: interval %s above %s", minInterval, readActionLastRetention)
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit
	if _, err := tx.Exec(`INSERT INTO read_clock (id, high_water) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET high_water = MAX(read_clock.high_water, excluded.high_water)`, now.Unix()); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	var effective int64
	if err := tx.QueryRow(`SELECT high_water FROM read_clock WHERE id = 1`).Scan(&effective); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	// Denials still observe time. Commit the high-water update so rollback
	// or restart cannot resurrect expired authority or rewind the window.
	deny := func(reason error) (bool, error) {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("executordb: reserve read run: %w", err)
		}
		return false, reason
	}
	var active bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM read_grants WHERE id = ? AND revoked_at IS NULL AND expires_at > ?)
		AND NOT EXISTS (SELECT 1 FROM recovery_state)`, grantID, effective).Scan(&active); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	if !active {
		return deny(permit.ErrReadGrantInactive)
	}
	cutoff := effective - int64(permit.RollingHour/time.Second)
	// Rows at or before the cutoff can never count again; drop them so the
	// log stays bounded.
	if _, err := tx.Exec(`DELETE FROM read_run_log WHERE at <= ?`, cutoff); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	var spent int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM read_run_log WHERE host_id = ? AND at > ?`, hostID, cutoff).Scan(&spent); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	if spent >= budget {
		return deny(nil)
	}
	// Interval rows older than the longest approvable interval can never
	// deny again; drop them so per-guest and per-target keys stay bounded.
	if _, err := tx.Exec(`DELETE FROM read_action_last WHERE last_run <= ?`, effective-int64(readActionLastRetention/time.Second)); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	var last int64
	err = tx.QueryRow(`SELECT last_run FROM read_action_last WHERE action_id = ? AND host_id = ?`, actionID, hostID).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	if last > effective-int64(minInterval/time.Second) {
		return deny(nil)
	}
	if _, err := tx.Exec(`INSERT INTO read_run_log (grant_id, host_id, at) VALUES (?, ?, ?)`, grantID, hostID, effective); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO read_action_last (action_id, host_id, last_run) VALUES (?, ?, ?)
		ON CONFLICT(action_id, host_id) DO UPDATE SET last_run = excluded.last_run`, actionID, hostID, effective); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("executordb: reserve read run: %w", err)
	}
	return true, nil
}

var _ permit.ReadGrantStore = (*DB)(nil)

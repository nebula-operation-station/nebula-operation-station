// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNoTOTP is returned when no TOTP secret is set up.
var ErrNoTOTP = errors.New("executordb: TOTP recovery is not set up")

// ErrTOTPReplay is returned by UseTOTPStep for a step that is not newer
// than the last one used.
var ErrTOTPReplay = errors.New("executordb: TOTP code already used")

// TOTP is the recovery secret.
type TOTP struct {
	Secret    []byte
	Activated bool
	LastStep  int64
	CreatedAt time.Time
	CreatedBy string
}

// SetTOTP stores a new, not yet activated secret, replacing any earlier one.
func (db *DB) SetTOTP(secret []byte, by string) error {
	if len(secret) != 20 {
		return fmt.Errorf("executordb: %w: TOTP secret must be 20 bytes", ErrInvalid)
	}
	if err := checkText("created_by", by, maxActorLen, false); err != nil {
		return err
	}
	_, err := db.sql.Exec(`INSERT INTO totp (id, secret, activated, last_step, created_at, created_by) VALUES (1, ?, 0, 0, ?, ?)
		ON CONFLICT(id) DO UPDATE SET secret = excluded.secret, activated = 0, last_step = 0,
			created_at = excluded.created_at, created_by = excluded.created_by`, secret, db.now().Unix(), by)
	if err != nil {
		return fmt.Errorf("executordb: set TOTP: %w", err)
	}
	return nil
}

// GetTOTP returns the recovery secret or ErrNoTOTP.
func (db *DB) GetTOTP() (TOTP, error) {
	var t TOTP
	var act int
	var at int64
	err := db.sql.QueryRow(`SELECT secret, activated, last_step, created_at, created_by FROM totp WHERE id = 1`).
		Scan(&t.Secret, &act, &t.LastStep, &at, &t.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return TOTP{}, ErrNoTOTP
	}
	if err != nil {
		return TOTP{}, fmt.Errorf("executordb: get TOTP: %w", err)
	}
	t.Activated, t.CreatedAt = act == 1, time.Unix(at, 0)
	return t, nil
}

// UseTOTPStep records step as used (and activates the secret). It fails
// with ErrTOTPReplay unless step is newer than every step used before, so
// concurrent use of one code succeeds once.
func (db *DB) UseTOTPStep(step int64) error {
	res, err := db.sql.Exec(`UPDATE totp SET last_step = ?, activated = 1 WHERE id = 1 AND last_step < ?`, step, step)
	if err != nil {
		return fmt.Errorf("executordb: use TOTP step: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("executordb: use TOTP step: %w", err)
	}
	if n == 0 {
		return ErrTOTPReplay
	}
	return nil
}

// RemoveTOTP deletes the secret and reports whether one existed.
func (db *DB) RemoveTOTP() (bool, error) {
	res, err := db.sql.Exec(`DELETE FROM totp WHERE id = 1`)
	if err != nil {
		return false, fmt.Errorf("executordb: remove TOTP: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetRecoveryPending records a recovery login; an earlier pending time is kept.
func (db *DB) SetRecoveryPending() error {
	_, err := db.sql.Exec(`INSERT INTO recovery_state (id, pending_since) VALUES (1, ?) ON CONFLICT(id) DO NOTHING`, db.now().Unix())
	if err != nil {
		return fmt.Errorf("executordb: set recovery pending: %w", err)
	}
	return nil
}

// RecoveryPending reports whether a recovery login is waiting for a new
// WebAuthn registration, and since when.
func (db *DB) RecoveryPending() (time.Time, bool, error) {
	var at int64
	err := db.sql.QueryRow(`SELECT pending_since FROM recovery_state WHERE id = 1`).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("executordb: recovery state: %w", err)
	}
	return time.Unix(at, 0), true, nil
}

// ClearRecoveryPending ends the recovery state (a new credential was registered).
func (db *DB) ClearRecoveryPending() error {
	if _, err := db.sql.Exec(`DELETE FROM recovery_state WHERE id = 1`); err != nil {
		return fmt.Errorf("executordb: clear recovery pending: %w", err)
	}
	return nil
}

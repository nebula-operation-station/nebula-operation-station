// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Signer is a trusted module signer (M7-5).
type Signer struct {
	Fingerprint string
	PublicKey   string // authorized_keys form, without comment
	Name        string
	AddedAt     time.Time
	AddedBy     string
}

// ModuleVersion is a registered, signed module version.
type ModuleVersion struct {
	Name, Version, LockSHA256, Fingerprint string
	RegisteredAt                           time.Time
}

// Errors of module registration.
var (
	ErrSignerChanged  = errors.New("executordb: the module was signed by another signer before; an admin must confirm the new signer")
	ErrVersionChanged = errors.New("executordb: this module version was registered with another lock")
	// ErrPreviousSigner: the module's signer is not the one the admin saw.
	ErrPreviousSigner = errors.New("executordb: the module's signer is not the one you confirmed against")
)

var (
	fpRe         = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	moduleNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,30}$`)
)

// SignerPrefix starts the trusted_by of trust entries a signer's module
// created; removing the signer removes them.
const SignerPrefix = "signer:"

// AddSigner records a trusted signer.
func (db *DB) AddSigner(s Signer) error {
	if !fpRe.MatchString(s.Fingerprint) || len(s.PublicKey) > 200 || !strings.HasPrefix(s.PublicKey, "ssh-ed25519 ") {
		return fmt.Errorf("executordb: %w: signer key", ErrInvalid)
	}
	if err := checkText("name", s.Name, 100, false); err != nil {
		return err
	}
	if err := checkText("actor", s.AddedBy, maxActorLen, false); err != nil {
		return err
	}
	if _, err := db.sql.Exec(`INSERT INTO trusted_signers (fingerprint, public_key, name, added_at, added_by) VALUES (?, ?, ?, ?, ?)`,
		s.Fingerprint, s.PublicKey, s.Name, db.now().Unix(), s.AddedBy); err != nil {
		return fmt.Errorf("executordb: add signer: %w", err)
	}
	return nil
}

// Signers lists the trusted signers.
func (db *DB) Signers() ([]Signer, error) {
	rows, err := db.sql.Query(`SELECT fingerprint, public_key, name, added_at, added_by FROM trusted_signers ORDER BY name, fingerprint`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list signers: %w", err)
	}
	defer rows.Close()
	var out []Signer
	for rows.Next() {
		var s Signer
		var at int64
		if err := rows.Scan(&s.Fingerprint, &s.PublicKey, &s.Name, &at, &s.AddedBy); err != nil {
			return nil, fmt.Errorf("executordb: list signers: %w", err)
		}
		s.AddedAt = time.Unix(at, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Signer returns the trusted signer with fingerprint.
func (db *DB) Signer(fingerprint string) (Signer, bool, error) {
	var s Signer
	var at int64
	err := db.sql.QueryRow(`SELECT fingerprint, public_key, name, added_at, added_by FROM trusted_signers WHERE fingerprint = ?`, fingerprint).
		Scan(&s.Fingerprint, &s.PublicKey, &s.Name, &at, &s.AddedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return Signer{}, false, nil
	}
	if err != nil {
		return Signer{}, false, fmt.Errorf("executordb: signer: %w", err)
	}
	s.AddedAt = time.Unix(at, 0)
	return s, true, nil
}

// RemoveSigner removes a signer and every trust entry its modules created.
// It reports how many trust entries went.
func (db *DB) RemoveSigner(fingerprint string) (bool, int64, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return false, 0, fmt.Errorf("executordb: remove signer: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`DELETE FROM trusted_signers WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return false, 0, fmt.Errorf("executordb: remove signer: %w", err)
	}
	n, _ := res.RowsAffected()
	res, err = tx.Exec(`DELETE FROM trusted_artifacts WHERE trusted_by = ?`, SignerPrefix+fingerprint)
	if err != nil {
		return false, 0, fmt.Errorf("executordb: remove signer: %w", err)
	}
	m, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("executordb: remove signer: %w", err)
	}
	return n > 0, m, nil
}

// ConfirmModuleSigner makes fingerprint the signer of module name (an
// admin's manual review of a signer change, or a first assignment).
// The previous signer must be expectedPrevious ("" for none), so the admin
// confirms the change they reviewed; it returns the previous signer.
func (db *DB) ConfirmModuleSigner(name, fingerprint, by, expectedPrevious string) (string, error) {
	if !moduleNameRe.MatchString(name) || !fpRe.MatchString(fingerprint) || expectedPrevious != "" && !fpRe.MatchString(expectedPrevious) {
		return "", fmt.Errorf("executordb: %w: module name or fingerprint", ErrInvalid)
	}
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return "", err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return "", fmt.Errorf("executordb: confirm module signer: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var prev string
	err = tx.QueryRow(`SELECT fingerprint FROM module_signers WHERE name = ?`, name).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("executordb: confirm module signer: %w", err)
	}
	if prev != expectedPrevious {
		return prev, ErrPreviousSigner
	}
	if _, err := tx.Exec(`INSERT INTO module_signers (name, fingerprint, confirmed_by, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET fingerprint = excluded.fingerprint, confirmed_by = excluded.confirmed_by, updated_at = excluded.updated_at`,
		name, fingerprint, by, db.now().Unix()); err != nil {
		return "", fmt.Errorf("executordb: confirm module signer: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("executordb: confirm module signer: %w", err)
	}
	return prev, nil
}

// ModuleSigner is the signer a module is bound to.
type ModuleSigner struct {
	Name, Fingerprint, ConfirmedBy string
	UpdatedAt                      time.Time
}

// ModuleSigners lists the module bindings by module name.
func (db *DB) ModuleSigners() ([]ModuleSigner, error) {
	rows, err := db.sql.Query(`SELECT name, fingerprint, confirmed_by, updated_at FROM module_signers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list module signers: %w", err)
	}
	defer rows.Close()
	var out []ModuleSigner
	for rows.Next() {
		var m ModuleSigner
		var at int64
		if err := rows.Scan(&m.Name, &m.Fingerprint, &m.ConfirmedBy, &at); err != nil {
			return nil, fmt.Errorf("executordb: list module signers: %w", err)
		}
		m.UpdatedAt = time.Unix(at, 0)
		out = append(out, m)
	}
	return out, rows.Err()
}

// RegisterModule records a verified module version and trusts its
// actions' artifacts, in one transaction. An existing trust entry for the
// same bytes, action and version (an admin's) is kept as it is. The signer must still be
// trusted and must be the module's signer (the first registration makes
// it so); a known version must have the same lock.
func (db *DB) RegisterModule(v ModuleVersion, arts []TrustedArtifact) error {
	if !moduleNameRe.MatchString(v.Name) || !fpRe.MatchString(v.Fingerprint) || len(v.LockSHA256) != 64 {
		return fmt.Errorf("executordb: %w: module", ErrInvalid)
	}
	for _, a := range arts {
		if a.TrustedBy != SignerPrefix+v.Fingerprint {
			return fmt.Errorf("executordb: %w: trust entry not by the module's signer", ErrInvalid)
		}
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: register module: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM trusted_signers WHERE fingerprint = ?`, v.Fingerprint).Scan(&n); err != nil {
		return fmt.Errorf("executordb: register module: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("executordb: %w: the signer is not trusted", ErrInvalid)
	}
	var signer string
	switch err := tx.QueryRow(`SELECT fingerprint FROM module_signers WHERE name = ?`, v.Name).Scan(&signer); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO module_signers (name, fingerprint, confirmed_by, updated_at) VALUES (?, ?, ?, ?)`,
			v.Name, v.Fingerprint, "first registration", db.now().Unix()); err != nil {
			return fmt.Errorf("executordb: register module: %w", err)
		}
	case err != nil:
		return fmt.Errorf("executordb: register module: %w", err)
	case signer != v.Fingerprint:
		return ErrSignerChanged
	}
	var lock string
	switch err := tx.QueryRow(`SELECT lock_sha256 FROM module_versions WHERE name = ? AND version = ?`, v.Name, v.Version).Scan(&lock); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO module_versions (name, version, lock_sha256, fingerprint, registered_at) VALUES (?, ?, ?, ?, ?)`,
			v.Name, v.Version, v.LockSHA256, v.Fingerprint, db.now().Unix()); err != nil {
			return fmt.Errorf("executordb: register module: %w", err)
		}
	case err != nil:
		return fmt.Errorf("executordb: register module: %w", err)
	case lock != v.LockSHA256:
		return ErrVersionChanged
	}
	for _, a := range arts {
		sum, err := parseSHA256(a.SHA256)
		if err != nil {
			return err
		}
		if err := checkText("label", a.Label, maxLabelLen, true); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO trusted_artifacts (artifact_sha256, action_id, module_version, risk, label, trusted_at, trusted_by)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(artifact_sha256, action_id, module_version) DO NOTHING`,
			sum, a.ActionID, a.ModuleVersion, a.Risk.Rank(), a.Label, db.now().Unix(), a.TrustedBy); err != nil {
			return fmt.Errorf("executordb: register module: %w", err)
		}
	}
	return tx.Commit()
}

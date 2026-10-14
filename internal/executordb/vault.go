// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Vault errors.
var (
	ErrNoVault       = errors.New("executordb: vault is not initialized")
	ErrVaultExists   = errors.New("executordb: vault is already initialized")
	ErrNoSecret      = errors.New("executordb: secret not found")
	ErrSecretVersion = errors.New("executordb: secret changed concurrently")
)

// VaultMeta is the vault header: KDF parameters, salt and the wrapped
// master key (nonce || ciphertext). Only package vault interprets it.
type VaultMeta struct {
	Format        int
	KDFTime       uint32
	KDFMemoryKiB  uint32
	KDFThreads    uint8
	Salt          []byte
	WrappedMaster []byte
	CreatedAt     time.Time
	CreatedBy     string
}

// VaultSecret is one encrypted secret.
type VaultSecret struct {
	ID         string
	Version    int64
	WrappedDEK []byte // nonce || ciphertext of the data key
	Sealed     []byte // nonce || ciphertext of the value
	UpdatedAt  time.Time
	UpdatedBy  string
}

// InitVault stores the vault header once; a second call fails with
// ErrVaultExists.
func (db *DB) InitVault(m VaultMeta) error {
	if err := checkText("created_by", m.CreatedBy, maxActorLen, false); err != nil {
		return err
	}
	res, err := db.sql.Exec(`INSERT INTO vault_meta (id, format, kdf_time, kdf_memory_kib, kdf_threads, salt, wrapped_master, created_at, created_by)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`,
		m.Format, m.KDFTime, m.KDFMemoryKiB, m.KDFThreads, m.Salt, m.WrappedMaster, db.now().Unix(), m.CreatedBy)
	if err != nil {
		return fmt.Errorf("executordb: init vault: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return ErrVaultExists
	}
	return nil
}

// GetVault returns the vault header or ErrNoVault.
func (db *DB) GetVault() (VaultMeta, error) {
	var m VaultMeta
	var at int64
	err := db.sql.QueryRow(`SELECT format, kdf_time, kdf_memory_kib, kdf_threads, salt, wrapped_master, created_at, created_by
		FROM vault_meta WHERE id = 1`).Scan(&m.Format, &m.KDFTime, &m.KDFMemoryKiB, &m.KDFThreads, &m.Salt, &m.WrappedMaster, &at, &m.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return VaultMeta{}, ErrNoVault
	}
	if err != nil {
		return VaultMeta{}, fmt.Errorf("executordb: get vault: %w", err)
	}
	m.CreatedAt = time.Unix(at, 0)
	return m, nil
}

// PutSecret stores s. s.Version must be one more than the stored version
// (1 for a new secret); otherwise ErrSecretVersion, so two concurrent
// writers cannot both win.
func (db *DB) PutSecret(s VaultSecret) error {
	if err := checkText("updated_by", s.UpdatedBy, maxActorLen, false); err != nil {
		return err
	}
	var res sql.Result
	var err error
	if s.Version == 1 {
		res, err = db.sql.Exec(`INSERT INTO vault_secrets (id, version, wrapped_dek, sealed, updated_at, updated_by)
			VALUES (?, 1, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`, s.ID, s.WrappedDEK, s.Sealed, db.now().Unix(), s.UpdatedBy)
	} else {
		res, err = db.sql.Exec(`UPDATE vault_secrets SET version = ?, wrapped_dek = ?, sealed = ?, updated_at = ?, updated_by = ?
			WHERE id = ? AND version = ?`, s.Version, s.WrappedDEK, s.Sealed, db.now().Unix(), s.UpdatedBy, s.ID, s.Version-1)
	}
	if err != nil {
		return fmt.Errorf("executordb: put secret: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return ErrSecretVersion
	}
	return nil
}

// GetSecret returns the encrypted secret id or ErrNoSecret.
func (db *DB) GetSecret(id string) (VaultSecret, error) {
	s := VaultSecret{ID: id}
	var at int64
	err := db.sql.QueryRow(`SELECT version, wrapped_dek, sealed, updated_at, updated_by FROM vault_secrets WHERE id = ?`, id).
		Scan(&s.Version, &s.WrappedDEK, &s.Sealed, &at, &s.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return VaultSecret{}, ErrNoSecret
	}
	if err != nil {
		return VaultSecret{}, fmt.Errorf("executordb: get secret: %w", err)
	}
	s.UpdatedAt = time.Unix(at, 0)
	return s, nil
}

// ListSecrets returns all secrets ordered by ID, without their blobs.
func (db *DB) ListSecrets() ([]VaultSecret, error) {
	rows, err := db.sql.Query(`SELECT id, version, updated_at, updated_by FROM vault_secrets ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list secrets: %w", err)
	}
	defer rows.Close()
	var out []VaultSecret
	for rows.Next() {
		var s VaultSecret
		var at int64
		if err := rows.Scan(&s.ID, &s.Version, &at, &s.UpdatedBy); err != nil {
			return nil, fmt.Errorf("executordb: list secrets: %w", err)
		}
		s.UpdatedAt = time.Unix(at, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteSecret removes secret id and reports whether it existed.
func (db *DB) DeleteSecret(id string) (bool, error) {
	res, err := db.sql.Exec(`DELETE FROM vault_secrets WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("executordb: delete secret: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

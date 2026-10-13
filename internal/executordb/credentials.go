// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"fmt"
	"time"
)

// ErrCredentialExists is returned by AddWebAuthnCredential for an ID that
// is already registered.
var ErrCredentialExists = errors.New("executordb: credential already registered")

// Limits on stored credential fields (CHECKs in 0003_webauthn_credentials.sql).
const (
	maxPublicKeyLen  = 2048
	maxUserHandleLen = 64
	maxUserNameLen   = 64
	maxFormatLen     = 32
	maxCreatedByLen  = 200
)

// WebAuthnCredential is a credential registered on the executor (H03).
type WebAuthnCredential struct {
	ID                []byte
	PublicKey         []byte // COSE_Key
	UserHandle        []byte
	UserName          string
	Label             string
	AAGUID            []byte // 16 bytes, or empty
	AttestationFormat string
	CreatedAt         time.Time
	CreatedBy         string
	// SignCount is the initial signature counter, stored together with the
	// credential (AddWebAuthnCredential only; not returned by List).
	SignCount uint32
}

// AddWebAuthnCredential stores a new credential. CreatedAt is set by the
// database. An ID that is already stored returns ErrCredentialExists.
func (db *DB) AddWebAuthnCredential(c WebAuthnCredential) error {
	switch {
	case len(c.ID) == 0 || len(c.ID) > maxCredentialID:
		return fmt.Errorf("executordb: %w: credential ID length %d outside 1..%d", ErrInvalid, len(c.ID), maxCredentialID)
	case len(c.PublicKey) == 0 || len(c.PublicKey) > maxPublicKeyLen:
		return fmt.Errorf("executordb: %w: public key length %d outside 1..%d", ErrInvalid, len(c.PublicKey), maxPublicKeyLen)
	case len(c.UserHandle) > maxUserHandleLen:
		return fmt.Errorf("executordb: %w: user handle longer than %d bytes", ErrInvalid, maxUserHandleLen)
	case len(c.AAGUID) != 0 && len(c.AAGUID) != 16:
		return fmt.Errorf("executordb: %w: AAGUID must be 16 bytes", ErrInvalid)
	case len(c.AttestationFormat) > maxFormatLen:
		return fmt.Errorf("executordb: %w: attestation format too long", ErrInvalid)
	}
	if err := checkText("user name", c.UserName, maxUserNameLen, false); err != nil {
		return err
	}
	if err := checkText("label", c.Label, maxLabelLen, true); err != nil {
		return err
	}
	if err := checkText("created_by", c.CreatedBy, maxCreatedByLen, false); err != nil {
		return err
	}
	if err := checkText("attestation format", c.AttestationFormat, maxFormatLen, true); err != nil {
		return err
	}
	if c.UserHandle == nil {
		c.UserHandle = []byte{}
	}
	if c.AAGUID == nil {
		c.AAGUID = []byte{}
	}
	// Credential and counter in one transaction: a counter is only raised
	// for a credential that this call actually adds.
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: add credential: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	res, err := tx.Exec(`INSERT INTO webauthn_credentials
		(credential_id, public_key, user_handle, user_name, label, aaguid, attestation_format, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(credential_id) DO NOTHING`,
		c.ID, c.PublicKey, c.UserHandle, c.UserName, c.Label, c.AAGUID, c.AttestationFormat, db.now().Unix(), c.CreatedBy)
	if err != nil {
		return fmt.Errorf("executordb: add credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("executordb: add credential: %w", err)
	}
	if n == 0 {
		return ErrCredentialExists
	}
	if c.SignCount > 0 {
		if _, err := tx.Exec(`INSERT INTO webauthn_counters (credential_id, sign_count, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(credential_id) DO UPDATE SET sign_count = excluded.sign_count, updated_at = excluded.updated_at
			WHERE excluded.sign_count > webauthn_counters.sign_count`,
			c.ID, int64(c.SignCount), db.now().Unix()); err != nil {
			return fmt.Errorf("executordb: add credential counter: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: add credential: %w", err)
	}
	return nil
}

// ListWebAuthnCredentials returns all credentials, oldest first.
func (db *DB) ListWebAuthnCredentials() ([]WebAuthnCredential, error) {
	rows, err := db.sql.Query(`SELECT credential_id, public_key, user_handle, user_name, label, aaguid,
		attestation_format, created_at, created_by FROM webauthn_credentials ORDER BY created_at, credential_id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list credentials: %w", err)
	}
	defer rows.Close()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var at int64
		if err := rows.Scan(&c.ID, &c.PublicKey, &c.UserHandle, &c.UserName, &c.Label, &c.AAGUID,
			&c.AttestationFormat, &at, &c.CreatedBy); err != nil {
			return nil, fmt.Errorf("executordb: list credentials: %w", err)
		}
		c.CreatedAt = time.Unix(at, 0)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: list credentials: %w", err)
	}
	return out, nil
}

// RemoveWebAuthnCredential deletes a credential and reports whether it
// existed. Its signature counter is kept.
func (db *DB) RemoveWebAuthnCredential(id []byte) (bool, error) {
	res, err := db.sql.Exec(`DELETE FROM webauthn_credentials WHERE credential_id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("executordb: remove credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("executordb: remove credential: %w", err)
	}
	return n > 0, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// ErrHostPinned is returned by PinHostKey for a host that already has a
// pinned key. Re-pinning is an explicit unpin followed by a new pin.
var ErrHostPinned = errors.New("executordb: host already has a pinned key")

// Host key sources.
const (
	SourceProbe      = "probe"       // the admin confirmed the fingerprint the executor read
	SourceKnownHosts = "known_hosts" // imported from an OpenSSH known_hosts file
)

var (
	sshUserRe       = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	credentialRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`) // keyring file name without .key
)

const (
	maxHostKeyLen     = 2048
	maxBlockedEndpLen = 300
)

// HostKey is the pin of one host and how the executor logs in there.
type HostKey struct {
	HostID        string
	PublicKey     []byte // SSH wire format
	Fingerprint   string // set by PinHostKey from PublicKey
	User          string
	CredentialRef string
	Source        string
	PinnedAt      time.Time
	PinnedBy      string
	Blocked       *HostKeyBlock // nil unless a mismatch was seen
}

// HostKeyBlock records the first host key mismatch seen for a host.
type HostKeyBlock struct {
	At          time.Time
	Fingerprint string // the key the endpoint presented; "" if it offered no key of the pinned type
	Endpoint    string
}

// PinHostKey stores the pin of a host. The fingerprint is computed here
// from PublicKey. A host that is already pinned returns ErrHostPinned; a
// key pinned for another host is refused (cloned machines share host keys
// and must be re-keyed).
func (db *DB) PinHostKey(k HostKey) (HostKey, error) {
	if !canonical.ValidHostID(k.HostID) {
		return HostKey{}, fmt.Errorf("executordb: %w: host_id %q is malformed", ErrInvalid, k.HostID)
	}
	if len(k.PublicKey) == 0 || len(k.PublicKey) > maxHostKeyLen {
		return HostKey{}, fmt.Errorf("executordb: %w: host key length %d outside 1..%d", ErrInvalid, len(k.PublicKey), maxHostKeyLen)
	}
	pk, err := ssh.ParsePublicKey(k.PublicKey)
	if err != nil {
		return HostKey{}, fmt.Errorf("executordb: %w: host key: %v", ErrInvalid, err)
	}
	if string(pk.Marshal()) != string(k.PublicKey) {
		return HostKey{}, fmt.Errorf("executordb: %w: host key is not in canonical wire format", ErrInvalid)
	}
	if err := sshtransport.CheckHostKey(pk); err != nil {
		return HostKey{}, fmt.Errorf("executordb: %w: %v", ErrInvalid, err)
	}
	if !sshUserRe.MatchString(k.User) {
		return HostKey{}, fmt.Errorf("executordb: %w: SSH user %q is not a valid user name", ErrInvalid, k.User)
	}
	if !credentialRefRe.MatchString(k.CredentialRef) {
		return HostKey{}, fmt.Errorf("executordb: %w: credential reference %q is malformed", ErrInvalid, k.CredentialRef)
	}
	if k.Source != SourceProbe && k.Source != SourceKnownHosts {
		return HostKey{}, fmt.Errorf("executordb: %w: source %q is unknown", ErrInvalid, k.Source)
	}
	if err := checkText("pinned_by", k.PinnedBy, maxActorLen, false); err != nil {
		return HostKey{}, err
	}
	k.Fingerprint = ssh.FingerprintSHA256(pk)
	k.PinnedAt = db.now().Truncate(time.Second)
	k.Blocked = nil

	tx, err := db.sql.Begin()
	if err != nil {
		return HostKey{}, fmt.Errorf("executordb: pin host key: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	var other string
	err = tx.QueryRow(`SELECT host_id FROM host_keys WHERE fingerprint = ? OR host_id = ?`, k.Fingerprint, k.HostID).Scan(&other)
	switch {
	case err == nil && other == k.HostID:
		return HostKey{}, ErrHostPinned
	case err == nil:
		return HostKey{}, fmt.Errorf("executordb: %w: key %s is already pinned for host %s", ErrInvalid, k.Fingerprint, other)
	case !errors.Is(err, sql.ErrNoRows):
		return HostKey{}, fmt.Errorf("executordb: pin host key: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO host_keys (host_id, public_key, fingerprint, ssh_user, credential_ref, source, pinned_at, pinned_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.HostID, k.PublicKey, k.Fingerprint, k.User, k.CredentialRef, k.Source, k.PinnedAt.Unix(), k.PinnedBy); err != nil {
		return HostKey{}, fmt.Errorf("executordb: pin host key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return HostKey{}, fmt.Errorf("executordb: pin host key: %w", err)
	}
	return k, nil
}

const hostKeyColumns = `host_id, public_key, fingerprint, ssh_user, credential_ref, source, pinned_at, pinned_by,
	blocked_at, blocked_fingerprint, blocked_endpoint`

type rowScanner interface{ Scan(dest ...any) error }

func scanHostKey(r rowScanner) (HostKey, error) {
	var (
		k                   HostKey
		pinnedAt            int64
		blockedAt           sql.NullInt64
		blockedFP, blockedE sql.NullString
	)
	if err := r.Scan(&k.HostID, &k.PublicKey, &k.Fingerprint, &k.User, &k.CredentialRef, &k.Source, &pinnedAt, &k.PinnedBy,
		&blockedAt, &blockedFP, &blockedE); err != nil {
		return HostKey{}, err
	}
	k.PinnedAt = time.Unix(pinnedAt, 0)
	if blockedAt.Valid {
		k.Blocked = &HostKeyBlock{At: time.Unix(blockedAt.Int64, 0), Fingerprint: blockedFP.String, Endpoint: blockedE.String}
	}
	return k, nil
}

// HostKey returns the pin of a host.
func (db *DB) HostKey(hostID string) (HostKey, bool, error) {
	k, err := scanHostKey(db.sql.QueryRow(`SELECT `+hostKeyColumns+` FROM host_keys WHERE host_id = ?`, hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return HostKey{}, false, nil
	}
	if err != nil {
		return HostKey{}, false, fmt.Errorf("executordb: host key: %w", err)
	}
	return k, true, nil
}

// ListHostKeys returns every pin, ordered by host_id.
func (db *DB) ListHostKeys() ([]HostKey, error) {
	rows, err := db.sql.Query(`SELECT ` + hostKeyColumns + ` FROM host_keys ORDER BY host_id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list host keys: %w", err)
	}
	defer rows.Close()
	var out []HostKey
	for rows.Next() {
		k, err := scanHostKey(rows)
		if err != nil {
			return nil, fmt.Errorf("executordb: list host keys: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: list host keys: %w", err)
	}
	return out, nil
}

// UnpinHostKey removes the pin of a host (and with it any block) if it is
// still pinned to fingerprint, and returns the removed record. A stale
// fingerprint returns ErrInvalid and removes nothing. A criticality record
// bound to the old key stays, but no longer matches once another key is
// pinned.
func (db *DB) UnpinHostKey(hostID, fingerprint string) (HostKey, bool, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return HostKey{}, false, fmt.Errorf("executordb: unpin host key: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	k, err := scanHostKey(tx.QueryRow(`SELECT `+hostKeyColumns+` FROM host_keys WHERE host_id = ?`, hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return HostKey{}, false, nil
	}
	if err != nil {
		return HostKey{}, false, fmt.Errorf("executordb: unpin host key: %w", err)
	}
	if k.Fingerprint != fingerprint {
		return HostKey{}, false, fmt.Errorf("executordb: %w: host %s is pinned to %s, not %s", ErrInvalid, hostID, k.Fingerprint, fingerprint)
	}
	if _, err := tx.Exec(`DELETE FROM host_keys WHERE host_id = ?`, hostID); err != nil {
		return HostKey{}, false, fmt.Errorf("executordb: unpin host key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return HostKey{}, false, fmt.Errorf("executordb: unpin host key: %w", err)
	}
	return k, true, nil
}

// BlockHost records a host key mismatch. The first block stays: a later
// mismatch does not overwrite what was seen first. It reports whether this
// call set the block.
func (db *DB) BlockHost(hostID, presentedFingerprint, endpoint string) (bool, error) {
	if len(presentedFingerprint) > 64 {
		presentedFingerprint = presentedFingerprint[:64]
	}
	endpoint = strings.ToValidUTF8(endpoint, "?")
	if len(endpoint) > maxBlockedEndpLen {
		endpoint = endpoint[:maxBlockedEndpLen]
	}
	res, err := db.sql.Exec(`UPDATE host_keys SET blocked_at = ?, blocked_fingerprint = ?, blocked_endpoint = ?
		WHERE host_id = ? AND blocked_at IS NULL`, db.now().Unix(), presentedFingerprint, endpoint, hostID)
	if err != nil {
		return false, fmt.Errorf("executordb: block host: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("executordb: block host: %w", err)
	}
	return n > 0, nil
}

// ErrRepinStale is returned by RepinHostKey when the host is no longer in
// the approved state: not pinned to the approved key, not blocked, or
// blocked by another event or key.
var ErrRepinStale = errors.New("executordb: the host is no longer in the approved state")

// RepinHostKey replaces the pin of a blocked host with newKey, in one
// transaction, only if the host is still pinned to oldFingerprint and
// blocked by exactly the approved event (blockedAt) with newKey's
// fingerprint. The host's criticality record moves to the new key, so the
// risk floor does not change. The block is cleared.
func (db *DB) RepinHostKey(hostID, oldFingerprint string, blockedAt time.Time, newKey []byte, by string) (HostKey, error) {
	pk, err := ssh.ParsePublicKey(newKey)
	if err != nil {
		return HostKey{}, fmt.Errorf("executordb: %w: host key: %v", ErrInvalid, err)
	}
	if len(newKey) > maxHostKeyLen || string(pk.Marshal()) != string(newKey) {
		return HostKey{}, fmt.Errorf("executordb: %w: host key is not in canonical wire format", ErrInvalid)
	}
	if err := sshtransport.CheckHostKey(pk); err != nil {
		return HostKey{}, fmt.Errorf("executordb: %w: %v", ErrInvalid, err)
	}
	if err := checkText("pinned_by", by, maxActorLen, false); err != nil {
		return HostKey{}, err
	}
	newFP := ssh.FingerprintSHA256(pk)
	tx, err := db.sql.Begin()
	if err != nil {
		return HostKey{}, fmt.Errorf("executordb: repin host key: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	k, err := scanHostKey(tx.QueryRow(`SELECT `+hostKeyColumns+` FROM host_keys WHERE host_id = ?`, hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return HostKey{}, ErrRepinStale
	}
	if err != nil {
		return HostKey{}, fmt.Errorf("executordb: repin host key: %w", err)
	}
	if k.Fingerprint != oldFingerprint || k.Blocked == nil || k.Blocked.At.Unix() != blockedAt.Unix() || k.Blocked.Fingerprint != newFP {
		return HostKey{}, ErrRepinStale
	}
	var other string
	err = tx.QueryRow(`SELECT host_id FROM host_keys WHERE fingerprint = ? AND host_id != ?`, newFP, hostID).Scan(&other)
	switch {
	case err == nil:
		return HostKey{}, fmt.Errorf("executordb: %w: key %s is already pinned for host %s", ErrInvalid, newFP, other)
	case !errors.Is(err, sql.ErrNoRows):
		return HostKey{}, fmt.Errorf("executordb: repin host key: %w", err)
	}
	err = tx.QueryRow(`SELECT host_id FROM host_criticality WHERE host_key_fingerprint = ? AND host_id != ?`, newFP, hostID).Scan(&other)
	switch {
	case err == nil:
		return HostKey{}, fmt.Errorf("executordb: %w: key %s is recorded for host %s", ErrInvalid, newFP, other)
	case !errors.Is(err, sql.ErrNoRows):
		return HostKey{}, fmt.Errorf("executordb: repin host key: %w", err)
	}
	now := db.now().Truncate(time.Second)
	if _, err := tx.Exec(`UPDATE host_keys SET public_key = ?, fingerprint = ?, source = ?, pinned_at = ?, pinned_by = ?,
			blocked_at = NULL, blocked_fingerprint = NULL, blocked_endpoint = NULL WHERE host_id = ?`,
		newKey, newFP, SourceProbe, now.Unix(), by, hostID); err != nil {
		return HostKey{}, fmt.Errorf("executordb: repin host key: %w", err)
	}
	if _, err := tx.Exec(`UPDATE host_criticality SET host_key_fingerprint = ?, updated_at = ?, updated_by = ?
			WHERE host_id = ? AND host_key_fingerprint = ?`, newFP, now.Unix(), by, hostID, oldFingerprint); err != nil {
		return HostKey{}, fmt.Errorf("executordb: repin host key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return HostKey{}, fmt.Errorf("executordb: repin host key: %w", err)
	}
	k.PublicKey, k.Fingerprint, k.Source, k.PinnedAt, k.PinnedBy, k.Blocked = newKey, newFP, SourceProbe, now, by, nil
	return k, nil
}

// HostByFingerprint returns the host a key is pinned for, or "".
func (db *DB) HostByFingerprint(fingerprint string) (string, error) {
	var host string
	err := db.sql.QueryRow(`SELECT host_id FROM host_keys WHERE fingerprint = ?`, fingerprint).Scan(&host)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("executordb: host by fingerprint: %w", err)
	}
	return host, nil
}

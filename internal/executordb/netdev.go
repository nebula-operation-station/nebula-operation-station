// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"modernc.org/sqlite"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Network device registry (ADR 0010 D1, ND-10). The executor alone owns a
// device's endpoint, trust pin, trust generation, block state and vault
// references. No secret is stored here: credentials and the per-device
// digest and fingerprint keys live in the executor vault and the registry
// holds only their opaque references. Endpoints are IP literals; this file
// never resolves a name.

var (
	// ErrNetDeviceNotFound is returned when a device id is not registered.
	ErrNetDeviceNotFound = errors.New("executordb: network device not found")
	// ErrNetDeviceExists is returned when a live device already has the id.
	ErrNetDeviceExists = errors.New("executordb: a network device with this id already exists")
	// ErrNetDeviceTombstoned is returned when the id was tombstoned: it can
	// never be registered again and its record can no longer change.
	ErrNetDeviceTombstoned = errors.New("executordb: the network device id is tombstoned")
	// ErrNetDeviceState is returned when the device is not in the block
	// state the operation requires.
	ErrNetDeviceState = errors.New("executordb: the network device is not in the required state")
	// ErrNetTrustIdentityInUse is returned when the trust identity (family,
	// pin kind, pin) belongs to another live device.
	ErrNetTrustIdentityInUse = errors.New("executordb: the trust identity is already registered for another network device")
	// ErrNetVaultRefInUse is returned when a vault reference is already
	// used by another device, live or tombstoned, in any role: a reference
	// belongs to one device for ever (ADR 0010 D2).
	ErrNetVaultRefInUse = errors.New("executordb: the vault reference is already used by another network device")
)

// sqliteConstraint is the primary SQLite result code of every constraint
// violation (UNIQUE, PRIMARY KEY, CHECK, trigger RAISE).
const sqliteConstraint = 19

// mapNetConstraintErr maps a SQLite uniqueness or trigger violation of the
// netdev registry to the typed error callers branch on, so a writer that
// lost a race after passing the Go pre-checks still sees ErrNetDeviceExists,
// ErrNetDeviceTombstoned, ErrNetTrustIdentityInUse or ErrNetVaultRefInUse.
// Any other error is returned unchanged.
func mapNetConstraintErr(err error) error {
	var se *sqlite.Error
	if !errors.As(err, &se) || se.Code()&0xff != sqliteConstraint {
		return err
	}
	msg := se.Error()
	var typed error
	switch {
	case strings.Contains(msg, "netdev vault reference in use"),
		strings.Contains(msg, "UNIQUE constraint failed: netdev_devices.credential_ref"),
		strings.Contains(msg, "UNIQUE constraint failed: netdev_devices.digest_key_ref"),
		strings.Contains(msg, "UNIQUE constraint failed: netdev_devices.fingerprint_key_ref"):
		typed = ErrNetVaultRefInUse
	case strings.Contains(msg, "UNIQUE constraint failed: netdev_devices.family, netdev_devices.pin_kind, netdev_devices.pin_value"):
		typed = ErrNetTrustIdentityInUse
	case strings.Contains(msg, "netdev device id is tombstoned"),
		strings.Contains(msg, "UNIQUE constraint failed: netdev_tombstones.id"):
		typed = ErrNetDeviceTombstoned
	case strings.Contains(msg, "UNIQUE constraint failed: netdev_devices.id"):
		typed = ErrNetDeviceExists
	default:
		return err
	}
	return fmt.Errorf("%w: %w", typed, err)
}

const (
	// maxNetDeviceLabel bounds a device label (CHECK in 0024).
	maxNetDeviceLabel = netdevcontract.MaxLabelBytes
	// maxNetBlockReason bounds a block reason (CHECK in 0024).
	maxNetBlockReason = 512
)

// netVaultRefRe is the shape of an opaque vault reference (CHECK in 0024).
var netVaultRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// NetDevice is the executor-owned registry record of one network device.
type NetDevice struct {
	// ID is the immutable device_id (netdevcontract.ValidDeviceID).
	ID     string
	Family netdevcontract.Family
	// Label is a display name only; it never authenticates a device and is
	// never resolved.
	Label string
	// EndpointIP is the management address as a canonical private IP
	// literal without zone (netdevcontract.ValidEndpointAddress).
	EndpointIP string
	Port       uint16
	PinKind    netdevcontract.PinKind
	// PinValue is the lowercase hex SHA-256 the device must present.
	PinValue        string
	TrustGeneration uint64
	Blocked         bool
	BlockReason     string
	// CredentialRef is the vault reference of the device credential, empty
	// while none is enrolled.
	CredentialRef string
	// DigestKeyRef and FingerprintKeyRef are the vault references of the
	// per-device HMAC keys (ADR 0010 D2); the keys never appear here.
	DigestKeyRef      string
	FingerprintKeyRef string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	// TombstonedAt is set once the device is removed; nil while live.
	TombstonedAt *time.Time
}

// validateNetDevice checks the fields every stored device must satisfy,
// on insert and on every read.
func validateNetDevice(d NetDevice) error {
	if !netdevcontract.ValidDeviceID(d.ID) {
		return fmt.Errorf("executordb: %w: network device id is malformed", ErrInvalid)
	}
	switch d.Family {
	case netdevcontract.FamilyCBS:
		if d.PinKind != netdevcontract.PinSSHHostKey {
			return fmt.Errorf("executordb: %w: cbs device %s requires pin kind %s", ErrInvalid, d.ID, netdevcontract.PinSSHHostKey)
		}
	case netdevcontract.FamilyPANOS:
		if d.PinKind != netdevcontract.PinTLSLeaf && d.PinKind != netdevcontract.PinTLSCA {
			return fmt.Errorf("executordb: %w: panos device %s requires a tls pin kind", ErrInvalid, d.ID)
		}
	default:
		return fmt.Errorf("executordb: %w: network device %s has an unknown family", ErrInvalid, d.ID)
	}
	if err := checkText("label", d.Label, maxNetDeviceLabel, true); err != nil {
		return err
	}
	if !netdevcontract.ValidEndpointAddress(d.EndpointIP) {
		return fmt.Errorf("executordb: %w: network device %s endpoint is not a canonical private IP literal", ErrInvalid, d.ID)
	}
	if d.Port == 0 {
		return fmt.Errorf("executordb: %w: network device %s port must be in 1..65535", ErrInvalid, d.ID)
	}
	if !netdevcontract.ValidTrustPin(d.PinValue) {
		return fmt.Errorf("executordb: %w: network device %s trust pin is malformed", ErrInvalid, d.ID)
	}
	if d.TrustGeneration < 1 || d.TrustGeneration > netdevcontract.MaxTrustGeneration {
		return fmt.Errorf("executordb: %w: network device %s trust generation out of range", ErrInvalid, d.ID)
	}
	if d.Blocked != (d.BlockReason != "") {
		return fmt.Errorf("executordb: %w: network device %s block flag and reason disagree", ErrInvalid, d.ID)
	}
	if d.Blocked {
		if err := checkText("block_reason", d.BlockReason, maxNetBlockReason, false); err != nil {
			return err
		}
	}
	if d.CredentialRef != "" && !netVaultRefRe.MatchString(d.CredentialRef) {
		return fmt.Errorf("executordb: %w: network device %s credential reference is malformed", ErrInvalid, d.ID)
	}
	if !netVaultRefRe.MatchString(d.DigestKeyRef) || !netVaultRefRe.MatchString(d.FingerprintKeyRef) {
		return fmt.Errorf("executordb: %w: network device %s key references are malformed", ErrInvalid, d.ID)
	}
	if d.DigestKeyRef == d.FingerprintKeyRef {
		return fmt.Errorf("executordb: %w: network device %s digest and fingerprint keys must be distinct vault entries", ErrInvalid, d.ID)
	}
	if d.CredentialRef != "" && (d.CredentialRef == d.DigestKeyRef || d.CredentialRef == d.FingerprintKeyRef) {
		return fmt.Errorf("executordb: %w: network device %s credential must be a vault entry distinct from its keys", ErrInvalid, d.ID)
	}
	return nil
}

// InsertNetDevice registers a new device at trust generation 1, unblocked.
// d.TrustGeneration must be 0 or 1; Blocked, BlockReason and TombstonedAt
// must be unset; CreatedAt and UpdatedAt are set from the injected clock.
// It refuses an id that is live (ErrNetDeviceExists) or was ever
// tombstoned (ErrNetDeviceTombstoned), and a trust identity that belongs
// to another live device (ErrNetTrustIdentityInUse).
func (db *DB) InsertNetDevice(d NetDevice) (NetDevice, error) {
	if d.TrustGeneration > 1 {
		return NetDevice{}, fmt.Errorf("executordb: %w: a new network device starts at trust generation 1", ErrInvalid)
	}
	if d.Blocked || d.BlockReason != "" || d.TombstonedAt != nil {
		return NetDevice{}, fmt.Errorf("executordb: %w: a new network device must be live and unblocked", ErrInvalid)
	}
	d.TrustGeneration = 1
	if err := validateNetDevice(d); err != nil {
		return NetDevice{}, err
	}

	tx, err := db.sql.Begin()
	if err != nil {
		return NetDevice{}, fmt.Errorf("executordb: insert network device %s: %w", d.ID, err)
	}
	defer func() { _ = tx.Rollback() }()

	var one int
	err = tx.QueryRow(`SELECT 1 FROM netdev_tombstones WHERE id = ?`, d.ID).Scan(&one)
	switch {
	case err == nil:
		return NetDevice{}, fmt.Errorf("%w: %s", ErrNetDeviceTombstoned, d.ID)
	case !errors.Is(err, sql.ErrNoRows):
		return NetDevice{}, fmt.Errorf("executordb: insert network device %s: %w", d.ID, err)
	}
	var tomb sql.NullInt64
	err = tx.QueryRow(`SELECT tombstoned_at FROM netdev_devices WHERE id = ?`, d.ID).Scan(&tomb)
	switch {
	case err == nil && tomb.Valid:
		return NetDevice{}, fmt.Errorf("%w: %s", ErrNetDeviceTombstoned, d.ID)
	case err == nil:
		return NetDevice{}, fmt.Errorf("%w: %s", ErrNetDeviceExists, d.ID)
	case !errors.Is(err, sql.ErrNoRows):
		return NetDevice{}, fmt.Errorf("executordb: insert network device %s: %w", d.ID, err)
	}
	if err := netTrustIdentityFree(tx, d.ID, d.Family, d.PinKind, d.PinValue); err != nil {
		return NetDevice{}, err
	}
	var credRef any
	if d.CredentialRef != "" {
		credRef = d.CredentialRef
	}
	if err := netVaultRefsFree(tx, credRef, d.DigestKeyRef, d.FingerprintKeyRef); err != nil {
		return NetDevice{}, err
	}

	now := db.now().Truncate(time.Second).Unix()
	if _, err := tx.Exec(`INSERT INTO netdev_devices (id, family, label, endpoint_ip, port, pin_kind, pin_value,
		trust_generation, blocked, block_reason, credential_ref, digest_key_ref, fingerprint_key_ref,
		created_at, updated_at, tombstoned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, NULL, ?, ?, ?, ?, ?, NULL)`,
		d.ID, string(d.Family), d.Label, d.EndpointIP, int64(d.Port), string(d.PinKind), d.PinValue,
		credRef, d.DigestKeyRef, d.FingerprintKeyRef, now, now); err != nil {
		return NetDevice{}, fmt.Errorf("executordb: insert network device %s: %w", d.ID, mapNetConstraintErr(err))
	}
	out, err := loadNetDevice(tx, d.ID)
	if err != nil {
		return NetDevice{}, err
	}
	if err := tx.Commit(); err != nil {
		return NetDevice{}, fmt.Errorf("executordb: insert network device %s: %w", d.ID, err)
	}
	return out, nil
}

// GetNetDevice returns the record of a device, live or tombstoned, and
// whether it exists. A stored row that fails validation is an error.
func (db *DB) GetNetDevice(id string) (NetDevice, bool, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return NetDevice{}, false, fmt.Errorf("executordb: get network device %s: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()
	d, err := loadNetDevice(tx, id)
	if errors.Is(err, ErrNetDeviceNotFound) {
		return NetDevice{}, false, nil
	}
	if err != nil {
		return NetDevice{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return NetDevice{}, false, fmt.Errorf("executordb: get network device %s: %w", id, err)
	}
	return d, true, nil
}

// ListNetDevices returns every live device ordered by id, blocked devices
// included with their flag. Any error, including one invalid stored row,
// returns no devices at all.
func (db *DB) ListNetDevices() ([]NetDevice, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("executordb: list network devices: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT ` + netDeviceColumns + ` FROM netdev_devices WHERE tombstoned_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list network devices: %w", err)
	}
	defer rows.Close()
	var out []NetDevice
	for rows.Next() {
		d, err := scanNetDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("executordb: list network devices: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: list network devices: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("executordb: list network devices: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("executordb: list network devices: %w", err)
	}
	if out == nil {
		out = []NetDevice{}
	}
	return out, nil
}

// BumpTrustGeneration replaces the trust pin of a live device with newPin
// (same pin kind) and increments its trust generation: the explicit
// re-pin of ADR 0010 D1. Revoking leases and permits bound to the old
// generation is the caller's job. A block is kept; lifting it is a
// separate, explicit UnblockNetDevice. newPin must differ from the current
// pin and must not be the trust identity of another live device.
func (db *DB) BumpTrustGeneration(id, newPin string) (NetDevice, error) {
	if !netdevcontract.ValidTrustPin(newPin) {
		return NetDevice{}, fmt.Errorf("executordb: %w: new trust pin is malformed", ErrInvalid)
	}
	return db.mutateNetDevice("re-pin", id, func(tx *sql.Tx, cur NetDevice, now int64) error {
		if newPin == cur.PinValue {
			return fmt.Errorf("executordb: %w: new trust pin equals the current pin", ErrInvalid)
		}
		if cur.TrustGeneration >= netdevcontract.MaxTrustGeneration {
			return fmt.Errorf("executordb: %w: network device %s trust generation exhausted", ErrInvalid, id)
		}
		if err := netTrustIdentityFree(tx, id, cur.Family, cur.PinKind, newPin); err != nil {
			return err
		}
		return execOne(tx, `UPDATE netdev_devices SET pin_value = ?, trust_generation = ?, updated_at = ?
			WHERE id = ? AND trust_generation = ? AND tombstoned_at IS NULL`,
			newPin, int64(cur.TrustGeneration+1), now, id, int64(cur.TrustGeneration))
	})
}

// BlockNetDevice persistently blocks a live, unblocked device with a
// reason (for example a pin mismatch). A blocked device stays registered
// and listed; emitting the event and notification is the caller's job.
func (db *DB) BlockNetDevice(id, reason string) (NetDevice, error) {
	if err := checkText("block_reason", reason, maxNetBlockReason, false); err != nil {
		return NetDevice{}, err
	}
	return db.mutateNetDevice("block", id, func(tx *sql.Tx, cur NetDevice, now int64) error {
		if cur.Blocked {
			return fmt.Errorf("%w: %s is already blocked", ErrNetDeviceState, id)
		}
		return execOne(tx, `UPDATE netdev_devices SET blocked = 1, block_reason = ?, updated_at = ?
			WHERE id = ? AND blocked = 0 AND tombstoned_at IS NULL`, reason, now, id)
	})
}

// UnblockNetDevice lifts the block of a live device; an explicit admin
// decision.
func (db *DB) UnblockNetDevice(id string) (NetDevice, error) {
	return db.mutateNetDevice("unblock", id, func(tx *sql.Tx, cur NetDevice, now int64) error {
		if !cur.Blocked {
			return fmt.Errorf("%w: %s is not blocked", ErrNetDeviceState, id)
		}
		return execOne(tx, `UPDATE netdev_devices SET blocked = 0, block_reason = NULL, updated_at = ?
			WHERE id = ? AND blocked = 1 AND tombstoned_at IS NULL`, now, id)
	})
}

// TombstoneNetDevice removes a live device. Its row stays readable with
// TombstonedAt set but can never change again, its id is reserved forever
// in netdev_tombstones, and its trust identity is released. The vault
// references stay on the row so the caller can delete the vault entries.
func (db *DB) TombstoneNetDevice(id string) (NetDevice, error) {
	return db.mutateNetDevice("tombstone", id, func(tx *sql.Tx, _ NetDevice, now int64) error {
		if _, err := tx.Exec(`INSERT INTO netdev_tombstones (id, tombstoned_at) VALUES (?, ?)`, id, now); err != nil {
			return fmt.Errorf("executordb: tombstone network device %s: %w", id, mapNetConstraintErr(err))
		}
		return execOne(tx, `UPDATE netdev_devices SET tombstoned_at = ?, updated_at = ?
			WHERE id = ? AND tombstoned_at IS NULL`, now, now, id)
	})
}

// mutateNetDevice runs change on the current, validated record of a live
// device inside one transaction and returns the record after the change.
// Nothing is committed unless every step succeeds.
func (db *DB) mutateNetDevice(op, id string, change func(tx *sql.Tx, cur NetDevice, now int64) error) (NetDevice, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return NetDevice{}, fmt.Errorf("executordb: %s network device %s: %w", op, id, err)
	}
	defer func() { _ = tx.Rollback() }()
	cur, err := loadNetDevice(tx, id)
	if err != nil {
		return NetDevice{}, err
	}
	if cur.TombstonedAt != nil {
		return NetDevice{}, fmt.Errorf("%w: %s", ErrNetDeviceTombstoned, id)
	}
	if err := change(tx, cur, db.now().Truncate(time.Second).Unix()); err != nil {
		return NetDevice{}, err
	}
	out, err := loadNetDevice(tx, id)
	if err != nil {
		return NetDevice{}, err
	}
	if err := tx.Commit(); err != nil {
		return NetDevice{}, fmt.Errorf("executordb: %s network device %s: %w", op, id, err)
	}
	return out, nil
}

// execOne runs an update that must change exactly one row.
func execOne(tx *sql.Tx, query string, args ...any) error {
	res, err := tx.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("executordb: update network device: %w", mapNetConstraintErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("executordb: update network device: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("executordb: update network device: %d rows changed, want 1", n)
	}
	return nil
}

// netTrustIdentityFree returns ErrNetTrustIdentityInUse if a live device
// other than id holds the trust identity.
func netTrustIdentityFree(tx *sql.Tx, id string, family netdevcontract.Family, kind netdevcontract.PinKind, pin string) error {
	var other string
	err := tx.QueryRow(`SELECT id FROM netdev_devices
		WHERE family = ? AND pin_kind = ? AND pin_value = ? AND tombstoned_at IS NULL AND id <> ?`,
		string(family), string(kind), pin, id).Scan(&other)
	switch {
	case err == nil:
		return fmt.Errorf("%w: held by %s", ErrNetTrustIdentityInUse, other)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("executordb: network device trust identity: %w", err)
	}
	return nil
}

// netVaultRefsFree returns ErrNetVaultRefInUse if any of the given vault
// references (credRef may be nil) is used by any device, live or
// tombstoned, in any role.
func netVaultRefsFree(tx *sql.Tx, credRef any, digestRef, fingerprintRef string) error {
	var other string
	err := tx.QueryRow(`SELECT id FROM netdev_devices
		WHERE digest_key_ref IN (?1, ?2, ?3)
		   OR fingerprint_key_ref IN (?1, ?2, ?3)
		   OR credential_ref IN (?1, ?2, ?3)
		ORDER BY id LIMIT 1`, credRef, digestRef, fingerprintRef).Scan(&other)
	switch {
	case err == nil:
		return fmt.Errorf("%w: held by %s", ErrNetVaultRefInUse, other)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("executordb: network device vault references: %w", err)
	}
	return nil
}

const netDeviceColumns = `id, family, label, endpoint_ip, port, pin_kind, pin_value, trust_generation,
	blocked, block_reason, credential_ref, digest_key_ref, fingerprint_key_ref, created_at, updated_at, tombstoned_at`

// loadNetDevice reads one device in tx; ErrNetDeviceNotFound if absent.
func loadNetDevice(tx *sql.Tx, id string) (NetDevice, error) {
	d, err := scanNetDevice(tx.QueryRow(`SELECT `+netDeviceColumns+` FROM netdev_devices WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return NetDevice{}, fmt.Errorf("%w: %s", ErrNetDeviceNotFound, id)
	}
	if err != nil {
		return NetDevice{}, fmt.Errorf("executordb: load network device %s: %w", id, err)
	}
	return d, nil
}

// scanNetDevice reads one row and validates it; a row that breaks the
// registry invariants is refused rather than returned.
func scanNetDevice(r rowScanner) (NetDevice, error) {
	var (
		d                  NetDevice
		family, kind       string
		port, gen, blocked int64
		reason, credRef    sql.NullString
		created, updated   int64
		tombstoned         sql.NullInt64
	)
	if err := r.Scan(&d.ID, &family, &d.Label, &d.EndpointIP, &port, &kind, &d.PinValue, &gen,
		&blocked, &reason, &credRef, &d.DigestKeyRef, &d.FingerprintKeyRef, &created, &updated, &tombstoned); err != nil {
		return NetDevice{}, err
	}
	if port < 1 || port > 65535 || gen < 1 || (blocked != 0 && blocked != 1) {
		return NetDevice{}, fmt.Errorf("%w: stored network device %s is out of range", ErrInvalid, d.ID)
	}
	d.Family = netdevcontract.Family(family)
	d.PinKind = netdevcontract.PinKind(kind)
	d.Port = uint16(port)
	d.TrustGeneration = uint64(gen)
	d.Blocked = blocked == 1
	d.BlockReason = reason.String
	d.CredentialRef = credRef.String
	d.CreatedAt = time.Unix(created, 0)
	d.UpdatedAt = time.Unix(updated, 0)
	if tombstoned.Valid {
		at := time.Unix(tombstoned.Int64, 0)
		d.TombstonedAt = &at
	}
	if err := validateNetDevice(d); err != nil {
		return NetDevice{}, fmt.Errorf("stored network device %s: %w", d.ID, err)
	}
	return d, nil
}

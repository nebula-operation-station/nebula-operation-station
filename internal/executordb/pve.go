// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// PVE remote states (ADR 0006: active, blocked, removed).
const (
	StateActive  = "active"
	StateBlocked = "blocked"
	StateRemoved = "removed"
)

// PVE trust pin kinds: which certificate the pin identifies.
const (
	PinKindCA   = "ca"   // cluster CA certificate (kind cluster)
	PinKindLeaf = "leaf" // served leaf certificate (kind standalone)
)

// PVE remote change types recorded in the append-only trail.
const (
	ChangeCreated        = "created"
	ChangeReAdded        = "re_added"
	ChangeEndpointChange = "endpoint_change"
	ChangeTrustRepin     = "trust_repin"
	ChangeBlocked        = "blocked"
	ChangeUnblocked      = "unblocked"
	ChangeCredentials    = "credentials"
	ChangeRemoved        = "removed"
)

var (
	// ErrRemoteNotFound is returned when a remote id is not in the registry.
	ErrRemoteNotFound = errors.New("executordb: pve remote not found")
	// ErrRemoteExists is returned when the id exists and is not a tombstone.
	ErrRemoteExists = errors.New("executordb: a pve remote with this id already exists")
	// ErrRemoteTombstoned is returned when a removed id is re-added under a
	// different trust identity.
	ErrRemoteTombstoned = errors.New("executordb: the pve remote id is tombstoned under a different trust identity")
	// ErrRemoteState is returned when the remote is not in the state the
	// operation requires.
	ErrRemoteState = errors.New("executordb: the pve remote is not in the required state")
	// ErrTrustPinInUse is returned when the trust identity is registered
	// for another remote, including tombstones.
	ErrTrustPinInUse = errors.New("executordb: the trust identity is already registered for another remote")
)

const (
	maxPveRemoteName    = pvecontract.MaxLabelBytes
	maxPveBlockedReason = 512
	maxPveChangeDetail  = 512
)

var pveCredentialRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// PveRemoteCredentials holds opaque vault references only. Secret values
// live in the vault (spec 06) and never in this registry; an empty ref
// with version 0 means "no credential of this kind registered".
type PveRemoteCredentials struct {
	ReadRef       string
	ReadVersion   int64
	ActionRef     string
	ActionVersion int64
}

// PveRemote is the executor-owned identity of one PVE cluster or
// standalone host, as stored in the registry (ADR 0006).
type PveRemote struct {
	RemoteID        string
	Name            string
	Kind            pvecontract.Kind
	Endpoints       []pvecontract.Endpoint
	TrustPinKind    string
	TrustPin        string
	TrustGeneration uint64
	State           string
	BlockedAt       *time.Time
	BlockedBy       string
	BlockedReason   string
	RemovedAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	UpdatedBy       string
	Credentials     PveRemoteCredentials
}

// PveRemoteChange is one entry of the append-only change trail. Detail is
// structured, nonsecret text.
type PveRemoteChange struct {
	RemoteID   string
	ChangeType string
	Detail     string
	Actor      string
	At         time.Time
}

func pvePinKind(kind pvecontract.Kind) (string, error) {
	switch kind {
	case pvecontract.KindCluster:
		return PinKindCA, nil
	case pvecontract.KindStandalone:
		return PinKindLeaf, nil
	}
	return "", fmt.Errorf("executordb: %w: pve kind %q is unknown", ErrInvalid, kind)
}

func validatePveCredentials(field, ref string, version int64) error {
	switch {
	case ref == "":
		if version != 0 {
			return fmt.Errorf("executordb: %w: pve %s credential version %d without a reference", ErrInvalid, field, version)
		}
		return nil
	case !pveCredentialRefRe.MatchString(ref):
		return fmt.Errorf("executordb: %w: pve %s credential reference %q is malformed", ErrInvalid, field, ref)
	case version < 1:
		return fmt.Errorf("executordb: %w: pve %s credential version %d outside 1..max", ErrInvalid, field, version)
	}
	return nil
}

// AddRemote registers a new PVE remote, or explicitly re-adds a
// tombstoned one.
//
// r is validated with pvecontract; a new remote must start at trust
// generation 1. The trust identity (pin) must not be registered for
// another remote, including tombstones. A tombstoned remote_id may only be
// re-added under the same trust identity; that re-add is the explicit
// operation the ADR requires, returns the remote to active and continues
// the trust generation. creds holds opaque vault references only.
func (db *DB) AddRemote(r pvecontract.Remote, creds PveRemoteCredentials, by string) (PveRemote, error) {
	v, err := pvecontract.ValidateRemote(r)
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: %w: %v", ErrInvalid, err)
	}
	if v.TrustGeneration != 1 {
		return PveRemote{}, fmt.Errorf("executordb: %w: a new pve remote must start at trust generation 1, got %d", ErrInvalid, v.TrustGeneration)
	}
	pinKind, err := pvePinKind(v.Kind)
	if err != nil {
		return PveRemote{}, err
	}
	if err := checkText("name", v.Name, maxPveRemoteName, true); err != nil {
		return PveRemote{}, err
	}
	if err := validatePveCredentials("read", creds.ReadRef, creds.ReadVersion); err != nil {
		return PveRemote{}, err
	}
	if err := validatePveCredentials("action", creds.ActionRef, creds.ActionVersion); err != nil {
		return PveRemote{}, err
	}
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return PveRemote{}, err
	}

	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: add pve remote: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		exists  bool
		state   string
		tombPin string
		tombGen int64
	)
	err = tx.QueryRow(`SELECT state, trust_pin, trust_generation FROM pve_remotes WHERE remote_id = ?`, v.RemoteID).
		Scan(&state, &tombPin, &tombGen)
	switch {
	case err == nil:
		exists = true
	case !errors.Is(err, sql.ErrNoRows):
		return PveRemote{}, fmt.Errorf("executordb: add pve remote: %w", err)
	}

	var gen int64
	if exists {
		if state != StateRemoved {
			return PveRemote{}, fmt.Errorf("%w: id %s is %s", ErrRemoteExists, v.RemoteID, state)
		}
		// Explicit re-add: the tombstone's trust identity must match.
		if v.TrustPin != tombPin {
			return PveRemote{}, fmt.Errorf("%w: id %s was removed under a different trust identity", ErrRemoteTombstoned, v.RemoteID)
		}
		gen = tombGen + 1
	} else {
		var other string
		err = tx.QueryRow(`SELECT remote_id FROM pve_remotes WHERE trust_pin = ?`, v.TrustPin).Scan(&other)
		switch {
		case err == nil:
			return PveRemote{}, fmt.Errorf("%w: %s is registered for %s", ErrTrustPinInUse, v.TrustPin, other)
		case !errors.Is(err, sql.ErrNoRows):
			return PveRemote{}, fmt.Errorf("executordb: add pve remote: %w", err)
		}
		gen = 1
	}
	if gen > int64(pvecontract.MaxTrustGeneration) {
		return PveRemote{}, fmt.Errorf("executordb: %w: pve trust generation %d out of range", ErrInvalid, gen)
	}

	now := db.now().Truncate(time.Second)
	var (
		remote PveRemote
	)
	if exists {
		if _, err := tx.Exec(`UPDATE pve_remotes SET name = ?, kind = ?, trust_pin_kind = ?, trust_generation = ?, state = ?,
			read_credential_ref = ?, read_credential_version = ?, action_credential_ref = ?, action_credential_version = ?,
			blocked_at = NULL, blocked_by = NULL, blocked_reason = NULL, removed_at = NULL,
			updated_at = ?, updated_by = ? WHERE remote_id = ?`,
			v.Name, string(v.Kind), pinKind, gen, StateActive,
			creds.ReadRef, creds.ReadVersion, creds.ActionRef, creds.ActionVersion,
			now.Unix(), by, v.RemoteID); err != nil {
			return PveRemote{}, fmt.Errorf("executordb: re-add pve remote: %w", err)
		}
	} else {
		if _, err := tx.Exec(`INSERT INTO pve_remotes (remote_id, name, kind, trust_pin_kind, trust_pin, trust_generation, state,
			read_credential_ref, read_credential_version, action_credential_ref, action_credential_version,
			created_at, updated_at, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			v.RemoteID, v.Name, string(v.Kind), pinKind, v.TrustPin, gen, StateActive,
			creds.ReadRef, creds.ReadVersion, creds.ActionRef, creds.ActionVersion,
			now.Unix(), now.Unix(), by); err != nil {
			return PveRemote{}, fmt.Errorf("executordb: add pve remote: %w", err)
		}
	}
	if err := db.setPveEndpoints(tx, v.RemoteID, v.Endpoints); err != nil {
		return PveRemote{}, err
	}
	changeType := ChangeCreated
	if exists {
		changeType = ChangeReAdded
	}
	if err := db.logPveChange(tx, v.RemoteID, changeType,
		fmt.Sprintf("pin=%s gen=%d endpoints=%d", v.TrustPin, gen, len(v.Endpoints)), by, now); err != nil {
		return PveRemote{}, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: add pve remote: %w", err)
	}
	remote, _, err = db.GetRemote(v.RemoteID)
	return remote, err
}

// GetRemote returns the registry record of a remote in any state,
// including tombstones.
func (db *DB) GetRemote(remoteID string) (PveRemote, bool, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, false, fmt.Errorf("executordb: get pve remote: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE remote_id = ?`, remoteID))
	if errors.Is(err, sql.ErrNoRows) {
		return PveRemote{}, false, nil
	}
	if err != nil {
		return PveRemote{}, false, fmt.Errorf("executordb: get pve remote: %w", err)
	}
	if err := db.loadPveEndpoints(tx, &rm); err != nil {
		return PveRemote{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, false, fmt.Errorf("executordb: get pve remote: %w", err)
	}
	return rm, true, nil
}

// ListRemotes returns every registry record, including tombstones,
// ordered by remote_id.
func (db *DB) ListRemotes() ([]PveRemote, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("executordb: list pve remotes: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT ` + pveRemoteColumns + ` FROM pve_remotes ORDER BY remote_id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list pve remotes: %w", err)
	}
	var out []PveRemote
	for rows.Next() {
		rm, err := scanPveRemote(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("executordb: list pve remotes: %w", err)
		}
		out = append(out, rm)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("executordb: list pve remotes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("executordb: list pve remotes: %w", err)
	}
	// Endpoints are loaded only after the list rows are closed: the
	// database runs on a single connection.
	for i := range out {
		if err := db.loadPveEndpoints(tx, &out[i]); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("executordb: list pve remotes: %w", err)
	}
	return out, nil
}

// RemoteByTrustPin returns the remote whose current trust identity is
// pin, in any state, or ("", false, nil) if no remote has it.
func (db *DB) RemoteByTrustPin(pin string) (PveRemote, bool, error) {
	if !pvecontract.ValidTrustPin(pin) {
		return PveRemote{}, false, nil
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, false, fmt.Errorf("executordb: pve remote by pin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE trust_pin = ?`, pin))
	if errors.Is(err, sql.ErrNoRows) {
		return PveRemote{}, false, nil
	}
	if err != nil {
		return PveRemote{}, false, fmt.Errorf("executordb: pve remote by pin: %w", err)
	}
	if err := db.loadPveEndpoints(tx, &rm); err != nil {
		return PveRemote{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, false, fmt.Errorf("executordb: pve remote by pin: %w", err)
	}
	return rm, true, nil
}

// BlockRemote persistently blocks an active remote (ADR 0006: a changed
// pin, an invalid chain or a SAN mismatch blocks the whole remote and
// stops failover). The first block is recorded with reason and actor;
// emitting the executor event and the notification is the caller's job.
func (db *DB) BlockRemote(remoteID, reason, by string) (PveRemote, error) {
	if err := checkText("blocked_reason", reason, maxPveBlockedReason, false); err != nil {
		return PveRemote{}, err
	}
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return PveRemote{}, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: block pve remote: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := db.now().Truncate(time.Second)
	res, err := tx.Exec(`UPDATE pve_remotes SET state = ?, blocked_at = ?, blocked_by = ?, blocked_reason = ?,
		updated_at = ?, updated_by = ? WHERE remote_id = ? AND state = ?`,
		StateBlocked, now.Unix(), by, reason, now.Unix(), by, remoteID, StateActive)
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: block pve remote: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return PveRemote{}, db.pveRemoteStateError(tx, remoteID, StateActive)
	}
	if err := db.logPveChange(tx, remoteID, ChangeBlocked, reason, by, now); err != nil {
		return PveRemote{}, err
	}
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE remote_id = ?`, remoteID))
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: block pve remote: %w", err)
	}
	if err := db.loadPveEndpoints(tx, &rm); err != nil {
		return PveRemote{}, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: block pve remote: %w", err)
	}
	return rm, nil
}

// UnblockRemote clears a block set by BlockRemote. It is an explicit
// admin decision; a re-pin does not imply it.
func (db *DB) UnblockRemote(remoteID, by string) (PveRemote, error) {
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return PveRemote{}, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: unblock pve remote: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := db.now().Truncate(time.Second)
	res, err := tx.Exec(`UPDATE pve_remotes SET state = ?, blocked_at = NULL, blocked_by = NULL, blocked_reason = NULL,
		updated_at = ?, updated_by = ? WHERE remote_id = ? AND state = ?`,
		StateActive, now.Unix(), by, remoteID, StateBlocked)
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: unblock pve remote: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return PveRemote{}, db.pveRemoteStateError(tx, remoteID, StateBlocked)
	}
	if err := db.logPveChange(tx, remoteID, ChangeUnblocked, "", by, now); err != nil {
		return PveRemote{}, err
	}
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE remote_id = ?`, remoteID))
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: unblock pve remote: %w", err)
	}
	if err := db.loadPveEndpoints(tx, &rm); err != nil {
		return PveRemote{}, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: unblock pve remote: %w", err)
	}
	return rm, nil
}

// RepinRemote replaces the trust pin of a remote with newPin, an explicit
// admin operation that increments the trust generation (ADR 0006). It
// requires the current pin (oldPin), works on active and blocked remotes,
// and on a blocked remote also clears the block: re-pin is the recovery
// path after a pin mismatch. Re-pinning to the same pin is refused. The
// new pin must not be the trust identity of another remote.
func (db *DB) RepinRemote(remoteID, oldPin, newPin, by string) (PveRemote, error) {
	if !pvecontract.ValidTrustPin(newPin) {
		return PveRemote{}, fmt.Errorf("executordb: %w: pve new trust pin is malformed", ErrInvalid)
	}
	if oldPin == newPin {
		return PveRemote{}, fmt.Errorf("executordb: %w: pve new trust pin equals the current pin", ErrInvalid)
	}
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return PveRemote{}, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: repin pve remote: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE remote_id = ?`, remoteID))
	if errors.Is(err, sql.ErrNoRows) {
		return PveRemote{}, fmt.Errorf("%w: %s", ErrRemoteNotFound, remoteID)
	}
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: repin pve remote: %w", err)
	}
	if rm.State == StateRemoved {
		return PveRemote{}, fmt.Errorf("%w: %s is removed", ErrRemoteState, remoteID)
	}
	if rm.TrustPin != oldPin {
		return PveRemote{}, fmt.Errorf("executordb: %w: %s is pinned to %s, not %s", ErrInvalid, remoteID, rm.TrustPin, oldPin)
	}
	if rm.TrustGeneration >= pvecontract.MaxTrustGeneration {
		return PveRemote{}, fmt.Errorf("executordb: %w: pve trust generation %d out of range", ErrInvalid, rm.TrustGeneration)
	}
	var other string
	err = tx.QueryRow(`SELECT remote_id FROM pve_remotes WHERE trust_pin = ? AND remote_id != ?`, newPin, remoteID).Scan(&other)
	switch {
	case err == nil:
		return PveRemote{}, fmt.Errorf("%w: %s is registered for %s", ErrTrustPinInUse, newPin, other)
	case !errors.Is(err, sql.ErrNoRows):
		return PveRemote{}, fmt.Errorf("executordb: repin pve remote: %w", err)
	}
	newGen := rm.TrustGeneration + 1
	state := rm.State
	if state == StateBlocked {
		state = StateActive
	}
	now := db.now().Truncate(time.Second)
	if _, err := tx.Exec(`UPDATE pve_remotes SET trust_pin = ?, trust_generation = ?, state = ?,
		blocked_at = NULL, blocked_by = NULL, blocked_reason = NULL, updated_at = ?, updated_by = ? WHERE remote_id = ?`,
		newPin, newGen, state, now.Unix(), by, remoteID); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: repin pve remote: %w", err)
	}
	if err := db.logPveChange(tx, remoteID, ChangeTrustRepin,
		fmt.Sprintf("from=%s to=%s gen=%d", oldPin, newPin, newGen), by, now); err != nil {
		return PveRemote{}, err
	}
	if err := db.loadPveEndpoints(tx, &rm); err != nil {
		return PveRemote{}, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: repin pve remote: %w", err)
	}
	rm.TrustPin = newPin
	rm.TrustGeneration = newGen
	rm.State = state
	rm.BlockedAt = nil
	rm.BlockedBy = ""
	rm.BlockedReason = ""
	rm.UpdatedAt = now
	rm.UpdatedBy = by
	return rm, nil
}

// SetEndpoints replaces the ordered endpoints of an active remote and
// records the change. The new set is validated with pvecontract against
// the remote's kind (a standalone remote keeps exactly one endpoint).
func (db *DB) SetEndpoints(remoteID string, eps []pvecontract.Endpoint, by string) (PveRemote, error) {
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return PveRemote{}, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote endpoints: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE remote_id = ?`, remoteID))
	if errors.Is(err, sql.ErrNoRows) {
		return PveRemote{}, fmt.Errorf("%w: %s", ErrRemoteNotFound, remoteID)
	}
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote endpoints: %w", err)
	}
	if rm.State != StateActive {
		return PveRemote{}, fmt.Errorf("%w: %s is %s", ErrRemoteState, remoteID, rm.State)
	}
	if _, err := pvecontract.ValidateRemote(pvecontract.Remote{
		RemoteID: rm.RemoteID, Name: rm.Name, Kind: rm.Kind,
		Endpoints: eps, TrustPin: rm.TrustPin, TrustGeneration: rm.TrustGeneration,
	}); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: %w: %v", ErrInvalid, err)
	}
	if err := db.setPveEndpoints(tx, remoteID, eps); err != nil {
		return PveRemote{}, err
	}
	now := db.now().Truncate(time.Second)
	if _, err := tx.Exec(`UPDATE pve_remotes SET updated_at = ?, updated_by = ? WHERE remote_id = ?`, now.Unix(), by, remoteID); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote endpoints: %w", err)
	}
	if err := db.logPveChange(tx, remoteID, ChangeEndpointChange,
		fmt.Sprintf("endpoints=%d", len(eps)), by, now); err != nil {
		return PveRemote{}, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote endpoints: %w", err)
	}
	rm.Endpoints = eps
	rm.UpdatedAt = now
	rm.UpdatedBy = by
	return rm, nil
}

// RemoveRemote tombstones a remote (ADR 0006): it is disabled and its id
// and trust identity stay reserved. The record, endpoints and change
// trail are kept as nonsecret audit data. Revoking the remote's
// authorizations and removing its vault secrets are the caller's job and
// happen before this call is used.
func (db *DB) RemoveRemote(remoteID, by string) (PveRemote, error) {
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return PveRemote{}, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: remove pve remote: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE remote_id = ?`, remoteID))
	if errors.Is(err, sql.ErrNoRows) {
		return PveRemote{}, fmt.Errorf("%w: %s", ErrRemoteNotFound, remoteID)
	}
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: remove pve remote: %w", err)
	}
	if rm.State == StateRemoved {
		return PveRemote{}, fmt.Errorf("%w: %s is removed", ErrRemoteState, remoteID)
	}
	now := db.now().Truncate(time.Second)
	if _, err := tx.Exec(`UPDATE pve_remotes SET state = ?, removed_at = ?, updated_at = ?, updated_by = ? WHERE remote_id = ?`,
		StateRemoved, now.Unix(), now.Unix(), by, remoteID); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: remove pve remote: %w", err)
	}
	if err := db.logPveChange(tx, remoteID, ChangeRemoved, "", by, now); err != nil {
		return PveRemote{}, err
	}
	if err := db.loadPveEndpoints(tx, &rm); err != nil {
		return PveRemote{}, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: remove pve remote: %w", err)
	}
	rm.State = StateRemoved
	rm.RemovedAt = &now
	rm.UpdatedAt = now
	rm.UpdatedBy = by
	return rm, nil
}

// SetRemoteCredentials atomically changes the opaque credential
// references of an active remote (rotation, spec 06). Secret values are
// never accepted here; they live in the vault.
func (db *DB) SetRemoteCredentials(remoteID string, creds PveRemoteCredentials, by string) (PveRemote, error) {
	return db.setRemoteCredentials(remoteID, creds, by, nil, nil)
}

// RotateRemoteSecret commits an encrypted vault secret and its registry
// version together. Stale remote trust or credentials reject the whole write.
func (db *DB) RotateRemoteSecret(expected PveRemote, purpose string, secret VaultSecret, by string) (PveRemote, error) {
	creds := expected.Credentials
	var ref string
	var version int64
	switch purpose {
	case "read":
		ref, version = creds.ReadRef, creds.ReadVersion
		creds.ReadRef, creds.ReadVersion = secret.ID, secret.Version
	case "action":
		ref, version = creds.ActionRef, creds.ActionVersion
		creds.ActionRef, creds.ActionVersion = secret.ID, secret.Version
	default:
		return PveRemote{}, ErrInvalid
	}
	if (ref != "" && ref != secret.ID) || secret.Version != version+1 || len(secret.WrappedDEK) == 0 || len(secret.Sealed) == 0 {
		return PveRemote{}, ErrSecretVersion
	}
	return db.setRemoteCredentials(expected.RemoteID, creds, by, &expected, &secret)
}

func (db *DB) setRemoteCredentials(remoteID string, creds PveRemoteCredentials, by string, expected *PveRemote, secret *VaultSecret) (PveRemote, error) {
	if err := validatePveCredentials("read", creds.ReadRef, creds.ReadVersion); err != nil {
		return PveRemote{}, err
	}
	if err := validatePveCredentials("action", creds.ActionRef, creds.ActionVersion); err != nil {
		return PveRemote{}, err
	}
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return PveRemote{}, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote credentials: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rm, err := scanPveRemote(tx.QueryRow(`SELECT `+pveRemoteColumns+` FROM pve_remotes WHERE remote_id = ?`, remoteID))
	if errors.Is(err, sql.ErrNoRows) {
		return PveRemote{}, fmt.Errorf("%w: %s", ErrRemoteNotFound, remoteID)
	}
	if err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote credentials: %w", err)
	}
	if rm.State != StateActive {
		return PveRemote{}, fmt.Errorf("%w: %s is %s", ErrRemoteState, remoteID, rm.State)
	}
	if expected != nil && (rm.TrustPin != expected.TrustPin || rm.TrustGeneration != expected.TrustGeneration || rm.Credentials != expected.Credentials) {
		return PveRemote{}, ErrSecretVersion
	}
	now := db.now().Truncate(time.Second)
	if secret != nil {
		if err := putSecret(tx, *secret, now); err != nil {
			return PveRemote{}, err
		}
	}
	if _, err := tx.Exec(`UPDATE pve_remotes SET read_credential_ref = ?, read_credential_version = ?,
		action_credential_ref = ?, action_credential_version = ?, updated_at = ?, updated_by = ? WHERE remote_id = ?`,
		creds.ReadRef, creds.ReadVersion, creds.ActionRef, creds.ActionVersion, now.Unix(), by, remoteID); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote credentials: %w", err)
	}
	if err := db.logPveChange(tx, remoteID, ChangeCredentials,
		fmt.Sprintf("read=%s@%d action=%s@%d", creds.ReadRef, creds.ReadVersion, creds.ActionRef, creds.ActionVersion), by, now); err != nil {
		return PveRemote{}, err
	}
	if err := db.loadPveEndpoints(tx, &rm); err != nil {
		return PveRemote{}, err
	}
	if err := tx.Commit(); err != nil {
		return PveRemote{}, fmt.Errorf("executordb: pve remote credentials: %w", err)
	}
	rm.Credentials = creds
	rm.UpdatedAt = now
	rm.UpdatedBy = by
	return rm, nil
}

// RemoteChanges returns the append-only change trail of a remote, oldest
// first.
func (db *DB) RemoteChanges(remoteID string) ([]PveRemoteChange, error) {
	rows, err := db.sql.Query(`SELECT remote_id, change_type, detail, actor, at
		FROM pve_remote_changes WHERE remote_id = ? ORDER BY id`, remoteID)
	if err != nil {
		return nil, fmt.Errorf("executordb: pve remote changes: %w", err)
	}
	defer rows.Close()
	var out []PveRemoteChange
	for rows.Next() {
		var c PveRemoteChange
		var at int64
		if err := rows.Scan(&c.RemoteID, &c.ChangeType, &c.Detail, &c.Actor, &at); err != nil {
			return nil, fmt.Errorf("executordb: pve remote changes: %w", err)
		}
		c.At = time.Unix(at, 0)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: pve remote changes: %w", err)
	}
	return out, nil
}

const pveRemoteColumns = `remote_id, name, kind, trust_pin_kind, trust_pin, trust_generation, state,
	read_credential_ref, read_credential_version, action_credential_ref, action_credential_version,
	blocked_at, blocked_by, blocked_reason, removed_at, created_at, updated_at, updated_by`

func scanPveRemote(r rowScanner) (PveRemote, error) {
	var (
		rm            PveRemote
		kind, pinKind string
		gen           int64
		blockedAt     sql.NullInt64
		blockedBy     sql.NullString
		blockedReason sql.NullString
		removedAt     sql.NullInt64
		created, up   int64
	)
	if err := r.Scan(&rm.RemoteID, &rm.Name, &kind, &pinKind, &rm.TrustPin, &gen, &rm.State,
		&rm.Credentials.ReadRef, &rm.Credentials.ReadVersion, &rm.Credentials.ActionRef, &rm.Credentials.ActionVersion,
		&blockedAt, &blockedBy, &blockedReason, &removedAt, &created, &up, &rm.UpdatedBy); err != nil {
		return PveRemote{}, err
	}
	rm.Kind = pvecontract.Kind(kind)
	rm.TrustPinKind = pinKind
	rm.TrustGeneration = uint64(gen)
	rm.CreatedAt = time.Unix(created, 0)
	rm.UpdatedAt = time.Unix(up, 0)
	if blockedAt.Valid {
		at := time.Unix(blockedAt.Int64, 0)
		rm.BlockedAt = &at
		rm.BlockedBy = blockedBy.String
		rm.BlockedReason = blockedReason.String
	}
	if removedAt.Valid {
		at := time.Unix(removedAt.Int64, 0)
		rm.RemovedAt = &at
	}
	return rm, nil
}

func (db *DB) loadPveEndpoints(tx *sql.Tx, rm *PveRemote) error {
	rows, err := tx.Query(`SELECT host, port FROM pve_remote_endpoints WHERE remote_id = ? ORDER BY seq`, rm.RemoteID)
	if err != nil {
		return fmt.Errorf("executordb: pve remote endpoints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ep pvecontract.Endpoint
		if err := rows.Scan(&ep.Host, &ep.Port); err != nil {
			return fmt.Errorf("executordb: pve remote endpoints: %w", err)
		}
		rm.Endpoints = append(rm.Endpoints, ep)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("executordb: pve remote endpoints: %w", err)
	}
	return nil
}

func (db *DB) setPveEndpoints(tx *sql.Tx, remoteID string, eps []pvecontract.Endpoint) error {
	if _, err := tx.Exec(`DELETE FROM pve_remote_endpoints WHERE remote_id = ?`, remoteID); err != nil {
		return fmt.Errorf("executordb: pve remote endpoints: %w", err)
	}
	for i, ep := range eps {
		if _, err := tx.Exec(`INSERT INTO pve_remote_endpoints (remote_id, seq, host, port) VALUES (?, ?, ?, ?)`,
			remoteID, i+1, ep.Host, ep.Port); err != nil {
			return fmt.Errorf("executordb: pve remote endpoints: %w", err)
		}
	}
	return nil
}

func (db *DB) logPveChange(tx *sql.Tx, remoteID, changeType, detail, by string, at time.Time) error {
	detail = strings.ToValidUTF8(detail, "?")
	if len(detail) > maxPveChangeDetail {
		detail = detail[:maxPveChangeDetail]
	}
	if _, err := tx.Exec(`INSERT INTO pve_remote_changes (remote_id, change_type, detail, actor, at) VALUES (?, ?, ?, ?, ?)`,
		remoteID, changeType, detail, by, at.Unix()); err != nil {
		return fmt.Errorf("executordb: pve remote change: %w", err)
	}
	return nil
}

// pveRemoteStateError reports ErrRemoteNotFound or ErrRemoteState for a
// remote that is missing or not in want. It queries through the caller's
// transaction: the database runs on a single connection, so a query on
// db.sql while a transaction is open would deadlock.
func (db *DB) pveRemoteStateError(tx *sql.Tx, remoteID, want string) error {
	var state string
	err := tx.QueryRow(`SELECT state FROM pve_remotes WHERE remote_id = ?`, remoteID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrRemoteNotFound, remoteID)
	}
	if err != nil {
		return fmt.Errorf("executordb: pve remote state: %w", err)
	}
	return fmt.Errorf("%w: %s is %s, want %s", ErrRemoteState, remoteID, state, want)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netdevinventory persists validated network device observations
// (internal/netdevcontract) in the server database (ADR 0010 D4, plan
// ND-16).
//
// These tables are presentation copies only: the executor owns device
// identity, trust pins and credentials. The unit of storage is a dataset:
// one read (facts, ports, VLANs, MAC table, LLDP neighbors, firewall
// policy, hit counts) of one device at one observed_at. Rules:
//
//   - a dataset is replaced atomically: the new dataset and all its typed
//     rows are written in one transaction, or nothing changes;
//   - a dataset older than (or as old as, with other content) the stored
//     one is refused, so a delayed spool can never roll data back;
//   - a dataset that is cut at its parse limit is stored with state
//     partial; rows it did not cover are carried over, never dropped;
//   - rows a complete read no longer contains are carried over as absent
//     with the time they were last seen; nothing is silently deleted;
//   - a dataset observed under another trust generation than the device's
//     current one is refused inside the write transaction;
//   - superseded datasets stay as history within the retention window
//     (Q11); every write enforces that window and MaxHistoryPerRead for its
//     (device, read) in its own transaction, Prune does the same for all
//     devices; the newest dataset per (device, read) is never removed; MAC,
//     LLDP and hit-count history closer than MinHistorySpacing collapses
//     into the next dataset; an observed_at before the window is refused;
//   - a device or dataset not refreshed for StaleAfterIntervals poll
//     intervals is marked stale, never deleted.
//
// Every string is device text: it is validated with the netdevcontract
// limits (printable UTF-8 of bounded length), stored verbatim and must be
// rendered as text only. Configuration text, credentials and raw device
// output are not stored by this file; config versions belong to ND-17.
package netdevinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// Read names one dataset kind of a device.
type Read string

// Reads stored by the inventory (ADR 0010 D4 read table). Configurations
// are versioned separately (ND-17).
const (
	ReadFacts          Read = "facts"
	ReadPorts          Read = "ports"
	ReadVLANs          Read = "vlans"
	ReadMACTable       Read = "mac_table"
	ReadLLDPNeighbors  Read = "lldp_neighbors"
	ReadFirewallPolicy Read = "firewall_policy"
	ReadHitCounts      Read = "hit_counts"
)

// Reads lists every stored read in a fixed order.
var Reads = []Read{ReadFacts, ReadPorts, ReadVLANs, ReadMACTable, ReadLLDPNeighbors, ReadFirewallPolicy, ReadHitCounts}

// DatasetState is the state of one stored dataset.
type DatasetState string

// Dataset states.
const (
	// StateFresh is a complete read within StaleAfterIntervals poll
	// intervals. Its rows may be empty: a complete read that found nothing.
	StateFresh DatasetState = "fresh"
	// StatePartial is a read cut at its parse limit: rows it did not cover
	// are carried over and must not be treated as deleted.
	StatePartial DatasetState = "partial"
	// StateStale is a dataset not refreshed for StaleAfterIntervals poll
	// intervals. Its rows are kept and shown with their age.
	StateStale DatasetState = "stale"
)

// DeviceState is the state of one device seen by the server.
type DeviceState string

// Device states.
const (
	DeviceFresh DeviceState = "fresh"
	DeviceStale DeviceState = "stale"
)

// Poll intervals of ADR 0010 D4 ("What is read") and the stale rule
// ("stale after three missed intervals").
const (
	// FactsInterval is the poll interval of device facts.
	FactsInterval = 60 * time.Minute
	// SwitchInterval is the poll interval of CBS ports, VLANs, MAC table
	// and LLDP neighbors (the 15-minute floor of ADR 0007).
	SwitchInterval = 15 * time.Minute
	// FirewallPolicyInterval is the poll interval of the PAN-OS policy.
	FirewallPolicyInterval = 60 * time.Minute
	// HitCountInterval is the poll interval of PAN-OS rule hit counts.
	HitCountInterval = 60 * time.Minute
	// StaleAfterIntervals is the number of missed poll intervals after
	// which a device or dataset is stale.
	StaleAfterIntervals = 3
	// MaxFutureSkew bounds how far observed_at may lie ahead of the server
	// clock. A later timestamp is refused: stored, it would make every
	// genuine later read look out of order.
	MaxFutureSkew = 5 * time.Minute
)

// Sentinel errors callers branch on.
var (
	// ErrDeviceNotFound is returned for a device the server has not seen.
	ErrDeviceNotFound = errors.New("netdevinventory: device not found")
	// ErrDatasetNotFound is returned when no dataset is stored for a
	// (device, read).
	ErrDatasetNotFound = errors.New("netdevinventory: dataset not found")
	// ErrUnknownRead is returned for a read name the store does not know.
	ErrUnknownRead = errors.New("netdevinventory: unknown read")
	// ErrWrongFamily is returned for a read that the device family has not.
	ErrWrongFamily = errors.New("netdevinventory: read not supported by device family")
	// ErrRowsMismatch is returned when the rows do not belong to the read.
	ErrRowsMismatch = errors.New("netdevinventory: rows do not match read")
	// ErrInvalidRows wraps a netdevcontract validation failure of the rows.
	ErrInvalidRows = errors.New("netdevinventory: invalid rows")
	// ErrOutOfOrder is returned for a dataset older than the stored one,
	// or as old with different content.
	ErrOutOfOrder = errors.New("netdevinventory: dataset older than stored one")
	// ErrFutureObservation is returned for observed_at more than
	// MaxFutureSkew ahead of the server clock.
	ErrFutureObservation = errors.New("netdevinventory: observed_at in the future")
	// ErrObservationTooOld is returned for observed_at before the
	// retention window of the read (server clock minus HistoryRetention).
	// Nothing is written: stored, the dataset would be history that
	// retention removes at once.
	ErrObservationTooOld = errors.New("netdevinventory: observed_at before retention window")
	// ErrTrustGenerationRegressed is returned when a device update carries
	// a lower trust generation than the stored one.
	ErrTrustGenerationRegressed = errors.New("netdevinventory: trust generation regressed")
	// ErrTrustGenerationChanged is returned when a dataset was observed
	// under another trust generation than the device's current one (ADR
	// 0010: a re-pin bumps the generation). It is checked inside the write
	// transaction; nothing is written. The dataset must be dropped, not
	// retried.
	ErrTrustGenerationChanged = errors.New("netdevinventory: dataset observed under another trust generation")
	// ErrFamilyChanged is returned when a device update changes the
	// immutable family.
	ErrFamilyChanged = errors.New("netdevinventory: device family changed")
)

// Store persists network device inventory in the server database.
type Store struct {
	db  *sql.DB
	now func() time.Time
	// hook, when set (tests only), is called at named stages inside the
	// replace transaction; an error aborts the transaction.
	hook func(stage string) error
}

// New returns a Store for db using time.Now.
func New(db *sql.DB) *Store { return NewWithNow(db, time.Now) }

// NewWithNow returns a Store for db that uses now for timestamps, ages and
// retention. A nil now means time.Now.
func NewWithNow(db *sql.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}
}

// Open opens (and migrates) the server database at path and returns a
// Store over it. The caller closes the returned database.
func Open(path string) (*Store, *sql.DB, error) {
	db, err := serverdb.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return New(db), db, nil
}

// micros is the stored form of a time: microseconds since the Unix epoch.
func micros(t time.Time) int64 { return t.UTC().UnixMicro() }

func fromMicros(v int64) time.Time { return time.UnixMicro(v).UTC() }

// PollInterval returns the poll interval of read, or 0 for an unknown read.
func PollInterval(r Read) time.Duration {
	switch r {
	case ReadFacts:
		return FactsInterval
	case ReadPorts, ReadVLANs, ReadMACTable, ReadLLDPNeighbors:
		return SwitchInterval
	case ReadFirewallPolicy:
		return FirewallPolicyInterval
	case ReadHitCounts:
		return HitCountInterval
	}
	return 0
}

// devicePollInterval is the shortest poll interval of the family's reads:
// a device is seen at least that often while it is polled.
func devicePollInterval(f netdevcontract.Family) time.Duration {
	if f == netdevcontract.FamilyCBS {
		return SwitchInterval
	}
	return FirewallPolicyInterval
}

func readAllowed(r Read, f netdevcontract.Family) bool {
	switch r {
	case ReadFacts:
		return true
	case ReadPorts, ReadVLANs, ReadMACTable, ReadLLDPNeighbors:
		return f == netdevcontract.FamilyCBS
	case ReadFirewallPolicy, ReadHitCounts:
		return f == netdevcontract.FamilyPANOS
	}
	return false
}

// Device is the stored presentation copy of one device.
type Device struct {
	DeviceID        string
	Family          netdevcontract.Family
	Label           string
	TrustGeneration uint64
	// LastSeen is the newest observed_at of any stored dataset; zero if
	// none was stored yet.
	LastSeen time.Time
	State    DeviceState
}

// Dataset is the status of one stored dataset.
type Dataset struct {
	ID            int64
	DeviceID      string
	Read          Read
	ObservedAt    time.Time
	StoredAt      time.Time
	State         DatasetState
	Incomplete    bool
	PayloadSHA256 string
	// RowCount is the number of rows the read itself contained; carried
	// rows are not counted.
	RowCount int
	Current  bool
}

// lockWriteSQL takes the database write lock without changing a row.
const lockWriteSQL = `UPDATE netdev_devices_seen SET device_id = device_id WHERE 0`

// withTx runs fn in one transaction that takes the database write lock
// with its first statement (see pveinventory.withTx: SQLite fails a
// read-to-write upgrade at once while another connection writes).
func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("netdevinventory: begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, lockWriteSQL); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("netdevinventory: take write lock: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("netdevinventory: commit: %w", err)
	}
	return nil
}

func (s *Store) runHook(stage string) error {
	if s.hook == nil {
		return nil
	}
	return s.hook(stage)
}

// UpsertDevice records or updates the server copy of an executor device.
// The family is immutable and the trust generation never decreases.
func (s *Store) UpsertDevice(ctx context.Context, d netdevcontract.Device) error {
	v, err := netdevcontract.ValidateDevice(d)
	if err != nil {
		return fmt.Errorf("netdevinventory: upsert device: %w", err)
	}
	now := micros(s.now())
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var family string
		var gen int64
		err := tx.QueryRowContext(ctx, `SELECT family, trust_generation FROM netdev_devices_seen WHERE device_id = ?`,
			v.DeviceID).Scan(&family, &gen)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx, `INSERT INTO netdev_devices_seen
				(device_id, family, label, trust_generation, last_seen, state, created_at, updated_at)
				VALUES (?, ?, ?, ?, NULL, 'fresh', ?, ?)`,
				v.DeviceID, string(v.Family), v.Name, int64(v.TrustGeneration), now, now)
			if err != nil {
				return fmt.Errorf("netdevinventory: insert device %s: %w", v.DeviceID, err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("netdevinventory: load device %s: %w", v.DeviceID, err)
		}
		if netdevcontract.Family(family) != v.Family {
			return fmt.Errorf("netdevinventory: device %s: %w", v.DeviceID, ErrFamilyChanged)
		}
		if int64(v.TrustGeneration) < gen {
			return fmt.Errorf("netdevinventory: device %s: %w", v.DeviceID, ErrTrustGenerationRegressed)
		}
		_, err = tx.ExecContext(ctx, `UPDATE netdev_devices_seen SET label = ?, trust_generation = ?, updated_at = ?
			WHERE device_id = ?`, v.Name, int64(v.TrustGeneration), now, v.DeviceID)
		if err != nil {
			return fmt.Errorf("netdevinventory: update device %s: %w", v.DeviceID, err)
		}
		return nil
	})
}

// GetDevice returns the stored device. Its state is reported stale once
// it was not seen for StaleAfterIntervals poll intervals, even before
// MarkStale ran.
func (s *Store) GetDevice(ctx context.Context, deviceID string) (Device, error) {
	var d Device
	var family, state string
	var gen, created int64
	var last sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT device_id, family, label, trust_generation, last_seen, state, created_at
		FROM netdev_devices_seen WHERE device_id = ?`, deviceID).
		Scan(&d.DeviceID, &family, &d.Label, &gen, &last, &state, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	if err != nil {
		return Device{}, fmt.Errorf("netdevinventory: load device: %w", err)
	}
	d.Family = netdevcontract.Family(family)
	d.TrustGeneration = uint64(gen)
	d.State = DeviceState(state)
	ref := created
	if last.Valid {
		d.LastSeen = fromMicros(last.Int64)
		ref = last.Int64
	}
	if s.now().Sub(fromMicros(ref)) > StaleAfterIntervals*devicePollInterval(d.Family) {
		d.State = DeviceStale
	}
	return d, nil
}

// GetDataset returns the current dataset of (deviceID, read). Its state
// is reported stale once it is StaleAfterIntervals poll intervals old,
// even before MarkStale ran.
func (s *Store) GetDataset(ctx context.Context, deviceID string, read Read) (Dataset, error) {
	if PollInterval(read) == 0 {
		return Dataset{}, ErrUnknownRead
	}
	var d Dataset
	var rd, state string
	var observed, stored int64
	var incomplete, current int
	err := s.db.QueryRowContext(ctx, `SELECT id, device_id, read, observed_at, stored_at, state, incomplete,
			payload_sha256, row_count, current
		FROM netdev_datasets WHERE device_id = ? AND read = ? AND current = 1`, deviceID, string(read)).
		Scan(&d.ID, &d.DeviceID, &rd, &observed, &stored, &state, &incomplete, &d.PayloadSHA256, &d.RowCount, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return Dataset{}, ErrDatasetNotFound
	}
	if err != nil {
		return Dataset{}, fmt.Errorf("netdevinventory: load dataset: %w", err)
	}
	d.Read = Read(rd)
	d.ObservedAt = fromMicros(observed)
	d.StoredAt = fromMicros(stored)
	d.State = DatasetState(state)
	d.Incomplete = incomplete == 1
	d.Current = current == 1
	if s.now().Sub(d.ObservedAt) > StaleAfterIntervals*PollInterval(d.Read) {
		d.State = StateStale
	}
	return d, nil
}

// ReplaceResult describes what ReplaceDataset stored.
type ReplaceResult struct {
	// DatasetID is the current dataset after the call.
	DatasetID int64
	// Unchanged is true when the payload equalled the current dataset's and
	// only observed_at (and state) advanced, or when the same dataset was
	// delivered again.
	Unchanged bool
	// Carried is the number of rows carried over from the previous dataset
	// (absent rows and rows a partial read did not cover).
	Carried int
}

// ReplaceDataset stores rows as the new current dataset of (deviceID,
// read), observed at observedAt under trustGeneration. incomplete marks a
// list cut at its parse limit (state partial). The rows are validated with
// the netdevcontract limits; the whole replacement is one transaction.
//
// A trustGeneration other than the device's current one is refused with
// ErrTrustGenerationChanged inside that transaction, before anything is
// written: a concurrent re-pin either commits first (and the dataset is
// refused) or waits until the dataset is stored.
//
// A dataset older than the current one is refused with ErrOutOfOrder, and
// one observed before the read's retention window with
// ErrObservationTooOld. The same dataset delivered again stores nothing
// (the dataset is not rewritten), and an identical payload only advances
// observed_at; both still enforce the retention window (see below).
// Otherwise the previous
// dataset becomes history and its rows missing from the new read are
// carried over: as absent after a complete read, unchanged after a partial
// one. For reads with a MinHistorySpacing, a previous dataset closer than
// that to the newest history entry is not kept as history: it collapses
// into the new dataset, which carries its rows.
//
// Before the transaction commits, the history of (deviceID, read) is
// bounded: superseded datasets older than HistoryRetention are removed,
// the rest is trimmed to MaxHistoryPerRead, oldest first, and carried rows
// whose seen_at left the window are removed from every kept dataset,
// current or superseded. The current dataset is never removed. So after
// every committed write the (device, read) holds at most MaxHistoryPerRead
// + 1 datasets and no carried row older than the window, whatever the
// write rate or the observed_at values, and whether or not Prune runs. An
// identical payload or a redelivery runs the window part of that bound
// too (it adds no history, so the cap cannot grow): aged superseded
// datasets and expired carried rows of every kept dataset are removed
// inside the transaction, without rewriting the current dataset. So the
// window holds for a (device, read) whose payload never changes again.
func (s *Store) ReplaceDataset(ctx context.Context, deviceID string, read Read, trustGeneration uint64, observedAt time.Time, incomplete bool, rows Rows) (ReplaceResult, error) {
	if PollInterval(read) == 0 {
		return ReplaceResult{}, ErrUnknownRead
	}
	if rows == nil || rows.Read() != read {
		return ReplaceResult{}, ErrRowsMismatch
	}
	if !netdevcontract.ValidDeviceID(deviceID) {
		return ReplaceResult{}, ErrDeviceNotFound
	}
	now := s.now()
	if observedAt.After(now.Add(MaxFutureSkew)) {
		return ReplaceResult{}, ErrFutureObservation
	}
	if observedAt.Before(now.Add(-HistoryRetention(read))) {
		return ReplaceResult{}, fmt.Errorf("netdevinventory: device %s read %s: %w", deviceID, read, ErrObservationTooOld)
	}
	var res ReplaceResult
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		r, err := s.replace(ctx, tx, deviceID, read, trustGeneration, observedAt, incomplete, rows, now)
		res = r
		return err
	})
	if err != nil {
		return ReplaceResult{}, err
	}
	return res, nil
}

func (s *Store) replace(ctx context.Context, tx *sql.Tx, deviceID string, read Read, trustGeneration uint64,
	observedAt time.Time, incomplete bool, rows Rows, now time.Time) (ReplaceResult, error) {
	var family string
	var gen int64
	err := tx.QueryRowContext(ctx, `SELECT family, trust_generation FROM netdev_devices_seen WHERE device_id = ?`,
		deviceID).Scan(&family, &gen)
	if errors.Is(err, sql.ErrNoRows) {
		return ReplaceResult{}, ErrDeviceNotFound
	}
	if err != nil {
		return ReplaceResult{}, fmt.Errorf("netdevinventory: load device %s: %w", deviceID, err)
	}
	// The stored generation is never negative (CHECK >= 1); compare in
	// int64 space so a huge observed value cannot wrap onto it.
	if trustGeneration > uint64(1<<63-1) || int64(trustGeneration) != gen {
		return ReplaceResult{}, fmt.Errorf("netdevinventory: device %s read %s: observed generation %d, current %d: %w",
			deviceID, read, trustGeneration, gen, ErrTrustGenerationChanged)
	}
	fam := netdevcontract.Family(family)
	if !readAllowed(read, fam) {
		return ReplaceResult{}, fmt.Errorf("netdevinventory: device %s read %s: %w", deviceID, read, ErrWrongFamily)
	}
	if err := validateRows(deviceID, fam, trustGeneration, observedAt, incomplete, rows); err != nil {
		return ReplaceResult{}, err
	}
	sets, err := rows.tableRows()
	if err != nil {
		return ReplaceResult{}, err
	}
	sum, err := payloadSHA256(rows)
	if err != nil {
		return ReplaceResult{}, err
	}
	obs := micros(observedAt)
	nowM := micros(now)
	state := StateFresh
	if incomplete {
		state = StatePartial
	}

	var prevID, prevObs int64
	var prevSum string
	var prevIncomplete int
	err = tx.QueryRowContext(ctx, `SELECT id, observed_at, payload_sha256, incomplete FROM netdev_datasets
		WHERE device_id = ? AND read = ? AND current = 1`, deviceID, string(read)).
		Scan(&prevID, &prevObs, &prevSum, &prevIncomplete)
	hasPrev := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ReplaceResult{}, fmt.Errorf("netdevinventory: load current dataset: %w", err)
	}
	same := hasPrev && prevSum == sum && (prevIncomplete == 1) == incomplete
	if hasPrev {
		switch {
		case obs < prevObs:
			return ReplaceResult{}, fmt.Errorf("netdevinventory: device %s read %s: %w", deviceID, read, ErrOutOfOrder)
		case obs == prevObs && same:
			// Nothing to store, but the window still holds for the
			// history behind the current dataset.
			if err := boundUnchanged(ctx, tx, read, deviceID, now); err != nil {
				return ReplaceResult{}, err
			}
			return ReplaceResult{DatasetID: prevID, Unchanged: true}, nil
		case obs == prevObs:
			return ReplaceResult{}, fmt.Errorf("netdevinventory: device %s read %s: %w", deviceID, read, ErrOutOfOrder)
		}
	}
	if err := s.touchDevice(ctx, tx, deviceID, obs, nowM); err != nil {
		return ReplaceResult{}, err
	}
	if same {
		if _, err := tx.ExecContext(ctx, `UPDATE netdev_datasets SET observed_at = ?, stored_at = ?, state = ?
			WHERE id = ?`, obs, nowM, string(state), prevID); err != nil {
			return ReplaceResult{}, fmt.Errorf("netdevinventory: advance dataset: %w", err)
		}
		// A (device, read) whose payload never changes again must still
		// lose history that leaves the window, without Prune.
		if err := boundUnchanged(ctx, tx, read, deviceID, now); err != nil {
			return ReplaceResult{}, err
		}
		return ReplaceResult{DatasetID: prevID, Unchanged: true}, s.runHook("commit")
	}

	keepPrev := true
	if hasPrev && MinHistorySpacing(read) > 0 {
		var lastHist sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(observed_at) FROM netdev_datasets
			WHERE device_id = ? AND read = ? AND current = 0`, deviceID, string(read)).Scan(&lastHist); err != nil {
			return ReplaceResult{}, fmt.Errorf("netdevinventory: load newest history: %w", err)
		}
		keepPrev = !lastHist.Valid || prevObs-lastHist.Int64 >= MinHistorySpacing(read).Microseconds()
	}
	if hasPrev {
		if _, err := tx.ExecContext(ctx, `UPDATE netdev_datasets SET current = 0 WHERE id = ?`, prevID); err != nil {
			return ReplaceResult{}, fmt.Errorf("netdevinventory: supersede dataset: %w", err)
		}
	}
	present := 0
	for _, set := range sets {
		present += len(set.rows)
	}
	inc := 0
	if incomplete {
		inc = 1
	}
	ins, err := tx.ExecContext(ctx, `INSERT INTO netdev_datasets
		(device_id, read, observed_at, stored_at, state, incomplete, payload_sha256, row_count, current)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		deviceID, string(read), obs, nowM, string(state), inc, sum, present)
	if err != nil {
		return ReplaceResult{}, fmt.Errorf("netdevinventory: insert dataset: %w", err)
	}
	id, err := ins.LastInsertId()
	if err != nil {
		return ReplaceResult{}, fmt.Errorf("netdevinventory: dataset id: %w", err)
	}
	if err := s.runHook("dataset"); err != nil {
		return ReplaceResult{}, err
	}
	for _, set := range sets {
		if err := insertRows(ctx, tx, id, set); err != nil {
			return ReplaceResult{}, err
		}
		if err := s.runHook("rows:" + set.table.name); err != nil {
			return ReplaceResult{}, err
		}
	}
	res := ReplaceResult{DatasetID: id}
	if hasPrev {
		// Carry nothing that already left the window, measured from the
		// later of observed_at and the server clock.
		cutoff := max(obs, nowM) - HistoryRetention(read).Microseconds()
		for _, t := range readTables(read) {
			n, err := carryOver(ctx, tx, t, prevID, prevObs, id, !incomplete, cutoff)
			if err != nil {
				return ReplaceResult{}, err
			}
			res.Carried += n
		}
		if !keepPrev {
			// Too dense to keep as history: its rows live on as the carried
			// rows of the new dataset; the cascade removes its own rows.
			if _, err := tx.ExecContext(ctx, `DELETE FROM netdev_datasets WHERE id = ?`, prevID); err != nil {
				return ReplaceResult{}, fmt.Errorf("netdevinventory: collapse dataset: %w", err)
			}
		}
	}
	// Bound this (device, read)'s history in the same transaction, so it
	// holds after every write, not only after Prune: aged and surplus
	// datasets go, and expired carried rows leave every kept dataset.
	if _, err := boundHistory(ctx, tx, read, deviceID, now); err != nil {
		return ReplaceResult{}, err
	}
	if _, err := dropExpiredCarried(ctx, tx, read, deviceID, now); err != nil {
		return ReplaceResult{}, err
	}
	if err := s.runHook("commit"); err != nil {
		return ReplaceResult{}, err
	}
	return res, nil
}

// touchDevice advances last_seen (never backwards) and marks the device
// fresh.
func (s *Store) touchDevice(ctx context.Context, tx *sql.Tx, deviceID string, obs, now int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE netdev_devices_seen
		SET last_seen = MAX(COALESCE(last_seen, ?), ?), state = 'fresh', updated_at = ?
		WHERE device_id = ?`, obs, obs, now, deviceID)
	if err != nil {
		return fmt.Errorf("netdevinventory: touch device %s: %w", deviceID, err)
	}
	return nil
}

// StaleReport counts what MarkStale changed.
type StaleReport struct {
	Devices  int64
	Datasets int64
}

// MarkStale marks devices not seen, and current datasets not refreshed,
// for StaleAfterIntervals poll intervals as stale. Nothing is deleted.
func (s *Store) MarkStale(ctx context.Context) (StaleReport, error) {
	now := s.now()
	var rep StaleReport
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		for _, f := range []netdevcontract.Family{netdevcontract.FamilyCBS, netdevcontract.FamilyPANOS} {
			cutoff := micros(now.Add(-StaleAfterIntervals * devicePollInterval(f)))
			r, err := tx.ExecContext(ctx, `UPDATE netdev_devices_seen SET state = 'stale', updated_at = ?
				WHERE family = ? AND state <> 'stale' AND COALESCE(last_seen, created_at) < ?`,
				micros(now), string(f), cutoff)
			if err != nil {
				return fmt.Errorf("netdevinventory: mark stale devices: %w", err)
			}
			n, _ := r.RowsAffected()
			rep.Devices += n
		}
		for _, rd := range Reads {
			cutoff := micros(now.Add(-StaleAfterIntervals * PollInterval(rd)))
			r, err := tx.ExecContext(ctx, `UPDATE netdev_datasets SET state = 'stale'
				WHERE current = 1 AND read = ? AND state <> 'stale' AND observed_at < ?`, string(rd), cutoff)
			if err != nil {
				return fmt.Errorf("netdevinventory: mark stale datasets: %w", err)
			}
			n, _ := r.RowsAffected()
			rep.Datasets += n
		}
		return nil
	})
	if err != nil {
		return StaleReport{}, err
	}
	return rep, nil
}

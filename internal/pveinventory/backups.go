// SPDX-License-Identifier: AGPL-3.0-or-later

// Per-guest backup freshness model (ADR 0006, ticket P1-29).
//
// Freshness is a derived, presentation value computed at query time from the
// stored backup evidence (pve_backup_observations), the per-guest backup
// dataset status (pve_guest_dataset_status), and the guest's own state
// (pve_guests). It is never stored, mirroring how guest age is computed at
// query time: the source of truth stays in the observation tables.
//
// The model reports one overall state plus three confidence channels that are
// kept deliberately separate, because they are different claims:
//
//   - task:       a recent backup task summary said it ran (and how it ended);
//   - catalog:    a backup volume is actually present in a readable catalog;
//   - verification: a catalog entry was verified as restorable.
//
// A task success is not the same confidence as a present, verified backup.
// "Unknown" is a first-class state and is never rendered as safe: a denied
// catalog, a filtered read, or a missing sample yields unknown, not "no
// backups" or "backups are fresh".
package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Backup freshness knobs. They are named constants next to the code that
// enforces them, per the project conventions.
const (
	// DefaultBackupMaxAge is the operator-default maximum age of the last
	// evidenced successful backup before it is reported overdue.
	DefaultBackupMaxAge = 24 * time.Hour

	// backupCadence is the backup evidence collection interval (spec: the
	// backup sub-dataset is read on the 5-minute guest-detail cadence).
	backupCadence = 5 * time.Minute

	// backupStaleIntervals is how many missed collection intervals before the
	// backup evidence dataset is considered stale (spec: "mark a dataset
	// stale after three missed intervals").
	backupStaleIntervals = 3

	// DefaultBackupStaleAfter is the age at which stored backup evidence is
	// treated as stale data rather than as a basis for a freshness verdict.
	DefaultBackupStaleAfter = backupStaleIntervals * backupCadence

	// MaxFreshnessEvidence bounds how many evidence rows are loaded for a
	// freshness verdict. Freshness only needs the newest rows (it is a
	// max-over-time computation), so a bounded newest-first read is exact.
	MaxFreshnessEvidence = 1024
)

// Backup evidence status values. They mirror the vocabulary the PVE reader
// emits (internal/pveapi) and are validated by pvecontract; the store
// interprets stored rows without importing the PVE client.
const (
	backupStatusSuccess = "success"
	backupStatusFailed  = "failed"
)

// FreshnessState is the overall per-guest backup freshness verdict.
type FreshnessState string

// FreshnessState values.
const (
	// FreshnessOK: the last evidenced successful backup is within the maximum
	// age.
	FreshnessOK FreshnessState = "ok"
	// FreshnessOverdue: the last evidenced successful backup is older than the
	// maximum age, or no successful backup is evidenced at all (with a
	// complete enumeration).
	FreshnessOverdue FreshnessState = "overdue"
	// FreshnessFailed: the most recent backup attempt failed after the last
	// evidenced success.
	FreshnessFailed FreshnessState = "failed"
	// FreshnessStaleData: the backup evidence dataset itself is stale, so no
	// trustworthy verdict can be made from it.
	FreshnessStaleData FreshnessState = "stale-data"
	// FreshnessExpectedOff: the guest is expected off (stopped); no backup is
	// expected and no warning is raised.
	FreshnessExpectedOff FreshnessState = "expected-off"
	// FreshnessUnknown: there is no usable backup visibility (denied catalog,
	// filtered read, missing sample). Unknown is never safe.
	FreshnessUnknown FreshnessState = "unknown"
)

// TaskConfidence is the task channel: what recent backup task summaries say.
type TaskConfidence struct {
	// LastSuccessUnix is the newest successful task finish (0 = none).
	LastSuccessUnix int64
	// LastRunUnix is the newest task run of any status (0 = none).
	LastRunUnix int64
	// LastRunStatus is the status of the newest task run ("success",
	// "failed", or "" when there is no task evidence).
	LastRunStatus string
	// Count is the number of task evidence rows considered.
	Count int
}

// CatalogConfidence is the catalog channel: what readable backup catalogs
// show.
type CatalogConfidence struct {
	// Present reports whether at least one backup volume is evidenced in a
	// readable catalog.
	Present bool
	// NewestUnix is the newest catalog entry ctime (0 = none).
	NewestUnix int64
	// Count is the number of catalog evidence rows considered.
	Count int
}

// VerificationConfidence is the verification channel: whether catalog entries
// were verified as restorable.
type VerificationConfidence struct {
	// State is yes when any catalog entry is verified, no when catalog entries
	// exist but none are verified, unknown when there is no verification
	// information.
	State pvecontract.TriState
	// Count is the number of catalog entries carrying verification
	// information.
	Count int
}

// Freshness is the computed per-guest backup freshness verdict.
type Freshness struct {
	RemoteID   string
	VMID       uint64
	Generation uint64

	// State is the overall verdict.
	State FreshnessState
	// Reason is a short human-readable explanation (no secrets).
	Reason string

	// DatasetState is the visibility of the backup evidence dataset
	// (available/unavailable/partial).
	DatasetState DatasetState
	// DatasetReason is the dataset's stored reason (for unavailable).
	DatasetReason string

	// MaxAge is the maximum age used for the verdict.
	MaxAge time.Duration
	// EvaluatedAt is the (injected) clock reading the verdict was computed at.
	EvaluatedAt time.Time

	// LastSuccessUnix is the newest evidenced successful backup across the
	// task and catalog channels (0 = none).
	LastSuccessUnix int64
	// LastRunUnix is the newest backup evidence of any status (0 = none).
	LastRunUnix int64

	// The three confidence channels, kept separate.
	Task         TaskConfidence
	Catalog      CatalogConfidence
	Verification VerificationConfidence
}

// FreshnessInput is everything EvaluateFreshness needs. It is a value type so
// the verdict is a pure function of its inputs and trivially testable with an
// injected clock.
type FreshnessInput struct {
	RemoteID   string
	VMID       uint64
	Generation uint64

	// Now is the injected clock reading.
	Now time.Time
	// MaxAge is the maximum backup age; non-positive selects
	// DefaultBackupMaxAge.
	MaxAge time.Duration
	// StaleAfter is the age at which the evidence dataset is stale;
	// non-positive selects DefaultBackupStaleAfter.
	StaleAfter time.Duration

	// GuestStatus is the guest's stored state (pvecontract.GuestStatus).
	GuestStatus string
	// DatasetState is the backup evidence dataset visibility.
	DatasetState DatasetState
	// DatasetReason is the dataset's stored reason.
	DatasetReason string
	// DatasetObservedAt is when the backup evidence was last collected.
	DatasetObservedAt time.Time
	// Evidence is the stored backup evidence for the incarnation.
	Evidence []pvecontract.BackupEvidence
}

// EvaluateFreshness computes the per-guest backup freshness verdict from its
// inputs. It is a pure function: no I/O, no global clock.
func EvaluateFreshness(in FreshnessInput) Freshness {
	maxAge := in.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultBackupMaxAge
	}
	staleAfter := in.StaleAfter
	if staleAfter <= 0 {
		staleAfter = DefaultBackupStaleAfter
	}

	f := Freshness{
		RemoteID:      in.RemoteID,
		VMID:          in.VMID,
		Generation:    in.Generation,
		MaxAge:        maxAge,
		EvaluatedAt:   in.Now,
		DatasetState:  in.DatasetState,
		DatasetReason: in.DatasetReason,
	}

	// Channel metrics and the cross-channel max-over-time values.
	var task TaskConfidence
	var catalog CatalogConfidence
	verification := VerificationConfidence{State: pvecontract.Unknown}
	var lastSuccess, lastRun, lastFailed int64

	for _, e := range in.Evidence {
		t := e.FinishedUnix
		if t == 0 {
			t = e.StartedUnix
		}

		switch e.Kind {
		case pvecontract.BackupKindTask:
			task.Count++
			if t > task.LastRunUnix {
				task.LastRunUnix = t
				task.LastRunStatus = e.Status
			}
			if e.Status == backupStatusSuccess && t > task.LastSuccessUnix {
				task.LastSuccessUnix = t
			}
			if e.Status == backupStatusFailed && t > lastFailed {
				lastFailed = t
			}
		case pvecontract.BackupKindCatalog:
			catalog.Count++
			catalog.Present = true
			if t > catalog.NewestUnix {
				catalog.NewestUnix = t
			}
			if e.Verified == pvecontract.Yes || e.Verified == pvecontract.No {
				verification.Count++
				if e.Verified == pvecontract.Yes {
					verification.State = pvecontract.Yes
				} else if verification.State != pvecontract.Yes {
					verification.State = pvecontract.No
				}
			}
		}

		// A successful backup is evidenced by a successful task or by a
		// present catalog entry.
		isSuccess := (e.Kind == pvecontract.BackupKindTask && e.Status == backupStatusSuccess) ||
			e.Kind == pvecontract.BackupKindCatalog
		if isSuccess && t > lastSuccess {
			lastSuccess = t
		}
		if t > lastRun {
			lastRun = t
		}
	}

	f.Task = task
	f.Catalog = catalog
	f.Verification = verification
	f.LastSuccessUnix = lastSuccess
	f.LastRunUnix = lastRun

	// Verdict, by priority. Earlier states are more fundamental: a stopped
	// guest needs no backup; stale data and missing visibility cannot ground
	// any verdict; only then do we compare the last success against the age.
	switch {
	case in.GuestStatus == string(pvecontract.GuestStopped):
		f.State = FreshnessExpectedOff
		f.Reason = "guest is expected off (stopped); no backup expected"

	case in.DatasetState == StateUnavailable:
		f.State = FreshnessUnknown
		f.Reason = "backup evidence unavailable: " + in.DatasetReason

	case in.DatasetState == StatePartial && len(in.Evidence) == 0:
		f.State = FreshnessUnknown
		f.Reason = "backup evidence is partial and empty; absence is not established"

	case in.DatasetObservedAt != (time.Time{}) && in.Now.Sub(in.DatasetObservedAt) > staleAfter:
		f.State = FreshnessStaleData
		f.Reason = fmt.Sprintf("backup evidence is stale (collected %s ago, limit %s)",
			in.Now.Sub(in.DatasetObservedAt).Round(time.Second), staleAfter)

	case lastFailed > lastSuccess && lastFailed > 0:
		f.State = FreshnessFailed
		f.Reason = "most recent backup attempt failed after the last evidenced success"

	case lastSuccess > 0 && in.Now.Sub(time.Unix(lastSuccess, 0)) <= maxAge:
		f.State = FreshnessOK
		f.Reason = "last evidenced successful backup is within the maximum age"

	case lastSuccess > 0:
		f.State = FreshnessOverdue
		f.Reason = fmt.Sprintf("last evidenced successful backup is %s old (limit %s)",
			in.Now.Sub(time.Unix(lastSuccess, 0)).Round(time.Second), maxAge)

	default:
		f.State = FreshnessOverdue
		f.Reason = "no evidenced successful backup"
	}

	return f
}

// GuestBackupFreshness computes the backup freshness verdict for one exact
// guest incarnation, (remoteID, vmid, generation). maxAge non-positive selects
// DefaultBackupMaxAge. The clock is the store's injected Now.
func (s *Store) GuestBackupFreshness(ctx context.Context, remoteID string, vmid, generation uint64, maxAge time.Duration) (Freshness, error) {
	status, err := s.guestStatusForGeneration(ctx, remoteID, vmid, generation)
	if err != nil {
		return Freshness{}, err
	}
	dsState, dsReason, dsObserved, err := s.backupDatasetStatus(ctx, remoteID, vmid, generation)
	if err != nil {
		return Freshness{}, err
	}
	evidence, err := s.loadBackupEvidence(ctx, remoteID, vmid, generation)
	if err != nil {
		return Freshness{}, err
	}

	return EvaluateFreshness(FreshnessInput{
		RemoteID:          remoteID,
		VMID:              vmid,
		Generation:        generation,
		Now:               s.now(),
		MaxAge:            maxAge,
		GuestStatus:       status,
		DatasetState:      dsState,
		DatasetReason:     dsReason,
		DatasetObservedAt: dsObserved,
		Evidence:          evidence,
	}), nil
}

// guestStatusForGeneration returns the stored status of one exact guest
// incarnation, or ErrGuestNotFound when the incarnation is missing or
// tombstoned.
func (s *Store) guestStatusForGeneration(ctx context.Context, remoteID string, vmid, generation uint64) (string, error) {
	var status string
	var tombstoned int
	err := s.db.QueryRowContext(ctx,
		`SELECT status, tombstoned FROM pve_guests
		 WHERE remote_id = ? AND vmid = ? AND generation = ?`,
		remoteID, vmid, generation).Scan(&status, &tombstoned)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrGuestNotFound
	}
	if err != nil {
		return "", fmt.Errorf("pveinventory: read guest status: %w", err)
	}
	if tombstoned != 0 {
		return "", ErrGuestNotFound
	}
	return status, nil
}

// backupDatasetStatus returns the stored state, reason and observed-at of the
// per-guest backup evidence dataset. A missing row means no backup dataset was
// ever recorded for the incarnation, which is reported as unavailable.
func (s *Store) backupDatasetStatus(ctx context.Context, remoteID string, vmid, generation uint64) (DatasetState, string, time.Time, error) {
	var state string
	var observed string
	var reason string
	err := s.db.QueryRowContext(ctx,
		`SELECT state, observed_at, reason FROM pve_guest_dataset_status
		 WHERE remote_id = ? AND vmid = ? AND generation = ? AND dataset = ?`,
		remoteID, vmid, generation, DatasetBackups).Scan(&state, &observed, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return StateUnavailable, "no backup dataset recorded", time.Time{}, nil
	}
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("pveinventory: read backup dataset status: %w", err)
	}
	obs, err := time.Parse(time.RFC3339Nano, observed)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("pveinventory: parse backup dataset observed_at: %w", err)
	}
	return DatasetState(state), reason, obs, nil
}

// loadBackupEvidence returns the newest backup evidence rows for one exact
// guest incarnation, bounded by MaxFreshnessEvidence. Newest-first ordering
// keeps the max-over-time computations in EvaluateFreshness exact.
func (s *Store) loadBackupEvidence(ctx context.Context, remoteID string, vmid, generation uint64) ([]pvecontract.BackupEvidence, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT source, kind, name, status, started_unix, finished_unix, verified
		 FROM pve_backup_observations
		 WHERE remote_id = ? AND vmid = ? AND generation = ?
		 ORDER BY finished_unix DESC, started_unix DESC, source DESC, kind DESC, name DESC
		 LIMIT ?`,
		remoteID, vmid, generation, MaxFreshnessEvidence)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: query backup evidence: %w", err)
	}
	defer rows.Close()

	out := make([]pvecontract.BackupEvidence, 0, MaxFreshnessEvidence)
	for rows.Next() {
		var e pvecontract.BackupEvidence
		if err := rows.Scan(&e.Source, &e.Kind, &e.Name, &e.Status, &e.StartedUnix, &e.FinishedUnix, &e.Verified); err != nil {
			return nil, fmt.Errorf("pveinventory: scan backup evidence: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pveinventory: iterate backup evidence: %w", err)
	}
	return out, nil
}

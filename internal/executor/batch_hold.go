// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
)

// Held batch targets (ADR 0007 E11). A target whose last batch member may
// still be running there is held: no batch member starts there until the
// host positively shows that run gone (hostrun.RunVisible). Holds are
// persisted in the executor's data directory, so an executor restart does
// not free them: they are restored at startup and rechecked before any
// member starts on the target.
//
// A hold lasts at most batchHoldMax while the executor rechecks it
// automatically. A target still held then (the run still visible, or its
// visibility unknown) is never freed by time: the hold expires into a
// terminal state that only an operator ends. The operator path is the
// offline `nebula-executor batch-holds rearm` (RearmHeldBatchTarget),
// which returns the hold to automatic rechecks counted from now; the
// target is freed only once the host shows the run gone. The online
// release (ReleaseHeldBatchTarget) is reserved for a future online
// operator release; it has no production caller today and, too, needs
// the host to show the run gone.
//
// A target is held from its member's reservation on, before the member
// starts, so an executor crash or kill during an attached run restarts
// with the target held, too.
//
// The file holds what reaching the target needs (host ID, pinned
// fingerprint, endpoints) and the execution ID; never the run's secrets,
// parameters or artifact.

// batchHeldFile is the held-target file in the executor's data directory.
const batchHeldFile = "batch-held-targets.json"

// batchHoldMax is the longest a target is held with automatic rechecks.
const batchHoldMax = 24 * time.Hour

// Limits of the held-target file.
const (
	// maxBatchHeldTargets bounds the held targets (one per host).
	maxBatchHeldTargets = 4096
	// maxBatchHeldFileBytes bounds the file read at startup.
	maxBatchHeldFileBytes = 4 << 20
	// maxBatchHeldField bounds the host ID, fingerprint and execution ID.
	maxBatchHeldField = 256
	// maxBatchHoldReason bounds an operator's release reason and name.
	maxBatchHoldReason = 256
)

// batchHeldVersion is the held-target file format version.
const batchHeldVersion = 1

// Errors of the held-target store and the operator release.
var (
	// ErrBatchHoldStore: the held targets cannot be read or written, so no
	// batch member starts anywhere (fail closed).
	ErrBatchHoldStore = errors.New("batch: held targets cannot be persisted")
	// ErrBatchTargetNotHeld: no hold of that target for that execution.
	ErrBatchTargetNotHeld = errors.New("batch: the target is not held for that execution")
	// ErrBatchTargetStillRunning: the host shows the held run, or cannot
	// tell; the target stays held.
	ErrBatchTargetStillRunning = errors.New("batch: the held run is still running on the target, or the target cannot tell")
	// ErrBatchHoldBusy: a recheck of the target is in flight, or its
	// member runs there now.
	ErrBatchHoldBusy = errors.New("batch: the held target is being rechecked; try again")
	// ErrBatchHoldReason: missing or malformed operator name or reason.
	ErrBatchHoldReason = errors.New("batch: an operator name and a printable reason of at most 256 bytes are required")
	// ErrBatchHoldNotExpired: the hold is still rechecked automatically;
	// only an expired hold is re-armed.
	ErrBatchHoldNotExpired = errors.New("batch: the hold has not expired; the executor still rechecks it")
)

// heldRecord is one persisted hold.
type heldRecord struct {
	HostID      string   `json:"host_id"`
	Fingerprint string   `json:"fingerprint"`
	ExecutionID string   `json:"execution_id"`
	Endpoints   []string `json:"endpoints"`
	HeldAtUnix  int64    `json:"held_at_unix"`
	Expired     bool     `json:"expired,omitempty"`
}

type heldDocument struct {
	Version int          `json:"version"`
	Targets []heldRecord `json:"targets"`
}

// HeldBatchTarget describes one held target (for an operator view).
type HeldBatchTarget struct {
	HostID      string
	Fingerprint string
	ExecutionID string
	HeldAt      time.Time
	// Expired: held past batchHoldMax; the operator re-arms it offline
	// (`nebula-executor batch-holds rearm`) to end it.
	Expired bool
	// Running: a batch member runs on the target now (its reservation is
	// persisted as this hold).
	Running bool
}

// validExecutionID reports whether id is a lowercase UUID.
func validExecutionID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// validRecord checks one persisted hold before it is restored.
func validRecord(r heldRecord) error {
	for _, f := range []string{r.HostID, r.Fingerprint} {
		if !validBatchReason(f, maxBatchHeldField) || strings.ContainsRune(f, ' ') {
			return errors.New("malformed host ID or fingerprint")
		}
	}
	if !validExecutionID(r.ExecutionID) {
		return errors.New("malformed execution ID")
	}
	if _, err := parseEndpoints(r.Endpoints); err != nil {
		return fmt.Errorf("endpoints: %w", err)
	}
	if r.HeldAtUnix <= 0 {
		return errors.New("missing hold time")
	}
	return nil
}

// readHeld reads and validates the held-target file at path; a missing
// file holds nothing.
func readHeld(path string) ([]heldRecord, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBatchHeldFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(raw) > maxBatchHeldFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBatchHeldFileBytes)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("file is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc heldDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	if doc.Version != batchHeldVersion {
		return nil, fmt.Errorf("unsupported version %d", doc.Version)
	}
	if len(doc.Targets) > maxBatchHeldTargets {
		return nil, fmt.Errorf("more than %d held targets", maxBatchHeldTargets)
	}
	seen := map[string]bool{}
	for i, r := range doc.Targets {
		if err := validRecord(r); err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		if seen[r.HostID] {
			return nil, fmt.Errorf("target %d: host held twice", i)
		}
		seen[r.HostID] = true
	}
	return doc.Targets, nil
}

// restoreHeld loads the persisted holds into x at startup. Without a data
// directory, or with a file that cannot be read or validated, the store is
// broken and every batch member is refused (fail closed).
func (s *Service) restoreHeld(x *batchExec) {
	if s.dataDir == "" {
		x.holdErr = errors.New("no executor data directory")
		s.log.Error("audit", "kind", "batch_hold_store_error", "detail", "no data directory: batch members are refused")
		return
	}
	x.holdPath = filepath.Join(s.dataDir, batchHeldFile)
	recs, err := readHeld(x.holdPath)
	if err != nil {
		x.holdErr = err
		s.log.Error("audit", "kind", "batch_hold_store_error", "detail", "held targets unreadable: batch members are refused: "+err.Error())
		return
	}
	for _, r := range recs {
		eps, _ := parseEndpoints(r.Endpoints) // validated by readHeld
		x.held[r.HostID] = &heldTarget{executionID: r.ExecutionID, heldAt: time.Unix(r.HeldAtUnix, 0), expired: r.Expired,
			call: &batchMemberCall{hostID: r.HostID, fingerprint: r.Fingerprint, endpoints: slices.Clone(r.Endpoints), eps: eps}}
		x.hosts[r.HostID] = r.ExecutionID
		s.log.Warn("audit", "kind", "batch_target_held_restored", "execution", r.ExecutionID, "host", r.HostID, "expired", r.Expired,
			"detail", "held before the restart: no batch member starts there until the target shows the run gone")
	}
}

// heldRecordsLocked returns the persisted form of x.held, sorted by host;
// skip, if set, is left out. x.mu is held.
func (x *batchExec) heldRecordsLocked(skip string) []heldRecord {
	out := make([]heldRecord, 0, len(x.held))
	for _, host := range slices.Sorted(maps.Keys(x.held)) {
		if host == skip {
			continue
		}
		h := x.held[host]
		out = append(out, heldRecord{HostID: host, Fingerprint: h.call.fingerprint, ExecutionID: h.executionID,
			Endpoints: slices.Clone(h.call.endpoints), HeldAtUnix: h.heldAt.Unix(), Expired: h.expired})
	}
	return out
}

// writeHeldLocked persists recs. x.mu is held.
func (x *batchExec) writeHeldLocked(recs []heldRecord) error {
	if x.holdErr != nil {
		return fmt.Errorf("%w: %w", ErrBatchHoldStore, x.holdErr)
	}
	if len(recs) > maxBatchHeldTargets {
		return fmt.Errorf("%w: more than %d held targets", ErrBatchHoldStore, maxBatchHeldTargets)
	}
	raw, err := json.Marshal(heldDocument{Version: batchHeldVersion, Targets: recs})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBatchHoldStore, err)
	}
	if len(raw) > maxBatchHeldFileBytes {
		return fmt.Errorf("%w: file exceeds %d bytes", ErrBatchHoldStore, maxBatchHeldFileBytes)
	}
	if err := x.writeHeld(x.holdPath, raw); err != nil {
		return fmt.Errorf("%w: %w", ErrBatchHoldStore, err)
	}
	return nil
}

// saveHeldLocked persists x.held; a failure marks the store dirty, and no
// batch member starts until a later save succeeds. x.mu is held.
func (s *Service) saveHeldLocked(x *batchExec) error {
	if err := x.writeHeldLocked(x.heldRecordsLocked("")); err != nil {
		x.holdDirty = true
		s.log.Error("audit", "kind", "batch_hold_store_error", "detail", err.Error())
		return err
	}
	x.holdDirty = false
	return nil
}

// holdStoreReady reports, as a refusal status, whether batch members may
// start: the held targets are persisted (a dirty store is written again
// first).
func (s *Service) holdStoreReady(x *batchExec) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.holdErr == nil && !x.holdDirty {
		return nil
	}
	return s.saveHeldLocked(x)
}

// holdExpiredLocked moves a hold older than batchHoldMax into its terminal
// expired state (persisted, audited) and reports whether it is expired.
// x.mu is held.
func (s *Service) holdExpiredLocked(x *batchExec, hostID string, h *heldTarget) bool {
	if h.expired {
		return true
	}
	if s.clock().Sub(h.heldAt) < batchHoldMax {
		return false
	}
	h.expired = true
	_ = s.saveHeldLocked(x) // a failure is audited and blocks all members
	s.log.Error("audit", "kind", "batch_target_hold_expired", "execution", h.executionID, "host", hostID,
		"detail", "held for the maximum time without the target showing the run gone; only an operator release (with the run gone) frees it")
	return true
}

// HeldBatchTargets lists the held targets, sorted by host.
func (s *Service) HeldBatchTargets() []HeldBatchTarget {
	x := s.batchRun
	if x == nil {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []HeldBatchTarget
	for _, r := range x.heldRecordsLocked("") {
		out = append(out, HeldBatchTarget{HostID: r.HostID, Fingerprint: r.Fingerprint, ExecutionID: r.ExecutionID,
			HeldAt: time.Unix(r.HeldAtUnix, 0), Expired: r.Expired, Running: x.held[r.HostID].running})
	}
	return out
}

// ReleaseHeldBatchTarget is the audited operator release of a held target
// (for example one whose hold expired). It is reserved for a future
// online operator release; today the only operator path is the offline
// rearm (RearmHeldBatchTarget). It names the exact hold (host and
// execution ID), the operator and a reason. It never frees a target whose
// run may still be there: the host must positively show the run gone now
// (any error, or the run seen, is ErrBatchTargetStillRunning and the
// target stays held). The release is persisted before the target is freed.
func (s *Service) ReleaseHeldBatchTarget(ctx context.Context, hostID, executionID, by, reason string) error {
	x := s.batchRun
	if x == nil {
		return ErrBatchTargetNotHeld
	}
	if !validBatchReason(by, maxBatchHoldReason) || !validBatchReason(reason, maxBatchHoldReason) {
		return ErrBatchHoldReason
	}
	x.mu.Lock()
	h := x.held[hostID]
	switch {
	case h == nil || h.executionID != executionID:
		x.mu.Unlock()
		return ErrBatchTargetNotHeld
	case h.checking || h.running:
		x.mu.Unlock()
		return ErrBatchHoldBusy
	}
	h.checking = true
	x.mu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, batchHoldRecheck)
	running, verr := s.remoteRunVisible(cctx, x, h.call, executionID)
	cancel()

	x.mu.Lock()
	defer x.mu.Unlock()
	h.checking = false
	if verr != nil || running {
		s.log.Warn("audit", "kind", "batch_target_release_refused", "execution", executionID, "host", hostID, "by", by, "reason", reason,
			"detail", "the target does not show the held run gone; it stays held")
		if verr != nil {
			return fmt.Errorf("%w: %w", ErrBatchTargetStillRunning, verr)
		}
		return ErrBatchTargetStillRunning
	}
	if x.held[hostID] != h {
		return ErrBatchTargetNotHeld
	}
	if err := x.writeHeldLocked(x.heldRecordsLocked(hostID)); err != nil {
		s.log.Error("audit", "kind", "batch_hold_store_error", "detail", err.Error())
		return err
	}
	delete(x.held, hostID)
	delete(x.hosts, hostID)
	s.log.Warn("audit", "kind", "batch_target_released_by_operator", "execution", executionID, "host", hostID, "by", by,
		"reason", reason, "expired", h.expired, "detail", "the target shows the held run gone")
	return nil
}

// Offline operator access to the held targets (`nebula-executor
// batch-holds`). It needs the open executor.db of the data directory:
// executordb.Open holds the directory's flock, so no executor runs on it
// and none can start and overwrite the file meanwhile. It reads and writes
// the file only through readHeld and the atomic write, never by hand.

// errOfflineHoldsLock: the caller does not hold the data directory.
var errOfflineHoldsLock = errors.New("batch: the held targets are changed only with the executor stopped and executor.db open")

// OfflineHeldBatchTargets lists the held targets in dataDir, sorted by
// host. db is the open executor.db of dataDir (see above).
func OfflineHeldBatchTargets(db *executordb.DB, dataDir string) ([]HeldBatchTarget, error) {
	if db == nil {
		return nil, errOfflineHoldsLock
	}
	recs, err := readHeld(filepath.Join(dataDir, batchHeldFile))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBatchHoldStore, err)
	}
	slices.SortFunc(recs, func(a, b heldRecord) int { return strings.Compare(a.HostID, b.HostID) })
	out := make([]HeldBatchTarget, 0, len(recs))
	for _, r := range recs {
		out = append(out, HeldBatchTarget{HostID: r.HostID, Fingerprint: r.Fingerprint, ExecutionID: r.ExecutionID,
			HeldAt: time.Unix(r.HeldAtUnix, 0), Expired: r.Expired})
	}
	return out, nil
}

// RearmHeldBatchTarget is the audited offline operator recovery of an
// expired hold (the exact hold: host and execution ID, with the operator
// and a reason). It never frees the target: it returns the hold to
// automatic rechecks, counted from now, so the executor frees the target
// once the host shows the run gone (rechecked before the next member
// starts there) and keeps it held otherwise. db is the open executor.db
// of dataDir (see above); the file is written atomically.
func RearmHeldBatchTarget(db *executordb.DB, dataDir, hostID, executionID, by, reason string, now time.Time, log *slog.Logger) error {
	if db == nil {
		return errOfflineHoldsLock
	}
	if !validBatchReason(by, maxBatchHoldReason) || !validBatchReason(reason, maxBatchHoldReason) {
		return ErrBatchHoldReason
	}
	path := filepath.Join(dataDir, batchHeldFile)
	recs, err := readHeld(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBatchHoldStore, err)
	}
	i := slices.IndexFunc(recs, func(r heldRecord) bool { return r.HostID == hostID && r.ExecutionID == executionID })
	switch {
	case i < 0:
		return ErrBatchTargetNotHeld
	case !recs[i].Expired:
		return ErrBatchHoldNotExpired
	}
	recs[i].Expired = false
	recs[i].HeldAtUnix = now.Unix()
	x := &batchExec{holdPath: path, writeHeld: writeFileAtomic}
	if err := x.writeHeldLocked(recs); err != nil {
		return err
	}
	log.Warn("audit", "kind", "batch_target_hold_rearmed_by_operator", "execution", executionID, "host", hostID, "by", by,
		"reason", reason, "detail", "the expired hold is rechecked again; the target is freed only once it shows the run gone")
	return nil
}

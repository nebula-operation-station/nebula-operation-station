// SPDX-License-Identifier: AGPL-3.0-or-later

// Package integritystore is the integrity findings store of ADR 0015 D9
// (plan IG-03). It keeps what the integrity checks observed, per subject
// (the NOS machine or one host), keyed by (subject, class, path).
//
// Findings are notes for the admin. The store never triggers an action:
// it has no hooks, it sends no notifications, it does not block jobs and
// it never restores or changes anything on a host. Record and Finish return
// counts only; the caller decides what to show or send, and the messages
// it sends must not carry host-supplied paths or content (D9).
//
// The store owns:
//
//   - runs: one check run of one subject at a time. A run is started with
//     BeginRun, observations are recorded into it, and it ends with Finish.
//   - closing: only Finish of a run that completed with nothing dropped
//     resolves findings, and only those of the same subject that the run
//     did not see. An incomplete run (or one that dropped an observation
//     because of a limit or an invalid path) closes nothing.
//   - states: open, expected_pending, accepted and resolved. Each change
//     records the run ID that made it (or the admin who accepted).
//   - severity: derived from the class (D9 table); when several classes
//     match one path, Escalate picks the class with the highest severity.
//   - paths: stored as the raw bytes the host reported. The escaped display
//     form is computed here by EscapePath; it is never taken from input.
//   - limits and retention: named limits below; over a limit an observation
//     is counted in Result and the run is marked as dropped, never silently
//     discarded. Prune applies the retention periods.
//
// Authentication and the audit log are the caller's job. Errors never
// contain host-supplied paths or record text.
package integritystore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// Limits and periods. They are enforced in this package and mirrored by
// CHECK constraints in the serverdb migration where SQLite can check them.
const (
	// MaxPathBytes bounds the raw path (bytes, not characters).
	MaxPathBytes = 4096
	// MaxRecordBytes bounds the old and the new record text of a finding.
	// A larger record is stored empty and counted in Result.RecordsDropped.
	MaxRecordBytes = 2048
	// MaxObservationsPerBatch bounds one Record call; a larger batch is
	// refused whole with ErrBatchTooLarge, so the caller splits it.
	MaxObservationsPerBatch = 1000
	// MaxFindingsPerSubject bounds the findings of one subject that are open
	// or expected_pending. Accepted findings do not count, so an admin's
	// Accept frees a slot; a new finding over the bound is counted in
	// Result.OverLimit. Accepted findings are only created by Accept.
	MaxFindingsPerSubject = 10000
	// MaxResolvedPerSubject bounds the resolved findings kept per subject. A
	// complete run that closes more deletes the oldest closed ones first, so
	// a host that rotates its reported paths cannot grow the table until the
	// retention of Prune.
	MaxResolvedPerSubject = 10000
	// ReservedCriticalSlots of MaxFindingsPerSubject are kept for critical
	// findings: a finding of any lower severity is refused once the subject
	// has MaxFindingsPerSubject - ReservedCriticalSlots active findings.
	ReservedCriticalSlots = 1000
	// AcceptValidity: an accepted finding re-opens this long after Accept
	// unless its records change first (ADR 0011 D6 default, 90 days).
	AcceptValidity = 90 * 24 * time.Hour
	// MaxRunDuration: a run not finished within this time is aborted and
	// closes nothing.
	MaxRunDuration = 6 * time.Hour
	// MaxActorBytes bounds the admin name recorded by Accept.
	MaxActorBytes = 128
	// RetainRecords: the record text of a resolved finding is cleared
	// 90 days after closing.
	RetainRecords = 90 * 24 * time.Hour
	// RetainResolved: resolved findings are deleted 365 days after closing
	// (ADR 0011 D6 pattern).
	RetainResolved = 365 * 24 * time.Hour
	// RetainRuns: finished runs are deleted 90 days after they ended.
	RetainRuns = 90 * 24 * time.Hour
)

// Sentinel errors; callers branch on them with errors.Is.
var (
	// ErrInvalidInput: a caller-supplied value fails its check.
	ErrInvalidInput = errors.New("invalid input")
	// ErrBatchTooLarge: more than MaxObservationsPerBatch observations.
	ErrBatchTooLarge = errors.New("batch exceeds observation limit")
	// ErrRunActive: the subject already has a running run.
	ErrRunActive = errors.New("a run is already running for this subject")
	// ErrRunNotFound: no run with that ID.
	ErrRunNotFound = errors.New("run not found")
	// ErrRunNotRunning: the run already finished or was aborted.
	ErrRunNotRunning = errors.New("run is not running")
	// ErrRunExpired: the run exceeded MaxRunDuration; it is now aborted.
	ErrRunExpired = errors.New("run exceeded its time limit and was aborted")
	// ErrFindingNotFound: no finding with that key.
	ErrFindingNotFound = errors.New("finding not found")
	// ErrWrongState: the finding is not in a state the operation applies to.
	ErrWrongState = errors.New("finding is in the wrong state for this operation")
)

// Subject is who a finding belongs to: the NOS machine or one host. Its
// stored form is "nos" or "host/<id>".
type Subject string

// NOSSubject is the NOS machine itself.
const NOSSubject Subject = "nos"

// hostIDRe is the host ID pattern used in the subject key.
var hostIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// HostSubject returns the subject of the host with ID id.
func HostSubject(id string) (Subject, error) {
	if !hostIDRe.MatchString(id) {
		return "", fmt.Errorf("host id: %w", ErrInvalidInput)
	}
	return Subject("host/" + id), nil
}

// validate checks that s is NOSSubject or a host subject.
func (s Subject) validate() error {
	if s == NOSSubject {
		return nil
	}
	if len(s) > len("host/")+63 || len(s) <= len("host/") || s[:5] != "host/" || !hostIDRe.MatchString(string(s[5:])) {
		return fmt.Errorf("subject %q: %w", string(s), ErrInvalidInput)
	}
	return nil
}

// Key identifies one finding: (subject, class, path). Path is the raw bytes
// the host reported.
type Key struct {
	Subject Subject
	Class   Class
	Path    []byte
}

// validate checks the parts of a key.
func (k Key) validate() error {
	if err := k.Subject.validate(); err != nil {
		return err
	}
	if _, err := k.Class.Severity(); err != nil {
		return err
	}
	if !pathOK(k.Path) {
		return fmt.Errorf("path: %w", ErrInvalidInput)
	}
	return nil
}

// State is the state of a finding (D9).
type State string

// States of a finding.
const (
	StateOpen            State = "open"
	StateExpectedPending State = "expected_pending"
	StateAccepted        State = "accepted"
	StateResolved        State = "resolved"
)

// Outcome is how a run ended, as Finish reports it.
type Outcome string

// Outcomes of a finished run.
const (
	// OutcomeComplete: the run saw the whole subject; it closed what it did
	// not see.
	OutcomeComplete Outcome = "complete"
	// OutcomeIncomplete: the run closed nothing (not complete, or it
	// dropped an observation).
	OutcomeIncomplete Outcome = "incomplete"
)

// Run is a started check run of one subject.
type Run struct {
	ID      string
	Subject Subject
}

// Observation is one finding reported by a run. Path and the records come
// from the host and are untrusted: they are checked, never interpreted.
type Observation struct {
	Class     Class
	Path      []byte
	OldRecord string
	NewRecord string
}

// Finding is a stored finding.
type Finding struct {
	Key
	Severity    Severity
	PathDisplay string
	OldRecord   string
	NewRecord   string
	State       State
	FirstSeen   time.Time
	LastSeen    time.Time
	// OpenedRunID is the run that opened the current episode; LastRunID the
	// last run that saw it.
	OpenedRunID string
	LastRunID   string
	// ClosedRunID and ClosedAt are set when the finding is resolved.
	ClosedRunID string
	ClosedAt    time.Time
	// StateRunID is the run that made the last run-driven state change
	// (empty for Accept). StateBy is the admin who accepted it.
	StateRunID string
	StateBy    string
	StateAt    time.Time
	// BasisOldRecord and BasisNewRecord are the records an accepted or
	// expected_pending finding was decided for; empty otherwise. A run that
	// sees other records reopens the finding.
	BasisOldRecord string
	BasisNewRecord string
	// ExpiresAt is when an accepted finding re-opens; zero otherwise.
	ExpiresAt time.Time
}

// Result counts what one Record call did. Nothing in it is silent: every
// observation is stored, merged, or counted here.
type Result struct {
	Inserted int
	Updated  int
	// Reopened: a resolved finding seen again, opened as a new episode; or an
	// accepted or expected_pending finding whose records changed or whose
	// acceptance expired, opened again as open. Reopening an accepted
	// finding is not refused by the limit: it stores no new row.
	Reopened int
	// Duplicates: observations with a key already in the same batch; the
	// later one wins.
	Duplicates int
	// OverLimit: new findings refused by MaxFindingsPerSubject.
	OverLimit int
	// PathRejected: paths empty, longer than MaxPathBytes or containing NUL.
	PathRejected int
	// RecordsDropped: records stored empty because they were longer than
	// MaxRecordBytes or not valid UTF-8 (the finding itself is stored).
	RecordsDropped int
}

// FinishResult reports how a run ended.
type FinishResult struct {
	Outcome Outcome
	// Closed: findings of the subject resolved by this run.
	Closed int
	// Dropped: observations the run could not store (see Result).
	Dropped int
}

// Config configures a Store.
type Config struct {
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// Store is the integrity findings store. It is safe for concurrent use:
// writes are serialized in process by mu and in the database by the write
// lock taken at the start of every write transaction.
type Store struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex
	// lost holds the runs whose Record failed after the batch may have been
	// lost and whose lost marker could not be written; Finish does not
	// complete them. Guarded by mu; an entry is removed when its run is
	// finished.
	lost map[string]bool
}

// New returns a store on db, which must carry the serverdb schema.
func New(db *sql.DB, cfg Config) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("integritystore: new: db is required: %w", ErrInvalidInput)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now, lost: make(map[string]bool)}, nil
}

// writeTx starts a write transaction that holds the database write lock
// before it reads: it bumps the lock row first.
func (s *Store) writeTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("integritystore: begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE integrity_store_state SET lock_counter = lock_counter + 1 WHERE id = 1`); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("integritystore: lock: %w", err)
	}
	return tx, nil
}

func unix(t time.Time) int64 { return t.UTC().Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

// pathOK reports whether a raw path is storable.
func pathOK(p []byte) bool {
	if len(p) == 0 || len(p) > MaxPathBytes {
		return false
	}
	for _, b := range p {
		if b == 0 {
			return false
		}
	}
	return true
}

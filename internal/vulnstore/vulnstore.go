// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnstore is the findings store of ADR 0011 (D2, D5, D6; plan
// VU-07): Hermes runs, findings upserted by the NOS-computed finding_key,
// run closures with their ordering and guards, held closures, human
// states, retention and staleness.
//
// The store trusts nothing Hermes says about state. It owns:
//
//   - run ordering: every run gets a strictly increasing run_seq at start;
//     every finding stores state_run_seq, the run_seq of the run that last
//     wrote it, and a run writes a finding only if its run_seq is at least
//     that (otherwise the write is dropped and counted as superseded);
//   - closures: only a completed run requests run closures, per subject it
//     fully covered, re-checking each subject's coverage watermark and
//     each finding's state_run_seq; planning, closures, the completed
//     state and the saved completion commit in one transaction, so a
//     complete that stops part-way applies nothing and a retry after a
//     restart reads the saved completion (CompletionOf);
//   - feed sources: judged one by one against NOS's fixed source list and
//     per-source high-water marks; a record resting on a source that is not
//     accepted, undated or on probation after an admin mark reset only
//     raises current values;
//   - episode high-water marks (fixed version, KEV, peak tier) that only
//     rise until the finding closes;
//   - human states (accepted_risk, false_positive), which no run changes.
//
// Authentication of callers (the hermes-vuln token, admin sessions with a
// fresh WebAuthn assertion) and the audit log are the caller's job; the
// store returns everything the caller needs to log. Store methods never
// return or log assessment text in errors.
package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Limits and defaults (ADR 0011 D5, D6 and the decisions of 2026-11-09).
const (
	// MaxRunDuration: a run not completed within 6 h of its start is
	// aborted and closes nothing (D5).
	MaxRunDuration = 6 * time.Hour
	// MaxInventoryAge: a run start whose inventory snapshot is older than
	// 24 h is rejected (D5).
	MaxInventoryAge = 24 * time.Hour
	// MaxFutureSkew: a content date beyond NOS's clock plus 10 minutes is
	// invalid (D5).
	MaxFutureSkew = 10 * time.Minute
	// MaxFindingsPerBatch and MaxFindingsPerRun are the D5 limits.
	MaxFindingsPerBatch = 1000
	MaxFindingsPerRun   = 200000
	// MaxCoveredPerBatch and MaxCoveredPerRun bound the subjects a run
	// claims to cover (D3 last_part). Each covered subject becomes a
	// closure plan, a write transaction at complete and a watermark row,
	// so a hostile batch must not name an unbounded number of them.
	MaxCoveredPerBatch = MaxFindingsPerBatch
	MaxCoveredPerRun   = 10000
	// MaxRunningPerToken: two concurrent runs per token (D5).
	MaxRunningPerToken = 2
	// MaxUnknownSourcesShown: unknown source IDs listed in a run report;
	// the rest are counted (D5).
	MaxUnknownSourcesShown = 16
	// MaxIgnoredListed bounds the ignored raise-only changes listed in one
	// run report; the rest are counted.
	MaxIgnoredListed = 256

	// StaleAfter: a subject whose last complete run is older is stale, and
	// Hermes is offline when no run completed for that long (D6, Q5).
	StaleAfter = 48 * time.Hour
	// RetainFixed: fixed findings are kept 365 days after closing (Q3).
	RetainFixed = 365 * 24 * time.Hour
	// RetainRuns: run records are kept 90 days after they ended (Q3).
	RetainRuns = 90 * 24 * time.Hour
	// RetainClosedAssessment: assessment text of a closed finding is kept
	// 90 days after closing (Q3).
	RetainClosedAssessment = 90 * 24 * time.Hour

	// MaxHumanReason bounds the reason of a human state or confirmation.
	MaxHumanReason = 1024
	// DefaultAcceptExpiry and MaxAcceptExpiry bound accepted_risk (Q4).
	DefaultAcceptExpiry = 90 * 24 * time.Hour
	MaxAcceptExpiry     = 365 * 24 * time.Hour

	// Guard thresholds (D5): more than half of the scope and at least
	// guardMinTotal closures overall, or more than half of one subject's
	// scope and at least guardMinSubject closures of that subject.
	guardMinTotal   = 20
	guardMinSubject = 10
	// WindowGuardSpan is the rolling window of the window guard (D5).
	WindowGuardSpan = 24 * time.Hour
)

// Sentinel errors; callers branch on them with errors.Is.
var (
	// ErrMalformedRun: a run start that names a source ID failing the
	// pattern, an ID twice, more sources than the list holds, or bad
	// metadata. The caller audits it with lengths and hashes only.
	ErrMalformedRun = errors.New("malformed run start")
	// ErrInventoryRegressed: the run's inventory generation is lower than
	// that of a run started before it (D5).
	ErrInventoryRegressed = errors.New("inventory generation lower than an earlier run's")
	// ErrInventoryTooOld: the inventory snapshot is older than
	// MaxInventoryAge.
	ErrInventoryTooOld = errors.New("inventory snapshot too old")
	// ErrTooManyRuns: the token already has MaxRunningPerToken runs open.
	ErrTooManyRuns = errors.New("too many concurrent runs for token")
	// ErrRunNotFound: no run with that ID.
	ErrRunNotFound = errors.New("run not found")
	// ErrRunNotRunning: the run already completed or was aborted.
	ErrRunNotRunning = errors.New("run is not running")
	// ErrRunExpired: the run exceeded MaxRunDuration; it is now aborted.
	ErrRunExpired = errors.New("run exceeded its time limit and was aborted")
	// ErrBatchConflict: a batch_seq repeated with a different body hash.
	ErrBatchConflict = errors.New("batch repeated with a different body")
	// ErrBatchTooLarge: more than MaxFindingsPerBatch records or
	// MaxCoveredPerBatch covered subjects, or the run would exceed
	// MaxFindingsPerRun or MaxCoveredPerRun.
	ErrBatchTooLarge = errors.New("batch exceeds finding limits")
	// ErrInvalidInput: a caller-supplied value fails its bound.
	ErrInvalidInput = errors.New("invalid input")
	// ErrFindingNotFound: no finding with that key.
	ErrFindingNotFound = errors.New("finding not found")
	// ErrWrongState: the finding is not in a state the operation applies to.
	ErrWrongState = errors.New("finding is in the wrong state for this operation")
	// ErrHoldNotFound: no held closure for that run and key.
	ErrHoldNotFound = errors.New("held closure not found")
	// ErrHoldSuperseded: the finding or subject changed since the hold; the
	// hold was dropped (closure path 6).
	ErrHoldSuperseded = errors.New("held closure superseded")
	// ErrContradicted: NOS's inventory contradicts the closure; it can never
	// become fixed (closure path 6).
	ErrContradicted = errors.New("closure contradicted by NOS inventory")
	// ErrResetRefused: a high-water mark reset that the D5 rules refuse
	// (source not listed, value not reported by the latest regressed run,
	// not below the mark, or beyond NOS's clock plus MaxFutureSkew).
	ErrResetRefused = errors.New("high-water mark reset refused")
)

// Tier is a D7 priority tier. The zero value is unknown.
type Tier int

// Tiers in rising order.
const (
	TierUnknown Tier = iota
	TierLow
	TierMedium
	TierHigh
	TierCritical
)

// TierFunc computes the D7 tier of a finding's current values. It is
// injected because D7 needs exposure and host criticality the store does
// not hold.
type TierFunc func(subject Subject, r vulnfinding.Record) Tier

// Class is the D5 closure class of a requested run closure.
type Class int

// Closure classes (D5).
const (
	// ClassUnconfirmed: NOS cannot confirm the closure.
	ClassUnconfirmed Class = iota + 1
	// ClassUnconfirmedUnchanged: unconfirmed, the finding has no episode
	// fixed version and NOS still sees the same basis version.
	ClassUnconfirmedUnchanged
	// ClassEvidenced: NOS's own complete inventory proves the fix (closure
	// rows 1 or 2).
	ClassEvidenced
	// ClassContradicted: NOS's inventory still shows the component below
	// the episode fixed version.
	ClassContradicted
)

// Classifier classifies a requested closure against NOS's current
// inventory (D5 closure classes). An error holds the closure.
type Classifier interface {
	Classify(ctx context.Context, f Finding) (Class, error)
}

// Source is one entry of NOS's fixed feed source list (D5). The list ships
// with NOS; it never comes from the API or Hermes.
type Source struct {
	ID string
	// MaxAge is the maximum snapshot age (D4, Q5): 72 h for daily feeds,
	// 30 days for vendor CSAF and offline bundles.
	MaxAge time.Duration
}

// Config configures a Store.
type Config struct {
	// Sources is NOS's fixed source list. Required.
	Sources []Source
	// Tier computes D7 tiers. Required.
	Tier TierFunc
	// Classifier classifies run closures. Required.
	Classifier Classifier
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// Store is the findings store. It is safe for concurrent use; writes are
// serialized in process and, through a lock row, across processes.
type Store struct {
	db       *sql.DB
	sources  map[string]Source
	tier     TierFunc
	classify Classifier
	now      func() time.Time
	mu       sync.Mutex
}

// sourceIDRe is the D5 source ID pattern (64 bytes at most).
var sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

// New returns a store on db, which must carry the serverdb schema.
func New(db *sql.DB, cfg Config) (*Store, error) {
	if db == nil || cfg.Tier == nil || cfg.Classifier == nil || len(cfg.Sources) == 0 {
		return nil, fmt.Errorf("vulnstore: new: db, sources, tier and classifier are required: %w", ErrInvalidInput)
	}
	src := make(map[string]Source, len(cfg.Sources))
	for _, s := range cfg.Sources {
		if !sourceIDRe.MatchString(s.ID) || s.MaxAge <= 0 {
			return nil, fmt.Errorf("vulnstore: new: source list entry: %w", ErrInvalidInput)
		}
		if _, dup := src[s.ID]; dup {
			return nil, fmt.Errorf("vulnstore: new: duplicate source %s: %w", s.ID, ErrInvalidInput)
		}
		src[s.ID] = s
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, sources: src, tier: cfg.Tier, classify: cfg.Classifier, now: now}, nil
}

// Subject identifies the subject of a finding.
type Subject struct {
	Kind        vulnfinding.SubjectKind
	ID          string
	ImageDigest string
}

// SubjectOf returns the subject of a record.
func SubjectOf(r vulnfinding.Record) Subject {
	return Subject{Kind: r.SubjectKind, ID: r.SubjectRef.ID, ImageDigest: r.SubjectRef.ImageDigest}
}

// String returns the stored subject key: kind/id or image/id/digest.
// Subject IDs and digests cannot contain '/', so the key is unambiguous.
func (s Subject) String() string {
	if s.Kind == vulnfinding.SubjectImage {
		return string(s.Kind) + "/" + s.ID + "/" + s.ImageDigest
	}
	return string(s.Kind) + "/" + s.ID
}

var (
	subjectIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func (s Subject) validate() error {
	if !subjectIDRe.MatchString(s.ID) {
		return fmt.Errorf("subject id: %w", ErrInvalidInput)
	}
	switch s.Kind {
	case vulnfinding.SubjectHost, vulnfinding.SubjectDevice:
		if s.ImageDigest != "" {
			return fmt.Errorf("subject digest: %w", ErrInvalidInput)
		}
	case vulnfinding.SubjectImage:
		if !imageDigestRe.MatchString(s.ImageDigest) {
			return fmt.Errorf("subject digest: %w", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("subject kind: %w", ErrInvalidInput)
	}
	return nil
}

// writeTx starts a write transaction that holds the database write lock
// before it reads: it bumps the lock row first.
func (s *Store) writeTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_store_state SET lock_counter = lock_counter + 1 WHERE id = 1`); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("lock: %w", err)
	}
	return tx, nil
}

func unix(t time.Time) int64 { return t.UTC().Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

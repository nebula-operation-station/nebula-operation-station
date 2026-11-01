// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dispatch executes claimed batch members exactly once.
//
// A member run is recorded durably before anything reaches the target. A
// definitive outcome is recorded when it is known; an uncertain outcome
// (the connection broke, the result is unknown) is terminal: the run is
// never dispatched again. Reconciliation of the remote job is the only way
// an uncertain run ends; retry or rollback needs a fresh exact-target
// approval.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
)

// Outcome classifies one member dispatch.
type Outcome string

// Outcomes a dispatch can end in.
const (
	// OutcomeSuccess means the target reported success.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure means the target reported failure; the outcome is
	// definitive.
	OutcomeFailure Outcome = "failure"
	// OutcomeUnknown means the outcome cannot be known: the remote
	// operation may have run. It is terminal and the run is never
	// redispatched.
	OutcomeUnknown Outcome = "unknown"
	// OutcomeNotExecuted means the intent was recorded but the permit was
	// revoked (lock, expiry, invalidation) before anything reached the
	// target. It is terminal: the run is never dispatched.
	OutcomeNotExecuted Outcome = "not_executed"
)

// ErrAlreadyDispatched means the run was dispatched or its dispatch intent
// was recorded before (in this process or an earlier one). It is never
// retried.
var ErrAlreadyDispatched = errors.New("dispatch: run already dispatched")

// ErrNotClaimed means no live claimed permit exists for the member: it was
// never claimed, or Lock, expiry, invalidation or a restart revoked it.
var ErrNotClaimed = errors.New("dispatch: no claimed member permit")

// ErrIntentRecorded is returned by Recorder.RecordIntent when the run's
// dispatch intent is already recorded, including from a process that died
// before its transport call.
var ErrIntentRecorded = errors.New("dispatch: intent already recorded")

// Run is one claimed member dispatch. Dispatch builds it from the member
// permit the batch authority holds for (parent, member ID); the caller
// names only which claimed member to run and chooses none of its content.
type Run struct {
	// ParentDigest is the hex digest of the approved parent batch.
	ParentDigest string
	// MemberID is the member's ID inside the parent plan.
	MemberID string
	// ExecutionID is the single-use execution ID claimed for the member.
	ExecutionID string
	// ActionID is the exact frozen action ID.
	ActionID string
	// Member is the exact frozen member: request, targets, credential
	// versions, preconditions and container/provider binding.
	Member canonical.BatchMember
	// Parameters are the member's canonical parameters as approved.
	Parameters []byte
}

// Permits is the batch authority's view of claimed member permits
// (batch.Authority implements it). A permit is gone once Lock, expiry,
// invalidation or a restart revoked it.
type Permits interface {
	Member(parent canonical.Digest, memberID string) (batch.MemberPermit, bool)
}

// The batch authority is the production Permits.
var _ Permits = (*batch.Authority)(nil)

// Recorder durably records dispatch intent and outcome for reconciliation.
// Implementations must be safe for concurrent use and must return
// ErrIntentRecorded from RecordIntent when an intent or outcome already
// exists for the execution ID, so a restarted executor can never
// redispatch a run.
type Recorder interface {
	// RecordIntent durably records that the member dispatch is starting,
	// before anything reaches the target.
	RecordIntent(ctx context.Context, run Run) error
	// RecordOutcome durably records the terminal outcome of a recorded
	// intent.
	RecordOutcome(ctx context.Context, run Run, outcome Outcome) error
}

// Transport executes one claimed member on its exact target. It returns a
// definitive Outcome (OutcomeSuccess or OutcomeFailure) with a nil error,
// or a non-nil error when the outcome is uncertain, for example because
// the connection broke mid-dispatch.
type Transport func(ctx context.Context, run Run) (Outcome, error)

// Event is an audit record for one dispatch decision.
type Event struct {
	// Time is the audit timestamp from the injected clock.
	Time time.Time
	// Kind is one of "dispatched", "uncertain", "not_executed", "refused".
	Kind string
	// ExecutionID is the run's single-use execution ID.
	ExecutionID string
	// Outcome is set once the run ended.
	Outcome Outcome
	// Detail is a human-readable reason for refused events.
	Detail string
}

// Options wires a Dispatcher.
type Options struct {
	// Permits is the batch authority holding claimed member permits.
	// Required.
	Permits Permits
	// Recorder is the durable intent/outcome store. Required.
	Recorder Recorder
	// Transport performs the actual member execution. Required.
	Transport Transport
	// Now is the audit clock; defaults to time.Now.
	Now func() time.Time
	// Log receives store errors; defaults to slog.Default().
	Log *slog.Logger
	// Audit receives dispatch decisions.
	Audit func(Event)
}

// Dispatcher enforces single-use dispatch of claimed member runs. The
// durable Recorder is the authority on whether a run was dispatched; the
// in-memory set only serializes runs that are in flight right now, so it
// is bounded by concurrency.
type Dispatcher struct {
	mu        sync.Mutex
	permits   Permits
	recorder  Recorder
	transport Transport
	now       func() time.Time
	log       *slog.Logger
	audit     func(Event)
	inFlight  map[string]bool
}

// New builds a Dispatcher from its options.
func New(o Options) (*Dispatcher, error) {
	if o.Permits == nil || o.Recorder == nil || o.Transport == nil {
		return nil, errors.New("dispatch: permits, recorder and transport are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Audit == nil {
		o.Audit = func(Event) {}
	}
	return &Dispatcher{
		permits:   o.Permits,
		recorder:  o.Recorder,
		transport: o.Transport,
		now:       o.Now,
		log:       o.Log,
		audit:     o.Audit,
		inFlight:  map[string]bool{},
	}, nil
}

// runFrom builds the run from a claimed permit; nothing in it comes from
// the caller.
func runFrom(mp batch.MemberPermit) Run {
	return Run{
		ParentDigest: mp.ParentDigest.String(), MemberID: mp.Member.MemberID, ExecutionID: mp.ExecutionID(),
		ActionID: mp.Member.Request.ActionID, Member: mp.Member, Parameters: slices.Clone(mp.Parameters),
	}
}

// samePermit reports whether the permit still held is the one the run was
// built from.
func samePermit(mp batch.MemberPermit, run Run) bool {
	return mp.ParentDigest.String() == run.ParentDigest && mp.Member.MemberID == run.MemberID &&
		mp.ExecutionID() == run.ExecutionID
}

// Dispatch executes the claimed member (parent, memberID) exactly once.
// The run is built from the live member permit; without one the call is
// refused with ErrNotClaimed before anything is recorded. The permit is
// checked again after the intent is durable and before the transport is
// called, so a Lock, expiry or invalidation in between ends the run as
// OutcomeNotExecuted. A second call for the same execution ID —
// concurrent, or after any outcome, in this process or after a restart —
// is refused with ErrAlreadyDispatched. An uncertain outcome comes back as
// OutcomeUnknown with the transport error.
func (d *Dispatcher) Dispatch(ctx context.Context, parent canonical.Digest, memberID string) (Outcome, error) {
	mp, ok := d.permits.Member(parent, memberID)
	if !ok {
		d.audit(Event{Time: d.now(), Kind: "refused", Detail: "no claimed member permit"})
		return OutcomeNotExecuted, ErrNotClaimed
	}
	run := runFrom(mp)
	if run.ExecutionID == "" {
		return OutcomeNotExecuted, errors.New("dispatch: execution ID is required")
	}
	d.mu.Lock()
	if d.inFlight[run.ExecutionID] {
		d.mu.Unlock()
		d.audit(Event{Time: d.now(), Kind: "refused", ExecutionID: run.ExecutionID, Detail: "run already in flight"})
		return OutcomeUnknown, fmt.Errorf("%w: %s", ErrAlreadyDispatched, run.ExecutionID)
	}
	d.inFlight[run.ExecutionID] = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.inFlight, run.ExecutionID)
		d.mu.Unlock()
	}()

	// Recorded durably before anything reaches the target: from here on a
	// crash is reconciled, never dispatched again.
	if err := d.recorder.RecordIntent(ctx, run); err != nil {
		if errors.Is(err, ErrIntentRecorded) {
			d.audit(Event{Time: d.now(), Kind: "refused", ExecutionID: run.ExecutionID,
				Detail: "intent already recorded; run not redispatched"})
			return OutcomeUnknown, fmt.Errorf("%w: %s", ErrAlreadyDispatched, run.ExecutionID)
		}
		d.log.Error("dispatch intent not recorded", "execution", run.ExecutionID, "detail", err.Error())
		return OutcomeNotExecuted, fmt.Errorf("dispatch %s: record intent: %w", run.ExecutionID, err)
	}
	// Outcomes are recorded even when the caller's context ended: that is
	// exactly when reconciliation needs them.
	octx := context.WithoutCancel(ctx)
	if cur, ok := d.permits.Member(parent, memberID); !ok || !samePermit(cur, run) {
		d.finish(octx, run, OutcomeNotExecuted)
		return OutcomeNotExecuted, fmt.Errorf("%w: revoked before dispatch: %s", ErrNotClaimed, run.ExecutionID)
	}
	outcome, err := d.transport(ctx, run)
	switch {
	case err != nil:
		outcome = OutcomeUnknown
	case outcome != OutcomeSuccess && outcome != OutcomeFailure:
		// A transport must report a definitive outcome or an error;
		// anything else is treated as uncertain.
		outcome = OutcomeUnknown
		err = fmt.Errorf("transport returned no definitive outcome")
	}
	d.finish(octx, run, outcome)
	if err != nil {
		return outcome, fmt.Errorf("dispatch %s: %w", run.ExecutionID, err)
	}
	return outcome, nil
}

// finish records the terminal outcome and audits it. A recording failure
// is logged; the run is consumed either way because its intent is durable.
func (d *Dispatcher) finish(ctx context.Context, run Run, outcome Outcome) {
	if err := d.recorder.RecordOutcome(ctx, run, outcome); err != nil {
		d.log.Error("dispatch outcome not recorded", "execution", run.ExecutionID, "detail", err.Error())
	}
	kind := "dispatched"
	switch outcome {
	case OutcomeUnknown:
		kind = "uncertain"
	case OutcomeNotExecuted:
		kind = "not_executed"
	}
	d.audit(Event{Time: d.now(), Kind: kind, ExecutionID: run.ExecutionID, Outcome: outcome})
}

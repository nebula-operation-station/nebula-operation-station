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
	"sync"
	"time"
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
)

// ErrAlreadyDispatched means the run was dispatched or its dispatch intent
// was recorded before (in this process or an earlier one). It is never
// retried.
var ErrAlreadyDispatched = errors.New("dispatch: run already dispatched")

// ErrIntentRecorded is returned by Recorder.RecordIntent when the run's
// dispatch intent is already recorded, including from a process that died
// before its transport call.
var ErrIntentRecorded = errors.New("dispatch: intent already recorded")

// Run identifies one claimed member dispatch. Every field comes from the
// executor's own claimed member permit; none is chosen by the caller at
// dispatch time.
type Run struct {
	// ParentDigest is the hex digest of the approved parent batch.
	ParentDigest string
	// MemberID is the member's ID inside the parent plan.
	MemberID string
	// ExecutionID is the single-use execution ID claimed for the member.
	ExecutionID string
	// Target is the exact frozen target identity (host ID or provider
	// resource).
	Target string
	// ActionID is the exact frozen action ID.
	ActionID string
}

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
	// Kind is one of "intent", "dispatched", "uncertain", "refused".
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

// Dispatcher enforces single-use dispatch of claimed member runs.
type Dispatcher struct {
	mu         sync.Mutex
	recorder   Recorder
	transport  Transport
	now        func() time.Time
	log        *slog.Logger
	audit      func(Event)
	inFlight   map[string]bool
	dispatched map[string]bool
}

// New builds a Dispatcher from its options.
func New(o Options) (*Dispatcher, error) {
	if o.Recorder == nil || o.Transport == nil {
		return nil, errors.New("dispatch: recorder and transport are required")
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
		recorder:   o.Recorder,
		transport:  o.Transport,
		now:        o.Now,
		log:        o.Log,
		audit:      o.Audit,
		inFlight:   map[string]bool{},
		dispatched: map[string]bool{},
	}, nil
}

// Dispatch executes run exactly once. A second call for the same execution
// ID — concurrent, or after a definitive or uncertain outcome, in this
// process or after a restart — is refused with ErrAlreadyDispatched. The
// returned Outcome is the definitive outcome when known; an uncertain
// outcome comes back as OutcomeUnknown with the transport error.
func (d *Dispatcher) Dispatch(ctx context.Context, run Run) (Outcome, error) {
	if run.ExecutionID == "" {
		return OutcomeUnknown, errors.New("dispatch: execution ID is required")
	}
	d.mu.Lock()
	if d.inFlight[run.ExecutionID] || d.dispatched[run.ExecutionID] {
		d.mu.Unlock()
		d.audit(Event{Time: d.now(), Kind: "refused", ExecutionID: run.ExecutionID, Detail: "run already dispatched"})
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
			d.markDispatched(run.ExecutionID)
			d.audit(Event{Time: d.now(), Kind: "refused", ExecutionID: run.ExecutionID,
				Detail: "intent already recorded; run not redispatched"})
			return OutcomeUnknown, fmt.Errorf("%w: %s", ErrAlreadyDispatched, run.ExecutionID)
		}
		d.log.Error("dispatch intent not recorded", "execution", run.ExecutionID, "detail", err.Error())
		return OutcomeUnknown, fmt.Errorf("dispatch %s: %w", run.ExecutionID, err)
	}
	outcome, err := d.transport(ctx, run)
	if err != nil || outcome == "" || outcome == OutcomeUnknown {
		outcome = OutcomeUnknown
	}
	if oerr := d.recorder.RecordOutcome(ctx, run, outcome); oerr != nil {
		// The remote operation may have run; the run is consumed either
		// way.
		d.log.Error("dispatch outcome not recorded", "execution", run.ExecutionID, "detail", oerr.Error())
	}
	d.markDispatched(run.ExecutionID)
	kind := "dispatched"
	if outcome == OutcomeUnknown {
		kind = "uncertain"
	}
	d.audit(Event{Time: d.now(), Kind: kind, ExecutionID: run.ExecutionID, Outcome: outcome})
	if err != nil {
		return outcome, fmt.Errorf("dispatch %s: %w", run.ExecutionID, err)
	}
	return outcome, nil
}

func (d *Dispatcher) markDispatched(executionID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dispatched[executionID] = true
}

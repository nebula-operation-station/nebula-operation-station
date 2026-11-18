// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// countLocked is the number of entries Propose checks against
// permit.MaxPending: live entries plus the pending-slot placeholders of
// rejected plans whose window has not ended (gcLocked drops ended ones).
func (a *Authority) countLocked() int { return len(a.entries) + len(a.placeholders) }

// batchIDFreshLocked refuses a batch ID that this process has seen or that
// a rejected marker of kind batch has spent (the only durable store of
// batch IDs). Both answer permit_wrong_state; admit runs it before the
// member work and Propose again before it binds execution IDs, so an
// identical rejected plan is refused here and never reaches
// bindExecutionIDs (execution_id_reused).
func (a *Authority) batchIDFreshLocked(batchID string) error {
	if _, ok := a.seen[batchID]; ok {
		return failure(permit.CodeWrongState, "batch ID already proposed; use a fresh plan")
	}
	if a.options.Rejections == nil {
		return nil
	}
	spent, err := a.options.Rejections.RejectedBatchID(batchID)
	if err != nil {
		return failure(permit.CodeStorage, "rejected-proposal store unavailable")
	}
	if spent {
		return failure(permit.CodeWrongState, "batch ID already proposed; use a fresh plan")
	}
	return nil
}

// approvableLocked is getLocked for approval and member derivation: the
// persisted rejected marker answers permit_rejected before the in-memory
// lookup, so a stale entry can never be approved or derived.
func (a *Authority) approvableLocked(d canonical.Digest, state permit.State) (*entry, error) {
	if a.options.Rejections != nil {
		_, rejected, err := a.options.Rejections.RejectedProposal(d)
		if err != nil {
			a.emit("batch_denied", d, permit.CodeStorage, "")
			return nil, failure(permit.CodeStorage, "rejected-proposal store unavailable")
		}
		if rejected {
			a.emit("batch_denied", d, permit.CodeRejected, "")
			return nil, failure(permit.CodeRejected, "the batch plan was rejected")
		}
	}
	return a.getLocked(d, state)
}

// PlanState reports the state of a live plan without changing it
// (GetPermitState for a batch digest). ok is false when there is none.
func (a *Authority) PlanState(d canonical.Digest) (permit.State, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcLocked()
	e, ok := a.entries[d]
	if !ok {
		return 0, false
	}
	return e.approval.State, true
}

// RejectPending rejects a pending execution permit of exec or a pending
// plan of b (b may be nil) by digest, following the three phases of spec
// 07 v29-07-01:
//
//  1. checks, nothing written: request limits, the privileged session for
//     the server role, the persisted marker (permit_already_rejected wins
//     over every other answer), then gcLocked of both authorities and the
//     in-memory lookup (permit_not_found, permit_already_approved);
//  2. one store transaction, the only fallible write: binding check,
//     marker row and signed event (storage_error, nothing changed);
//  3. infallible in-memory steps: delete the permit or plan with its
//     challenge and record the pending-slot placeholder.
//
// Lock order: b.mu first, then exec's mutex (permit.RejectTxn), held from
// the first check to the last delete. Both approval paths take the same
// mutex, so approval and rejection of one digest are serialised and the
// later one fails (permit_rejected or permit_already_approved).
func RejectPending(exec *permit.Authority, b *Authority, req permit.RejectRequest) (permit.Rejection, error) {
	reasonLen, err := req.Validate()
	if err != nil {
		return permit.Rejection{}, err
	}
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
	tx := exec.BeginReject()
	defer tx.End()
	refuse := func(code permit.Code, detail string) (permit.Rejection, error) {
		tx.Emit(permit.Event{Kind: "reject_refused", Digest: req.Digest.String(), Code: code, Detail: req.Who})
		return permit.Rejection{}, &permit.Error{Code: code, Detail: detail}
	}
	if req.Role == permit.RejectRoleServer && !tx.SessionActive() {
		return refuse(permit.CodeSessionRequired, "rejecting from the server needs an open privileged session")
	}
	store := tx.Store()
	if store == nil {
		return refuse(permit.CodeStorage, "executor state store unavailable")
	}
	if _, ok, err := store.RejectedProposal(req.Digest); err != nil {
		return refuse(permit.CodeStorage, "executor state store unavailable")
	} else if ok {
		return refuse(permit.CodeAlreadyRejected, "the proposal is already rejected")
	}

	tx.GC()
	if b != nil {
		b.gcLocked()
	}
	r := permit.Rejection{
		Digest:     req.Digest,
		Role:       req.Role,
		RejectedAt: tx.Now(),
		ReasonLen:  reasonLen,
	}
	if req.Role == permit.RejectRoleServer {
		r.RelayedUser = req.RelayedUser
		r.SessionCredentialID = tx.SessionCredentialID()
	}
	var bindings []permit.ExecutionBinding
	var batchEntry *entry
	if st, execID, end, ok := tx.Lookup(req.Digest); ok {
		if st != permit.StatePending {
			return refuse(permit.CodeAlreadyApproved, "the permit is already approved")
		}
		r.Kind, r.ID, r.WindowEnd = permit.ProposalExecution, execID, end
		bindings = []permit.ExecutionBinding{{ExecutionID: execID, Digest: req.Digest}}
	} else if e, ok := b.lookupLocked(req.Digest); ok {
		if e.approval.State != permit.StatePending {
			return refuse(permit.CodeAlreadyApproved, "the batch plan is already approved")
		}
		batchEntry = e
		r.Kind, r.ID, r.WindowEnd = permit.ProposalBatch, e.approval.Plan.BatchID, e.approval.ApprovalExpiry
		for _, m := range e.approval.Plan.Members {
			bindings = append(bindings, permit.ExecutionBinding{ExecutionID: m.Request.ExecutionID, Digest: req.Digest})
		}
	} else {
		return refuse(permit.CodeNotFound, "no pending proposal for the digest")
	}

	if err := store.CommitRejection(r, bindings); err != nil {
		return refuse(permit.CodeStorage, "executor state store unavailable")
	}

	// Committed: final. Only map deletions and one insertion follow.
	if batchEntry == nil {
		tx.Finish(req.Digest, r.WindowEnd)
	} else {
		b.finishRejectLocked(req.Digest, r.WindowEnd, b.options.Now())
	}
	return r, nil
}

// lookupLocked returns the live entry for d; a nil authority has none.
func (a *Authority) lookupLocked(d canonical.Digest) (*entry, bool) {
	if a == nil {
		return nil, false
	}
	e, ok := a.entries[d]
	return e, ok
}

// finishRejectLocked deletes a rejected pending plan with its challenge,
// returns its bytes to the budget and holds its count slot until end.
func (a *Authority) finishRejectLocked(d canonical.Digest, end, now time.Time) {
	a.removeLocked(d)
	if now.Before(end) {
		a.placeholders[d] = end
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Rejecting pending proposals (ADR 0007 amendment 2026-11-17, R1-R7; spec
// 07 v29-07-01). This file holds the execution-permit side and the types
// shared with the batch authority; the coordinator that spans both
// authorities is batch.RejectPending.
//
// Lock order. A rejection holds the batch authority's mutex and then this
// authority's mutex (batch.Authority.mu before permit.Authority.mu), from
// the first check to the last in-memory delete. That is the order the
// existing paths already use: batch Propose and batch SubmitAssertion call
// Options.Session (permit.Authority.Session, which takes this mutex) while
// they hold the batch mutex. Nothing in this package calls into the batch
// authority, so the order is acyclic.

// Failure codes of RejectPending and of approval paths that meet a
// rejected digest (spec 07, error table).
const (
	// CodeAlreadyRejected: RejectPending for a digest with a rejected
	// marker. It wins over every other digest answer.
	CodeAlreadyRejected Code = "permit_already_rejected"
	// CodeAlreadyApproved: RejectPending for an approved, in-use or
	// consumed permit or plan.
	CodeAlreadyApproved Code = "permit_already_approved"
	// CodeRejected: an approval path (SubmitAssertion, ApproveCLI, batch
	// approval, member derivation) for a rejected digest.
	CodeRejected Code = "permit_rejected"
)

// Input limits of RejectPending (spec 07 v29-07-01, "Reason" and
// "Executor RPC RejectPending").
const (
	MaxRejectReasonRunes = 200
	MaxRejectReasonBytes = 800
	MaxRelayedUserBytes  = 64
)

// RejectedEventKind is the kind of the signed event a rejection appends.
const RejectedEventKind = "permit.rejected"

// RejectRole is the caller role that rejected a proposal.
type RejectRole string

// Rejecting roles. Every other role is refused before any check.
const (
	RejectRoleServer RejectRole = "server"
	RejectRoleAdmin  RejectRole = "admin"
)

// ProposalKind names what a rejected digest identified.
type ProposalKind string

// Proposal kinds of the rejected_proposals table.
const (
	ProposalExecution ProposalKind = "execution"
	ProposalBatch     ProposalKind = "batch"
)

// RejectRequest is a validated-on-use RejectPending call. Role comes from
// the authenticated peer credentials, never from a request field.
type RejectRequest struct {
	Digest      canonical.Digest
	Reason      string
	RelayedUser string
	Role        RejectRole
	// Who names the caller for logs ("admin:uid1000").
	Who string
}

// Rejection is one rejected marker: a row of rejected_proposals plus the
// fields the signed event carries. It never holds the reason text.
type Rejection struct {
	Digest canonical.Digest
	Kind   ProposalKind
	// ID is the execution ID or the batch ID (unique per kind).
	ID   string
	Role RejectRole
	// WindowEnd is the end of the original approval window; the row is
	// pruned no earlier than RetainSpentExecutions after it.
	WindowEnd  time.Time
	RejectedAt time.Time
	// Event-only fields (not part of the marker row).
	RelayedUser         string
	SessionCredentialID []byte
	ReasonLen           int
}

// EventAttrs are the attributes of the signed permit.rejected event:
// digest, kind, ID, role, the server-claimed user, the executor-known
// session credential, time and the reason length, never the reason text.
func (r Rejection) EventAttrs() map[string]string {
	return map[string]string{
		"digest":                    r.Digest.String(),
		"proposal_kind":             string(r.Kind),
		"proposal_id":               r.ID,
		"role":                      string(r.Role),
		"relayed_user_server_claim": r.RelayedUser,
		"session_credential_id":     hex.EncodeToString(r.SessionCredentialID),
		"rejected_at":               r.RejectedAt.UTC().Format(time.RFC3339Nano),
		"approval_window_end":       r.WindowEnd.UTC().Format(time.RFC3339Nano),
		"reason_len":                strconv.Itoa(r.ReasonLen),
	}
}

// ExecutionBinding is an execution ID binding that a rejection checks
// (and never writes): Propose bound ID to Digest before the proposal
// existed.
type ExecutionBinding struct {
	ExecutionID string
	Digest      canonical.Digest
}

// RejectionStore persists rejected markers (table rejected_proposals in
// executor.db). The executordb implementation is a separate change; until
// an authority has one, RejectPending fails with storage_error and nothing
// can be rejected.
type RejectionStore interface {
	// RejectedProposal returns the marker for a digest.
	RejectedProposal(d canonical.Digest) (Rejection, bool, error)
	// RejectedBatchID reports whether a batch ID is spent by a marker of
	// kind batch.
	RejectedBatchID(batchID string) (bool, error)
	// CommitRejection runs one transaction that (1) checks every binding
	// exists in execution_ids and names its digest, (2) inserts the
	// marker row and (3) appends the signed event RejectedEventKind with
	// r.EventAttrs() to the event chain. It writes nothing to
	// execution_ids. On any error nothing is written.
	CommitRejection(r Rejection, bindings []ExecutionBinding) error
}

// ErrBindingMismatch is returned by a RejectionStore when a binding the
// rejection checks is missing or names another digest.
var ErrBindingMismatch = errors.New("permit: execution ID binding does not name the rejected digest")

// bidiControls are the Unicode bidirectional control characters.
func isBidiControl(r rune) bool {
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

func isControl(r rune) bool { return r < 0x20 || (r >= 0x7F && r <= 0x9F) }

// ValidateRejectReason checks the optional reason (spec 07 "Reason") and
// returns its length in code points.
func ValidateRejectReason(s string) (int, error) {
	if len(s) > MaxRejectReasonBytes {
		return 0, fail(CodeInvalidRequest, "reason longer than %d bytes", MaxRejectReasonBytes)
	}
	if !utf8.ValidString(s) {
		return 0, fail(CodeInvalidRequest, "reason is not valid UTF-8")
	}
	n := 0
	for _, r := range s {
		if isControl(r) || isBidiControl(r) {
			return 0, fail(CodeInvalidRequest, "reason contains a control character")
		}
		n++
	}
	if n > MaxRejectReasonRunes {
		return 0, fail(CodeInvalidRequest, "reason longer than %d characters", MaxRejectReasonRunes)
	}
	return n, nil
}

// ValidateRelayedUser checks relayed_user for role: required, 1-64 bytes
// of valid UTF-8 without control, bidirectional control or whitespace
// other than U+0020 from the server; empty from the admin.
func ValidateRelayedUser(role RejectRole, s string) error {
	switch role {
	case RejectRoleAdmin:
		if s != "" {
			return fail(CodeInvalidRequest, "relayed_user must be empty for the admin UID")
		}
		return nil
	case RejectRoleServer:
	default:
		return fail(CodeInvalidRequest, "role %q may not reject", role)
	}
	if s == "" || len(s) > MaxRelayedUserBytes {
		return fail(CodeInvalidRequest, "relayed_user must be 1 to %d bytes", MaxRelayedUserBytes)
	}
	if !utf8.ValidString(s) {
		return fail(CodeInvalidRequest, "relayed_user is not valid UTF-8")
	}
	for _, r := range s {
		if isControl(r) || isBidiControl(r) {
			return fail(CodeInvalidRequest, "relayed_user contains a control character")
		}
		if r != ' ' && (unicode.IsSpace(r) || unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp)) {
			return fail(CodeInvalidRequest, "relayed_user contains whitespace other than U+0020")
		}
	}
	return nil
}

// Validate checks the request limits (phase 1, step 1) and returns the
// reason length.
func (r RejectRequest) Validate() (int, error) {
	if err := ValidateRelayedUser(r.Role, r.RelayedUser); err != nil {
		return 0, err
	}
	return ValidateRejectReason(r.Reason)
}

// rejectedLocked refuses a digest that has a rejected marker. Every
// approval path calls it under a.mu before its in-memory lookup, so a
// stale in-memory entry can never be approved. Without a store nothing
// can have been rejected.
func (a *Authority) rejectedLocked(d canonical.Digest) error {
	if a.rejections == nil {
		return nil
	}
	_, ok, err := a.rejections.RejectedProposal(d)
	if err != nil {
		return a.storageFailure(d.String(), err)
	}
	if ok {
		a.emit(Event{Kind: "rejected", Digest: d.String(), Code: CodeRejected})
		return fail(CodeRejected, "the proposal was rejected")
	}
	return nil
}

// RejectionMarker returns the persisted marker for d (GetPermitState).
// ok is false without a store.
func (a *Authority) RejectionMarker(d canonical.Digest) (Rejection, bool, error) {
	if a.rejections == nil {
		return Rejection{}, false, nil
	}
	r, ok, err := a.rejections.RejectedProposal(d)
	if err != nil {
		return Rejection{}, false, fmt.Errorf("look up rejection %s: %w", d, err)
	}
	return r, ok, nil
}

// placeholdersLiveLocked is the number of pending-slot placeholders; the
// caller has run gcLocked, which drops the ended ones.
func (a *Authority) placeholdersLiveLocked() int { return len(a.placeholders) }

// RejectTxn holds the authority's mutex for one rejection. It exposes only
// what batch.RejectPending needs; End releases the mutex. A RejectTxn must
// be taken while the batch authority's mutex is held (or without a batch
// authority), never the other way round.
type RejectTxn struct {
	a   *Authority
	now time.Time
}

// BeginReject takes the authority's mutex and returns the transaction.
func (a *Authority) BeginReject() *RejectTxn {
	a.mu.Lock()
	return &RejectTxn{a: a, now: a.now()}
}

// End releases the mutex.
func (t *RejectTxn) End() { t.a.mu.Unlock() }

// Now is the time the transaction began.
func (t *RejectTxn) Now() time.Time { return t.now }

// Store is the authority's rejection store (nil if none).
func (t *RejectTxn) Store() RejectionStore { return t.a.rejections }

// SessionActive reports whether a privileged session is open.
func (t *RejectTxn) SessionActive() bool { return t.a.sessionActiveLocked(t.now) }

// SessionCredentialID is the credential ID of the assertion that opened
// the current privileged session (nil if none is open).
func (t *RejectTxn) SessionCredentialID() []byte {
	if !t.a.sessionActiveLocked(t.now) {
		return nil
	}
	return append([]byte(nil), t.a.sessionCred...)
}

// GC drops ended pending and approved permits and ended placeholders.
func (t *RejectTxn) GC() { t.a.gcLocked(t.now) }

// Lookup returns the live permit's state, execution ID and approval window
// end for d. ok is false when no permit is in memory.
func (t *RejectTxn) Lookup(d canonical.Digest) (state State, executionID string, windowEnd time.Time, ok bool) {
	p, ok := t.a.permits[d]
	if !ok {
		return 0, "", time.Time{}, false
	}
	return p.State, p.Request.ExecutionID, p.ApprovalExpiry, true
}

// Finish runs the infallible in-memory steps after a committed rejection:
// it deletes the pending permit with its challenge and records the
// pending-slot placeholder until windowEnd.
func (t *RejectTxn) Finish(d canonical.Digest, windowEnd time.Time) {
	a := t.a
	delete(a.permits, d)
	if t.now.Before(windowEnd) {
		a.placeholders[d] = windowEnd
	}
}

// Emit records an audit event through the authority's hook.
func (t *RejectTxn) Emit(e Event) { t.a.emit(e) }

// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"fmt"
	"unicode"
	"unicode/utf8"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Rejecting a pending proposal (ADR 0007 amendment R1-R7, spec 07
// v29-07-01). The executor decides: Reject calls its RejectPending RPC first
// and records the rejection on the server only after the executor answered
// success. A failed call changes nothing here.

const (
	// RejectReasonMaxRunes bounds the reason in Unicode code points.
	RejectReasonMaxRunes = 200
	// RejectReasonMaxBytes bounds the reason in bytes.
	RejectReasonMaxBytes = 800
	// relayedUserMaxBytes bounds the privileged session's user name the
	// server relays to the executor (spec 07: 1-64 bytes).
	relayedUserMaxBytes = 64
)

// CheckRejectReason validates an optional rejection reason with the rules of
// spec 07: at most 200 code points and 800 bytes, valid UTF-8, no control
// characters (C0, C1, DEL) and no bidirectional control characters. The
// empty reason is valid. A failure is a *ParamError (it names no text).
func CheckRejectReason(reason string) error {
	if len(reason) > RejectReasonMaxBytes {
		return &ParamError{Reason: fmt.Sprintf("the reason is longer than %d bytes", RejectReasonMaxBytes)}
	}
	if utf8.RuneCountInString(reason) > RejectReasonMaxRunes {
		return &ParamError{Reason: fmt.Sprintf("the reason is longer than %d characters", RejectReasonMaxRunes)}
	}
	if !utf8.ValidString(reason) {
		return &ParamError{Reason: "the reason is not valid UTF-8"}
	}
	for _, r := range reason {
		if isControlOrBidi(r) {
			return &ParamError{Reason: "the reason contains a control or bidirectional character"}
		}
	}
	return nil
}

// checkRelayedUser validates the user name relayed to the executor: 1-64
// bytes, valid UTF-8, no control or bidirectional characters and no
// whitespace other than U+0020 (spec 07).
func checkRelayedUser(user string) error {
	if len(user) == 0 || len(user) > relayedUserMaxBytes || !utf8.ValidString(user) {
		return &ParamError{Reason: "the user name cannot be used for this request"}
	}
	for _, r := range user {
		if isControlOrBidi(r) || (unicode.IsSpace(r) && r != ' ') {
			return &ParamError{Reason: "the user name cannot be used for this request"}
		}
	}
	return nil
}

// isControlOrBidi reports whether r is a C0, C1 or DEL control character or
// one of the bidirectional controls LRM, RLM, ALM, LRE..RLO, LRI..PDI.
func isControlOrBidi(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// rejectDetail is the detail text of a rejected execution. The reason, when
// given, follows it; it is rendered as text only.
func rejectDetail(reason string) string {
	if reason == "" {
		return "rejected; nothing was run"
	}
	return "rejected; nothing was run. Reason: " + reason
}

// Reject rejects a pending execution on the executor and records it
// rejected. The user is the browser's privileged session user, relayed to the
// executor and audited; reason is optional. The executor refuses the call
// unless its privileged session is open (ADR 0007), and every refusal is
// returned unchanged so the caller can show it. An execution that is not
// pending on the server is refused with ErrNotPending before the executor is
// asked.
func (s *Service) Reject(ctx context.Context, user, id, reason string) error {
	if err := CheckRejectReason(reason); err != nil {
		return err
	}
	if err := checkRelayedUser(user); err != nil {
		return err
	}
	e, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if e.State != "pending" {
		return ErrNotPending
	}
	if e.Digest == "" {
		return &ParamError{Reason: "the operation has no proposal digest to reject"}
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := s.exec.RejectPending(cctx, &pb.RejectPendingRequest{Digest: e.Digest, Reason: reason, RelayedUser: user}); err != nil {
		return err
	}
	ok, err := s.markRejected(ctx, id, rejectDetail(reason))
	if err != nil {
		// The executor has rejected the proposal and the server could not
		// record it. The next CheckCLIApproval or sweep reads the executor's
		// REJECTED state and records it then.
		return fmt.Errorf("record rejection of execution %s: %w", id, err)
	}
	if !ok {
		// Stopped being pending meanwhile (the sweep or another request):
		// the executor's answer stands, nothing is dispatched here.
		s.log.Warn("audit", "kind", "execution_rejection_not_recorded", "execution", id, "user", user)
		return ErrNotPending
	}
	s.log.Info("audit", "kind", "execution_rejected", "execution", id, "digest", e.Digest,
		"user", user, "reason_len", utf8.RuneCountInString(reason))
	return nil
}

// markRejected moves a pending execution to 'rejected' with a guarded update
// and sets its waiting host rows to finished/not_executed, in one
// transaction. It reports whether this call moved the execution; false means
// it was no longer pending and nothing changed.
func (s *Service) markRejected(ctx context.Context, id, detail string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	now := s.now().Unix()
	res, err := tx.ExecContext(ctx, `UPDATE executions SET state = 'rejected', detail = ?, finished_at = ?
		WHERE id = ? AND state = 'pending'`, detail, now, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE execution_hosts SET state = 'finished', class = 'not_executed',
		detail = ?, finished_at = ? WHERE execution_id = ? AND state = 'waiting'`, detail, now, id); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// recordCLIRejection records a rejection the executor reports for a pending
// execution (rejected on the executor host with `nebula reject`, or a server
// rejection whose record was lost). The executor's answer carries no reason.
func (s *Service) recordCLIRejection(ctx context.Context, id, digest string, role pb.RejectingRole) error {
	ok, err := s.markRejected(ctx, id, "rejected on the executor host; nothing was run")
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	kind := "execution_rejected_on_cli"
	if role != pb.RejectingRole_REJECTING_ROLE_ADMIN {
		kind = "execution_rejected"
	}
	s.log.Info("audit", "kind", kind, "execution", id, "digest", digest)
	return nil
}

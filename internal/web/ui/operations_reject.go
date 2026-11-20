// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// Reject pending proposals from the operations overview (ADR 0007 amendment
// R1-R7, spec 07 v29-07-01). Only a privileged session may reject: the
// executor's privileged session must be open and this web session must be
// the one that opened it (pvePrivileged, the rule of the PVE links). Without
// it the pages answer 403 and the list shows no reject control. A rejection
// needs no security key: it only removes authority, and the executor refuses
// it without the open session. Like abort, the form POST is refused by the
// security middleware without this server's Origin, each row is answered on
// its own, and each rejection is audited by executions.Service.Reject.

const (
	// rejectFormMax bounds the reject form body: 100 IDs of 36 bytes plus an
	// escaped reason of at most 800 bytes (at most 3 bytes per byte once
	// escaped) fit with room to spare.
	rejectFormMax = 16 << 10
	// rejectNotPrivileged is the 403 text when no privileged session is open.
	rejectNotPrivileged = "rejecting needs an open privileged session opened from this login: open one on the dashboard and try again"
	// rejectNotFoundText is the row text for an executor NotFound (spec 07).
	rejectNotFoundText = "No longer pending on the executor (expired, or the executor was locked or restarted)"
	// rejectExecutorMsgMax bounds the executor's refusal text in bytes.
	rejectExecutorMsgMax = 300
	// rejectOutcomeUnknownText is the row text when the executor's answer was
	// lost: it may have rejected the proposal, and the sweep checks it again.
	rejectOutcomeUnknownText = "outcome unknown - the executor may have rejected it; it is checked again"
)

// boundedText returns s cut to at most max bytes, at a rune boundary, after
// replacing invalid UTF-8 (the executor's text is untrusted input and is
// rendered as text only).
func boundedText(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// rejectData is the page data of the reject confirmation and result.
type rejectData struct {
	Rows []abortRow
	// Submit: the confirmation form has at least one row to submit.
	Submit bool
	// Result: the page reports what the POST did.
	Result bool
}

// rejectPrivileged reports whether the executor's privileged session is open
// and this web session holds it. It is the rule the PVE links use.
func (h *Handler) rejectPrivileged(ctx context.Context) bool {
	return h.pvePrivileged(ctx)
}

// handleOperationRejectConfirm shows which of the selected operations would be
// rejected and collects the optional reason. It is a GET and changes nothing.
func (h *Handler) handleOperationRejectConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if !h.rejectPrivileged(ctx) {
		http.Error(w, rejectNotPrivileged, http.StatusForbidden)
		return
	}
	ids, ok := abortSelection(w, r.URL.Query()["id"])
	if !ok {
		return
	}
	data := &rejectData{}
	for _, id := range ids {
		row := abortRowLabel(id)
		e, err := h.operations.Get(ctx, id)
		switch {
		case errors.Is(err, executions.ErrNotFound):
			row.Message = "operation not found"
		case err != nil:
			h.log.Error("reject confirm: get", "error", err.Error())
			row.Message = "operation unavailable"
		case e.State != "pending":
			row.Message = "not waiting for approval"
		default:
			row.Abortable = true
			data.Submit = true
		}
		data.Rows = append(data.Rows, row)
	}
	h.renderReject(w, r, data)
}

// handleOperationRejectForm rejects the selected pending proposals, one row
// at a time, and reports each row. The reason is checked once for the whole
// request (executions.CheckRejectReason); an invalid reason refuses the
// request before the executor is asked.
func (h *Handler) handleOperationRejectForm(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if !h.rejectPrivileged(ctx) {
		http.Error(w, rejectNotPrivileged, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, rejectFormMax)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	ids, ok := abortCount(w, r.PostForm["id"])
	if !ok {
		return
	}
	reason := r.PostForm.Get("reason")
	if err := executions.CheckRejectReason(reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data := &rejectData{Result: true}
	for _, id := range ids {
		if !abortIDRe.MatchString(id) {
			data.Rows = append(data.Rows, abortRow{Message: "invalid operation id"})
			continue
		}
		row := abortRowLabel(id)
		rctx, rcancel := context.WithTimeout(r.Context(), operationsCallTimeout)
		err := h.operations.Reject(rctx, webUser(r), id, reason)
		rcancel()
		if err != nil {
			row.Message = h.rejectRowMessage(err)
		} else {
			row.Message = "rejected"
		}
		data.Rows = append(data.Rows, row)
	}
	h.renderReject(w, r, data)
}

// rejectRowMessage says why one rejection failed. Executor refusals are shown
// as the executor said them (bounded); anything else is a fixed text and goes
// to the log.
func (h *Handler) rejectRowMessage(err error) string {
	var pe *executions.ParamError
	switch {
	case errors.Is(err, executions.ErrNotFound):
		return "operation not found"
	case errors.Is(err, executions.ErrNotPending):
		return "not waiting for approval any more"
	case errors.Is(err, executions.ErrRejectUnavailable):
		return "rejecting is not available on this server"
	case errors.Is(err, executions.ErrRejectOutcomeUnknown):
		h.log.Warn("reject proposal: outcome unknown", "error", err.Error())
		return rejectOutcomeUnknownText
	case errors.As(err, &pe):
		return pe.Reason
	}
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.NotFound:
		// RejectPending answers NotFound for permit_not_found (spec 07: never
		// proposed, window ended, or dropped by lock or restart).
		return rejectNotFoundText
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.AlreadyExists:
		return "the executor refused: " + boundedText(st.Message(), rejectExecutorMsgMax)
	default:
		h.log.Error("reject proposal", "error", err.Error())
		return "executor unavailable; nothing was rejected"
	}
}

// renderReject renders the confirmation or the result page.
func (h *Handler) renderReject(w http.ResponseWriter, r *http.Request, d *rejectData) {
	h.render(w, r, pageData{Title: "Reject proposal", Active: "operations", Content: "operations_reject",
		Ops: &operationsData{Reject: d}})
}

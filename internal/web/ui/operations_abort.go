// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// Abort staged rollouts from the operations overview. The list marks the
// rows that can be aborted (the detail page's rule, executions.Abortable);
// a row's button or the multi-select opens a confirmation page (GET, no
// change). Only its form POST aborts: the security middleware refuses a
// POST without this server's Origin, and each abort is audited with the
// user by executions.Service.Abort. Without JavaScript every step is a
// plain link or form.

const (
	// abortSelectionMax bounds the operations one request names.
	abortSelectionMax = 100
	// abortFormMax bounds the abort form body (100 IDs of 36 bytes and
	// the field names fit with room to spare).
	abortFormMax = 4 << 10
	// abortReasonWant is the reason a row cannot be aborted here: the
	// detail page's rule.
	abortReasonWant = "only a running staged rollout that is neither stopped nor aborted"
)

// abortIDRe matches an operation ID as the executions service makes it
// (lower-case UUID). Anything else is refused before the service sees it.
var abortIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// abortRow is one operation on the confirmation or result page.
type abortRow struct {
	// ID is empty for a malformed ID, which is never echoed.
	ID, Short string
	// Abortable: the row is submitted with the confirmation form.
	Abortable bool
	// Message is the reason a row is not offered (confirmation), or the
	// result of its abort (result page).
	Message string
}

// abortData is the page data of the confirmation and the result.
type abortData struct {
	Rows []abortRow
	// Submit: the confirmation form has at least one row to submit.
	Submit bool
	// Result: the page reports what the POST did.
	Result bool
}

// uniqueIDs keeps the first occurrence of each ID, in order.
func uniqueIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// abortRowLabel fills the display fields of a row for a valid ID.
func abortRowLabel(id string) abortRow {
	return abortRow{ID: id, Short: id[:8]}
}

// handleOperationAbortConfirm shows which of the selected operations
// would be aborted. It is a GET and changes nothing.
func (h *Handler) handleOperationAbortConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	ids, ok := abortSelection(w, r.URL.Query()["id"])
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	can, err := h.operations.Abortable(ctx, ids)
	if err != nil {
		// Without the executor's view nothing is offered.
		h.log.Error("abort confirm: abortable", "error", err.Error())
		can = map[string]bool{}
	}
	data := &abortData{}
	for _, id := range ids {
		row := abortRowLabel(id)
		if can[id] {
			row.Abortable = true
			data.Submit = true
		} else {
			row.Message = abortReasonWant
		}
		data.Rows = append(data.Rows, row)
	}
	h.renderAbort(w, r, data)
}

// handleOperationAbortForm aborts the selected staged rollouts, one row
// at a time, and reports each row. A row that cannot be aborted gets its
// own error, in the wording of the staged endpoints.
func (h *Handler) handleOperationAbortForm(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, abortFormMax)
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
	data := &abortData{Result: true}
	for _, id := range ids {
		if !abortIDRe.MatchString(id) {
			data.Rows = append(data.Rows, abortRow{Message: "invalid operation id"})
			continue
		}
		row := abortRowLabel(id)
		ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
		err := h.operations.Abort(ctx, webUser(r), id)
		cancel()
		if err != nil {
			row.Message = h.abortRowMessage("abort rollout", err)
		} else {
			row.Message = "aborted"
		}
		data.Rows = append(data.Rows, row)
	}
	h.renderAbort(w, r, data)
}

// abortSelection validates a list of operation IDs from a query: at
// least one, at most abortSelectionMax distinct, each well formed. A
// failed check writes the 400 response and reports false. The result has
// the duplicates removed.
func abortSelection(w http.ResponseWriter, raw []string) ([]string, bool) {
	ids, ok := abortCount(w, raw)
	if !ok {
		return nil, false
	}
	for _, id := range ids {
		if !abortIDRe.MatchString(id) {
			http.Error(w, "invalid operation id", http.StatusBadRequest)
			return nil, false
		}
	}
	return ids, true
}

// abortCount checks only how many operations a request names; the IDs
// themselves are checked row by row by the caller.
func abortCount(w http.ResponseWriter, raw []string) ([]string, bool) {
	ids := uniqueIDs(raw)
	switch {
	case len(ids) == 0:
		http.Error(w, "name at least one operation", http.StatusBadRequest)
		return nil, false
	case len(ids) > abortSelectionMax:
		http.Error(w, "too many operations in one request", http.StatusBadRequest)
		return nil, false
	}
	return ids, true
}

// abortRowMessage says why one abort failed. Executor refusals are shown
// as the executor said them (bounded); anything else is a fixed text and
// goes to the log, as in stagedError and executorRefusal.
func (h *Handler) abortRowMessage(op string, err error) string {
	var pe *executions.PlanError
	switch {
	case errors.Is(err, executions.ErrNotFound):
		return "operation not found"
	case errors.Is(err, executions.ErrNotStaged), errors.Is(err, executions.ErrNotRunning), errors.Is(err, executions.ErrNoRetry):
		return err.Error()
	case errors.As(err, &pe):
		return err.Error()
	}
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.ResourceExhausted, codes.AlreadyExists, codes.NotFound:
		msg := st.Message()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return "the executor refused: " + msg
	default:
		h.log.Error(op, "error", err.Error())
		return "executor unavailable"
	}
}

// renderAbort renders the confirmation or the result page.
func (h *Handler) renderAbort(w http.ResponseWriter, r *http.Request, d *abortData) {
	h.render(w, r, pageData{Title: "Abort rollout", Active: "operations", Content: "operations_abort",
		Ops: &operationsData{Abort: d}})
}

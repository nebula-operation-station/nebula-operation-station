// SPDX-License-Identifier: AGPL-3.0-or-later
// GET /operations/{id}/status: the read-only JSON the in-place run UI
// (web/static/runop.js, job ui5) polls while an operation runs: the
// operation's state and the per-host state counts. Nothing beyond that —
// no host output, no parameters, no fingerprints. GET only; it changes
// nothing, so it needs no approval and no privileged session.

package ui

import (
	"context"
	"errors"
	"net/http"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// handleOperationStatus answers the status poll. Only operations that
// exist get a 200; everything else is a JSON error.
func (h *Handler) handleOperationStatus(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	e, err := h.operations.Get(ctx, r.PathValue("id"))
	switch {
	case err == nil:
		byState := map[string]int{}
		for _, host := range e.Hosts {
			byState[host.State]++
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":    e.ID,
			"state": e.State,
			"hosts": map[string]any{"total": len(e.Hosts), "by_state": byState},
		})
	case errors.Is(err, executions.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "operation not found")
	default:
		h.log.Error("operation status", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "operations unavailable")
	}
}

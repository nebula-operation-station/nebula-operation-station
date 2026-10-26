// SPDX-License-Identifier: AGPL-3.0-or-later
// GET /privileged/session: whether a privileged session is open on the
// executor, as JSON for the in-place run UI (web/static/runop.js, job
// ui5). It reads the same GetStatus the dashboard uses; it opens nothing
// (POST /privileged/begin + /privileged/finish stay the only way).

package ui

import (
	"context"
	"net/http"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// handlePrivilegedSession answers the session check. Without a status
// provider (no executor wired) it says the session is not active and the
// executor unavailable; the client then falls back to the dashboard flow.
func (h *Handler) handlePrivilegedSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	if h.status == nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false, "available": false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st, err := h.status.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		h.log.Error("privileged session check", "error", err)
		writeJSON(w, http.StatusOK, map[string]any{"active": false, "available": false})
		return
	}
	out := map[string]any{"active": st.GetPrivilegedSessionActive(), "available": true}
	if st.GetPrivilegedSessionActive() {
		out["expiry_unix"] = st.GetPrivilegedSessionExpiryUnix()
	}
	writeJSON(w, http.StatusOK, out)
}

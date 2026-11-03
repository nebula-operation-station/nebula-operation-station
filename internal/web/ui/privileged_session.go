// SPDX-License-Identifier: AGPL-3.0-or-later
// GET /privileged/session: whether a privileged session is open on the
// executor, as JSON. It reads the same GetStatus the dashboard uses; it
// opens nothing (POST /privileged/begin + /privileged/finish stay the only
// way).
//
// Two clients read it: the in-place run UI (web/static/runop.js, job ui5)
// uses active/available, and the topbar session display
// (web/static/nav.js, ADR 0007 E20) renders the computed display
// (internal/web/ui/session.View) the server adds to every answer. The
// display client sends the state it shows as ?prev= so the server can
// tell an expired session from one that never existed; it polls with
// auth.PassiveHeader so the poll is not recorded as activity.

package ui

import (
	"context"
	"net/http"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/session"
)

// privilegedSessionResponse is the JSON answer of GET /privileged/session.
type privilegedSessionResponse struct {
	Active     bool  `json:"active"`
	Available  bool  `json:"available"`
	ExpiryUnix int64 `json:"expiry_unix,omitempty"`
	session.View
}

// handlePrivilegedSession answers the session check. Without a status
// provider (no executor wired) it says the session is not active and the
// executor unavailable; the client then falls back to the dashboard flow.
func (h *Handler) handlePrivilegedSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	// Unrecognised or missing values are StateUnknown (session.ParseState).
	prev := session.ParseState(r.URL.Query().Get("prev"))
	var p session.Poll
	if h.status != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		st, err := h.status.GetStatus(ctx, &pb.GetStatusRequest{})
		if err != nil {
			h.log.Error("privileged session check", "error", err)
		} else {
			p = session.Poll{Available: true, Active: st.GetPrivilegedSessionActive()}
			if p.Active {
				p.ExpiryUnix = st.GetPrivilegedSessionExpiryUnix()
			}
		}
	}
	writeJSON(w, http.StatusOK, privilegedSessionResponse{
		Active:     p.Active,
		Available:  p.Available,
		ExpiryUnix: p.ExpiryUnix,
		View:       session.Display(prev, p, h.clockNow()),
	})
}

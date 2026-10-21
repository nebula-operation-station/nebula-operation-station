// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// audit logs one line per inventory change: the kind, the host ID and
// the web user.
func (h *Handler) audit(r *http.Request, kind, hostID string) {
	user := "unknown"
	if s, ok := auth.SessionFrom(r.Context()); ok {
		user = s.UserName
	}
	h.log.Info("audit", "kind", kind, "host", hostID, "user", user)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// answerDecodeError turns a decodeHostRequest error into a response:
// an oversized body is 413, anything else (bad JSON, unknown fields,
// bad endpoint) is 400 with the input-describing text.
func answerDecodeError(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeJSONError(w, http.StatusBadRequest, err.Error())
}

// deleteRequest is the JSON body of the delete endpoint.
type deleteRequest struct {
	ID string `json:"id"`
}

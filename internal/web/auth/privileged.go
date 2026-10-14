// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"google.golang.org/grpc/codes"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Privileged session and lock from the dashboard (M2, spec 05). They need a
// web session; the privileged session itself is held by the executor and
// opened only with a user-verified assertion that the executor verifies.
//
//	POST /privileged/begin   -> executor BeginPrivilegedSession
//	POST /privileged/finish  -> executor CompletePrivilegedSession
//	POST /executor/lock      -> executor Lock (session ended, permits revoked, keys wiped)

func (h *Handler) privilegedBegin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), executorCallTimeout)
	defer cancel()
	b, err := h.exec.BeginPrivilegedSession(ctx, &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		h.relayError(w, "begin_privileged_session", err, nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": json.RawMessage(b.GetRequestOptionsJson())})
}

func (h *Handler) privilegedFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), executorCallTimeout)
	defer cancel()
	res, err := h.exec.CompletePrivilegedSession(ctx, &pb.CompletePrivilegedSessionRequest{AssertionJson: req.Assertion})
	if err != nil {
		h.relayError(w, "complete_privileged_session", err, map[codes.Code]string{
			codes.PermissionDenied:   "security key not accepted",
			codes.Unauthenticated:    "security key not accepted",
			codes.InvalidArgument:    "security key not accepted",
			codes.FailedPrecondition: "challenge expired, try again",
			codes.NotFound:           "challenge expired, try again",
		})
		return
	}
	sess, _ := SessionFrom(r.Context())
	h.log.Info("audit", "kind", "privileged_session_opened", "user", sess.UserName, "credential", sess.CredentialID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "expiry_unix": res.GetSessionExpiryUnix()})
}

func (h *Handler) executorLock(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), executorCallTimeout)
	defer cancel()
	if _, err := h.exec.Lock(ctx, &pb.LockRequest{}); err != nil {
		h.relayError(w, "lock", err, nil)
		return
	}
	sess, _ := SessionFrom(r.Context())
	h.log.Info("audit", "kind", "executor_locked_from_web", "user", sess.UserName, "credential", sess.CredentialID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

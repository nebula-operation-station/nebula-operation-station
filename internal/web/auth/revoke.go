// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// A web session ends when the credential that opened it is removed on the
// executor (`nebula webauthn remove`). The server asks the executor at most
// once per CredentialCheckInterval per session.
const (
	CredentialCheckInterval = 5 * time.Minute
	maxTrackedChecks        = 10000
)

type credentialChecks struct {
	mu   sync.Mutex
	last map[[sha256.Size]byte]time.Time
}

// credentialStillRegistered reports false only when the executor says the
// session's credential is gone. If the executor cannot be asked, the
// session stays (reading only; every privileged action is verified by the
// executor against its own credentials) and the check is repeated on the
// next request.
func (h *Handler) credentialStillRegistered(ctx context.Context, token string, sess Session) bool {
	key := sha256.Sum256([]byte(token))
	now := h.sessions.now()
	h.checks.mu.Lock()
	if h.checks.last == nil {
		h.checks.last = map[[sha256.Size]byte]time.Time{}
	}
	last, ok := h.checks.last[key]
	h.checks.mu.Unlock()
	if ok && now.Sub(last) < CredentialCheckInterval {
		return true
	}
	cctx, cancel := context.WithTimeout(ctx, executorCallTimeout)
	defer cancel()
	res, err := h.exec.CheckCredential(cctx, &pb.CheckCredentialRequest{CredentialId: sess.CredentialID})
	if err != nil {
		h.log.Warn("credential check failed; session kept", "error", err)
		return true
	}
	h.checks.mu.Lock()
	defer h.checks.mu.Unlock()
	if !res.GetRegistered() {
		delete(h.checks.last, key)
		return false
	}
	if len(h.checks.last) >= maxTrackedChecks {
		for k, t := range h.checks.last {
			if now.Sub(t) >= CredentialCheckInterval {
				delete(h.checks.last, k)
			}
		}
	}
	h.checks.last[key] = now
	return true
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

// The executor's privileged session is executor-wide: the executor does not
// report which web user opened it. The server therefore records the web
// session that opened it through POST /privileged/finish (the holder):
// the hash of that session's token, its credential and user, and the
// expiry the executor reported for exactly that privileged session.
// Actions that must be taken only by the user who opened the privileged
// session (PVE guest links) ask HoldsPrivilegedSession; who may open a
// privileged session is unchanged (the executor decides).
//
// The record lives in memory only: after a server restart nobody holds the
// session until it is opened again from the web (fail closed). It ends
// when the executor expiry passes, when the executor is locked from the
// web, when the holding web session logs out, and when that session's
// credential is removed. A privileged session opened or reopened outside
// the web (another expiry) is not the holder's: callers pass the expiry
// the executor reports now and it must equal the recorded one.

// holder is the recorded opener of the executor's privileged session. The
// zero value is "nobody".
type holder struct {
	set          bool
	tokenHash    [sha256.Size]byte
	credentialID string
	user         string
	expiry       time.Time
}

// holderState guards the record.
type holderState struct {
	mu  sync.Mutex
	rec holder
}

// holderCtx is what Wrap attaches to an authenticated request: the
// handler (for its record and clock) and the request's own session.
type holderCtx struct {
	h         *Handler
	tokenHash [sha256.Size]byte
	sess      Session
}

type holderCtxKey struct{}

// withHolderCtx attaches the holder view of an authenticated request.
func (h *Handler) withHolderCtx(ctx context.Context, token string, sess Session) context.Context {
	return context.WithValue(ctx, holderCtxKey{}, holderCtx{h: h, tokenHash: sessionKey(token), sess: sess})
}

func sessionKey(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }

// recordHolder makes the web session of token the holder of the executor
// privileged session that ends at expiryUnix. An expiry not in the future
// clears the record.
func (h *Handler) recordHolder(token string, sess Session, expiryUnix int64) {
	exp := time.Unix(expiryUnix, 0)
	h.holder.mu.Lock()
	defer h.holder.mu.Unlock()
	if expiryUnix <= 0 || !h.sessions.now().Before(exp) {
		h.holder.rec = holder{}
		return
	}
	h.holder.rec = holder{set: true, tokenHash: sessionKey(token), credentialID: sess.CredentialID,
		user: sess.UserName, expiry: exp}
}

// clearHolder ends the record unconditionally (executor lock).
func (h *Handler) clearHolder() {
	h.holder.mu.Lock()
	h.holder.rec = holder{}
	h.holder.mu.Unlock()
}

// clearHolderOf ends the record if the web session of token holds it
// (logout, credential removed).
func (h *Handler) clearHolderOf(token string) {
	key := sessionKey(token)
	h.holder.mu.Lock()
	defer h.holder.mu.Unlock()
	if h.holder.rec.set && subtle.ConstantTimeCompare(h.holder.rec.tokenHash[:], key[:]) == 1 {
		h.holder.rec = holder{}
	}
}

// currentHolder returns the record, cleared first if its expiry passed.
func (h *Handler) currentHolder() (holder, bool) {
	h.holder.mu.Lock()
	defer h.holder.mu.Unlock()
	if !h.holder.rec.set {
		return holder{}, false
	}
	if !h.sessions.now().Before(h.holder.rec.expiry) {
		h.holder.rec = holder{}
		return holder{}, false
	}
	return h.holder.rec, true
}

// PrivilegedHolder reports the credential and user of the web session that
// opened the executor's current privileged session from the web, if one is
// recorded and its expiry has not passed. ctx must be an authenticated
// request's context (Wrap); otherwise ok is false. It is informational: to
// authorise an action use HoldsPrivilegedSession.
func PrivilegedHolder(ctx context.Context) (credentialID, user string, ok bool) {
	hc, found := ctx.Value(holderCtxKey{}).(holderCtx)
	if !found || hc.h == nil {
		return "", "", false
	}
	rec, ok := hc.h.currentHolder()
	if !ok {
		return "", "", false
	}
	return rec.credentialID, rec.user, true
}

// HoldsPrivilegedSession reports whether the authenticated request of ctx
// comes from the very web session that opened the executor's privileged
// session, with the same credential, and whether that privileged session
// is the one the executor reports now: executorExpiryUnix (the executor's
// current privileged_session_expiry_unix) must equal the recorded expiry,
// which must not have passed. Callers must also check that the executor
// reports the session active. Outside the login chain it is false.
func HoldsPrivilegedSession(ctx context.Context, executorExpiryUnix int64) bool {
	hc, found := ctx.Value(holderCtxKey{}).(holderCtx)
	if !found || hc.h == nil || executorExpiryUnix <= 0 {
		return false
	}
	rec, ok := hc.h.currentHolder()
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(rec.tokenHash[:], hc.tokenHash[:]) == 1 &&
		rec.credentialID == hc.sess.CredentialID &&
		rec.expiry.Unix() == executorExpiryUnix
}

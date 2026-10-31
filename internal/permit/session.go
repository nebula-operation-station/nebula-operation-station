// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	// MinSessionLength is the shortest executor-local privileged session.
	MinSessionLength = 15 * time.Minute
	// MaxSessionLength is the longest executor-local privileged session.
	MaxSessionLength = 240 * time.Minute

	sessionExtensionDomain = "nebula-session-extension-v1\x00"

	// SessionExtensionOperation names the operation bound into the
	// session-extension challenge. The same operation opens an expired
	// session as well (spec 05).
	SessionExtensionOperation = "session_extension"
)

func normalizeSessionLength(length time.Duration) (time.Duration, error) {
	if length == 0 {
		return DefaultSessionLength, nil
	}
	if length < MinSessionLength || length > MaxSessionLength {
		return 0, fmt.Errorf("permit: session length must be between %s and %s", MinSessionLength, MaxSessionLength)
	}
	return length, nil
}

// sessionChallenge binds this operation, the executor's configured duration,
// the challenge deadline and a fresh nonce. Other approval domains cannot be
// interpreted as a session extension, including when reopening an expired one.
func sessionChallenge(nonce [32]byte, length time.Duration, expiry time.Time) []byte {
	preimage := append([]byte(sessionExtensionDomain), nonce[:]...)
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(length))
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(expiry.UnixNano()))
	digest := sha256.Sum256(preimage)
	return digest[:]
}

// beginSessionPolicy prepares a single-use session-extension challenge.
func (a *Authority) beginSessionPolicy() ([]byte, time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, time.Time{}, fmt.Errorf("permit: create session challenge: %w", err)
	}
	a.sessChalExp = a.now().Add(SessionChallengeTTL)
	a.sessChal = sessionChallenge(nonce, a.sessLen, a.sessChalExp)
	return slices.Clone(a.sessChal), a.sessChalExp, nil
}

// completeSessionPolicy opens or extends a session after one UV assertion.
func (a *Authority) completeSessionPolicy(assertionJSON []byte) (time.Time, error) {
	// Keep verification and its durable counter update serialized with Lock.
	// If verification wins, Lock subsequently clears the new session. If Lock
	// wins, there is no pending challenge for the assertion to complete.
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, exp := a.sessChal, a.sessChalExp
	a.sessChal, a.sessChalExp = nil, time.Time{}
	if ch == nil {
		return time.Time{}, a.sessionFailureLocked(CodeNoChallenge, "call BeginPrivilegedSession first")
	}
	if !a.now().Before(exp) {
		return time.Time{}, a.sessionFailureLocked(CodeExpired, "session challenge expired")
	}
	credID, err := a.verifier.Verify(assertionJSON, ch, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return time.Time{}, a.storageFailure("", err)
	}
	if err != nil {
		return time.Time{}, a.sessionFailureLocked(CodeAssertionRejected, err.Error())
	}
	// Verification may block on storage. Recheck its deadline and use the
	// approval time, rather than the time before verification, for expiry.
	now := a.now()
	if !now.Before(exp) {
		return time.Time{}, a.sessionFailureLocked(CodeExpired, "session challenge expired")
	}
	kind := "session_opened"
	if a.sessionActiveLocked(now) {
		kind = "session_extended"
	}
	a.sessionTill = now.Add(a.sessLen)
	a.emit(Event{Time: now, Kind: kind, Detail: fmt.Sprintf("webauthn:%s duration=%s expiry=%s", hex.EncodeToString(credID), a.sessLen, a.sessionTill.Format(time.RFC3339Nano))})
	return a.sessionTill, nil
}

func (a *Authority) sessionFailureLocked(code Code, detail string) error {
	a.emit(Event{Kind: "rejected", Code: code, Detail: "privileged session: " + detail})
	return fail(code, "%s", detail)
}

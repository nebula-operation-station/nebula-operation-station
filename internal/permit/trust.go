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

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Trusting an artifact from the browser (M7-4). Trust lowers the
// executor's minimum risk for exactly these bytes as this action and
// version, so it needs a fresh user-verified assertion over a challenge
// bound to (artifact hash, action, version, risk), inside the privileged
// session; hardened mode keeps it on the CLI (`nebula artifact trust`).
// The executor hashes the bytes itself; the server only names them.

// MaxPendingTrusts bounds trust requests waiting for the security key.
const MaxPendingTrusts = 16

// PendingTrust is a trust request waiting for its assertion.
type PendingTrust struct {
	ID            string
	SHA256        string
	ActionID      string
	ModuleVersion string
	Risk          canonical.Risk
	Label         string
	Challenge     []byte
	Expiry        time.Time
}

func trustChallenge(t PendingTrust) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("permit: nonce: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("nebula-artifact-trust-v1\x00"))
	for _, s := range []string{t.SHA256, t.ActionID, t.ModuleVersion, string(t.Risk)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	h.Write(nonce[:])
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(t.Expiry.Unix()))
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// BeginTrust hashes artifact and returns a challenge for trusting it as
// actionID at version with risk.
// label is stored with the trust (the caller checks it).
func (a *Authority) BeginTrust(artifact []byte, actionID, version string, risk canonical.Risk, label string) (PendingTrust, error) {
	if len(artifact) == 0 || len(artifact) > MaxArtifactSize {
		return PendingTrust{}, fail(CodeArtifactMismatch, "artifact size %d outside 1..%d", len(artifact), MaxArtifactSize)
	}
	if !canonical.ValidActionID(actionID) || !canonical.ValidModuleVersion(version) || risk.Rank() == 0 {
		return PendingTrust{}, fail(CodeInvalidRequest, "action, version or risk is malformed")
	}
	sum := sha256.Sum256(artifact)
	a.observe(sum, artifact)
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcTrustsLocked(now)
	if a.mode == ModeHardened {
		return PendingTrust{}, fail(CodeCLIRequired, "hardened mode: trust artifacts with nebula artifact trust on the executor host")
	}
	if !a.sessionActiveLocked(now) {
		return PendingTrust{}, fail(CodeSessionRequired, "trusting an artifact needs an active privileged session")
	}
	if len(a.trusts) >= MaxPendingTrusts {
		return PendingTrust{}, fail(CodeLimit, "too many pending trust requests")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return PendingTrust{}, fmt.Errorf("permit: id: %w", err)
	}
	t := PendingTrust{ID: hex.EncodeToString(id[:]), SHA256: hex.EncodeToString(sum[:]), ActionID: actionID, ModuleVersion: version,
		Risk: risk, Label: label, Expiry: now.Add(ApprovalWindow)}
	ch, err := trustChallenge(t)
	if err != nil {
		return PendingTrust{}, err
	}
	t.Challenge = ch
	a.trusts[t.ID] = &t
	a.emit(Event{Kind: "artifact_trust_requested", Digest: t.SHA256, Detail: fmt.Sprintf("%s@%s as %s", actionID, version, risk)})
	out := t
	out.Challenge = slices.Clone(ch)
	return out, nil
}

// CommitTrust checks the assertion for a pending trust request and returns
// it with who approved it; the caller stores the trust. The request is
// consumed whether or not the assertion verifies.
func (a *Authority) CommitTrust(id string, assertionJSON []byte) (PendingTrust, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcTrustsLocked(now)
	t, ok := a.trusts[id]
	if !ok {
		return PendingTrust{}, "", fail(CodeNotFound, "no pending trust request with this ID")
	}
	delete(a.trusts, id)
	if a.mode == ModeHardened {
		return PendingTrust{}, "", fail(CodeCLIRequired, "hardened mode: use nebula artifact trust")
	}
	if !a.sessionActiveLocked(now) {
		return PendingTrust{}, "", fail(CodeSessionRequired, "trusting an artifact needs an active privileged session")
	}
	credID, err := a.verifier.Verify(assertionJSON, t.Challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return PendingTrust{}, "", a.storageFailure(t.SHA256, err)
	}
	if err != nil {
		a.emit(Event{Kind: "rejected", Digest: t.SHA256, Code: CodeAssertionRejected, Detail: "artifact trust: " + err.Error()})
		return PendingTrust{}, "", fail(CodeAssertionRejected, "%v", err)
	}
	// The store keeps at most 64 bytes of actor: the credential ID's
	// first 16 bytes name it well enough for the audit trail.
	return *t, "webauthn:" + hex.EncodeToString(credID[:min(len(credID), 16)]), nil
}

func (a *Authority) gcTrustsLocked(now time.Time) {
	for id, t := range a.trusts {
		if !now.Before(t.Expiry) {
			delete(a.trusts, id)
		}
	}
}

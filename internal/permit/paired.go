// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Paired enrollment permit (ADR 0013 D4, spec 05 v25-05-01 and v25-05-02).
//
// The executor proposes it after its own constant-time match of the
// pairing code against the key presented at the endpoint. It is always
// HIGH with user verification: in Standard mode it is approved by a
// user-verified browser assertion inside the privileged session or by
// `nebula approve`, in hardened mode only by `nebula approve`. It binds
// every field of canonical.PairedEnroll; the commit must present exactly
// that binding and consumes the permit (single use). One offer gets at
// most one permit for the lifetime of the process, so a permit that
// expired, was consumed or was revoked by Lock can never be replayed or
// re-proposed for the same offer. Paired permits are never persisted: a
// restart revokes them (the executor's offer state machine refuses a second
// pairing of the same offer across restarts).

// Paired permit limits.
const (
	// MaxPendingPaired bounds paired permits waiting for approval.
	MaxPendingPaired = 16
	// MaxPairedOffers bounds the offers remembered as spent; when the table
	// is full no further paired permit is proposed until a restart.
	MaxPairedOffers = 65536
)

// Failure codes specific to paired permits.
const (
	// CodeBindingMismatch: the commit presented a binding that differs from
	// the approved one in at least one field.
	CodeBindingMismatch Code = "binding_mismatch"
	// CodeReplay: the permit was already used, or the offer already had a
	// paired permit.
	CodeReplay Code = "permit_replayed"
)

// pairedChallengeDomain separates paired permit challenges from every
// other challenge the executor issues.
const pairedChallengeDomain = "nebula-paired-enroll-v1\x00"

// PairedPermit is one paired enrollment permit.
type PairedPermit struct {
	Digest canonical.Digest
	// Binding is the normalized binding the approval covers.
	Binding canonical.PairedEnroll
	// Canonical is the RFC 8785 form of Binding; Digest is its SHA-256.
	Canonical      []byte
	Requirement    Requirement
	State          State
	Challenge      []byte
	ApprovalExpiry time.Time
	ApprovedAt     time.Time
	ApprovedBy     string

	failed int
}

// Risk is the risk class of a paired permit: always HIGH.
func (p *PairedPermit) Risk() canonical.Risk { return canonical.RiskHigh }

func (p *PairedPermit) clone() PairedPermit {
	c := *p
	c.Canonical = slices.Clone(p.Canonical)
	c.Challenge = slices.Clone(p.Challenge)
	return c
}

// pairedRequirement is the approval requirement of a paired permit: HIGH
// with user verification, CLI only in hardened mode.
func pairedRequirement(mode Mode) Requirement {
	r := RequirementFor(canonical.RiskHigh, mode)
	if r < RequireAssertionVerified {
		return RequireAssertionVerified
	}
	return r
}

// pairedChallenge returns SHA-256(domain || digest || 32-byte nonce ||
// expiry as big-endian int64 Unix seconds).
func pairedChallenge(d canonical.Digest, expiry time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("permit: nonce: %w", err)
	}
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h := sha256.New()
	h.Write([]byte(pairedChallengeDomain))
	h.Write(d[:])
	h.Write(nonce[:])
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// ProposePaired registers a paired enrollment permit for b. The executor
// calls it only after its own code match. Proposing the identical binding
// again while its permit is pending returns that permit; any other binding
// for an offer that already had a paired permit is refused, as is any
// proposal after that permit ended (expired, consumed, discarded or
// revoked by Lock).
func (a *Authority) ProposePaired(b canonical.PairedEnroll) (PairedPermit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcPairedLocked(now)

	norm, canon, digest, err := canonical.CanonicalizePairedEnroll(b, now)
	if err != nil {
		return PairedPermit{}, fail(CodeInvalidRequest, "%v", err)
	}
	if prev, seen := a.pairedOffers[norm.OfferIDHash]; seen {
		if p, live := a.paired[prev]; live && prev == digest && p.State == StatePending {
			return p.clone(), nil
		}
		a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeReplay, Detail: "paired permit: offer already had a permit"})
		return PairedPermit{}, fail(CodeReplay, "offer already had a paired enrollment permit; create a new offer")
	}
	if a.pairedPendingCountLocked() >= MaxPendingPaired {
		return PairedPermit{}, fail(CodeLimit, "too many pending paired enrollment permits")
	}
	if len(a.pairedOffers) >= MaxPairedOffers {
		return PairedPermit{}, fail(CodeLimit, "paired offer table full; restart the executor")
	}
	p := &PairedPermit{
		Digest:         digest,
		Binding:        norm,
		Canonical:      canon,
		Requirement:    pairedRequirement(a.mode),
		State:          StatePending,
		ApprovalExpiry: minTime(now.Add(ApprovalWindow), time.Unix(norm.ExpiryUnix, 0)),
	}
	if p.Challenge, err = pairedChallenge(digest, p.ApprovalExpiry); err != nil {
		return PairedPermit{}, err
	}
	a.paired[digest] = p
	a.pairedOffers[norm.OfferIDHash] = digest
	a.emit(Event{Kind: "proposed", Digest: digest.String(), Host: norm.HostID, Detail: "paired enrollment: " + p.Requirement.String()})
	return p.clone(), nil
}

// IsPaired reports whether d names a paired enrollment permit the
// authority knows: pending, approved or already used. The executor uses it
// to route a browser approval (SubmitAssertion with the permit digest) to
// SubmitPairedAssertion instead of the execution-permit path.
func (a *Authority) IsPaired(d canonical.Digest) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.paired[d]; ok {
		return true
	}
	_, spent := a.pairedSpent[d]
	return spent
}

// SubmitPairedAssertion approves a pending paired permit with a WebAuthn
// assertion over its challenge. User verification is always required, and
// the privileged session must be open. Hardened mode refuses it.
func (a *Authority) SubmitPairedAssertion(d canonical.Digest, assertionJSON []byte) (PairedPermit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	p, err := a.pairedPendingLocked(d, now)
	if err != nil {
		return PairedPermit{}, err
	}
	if p.Requirement == RequireCLI || a.mode == ModeHardened {
		return PairedPermit{}, a.rejectPaired(p, CodeCLIRequired, "hardened mode: use nebula approve")
	}
	if !a.sessionActiveLocked(now) {
		return PairedPermit{}, a.rejectPaired(p, CodeSessionRequired, "browser approval needs an active privileged session")
	}
	credID, err := a.verifier.Verify(assertionJSON, p.Challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return PairedPermit{}, a.storageFailure(d.String(), err)
	}
	if err != nil {
		p.failed++
		rerr := a.rejectPaired(p, CodeAssertionRejected, "%v", err)
		if p.failed >= MaxFailedAssertions {
			delete(a.paired, d)
			a.emit(Event{Kind: "rejected", Digest: d.String(), Code: CodeLimit, Detail: "too many failed approvals, paired permit discarded"})
		}
		return PairedPermit{}, rerr
	}
	p.State = StateApproved
	p.Challenge = nil // single use
	p.ApprovedAt = now
	p.ApprovedBy = "webauthn:" + hex.EncodeToString(credID)
	a.emit(Event{Kind: "approved", Digest: d.String(), Host: p.Binding.HostID, Detail: p.ApprovedBy})
	return p.clone(), nil
}

// ApprovePairedCLI approves a pending paired permit from `nebula approve`.
// The caller has established that the peer is an admin UID on the
// executor host. It is accepted in both modes.
func (a *Authority) ApprovePairedCLI(d canonical.Digest, who string) (PairedPermit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	p, err := a.pairedPendingLocked(d, now)
	if err != nil {
		return PairedPermit{}, err
	}
	p.State = StateApproved
	p.Challenge = nil
	p.ApprovedAt = now
	p.ApprovedBy = "cli:" + who
	a.emit(Event{Kind: "approved", Digest: d.String(), Host: p.Binding.HostID, Detail: p.ApprovedBy})
	return p.clone(), nil
}

// ConsumePaired checks the binding a commit presents against the approved
// paired permit d and, if every field is equal, consumes the permit and
// returns it. A permit is consumed at most once. A presented binding that
// differs in any field discards the permit: the commit must not be retried
// with other values.
func (a *Authority) ConsumePaired(d canonical.Digest, presented canonical.PairedEnroll) (PairedPermit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	p, ok := a.paired[d]
	if !ok {
		a.gcPairedLocked(now)
		if _, spent := a.pairedSpent[d]; spent {
			return PairedPermit{}, a.denyPaired(d, "", CodeReplay, "paired permit already used")
		}
		return PairedPermit{}, a.denyPaired(d, "", CodeNotFound, "")
	}
	host := p.Binding.HostID
	if p.State != StateApproved {
		return PairedPermit{}, a.denyPaired(d, host, CodeWrongState, "paired permit is not approved")
	}
	if !now.Before(time.Unix(p.Binding.ExpiryUnix, 0)) {
		delete(a.paired, d)
		return PairedPermit{}, a.denyPaired(d, host, CodeExpired, "")
	}
	a.gcPairedLocked(now)
	field := canonical.PairedEnrollDiff(p.Binding, presented)
	pd, derr := canonical.PairedEnrollDigest(presented)
	if field != "" || derr != nil || subtle.ConstantTimeCompare(pd[:], d[:]) != 1 {
		if field == "" {
			field = "binding"
		}
		delete(a.paired, d)
		a.pairedSpent[d] = struct{}{}
		return PairedPermit{}, a.denyPaired(d, host, CodeBindingMismatch, field+" differs from the approval; paired permit discarded")
	}
	delete(a.paired, d)
	a.pairedSpent[d] = struct{}{}
	a.emit(Event{Kind: "authorized", Digest: d.String(), Host: host, Detail: "paired enrollment"})
	return p.clone(), nil
}

// PendingPaired returns copies of all pending, unexpired paired permits.
func (a *Authority) PendingPaired() []PairedPermit {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcPairedLocked(a.now())
	var out []PairedPermit
	for _, p := range a.paired {
		if p.State == StatePending {
			out = append(out, p.clone())
		}
	}
	slices.SortFunc(out, func(x, y PairedPermit) int { return x.ApprovalExpiry.Compare(y.ApprovalExpiry) })
	return out
}

// pairedPendingLocked returns the pending paired permit d. A permit whose
// approval window closed is dropped and reported as expired.
func (a *Authority) pairedPendingLocked(d canonical.Digest, now time.Time) (*PairedPermit, error) {
	p, ok := a.paired[d]
	if !ok {
		a.gcPairedLocked(now)
		if _, spent := a.pairedSpent[d]; spent {
			return nil, fail(CodeReplay, "paired permit already used")
		}
		return nil, fail(CodeNotFound, "")
	}
	if p.State != StatePending {
		return nil, fail(CodeWrongState, "paired permit is not pending")
	}
	if !now.Before(p.ApprovalExpiry) {
		delete(a.paired, d)
		return nil, fail(CodeExpired, "approval window closed")
	}
	a.gcPairedLocked(now)
	return p, nil
}

func (a *Authority) pairedPendingCountLocked() int {
	n := 0
	for _, p := range a.paired {
		if p.State == StatePending {
			n++
		}
	}
	return n
}

// gcPairedLocked drops pending paired permits whose approval window closed
// and approved ones whose binding expired. Their offers stay spent.
func (a *Authority) gcPairedLocked(now time.Time) {
	for d, p := range a.paired {
		if p.State == StatePending && !now.Before(p.ApprovalExpiry) {
			delete(a.paired, d)
			continue
		}
		if !now.Before(time.Unix(p.Binding.ExpiryUnix, 0)) {
			delete(a.paired, d)
		}
	}
}

func (a *Authority) rejectPaired(p *PairedPermit, code Code, format string, args ...any) error {
	err := fail(code, format, args...)
	a.emit(Event{Kind: "rejected", Digest: p.Digest.String(), Host: p.Binding.HostID, Code: code, Detail: "paired permit: " + err.Error()})
	return err
}

func (a *Authority) denyPaired(d canonical.Digest, host string, code Code, detail string) error {
	a.emit(Event{Kind: "denied", Digest: d.String(), Host: host, Code: code, Detail: "paired permit: " + detail})
	return &Error{Code: code, Detail: detail}
}

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

// NetBird offer permit and NetBird peer delete permit (ADR 0013 D1 step 2
// and D6, EN-07 part 2).
//
// Both follow the paired enrollment permit (paired.go): always HIGH with
// user verification (browser assertion inside the privileged session in
// Standard mode, `nebula approve` in both modes, CLI only in hardened
// mode); the executor must present exactly the approved binding to act,
// which consumes the permit; a binding that differs in any field discards
// it. Each subject gets at most one permit for the lifetime of the
// process: an offer gets one NetBird offer permit (so one approval yields
// at most one setup key), a peer gets one delete permit. A permit that
// expired, was consumed or discarded or was revoked by Lock can never be
// replayed or re-proposed for the same subject. They are never persisted;
// a restart revokes them.

// NetBird permit limits.
const (
	// MaxPendingNetBirdOffers bounds NetBird offer permits waiting for
	// approval (D2 allows only 2 open NetBird offers; this is the
	// authority's own backstop).
	MaxPendingNetBirdOffers = 16
	// MaxPendingNetBirdPeerDeletes bounds peer delete permits waiting for
	// approval.
	MaxPendingNetBirdPeerDeletes = 16
	// MaxNetBirdSubjects bounds the offers or peers remembered as spent per
	// kind; when the table is full no further permit of that kind is
	// proposed until a restart.
	MaxNetBirdSubjects = 65536
)

// Challenge domains; they separate the NetBird challenges from each other
// and from every other challenge the executor issues.
const (
	netbirdOfferChallengeDomain      = "nebula-netbird-offer-v1\x00"
	netbirdPeerDeleteChallengeDomain = "nebula-netbird-peer-delete-v1\x00"
)

// BoundPermit is a single-use HIGH permit over a canonical binding B.
type BoundPermit[B any] struct {
	Digest canonical.Digest
	// Binding is the normalized binding the approval covers.
	Binding B
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

// NetBirdOfferPermit is a NetBird offer permit; its consumption lets the
// executor create the offer's one-off setup key.
type NetBirdOfferPermit = BoundPermit[canonical.NetBirdOffer]

// NetBirdPeerDeletePermit is a NetBird peer delete permit.
type NetBirdPeerDeletePermit = BoundPermit[canonical.NetBirdPeerDelete]

// Risk is the risk class of a bound permit: always HIGH.
func (p *BoundPermit[B]) Risk() canonical.Risk { return canonical.RiskHigh }

func (p *BoundPermit[B]) clone() BoundPermit[B] {
	c := *p
	c.Canonical = slices.Clone(p.Canonical)
	c.Challenge = slices.Clone(p.Challenge)
	return c
}

// boundKind describes one kind of bound permit.
type boundKind[B any] struct {
	name         string // for errors and audit, e.g. "NetBird offer permit"
	domain       string // challenge domain
	maxPending   int
	canonicalize func(B, time.Time) (B, []byte, canonical.Digest, error)
	digest       func(B) (canonical.Digest, error)
	diff         func(a, b B) string
	subject      func(B) string // replay key: one permit per subject
	host         func(B) string // host ID for audit, may be ""
	expiry       func(B) int64  // permit expiry, Unix seconds
}

// boundStore holds the live permits of one kind. subjects maps every
// subject that ever had a permit to its digest and spent records consumed
// or discarded digests, both for the lifetime of the process.
type boundStore[B any] struct {
	kind     *boundKind[B]
	live     map[canonical.Digest]*BoundPermit[B]
	subjects map[string]canonical.Digest
	spent    map[canonical.Digest]struct{}
}

func newBoundStore[B any](k *boundKind[B]) *boundStore[B] {
	return &boundStore[B]{
		kind:     k,
		live:     map[canonical.Digest]*BoundPermit[B]{},
		subjects: map[string]canonical.Digest{},
		spent:    map[canonical.Digest]struct{}{},
	}
}

var netbirdOfferKind = &boundKind[canonical.NetBirdOffer]{
	name:         "NetBird offer permit",
	domain:       netbirdOfferChallengeDomain,
	maxPending:   MaxPendingNetBirdOffers,
	canonicalize: canonical.CanonicalizeNetBirdOffer,
	digest:       canonical.NetBirdOfferDigest,
	diff:         canonical.NetBirdOfferDiff,
	subject:      func(b canonical.NetBirdOffer) string { return b.OfferIDHash },
	host:         func(b canonical.NetBirdOffer) string { return b.HostID },
	expiry:       func(b canonical.NetBirdOffer) int64 { return b.ExpiryUnix },
}

var netbirdPeerDeleteKind = &boundKind[canonical.NetBirdPeerDelete]{
	name:         "NetBird peer delete permit",
	domain:       netbirdPeerDeleteChallengeDomain,
	maxPending:   MaxPendingNetBirdPeerDeletes,
	canonicalize: canonical.CanonicalizeNetBirdPeerDelete,
	digest:       canonical.NetBirdPeerDeleteDigest,
	diff:         canonical.NetBirdPeerDeleteDiff,
	subject:      func(b canonical.NetBirdPeerDelete) string { return b.PeerID },
	host:         func(canonical.NetBirdPeerDelete) string { return "" },
	expiry:       func(b canonical.NetBirdPeerDelete) int64 { return b.ExpiryUnix },
}

// boundChallenge returns SHA-256(domain || digest || 32-byte nonce ||
// expiry as big-endian int64 Unix seconds).
func boundChallenge(domain string, d canonical.Digest, expiry time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("permit: nonce: %w", err)
	}
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(d[:])
	h.Write(nonce[:])
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// ProposeNetBirdOffer registers a NetBird offer permit for b. The executor
// calls it for an offer awaiting approval and creates no setup key before
// ConsumeNetBirdOffer succeeded. Proposing the identical binding again
// while its permit is pending returns that permit; any other proposal for
// an offer that already had a NetBird offer permit is refused.
func (a *Authority) ProposeNetBirdOffer(b canonical.NetBirdOffer) (NetBirdOfferPermit, error) {
	return boundPropose(a, a.netbirdOffers, b)
}

// SubmitNetBirdOfferAssertion approves a pending NetBird offer permit with
// a user-verified WebAuthn assertion inside the privileged session.
// Hardened mode refuses it.
func (a *Authority) SubmitNetBirdOfferAssertion(d canonical.Digest, assertionJSON []byte) (NetBirdOfferPermit, error) {
	return boundSubmitAssertion(a, a.netbirdOffers, d, assertionJSON)
}

// ApproveNetBirdOfferCLI approves a pending NetBird offer permit from
// `nebula approve`; the caller has established an admin UID.
func (a *Authority) ApproveNetBirdOfferCLI(d canonical.Digest, who string) (NetBirdOfferPermit, error) {
	return boundApproveCLI(a, a.netbirdOffers, d, who)
}

// ConsumeNetBirdOffer checks the binding the executor is about to act on
// against the approved permit d and, if every field is equal, consumes
// the permit. A differing binding discards it.
func (a *Authority) ConsumeNetBirdOffer(d canonical.Digest, presented canonical.NetBirdOffer) (NetBirdOfferPermit, error) {
	return boundConsume(a, a.netbirdOffers, d, presented)
}

// PendingNetBirdOffers returns copies of all pending, unexpired NetBird
// offer permits.
func (a *Authority) PendingNetBirdOffers() []NetBirdOfferPermit {
	return boundPending(a, a.netbirdOffers)
}

// ProposeNetBirdPeerDelete registers a NetBird peer delete permit for b.
// Proposing the identical binding again while its permit is pending
// returns that permit; any other proposal for a peer that already had a
// delete permit is refused.
func (a *Authority) ProposeNetBirdPeerDelete(b canonical.NetBirdPeerDelete) (NetBirdPeerDeletePermit, error) {
	return boundPropose(a, a.netbirdPeerDeletes, b)
}

// SubmitNetBirdPeerDeleteAssertion approves a pending peer delete permit
// with a user-verified WebAuthn assertion inside the privileged session.
// Hardened mode refuses it.
func (a *Authority) SubmitNetBirdPeerDeleteAssertion(d canonical.Digest, assertionJSON []byte) (NetBirdPeerDeletePermit, error) {
	return boundSubmitAssertion(a, a.netbirdPeerDeletes, d, assertionJSON)
}

// ApproveNetBirdPeerDeleteCLI approves a pending peer delete permit from
// `nebula approve`; the caller has established an admin UID.
func (a *Authority) ApproveNetBirdPeerDeleteCLI(d canonical.Digest, who string) (NetBirdPeerDeletePermit, error) {
	return boundApproveCLI(a, a.netbirdPeerDeletes, d, who)
}

// ConsumeNetBirdPeerDelete checks the binding of the delete the executor
// is about to make against the approved permit d and, if every field is
// equal, consumes the permit. A differing binding discards it.
func (a *Authority) ConsumeNetBirdPeerDelete(d canonical.Digest, presented canonical.NetBirdPeerDelete) (NetBirdPeerDeletePermit, error) {
	return boundConsume(a, a.netbirdPeerDeletes, d, presented)
}

// PendingNetBirdPeerDeletes returns copies of all pending, unexpired
// NetBird peer delete permits.
func (a *Authority) PendingNetBirdPeerDeletes() []NetBirdPeerDeletePermit {
	return boundPending(a, a.netbirdPeerDeletes)
}

func boundPropose[B any](a *Authority, s *boundStore[B], b B) (BoundPermit[B], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	k := s.kind
	s.gcLocked(now)

	norm, canon, digest, err := k.canonicalize(b, now)
	if err != nil {
		return BoundPermit[B]{}, fail(CodeInvalidRequest, "%v", err)
	}
	subject := k.subject(norm)
	if prev, seen := s.subjects[subject]; seen {
		if p, live := s.live[prev]; live && prev == digest && p.State == StatePending {
			return p.clone(), nil
		}
		a.emit(Event{Kind: "rejected", Digest: digest.String(), Host: k.host(norm), Code: CodeReplay, Detail: k.name + ": subject already had a permit"})
		return BoundPermit[B]{}, fail(CodeReplay, "%s: subject already had a permit", k.name)
	}
	if s.pendingCountLocked() >= k.maxPending {
		return BoundPermit[B]{}, fail(CodeLimit, "too many pending %ss", k.name)
	}
	if len(s.subjects) >= MaxNetBirdSubjects {
		return BoundPermit[B]{}, fail(CodeLimit, "%s table full; restart the executor", k.name)
	}
	p := &BoundPermit[B]{
		Digest:         digest,
		Binding:        norm,
		Canonical:      canon,
		Requirement:    pairedRequirement(a.mode),
		State:          StatePending,
		ApprovalExpiry: minTime(now.Add(ApprovalWindow), time.Unix(k.expiry(norm), 0)),
	}
	if p.Challenge, err = boundChallenge(k.domain, digest, p.ApprovalExpiry); err != nil {
		return BoundPermit[B]{}, err
	}
	s.live[digest] = p
	s.subjects[subject] = digest
	a.emit(Event{Kind: "proposed", Digest: digest.String(), Host: k.host(norm), Detail: k.name + ": " + p.Requirement.String()})
	return p.clone(), nil
}

func boundSubmitAssertion[B any](a *Authority, s *boundStore[B], d canonical.Digest, assertionJSON []byte) (BoundPermit[B], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	p, err := s.pendingLocked(d, now)
	if err != nil {
		return BoundPermit[B]{}, err
	}
	if p.Requirement == RequireCLI || a.mode == ModeHardened {
		return BoundPermit[B]{}, s.reject(a, p, CodeCLIRequired, "hardened mode: use nebula approve")
	}
	if !a.sessionActiveLocked(now) {
		return BoundPermit[B]{}, s.reject(a, p, CodeSessionRequired, "browser approval needs an active privileged session")
	}
	credID, err := a.verifier.Verify(assertionJSON, p.Challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return BoundPermit[B]{}, a.storageFailure(d.String(), err)
	}
	if err != nil {
		p.failed++
		rerr := s.reject(a, p, CodeAssertionRejected, "%v", err)
		if p.failed >= MaxFailedAssertions {
			delete(s.live, d)
			s.spent[d] = struct{}{}
			a.emit(Event{Kind: "rejected", Digest: d.String(), Host: s.kind.host(p.Binding), Code: CodeLimit, Detail: "too many failed approvals, " + s.kind.name + " discarded"})
		}
		return BoundPermit[B]{}, rerr
	}
	p.State = StateApproved
	p.Challenge = nil // single use
	p.ApprovedAt = now
	p.ApprovedBy = "webauthn:" + hex.EncodeToString(credID)
	a.emit(Event{Kind: "approved", Digest: d.String(), Host: s.kind.host(p.Binding), Detail: s.kind.name + ": " + p.ApprovedBy})
	return p.clone(), nil
}

func boundApproveCLI[B any](a *Authority, s *boundStore[B], d canonical.Digest, who string) (BoundPermit[B], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	p, err := s.pendingLocked(d, now)
	if err != nil {
		return BoundPermit[B]{}, err
	}
	p.State = StateApproved
	p.Challenge = nil
	p.ApprovedAt = now
	p.ApprovedBy = "cli:" + who
	a.emit(Event{Kind: "approved", Digest: d.String(), Host: s.kind.host(p.Binding), Detail: s.kind.name + ": " + p.ApprovedBy})
	return p.clone(), nil
}

func boundConsume[B any](a *Authority, s *boundStore[B], d canonical.Digest, presented B) (BoundPermit[B], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	k := s.kind
	p, ok := s.live[d]
	if !ok {
		s.gcLocked(now)
		if _, spent := s.spent[d]; spent {
			return BoundPermit[B]{}, s.deny(a, d, "", CodeReplay, "permit already used")
		}
		return BoundPermit[B]{}, s.deny(a, d, "", CodeNotFound, "")
	}
	host := k.host(p.Binding)
	if p.State != StateApproved {
		return BoundPermit[B]{}, s.deny(a, d, host, CodeWrongState, "permit is not approved")
	}
	if !now.Before(time.Unix(k.expiry(p.Binding), 0)) {
		delete(s.live, d)
		s.spent[d] = struct{}{}
		return BoundPermit[B]{}, s.deny(a, d, host, CodeExpired, "")
	}
	s.gcLocked(now)
	field := k.diff(p.Binding, presented)
	pd, derr := k.digest(presented)
	delete(s.live, d)
	s.spent[d] = struct{}{}
	if field != "" || derr != nil || subtle.ConstantTimeCompare(pd[:], d[:]) != 1 {
		if field == "" {
			field = "binding"
		}
		return BoundPermit[B]{}, s.deny(a, d, host, CodeBindingMismatch, field+" differs from the approval; permit discarded")
	}
	a.emit(Event{Kind: "authorized", Digest: d.String(), Host: host, Detail: k.name})
	return p.clone(), nil
}

func boundPending[B any](a *Authority, s *boundStore[B]) []BoundPermit[B] {
	a.mu.Lock()
	defer a.mu.Unlock()
	s.gcLocked(a.now())
	var out []BoundPermit[B]
	for _, p := range s.live {
		if p.State == StatePending {
			out = append(out, p.clone())
		}
	}
	slices.SortFunc(out, func(x, y BoundPermit[B]) int { return x.ApprovalExpiry.Compare(y.ApprovalExpiry) })
	return out
}

// pendingLocked returns the pending permit d. A permit whose approval
// window closed is dropped and reported as expired.
func (s *boundStore[B]) pendingLocked(d canonical.Digest, now time.Time) (*BoundPermit[B], error) {
	p, ok := s.live[d]
	if !ok {
		s.gcLocked(now)
		if _, spent := s.spent[d]; spent {
			return nil, fail(CodeReplay, "%s already used", s.kind.name)
		}
		return nil, fail(CodeNotFound, "")
	}
	if p.State != StatePending {
		return nil, fail(CodeWrongState, "%s is not pending", s.kind.name)
	}
	if !now.Before(p.ApprovalExpiry) {
		delete(s.live, d)
		return nil, fail(CodeExpired, "approval window closed")
	}
	s.gcLocked(now)
	return p, nil
}

func (s *boundStore[B]) pendingCountLocked() int {
	n := 0
	for _, p := range s.live {
		if p.State == StatePending {
			n++
		}
	}
	return n
}

// gcLocked drops pending permits whose approval window closed and
// approved ones whose binding expired. Their subjects stay spent.
func (s *boundStore[B]) gcLocked(now time.Time) {
	for d, p := range s.live {
		if p.State == StatePending && !now.Before(p.ApprovalExpiry) {
			delete(s.live, d)
			continue
		}
		if !now.Before(time.Unix(s.kind.expiry(p.Binding), 0)) {
			delete(s.live, d)
		}
	}
}

// revokeLocked drops every live permit (Lock); subjects stay spent.
func (s *boundStore[B]) revokeLocked() int {
	n := len(s.live)
	s.live = map[canonical.Digest]*BoundPermit[B]{}
	return n
}

func (s *boundStore[B]) reject(a *Authority, p *BoundPermit[B], code Code, format string, args ...any) error {
	err := fail(code, format, args...)
	a.emit(Event{Kind: "rejected", Digest: p.Digest.String(), Host: s.kind.host(p.Binding), Code: code, Detail: s.kind.name + ": " + err.Error()})
	return err
}

func (s *boundStore[B]) deny(a *Authority, d canonical.Digest, host string, code Code, detail string) error {
	a.emit(Event{Kind: "denied", Digest: d.String(), Host: host, Code: code, Detail: s.kind.name + ": " + detail})
	return &Error{Code: code, Detail: detail}
}

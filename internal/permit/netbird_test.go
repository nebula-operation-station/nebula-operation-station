// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

var netbirdSeq int

// netbirdOfferBinding returns a valid NetBird offer binding for a fresh
// offer.
func (e *env) netbirdOfferBinding() canonical.NetBirdOffer {
	netbirdSeq++
	now := e.clk.Now()
	return canonical.NetBirdOffer{
		OfferIDHash:        fmt.Sprintf("%064x", 1<<40+netbirdSeq),
		HostID:             "vps01",
		SSHUser:            "nebula",
		CredentialRef:      "nebula-default",
		ManagedGroup:       "nos-managed",
		Ephemeral:          false,
		SetupKeyExpiryUnix: now.Add(canonical.MaxNetBirdOfferLifetime + 45*time.Minute).Unix(),
		ExpiryUnix:         now.Add(canonical.MaxNetBirdOfferLifetime).Unix(),
	}
}

// netbirdPeerDeleteBinding returns a valid peer delete binding for a
// fresh peer.
func (e *env) netbirdPeerDeleteBinding() canonical.NetBirdPeerDelete {
	netbirdSeq++
	return canonical.NetBirdPeerDelete{
		PeerID:            fmt.Sprintf("peer%016d", netbirdSeq),
		PeerName:          "vps01",
		NetBirdIP:         "100.64.12.7",
		OfferIDHash:       fmt.Sprintf("%064x", 1<<41+netbirdSeq),
		AttributionMethod: canonical.AttributionTimeWindow,
		ExpiryUnix:        e.clk.Now().Add(canonical.MaxNetBirdPeerDeleteLifetime).Unix(),
	}
}

// boundOps drives one permit kind through its Authority methods, so that
// every behaviour below is tested for both NetBird permits.
type boundOps[B any] struct {
	valid   func(*env) B
	propose func(*Authority, B) (BoundPermit[B], error)
	submit  func(*Authority, canonical.Digest, []byte) (BoundPermit[B], error)
	cli     func(*Authority, canonical.Digest, string) (BoundPermit[B], error)
	consume func(*Authority, canonical.Digest, B) (BoundPermit[B], error)
	pending func(*Authority) []BoundPermit[B]
	// subject changes the binding to another subject (offer or peer).
	subject func(*B)
	// revalue changes the binding to other valid values for the same
	// subject.
	revalue func(*B)
	// fields maps each canonical member to a substitution.
	fields map[string]func(*B)
	// invalid lists malformed bindings that must never become a permit.
	invalid map[string]func(*env, *B)
	expire  time.Duration
}

var offerOps = boundOps[canonical.NetBirdOffer]{
	valid:   (*env).netbirdOfferBinding,
	propose: (*Authority).ProposeNetBirdOffer,
	submit:  (*Authority).SubmitNetBirdOfferAssertion,
	cli:     (*Authority).ApproveNetBirdOfferCLI,
	consume: (*Authority).ConsumeNetBirdOffer,
	pending: (*Authority).PendingNetBirdOffers,
	subject: func(b *canonical.NetBirdOffer) { b.OfferIDHash = strings.Repeat("e", 64) },
	revalue: func(b *canonical.NetBirdOffer) { b.ExpiryUnix -= 60; b.ManagedGroup = "nos-other" },
	fields: map[string]func(*canonical.NetBirdOffer){
		"netbird_offer_version": func(b *canonical.NetBirdOffer) { b.Version = canonical.NetBirdOfferVersion + 1 },
		"kind":                  func(b *canonical.NetBirdOffer) { b.Kind = canonical.PairedEnrollKind },
		"offer_id_hash":         func(b *canonical.NetBirdOffer) { b.OfferIDHash = strings.Repeat("f", 64) },
		"host_id":               func(b *canonical.NetBirdOffer) { b.HostID = "vps02" },
		"ssh_user":              func(b *canonical.NetBirdOffer) { b.SSHUser = "root" },
		"credential_ref":        func(b *canonical.NetBirdOffer) { b.CredentialRef = "admin-cred" },
		"managed_group":         func(b *canonical.NetBirdOffer) { b.ManagedGroup = "All" },
		"ephemeral":             func(b *canonical.NetBirdOffer) { b.Ephemeral = !b.Ephemeral },
		"setup_key_expiry_unix": func(b *canonical.NetBirdOffer) { b.SetupKeyExpiryUnix += 60 },
		"expiry_unix":           func(b *canonical.NetBirdOffer) { b.ExpiryUnix += 60 },
	},
	invalid: map[string]func(*env, *canonical.NetBirdOffer){
		"group with space":       func(_ *env, b *canonical.NetBirdOffer) { b.ManagedGroup = "nos managed" },
		"setup key too long":     func(_ *env, b *canonical.NetBirdOffer) { b.SetupKeyExpiryUnix += 3600 },
		"setup key before offer": func(_ *env, b *canonical.NetBirdOffer) { b.SetupKeyExpiryUnix = b.ExpiryUnix - 1 },
		"expiry too far":         func(_ *env, b *canonical.NetBirdOffer) { b.ExpiryUnix += 3600 },
		"expired":                func(e *env, b *canonical.NetBirdOffer) { b.ExpiryUnix = e.clk.Now().Unix() },
		"paired kind":            func(_ *env, b *canonical.NetBirdOffer) { b.Kind = canonical.PairedEnrollKind },
	},
	expire: canonical.MaxNetBirdOfferLifetime,
}

var peerDeleteOps = boundOps[canonical.NetBirdPeerDelete]{
	valid:   (*env).netbirdPeerDeleteBinding,
	propose: (*Authority).ProposeNetBirdPeerDelete,
	submit:  (*Authority).SubmitNetBirdPeerDeleteAssertion,
	cli:     (*Authority).ApproveNetBirdPeerDeleteCLI,
	consume: (*Authority).ConsumeNetBirdPeerDelete,
	pending: (*Authority).PendingNetBirdPeerDeletes,
	subject: func(b *canonical.NetBirdPeerDelete) { b.PeerID = "otherpeer" },
	revalue: func(b *canonical.NetBirdPeerDelete) { b.ExpiryUnix -= 60; b.NetBirdIP = "100.64.0.1" },
	fields: map[string]func(*canonical.NetBirdPeerDelete){
		"netbird_peer_delete_version": func(b *canonical.NetBirdPeerDelete) { b.Version = canonical.NetBirdPeerDeleteVersion + 1 },
		"kind":                        func(b *canonical.NetBirdPeerDelete) { b.Kind = canonical.NetBirdOfferKind },
		"peer_id":                     func(b *canonical.NetBirdPeerDelete) { b.PeerID = "legitpeer" },
		"peer_name":                   func(b *canonical.NetBirdPeerDelete) { b.PeerName = "prod-db" },
		"netbird_ip":                  func(b *canonical.NetBirdPeerDelete) { b.NetBirdIP = "100.64.0.1" },
		"offer_id_hash":               func(b *canonical.NetBirdPeerDelete) { b.OfferIDHash = strings.Repeat("f", 64) },
		"attribution_method":          func(b *canonical.NetBirdPeerDelete) { b.AttributionMethod = canonical.AttributionSetupKey },
		"expiry_unix":                 func(b *canonical.NetBirdPeerDelete) { b.ExpiryUnix += 60 },
	},
	invalid: map[string]func(*env, *canonical.NetBirdPeerDelete){
		"peer name control":   func(_ *env, b *canonical.NetBirdPeerDelete) { b.PeerName = "vps01\nApproval: none" },
		"peer id upper":       func(_ *env, b *canonical.NetBirdPeerDelete) { b.PeerID = "PEER" },
		"ip with zone":        func(_ *env, b *canonical.NetBirdPeerDelete) { b.NetBirdIP = "fe80::1%wt0" },
		"unknown attribution": func(_ *env, b *canonical.NetBirdPeerDelete) { b.AttributionMethod = "guess" },
		"expiry too far":      func(_ *env, b *canonical.NetBirdPeerDelete) { b.ExpiryUnix += 3600 },
		"expired":             func(e *env, b *canonical.NetBirdPeerDelete) { b.ExpiryUnix = e.clk.Now().Unix() },
	},
	expire: canonical.MaxNetBirdPeerDeleteLifetime,
}

func (o boundOps[B]) mustPropose(e *env, b B) BoundPermit[B] {
	e.t.Helper()
	p, err := o.propose(e.auth, b)
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	return p
}

func (o boundOps[B]) mustApprove(e *env, b B) BoundPermit[B] {
	e.t.Helper()
	p := o.mustPropose(e, b)
	got, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	if err != nil || got.State != StateApproved {
		e.t.Fatalf("approve: %v", err)
	}
	return got
}

// forBothKinds runs body once per NetBird permit kind.
func forBothKinds(t *testing.T, offer func(*testing.T, boundOps[canonical.NetBirdOffer]), del func(*testing.T, boundOps[canonical.NetBirdPeerDelete])) {
	t.Run("offer", func(t *testing.T) { offer(t, offerOps) })
	t.Run("peer_delete", func(t *testing.T) { del(t, peerDeleteOps) })
}

func TestNetBirdPermitsAreHighWithUserVerification(t *testing.T) {
	forBothKinds(t, testHighWithUV[canonical.NetBirdOffer], testHighWithUV[canonical.NetBirdPeerDelete])
}

func testHighWithUV[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := o.mustPropose(e, o.valid(e))
	if p.Requirement != RequireAssertionVerified || p.Risk() != canonical.RiskHigh {
		t.Fatalf("requirement %v risk %s, want UV and HIGH", p.Requirement, p.Risk())
	}
	if p.State != StatePending || len(p.Challenge) != 32 {
		t.Fatalf("not pending with a challenge: %+v", p)
	}
	// Presence alone (no user verification) is refused.
	e.dev.Options.UserNotVerified = true
	_, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeAssertionRejected)
	e.dev.Options.UserNotVerified = false
	got, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	if err != nil || got.State != StateApproved || !strings.HasPrefix(got.ApprovedBy, "webauthn:") {
		t.Fatalf("approve: %v %+v", err, got)
	}
	_, err = o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeWrongState)
	_, err = o.cli(e.auth, p.Digest, "garm")
	wantCode(t, err, CodeWrongState)
}

func TestNetBirdPermitsBrowserApprovalNeedsSession(t *testing.T) {
	forBothKinds(t, testNeedsSession[canonical.NetBirdOffer], testNeedsSession[canonical.NetBirdPeerDelete])
}

func testNeedsSession[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := o.mustPropose(e, o.valid(e))
	_, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeSessionRequired)
}

func TestNetBirdPermitsHardenedModeRequiresCLI(t *testing.T) {
	forBothKinds(t, testHardenedCLI[canonical.NetBirdOffer], testHardenedCLI[canonical.NetBirdPeerDelete])
}

func testHardenedCLI[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := o.mustPropose(e, o.valid(e))
	if p.Requirement != RequireCLI || p.Risk() != canonical.RiskHigh {
		t.Fatalf("requirement %v, want CLI", p.Requirement)
	}
	_, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeCLIRequired)
	got, err := o.cli(e.auth, p.Digest, "garm")
	if err != nil || got.State != StateApproved || got.ApprovedBy != "cli:garm" {
		t.Fatalf("cli approve: %v %+v", err, got)
	}
}

func TestNetBirdPermitsConsumeExactBinding(t *testing.T) {
	forBothKinds(t, testConsumeExact[canonical.NetBirdOffer], testConsumeExact[canonical.NetBirdPeerDelete])
}

func testConsumeExact[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := o.valid(e)
	p := o.mustApprove(e, b)
	got, err := o.consume(e.auth, p.Digest, b)
	if err != nil || got.Digest != p.Digest || got.State != StateApproved {
		t.Fatalf("consume: %v %+v", err, got)
	}
}

// TestNetBirdPermitsRejectSubstitutionOfEachField: presenting any bound
// field changed is refused, names only the field, and discards the permit
// so that the correct binding cannot follow.
func TestNetBirdPermitsRejectSubstitutionOfEachField(t *testing.T) {
	forBothKinds(t, testSubstitution[canonical.NetBirdOffer], testSubstitution[canonical.NetBirdPeerDelete])
}

func testSubstitution[B any](t *testing.T, o boundOps[B]) {
	for field, mut := range o.fields {
		t.Run(field, func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			e.openSession()
			b := o.valid(e)
			p := o.mustApprove(e, b)
			sub := b
			mut(&sub)
			_, err := o.consume(e.auth, p.Digest, sub)
			wantCode(t, err, CodeBindingMismatch)
			if !strings.HasPrefix(err.(*Error).Detail, field+" ") {
				t.Fatalf("detail %q does not name %s", err.(*Error).Detail, field)
			}
			_, err = o.consume(e.auth, p.Digest, b)
			wantCode(t, err, CodeReplay)
		})
	}
}

// TestNetBirdPermitsRejectOtherPermitsBinding: the binding of another
// approved permit of the same kind is no substitute.
func TestNetBirdPermitsRejectOtherPermitsBinding(t *testing.T) {
	forBothKinds(t, testOtherBinding[canonical.NetBirdOffer], testOtherBinding[canonical.NetBirdPeerDelete])
}

func testOtherBinding[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b1 := o.valid(e)
	p1 := o.mustApprove(e, b1)
	b2 := o.valid(e)
	p2 := o.mustApprove(e, b2)
	_, err := o.consume(e.auth, p1.Digest, b2)
	wantCode(t, err, CodeBindingMismatch)
	if _, err := o.consume(e.auth, p2.Digest, b2); err != nil {
		t.Fatalf("the other permit is unaffected: %v", err)
	}
}

// TestNetBirdPermitsAreSingleUse: a consumed permit is never consumed
// again, and its subject never gets another permit.
func TestNetBirdPermitsAreSingleUse(t *testing.T) {
	forBothKinds(t, testSingleUse[canonical.NetBirdOffer], testSingleUse[canonical.NetBirdPeerDelete])
}

func testSingleUse[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := o.valid(e)
	p := o.mustApprove(e, b)
	if _, err := o.consume(e.auth, p.Digest, b); err != nil {
		t.Fatal(err)
	}
	_, err := o.consume(e.auth, p.Digest, b)
	wantCode(t, err, CodeReplay)
	_, err = o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeReplay)
	_, err = o.propose(e.auth, b)
	wantCode(t, err, CodeReplay)
	// A fresh binding for the same subject (other values) is refused too.
	b3 := b
	o.revalue(&b3)
	_, err = o.propose(e.auth, b3)
	wantCode(t, err, CodeReplay)
}

// TestNetBirdPermitsOneSubjectOnePermit: an identical proposal while
// pending returns the same permit; any other binding for the subject is
// refused, and after approval even the identical one.
func TestNetBirdPermitsOneSubjectOnePermit(t *testing.T) {
	forBothKinds(t, testOneSubject[canonical.NetBirdOffer], testOneSubject[canonical.NetBirdPeerDelete])
}

func testOneSubject[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := o.valid(e)
	p := o.mustPropose(e, b)
	again := o.mustPropose(e, b)
	if again.Digest != p.Digest || string(again.Challenge) != string(p.Challenge) {
		t.Fatal("identical proposal returned another permit")
	}
	sub := b
	o.revalue(&sub)
	_, err := o.propose(e.auth, sub)
	wantCode(t, err, CodeReplay)
	if _, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge)); err != nil {
		t.Fatal(err)
	}
	_, err = o.propose(e.auth, b)
	wantCode(t, err, CodeReplay)
	// Another subject is independent.
	other := b
	o.subject(&other)
	o.mustPropose(e, other)
}

func TestNetBirdPermitsConsumeBeforeApprovalRefused(t *testing.T) {
	forBothKinds(t, testBeforeApproval[canonical.NetBirdOffer], testBeforeApproval[canonical.NetBirdPeerDelete])
}

func testBeforeApproval[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	b := o.valid(e)
	p := o.mustPropose(e, b)
	_, err := o.consume(e.auth, p.Digest, b)
	wantCode(t, err, CodeWrongState)
}

// TestNetBirdPermitExpiryEndsConsume: after the bound expiry an approved
// permit can no longer be used, and its subject stays spent.
func TestNetBirdPermitExpiryEndsConsume(t *testing.T) {
	forBothKinds(t, testExpiry[canonical.NetBirdOffer], testExpiry[canonical.NetBirdPeerDelete])
}

func testExpiry[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := o.valid(e)
	p := o.mustApprove(e, b)
	e.clk.Add(o.expire)
	_, err := o.consume(e.auth, p.Digest, b)
	wantCode(t, err, CodeExpired)
	_, err = o.consume(e.auth, p.Digest, b)
	wantCode(t, err, CodeReplay)
	// A binding that is valid now, but for the old subject, is refused.
	again := b
	o.fields["expiry_unix"](&again)
	_, err = o.propose(e.auth, again)
	wantCode(t, err, CodeReplay)
}

func TestNetBirdPermitConsumeJustBeforeExpiry(t *testing.T) {
	forBothKinds(t, testJustBeforeExpiry[canonical.NetBirdOffer], testJustBeforeExpiry[canonical.NetBirdPeerDelete])
}

func testJustBeforeExpiry[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := o.valid(e)
	p := o.mustApprove(e, b)
	e.clk.Add(o.expire - time.Second)
	if _, err := o.consume(e.auth, p.Digest, b); err != nil {
		t.Fatalf("consume within the lifetime: %v", err)
	}
}

func TestNetBirdPermitApprovalWindowExpires(t *testing.T) {
	forBothKinds(t, testApprovalWindow[canonical.NetBirdOffer], testApprovalWindow[canonical.NetBirdPeerDelete])
}

func testApprovalWindow[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := o.mustPropose(e, o.valid(e))
	e.clk.Add(ApprovalWindow)
	_, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeExpired)
	_, err = o.cli(e.auth, p.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	if n := len(o.pending(e.auth)); n != 0 {
		t.Fatalf("%d pending after the window", n)
	}
}

func TestNetBirdPermitTooManyFailedAssertionsDiscard(t *testing.T) {
	forBothKinds(t, testFailedAssertions[canonical.NetBirdOffer], testFailedAssertions[canonical.NetBirdPeerDelete])
}

func testFailedAssertions[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := o.valid(e)
	p := o.mustPropose(e, b)
	for range MaxFailedAssertions {
		_, err := o.submit(e.auth, p.Digest, []byte(`{"bogus":true}`))
		wantCode(t, err, CodeAssertionRejected)
	}
	_, err := o.submit(e.auth, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeReplay)
	_, err = o.propose(e.auth, b)
	wantCode(t, err, CodeReplay)
}

func TestNetBirdPermitsLockRevokes(t *testing.T) {
	forBothKinds(t, testLock[canonical.NetBirdOffer], testLock[canonical.NetBirdPeerDelete])
}

func testLock[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := o.valid(e)
	p := o.mustApprove(e, b)
	pending := o.mustPropose(e, o.valid(e))
	e.auth.Lock("test")
	_, err := o.consume(e.auth, p.Digest, b)
	wantCode(t, err, CodeNotFound)
	_, err = o.cli(e.auth, pending.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	_, err = o.propose(e.auth, b)
	wantCode(t, err, CodeReplay)
}

func TestNetBirdPermitsInvalidBindingRejected(t *testing.T) {
	forBothKinds(t, testInvalid[canonical.NetBirdOffer], testInvalid[canonical.NetBirdPeerDelete])
}

func testInvalid[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	for name, mut := range o.invalid {
		t.Run(name, func(t *testing.T) {
			b := o.valid(e)
			mut(e, &b)
			_, err := o.propose(e.auth, b)
			wantCode(t, err, CodeInvalidRequest)
		})
	}
	if n := len(o.pending(e.auth)); n != 0 {
		t.Fatalf("%d permits from invalid bindings", n)
	}
}

func TestNetBirdPermitsPendingLimit(t *testing.T) {
	forBothKinds(t, testPendingLimit[canonical.NetBirdOffer], testPendingLimit[canonical.NetBirdPeerDelete])
}

func testPendingLimit[B any](t *testing.T, o boundOps[B]) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	for range 16 {
		o.mustPropose(e, o.valid(e))
	}
	_, err := o.propose(e.auth, o.valid(e))
	wantCode(t, err, CodeLimit)
}

// TestNetBirdPermitsKindsAreSeparate: an approval or digest of one kind
// is worthless for another kind (paired, offer, peer delete, execution).
func TestNetBirdPermitsKindsAreSeparate(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	x := e.propose(e.request(canonical.RiskHigh))
	paired := e.proposePaired(e.pairedBinding())
	offer := offerOps.mustPropose(e, e.netbirdOfferBinding())
	del := peerDeleteOps.mustPropose(e, e.netbirdPeerDeleteBinding())

	// Challenges of other kinds do not approve.
	for _, ch := range [][]byte{x.Challenge, paired.Challenge, del.Challenge} {
		_, err := e.auth.SubmitNetBirdOfferAssertion(offer.Digest, e.sign(ch))
		wantCode(t, err, CodeAssertionRejected)
	}
	for _, ch := range [][]byte{x.Challenge, paired.Challenge, offer.Challenge} {
		_, err := e.auth.SubmitNetBirdPeerDeleteAssertion(del.Digest, e.sign(ch))
		wantCode(t, err, CodeAssertionRejected)
	}
	// Digests of one kind are unknown to the others.
	_, err := e.auth.ApproveNetBirdOfferCLI(del.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	_, err = e.auth.ApproveNetBirdPeerDeleteCLI(offer.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	_, err = e.auth.ApprovePairedCLI(offer.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	_, err = e.auth.ApproveNetBirdOfferCLI(paired.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	_, err = e.auth.SubmitAssertion(offer.Digest, e.sign(offer.Challenge), 0)
	wantCode(t, err, CodeNotFound)
}

// TestNetBirdPeerDeleteAuditCarriesNoPeerName: the peer name is
// untrusted provider text and stays out of audit events.
func TestNetBirdPeerDeleteAuditCarriesNoPeerName(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.netbirdPeerDeleteBinding()
	b.PeerName = "evil-name-marker"
	p := peerDeleteOps.mustApprove(e, b)
	sub := b
	sub.PeerName = "other-name-marker"
	_, _ = e.auth.ConsumeNetBirdPeerDelete(p.Digest, sub)
	e.evtMu.Lock()
	defer e.evtMu.Unlock()
	for _, ev := range e.evts {
		s := fmt.Sprintf("%+v", ev)
		if strings.Contains(s, "name-marker") {
			t.Fatalf("event carries the peer name: %s", s)
		}
	}
}

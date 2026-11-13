// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
)

var pairedSeq int

// pairedBinding returns a valid binding for a fresh offer, expiring at the
// enrollment permit lifetime.
func (e *env) pairedBinding() canonical.PairedEnroll {
	pairedSeq++
	return canonical.PairedEnroll{
		OfferIDHash:        fmt.Sprintf("%064x", pairedSeq),
		HostID:             "web01",
		Endpoint:           "192.0.2.10:22",
		EndpointToAdd:      true,
		SSHUser:            "nebula",
		CredentialRef:      "nebula-default",
		HostKeyFingerprint: fpA,
		CodeMatched:        true,
		PairingCode:        "00000-00000-00000-00000-00000",
		ExpiryUnix:         e.clk.Now().Add(canonical.MaxPairedEnrollLifetime).Unix(),
	}
}

func (e *env) proposePaired(b canonical.PairedEnroll) PairedPermit {
	e.t.Helper()
	p, err := e.auth.ProposePaired(b)
	if err != nil {
		e.t.Fatalf("propose paired: %v", err)
	}
	return p
}

func (e *env) approvedPaired(b canonical.PairedEnroll) PairedPermit {
	e.t.Helper()
	p := e.proposePaired(b)
	got, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	if err != nil || got.State != StateApproved {
		e.t.Fatalf("approve paired: %v", err)
	}
	return got
}

// otherCode is a well-formed code other than the one in pairedBinding.
func otherCode(t *testing.T) string {
	t.Helper()
	for _, ch := range "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U" {
		if c, err := pairing.Parse("10000-00000-00000-00000-0000" + string(ch)); err == nil {
			return c.String()
		}
	}
	t.Fatal("no check character")
	return ""
}

// IsPaired tells the executor which approval path a digest takes: true for
// a pending, approved or consumed paired permit, false for an execution
// permit and an unknown digest.
func TestIsPairedRoutesOnlyPairedDigests(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	pending := e.proposePaired(e.pairedBinding())
	b := e.pairedBinding()
	approved := e.approvedPaired(b)
	if !e.auth.IsPaired(pending.Digest) || !e.auth.IsPaired(approved.Digest) {
		t.Fatal("live paired permit not recognised")
	}
	if _, err := e.auth.ConsumePaired(approved.Digest, approved.Binding); err != nil {
		t.Fatal(err)
	}
	if !e.auth.IsPaired(approved.Digest) {
		t.Fatal("consumed paired permit not recognised")
	}
	var unknown canonical.Digest
	unknown[0] = 1
	if e.auth.IsPaired(unknown) {
		t.Fatal("unknown digest reported as paired")
	}
	exec := e.propose(e.request(canonical.RiskHigh))
	if e.auth.IsPaired(exec.Digest) {
		t.Fatal("execution permit reported as paired")
	}
}

func TestPairedPermitIsHighWithUserVerification(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.proposePaired(e.pairedBinding())
	if p.Requirement != RequireAssertionVerified || p.Risk() != canonical.RiskHigh {
		t.Fatalf("requirement %v risk %s, want UV and HIGH", p.Requirement, p.Risk())
	}
	if p.State != StatePending || len(p.Challenge) != 32 {
		t.Fatalf("not pending with a challenge: %+v", p)
	}
	e.dev.Options.UserNotVerified = true
	_, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeAssertionRejected)
	e.dev.Options.UserNotVerified = false
	got, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	if err != nil || got.State != StateApproved || !strings.HasPrefix(got.ApprovedBy, "webauthn:") {
		t.Fatalf("approve: %v %+v", err, got)
	}
	// The approval is single use.
	_, err = e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeWrongState)
}

func TestPairedBrowserApprovalNeedsSession(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := e.proposePaired(e.pairedBinding())
	_, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeSessionRequired)
}

func TestPairedHardenedModeRequiresCLI(t *testing.T) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.proposePaired(e.pairedBinding())
	if p.Requirement != RequireCLI {
		t.Fatalf("requirement %v, want CLI", p.Requirement)
	}
	_, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeCLIRequired)
	got, err := e.auth.ApprovePairedCLI(p.Digest, "garm")
	if err != nil || got.State != StateApproved || got.ApprovedBy != "cli:garm" {
		t.Fatalf("cli approve: %v %+v", err, got)
	}
}

func TestPairedStandardModeAcceptsCLIApprovalOnce(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.proposePaired(e.pairedBinding())
	if _, err := e.auth.ApprovePairedCLI(p.Digest, "garm"); err != nil {
		t.Fatal(err)
	}
	// Whichever approval comes first wins; the second is refused.
	_, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeWrongState)
	_, err = e.auth.ApprovePairedCLI(p.Digest, "garm")
	wantCode(t, err, CodeWrongState)
}

func TestPairedAssertionForOtherPermitRejected(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p1 := e.proposePaired(e.pairedBinding())
	p2 := e.proposePaired(e.pairedBinding())
	_, err := e.auth.SubmitPairedAssertion(p1.Digest, e.sign(p2.Challenge))
	wantCode(t, err, CodeAssertionRejected)
}

func TestPairedExecutionPermitChallengeRejected(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	x := e.propose(e.request(canonical.RiskHigh))
	p := e.proposePaired(e.pairedBinding())
	_, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(x.Challenge))
	wantCode(t, err, CodeAssertionRejected)
	// And a paired permit's digest is no execution permit.
	_, err = e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0)
	wantCode(t, err, CodeNotFound)
}

func TestPairedCommitAcceptsExactBinding(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.pairedBinding()
	p := e.approvedPaired(b)
	got, err := e.auth.ConsumePaired(p.Digest, b)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.PairedEnrollDiff(got.Binding, b) != "" || got.Digest != p.Digest {
		t.Fatalf("consumed permit differs: %+v", got)
	}
}

// TestPairedCommitRejectsSubstitutionOfEachField: a commit presenting any
// bound field changed is refused, names only the field, and discards the
// permit so that the correct binding cannot follow.
func TestPairedCommitRejectsSubstitutionOfEachField(t *testing.T) {
	cases := map[string]func(*canonical.PairedEnroll){
		"offer_id_hash":         func(b *canonical.PairedEnroll) { b.OfferIDHash = strings.Repeat("f", 64) },
		"host_id":               func(b *canonical.PairedEnroll) { b.HostID = "web02" },
		"endpoint":              func(b *canonical.PairedEnroll) { b.Endpoint = "192.0.2.66:22" },
		"endpoint_to_add":       func(b *canonical.PairedEnroll) { b.EndpointToAdd = !b.EndpointToAdd },
		"ssh_user":              func(b *canonical.PairedEnroll) { b.SSHUser = "root" },
		"credential_ref":        func(b *canonical.PairedEnroll) { b.CredentialRef = "admin-cred" },
		"host_key_fingerprint":  func(b *canonical.PairedEnroll) { b.HostKeyFingerprint = fpB },
		"code_matched":          func(b *canonical.PairedEnroll) { b.CodeMatched = false },
		"pairing_code":          func(b *canonical.PairedEnroll) { b.PairingCode = otherCode(t) },
		"expiry_unix":           func(b *canonical.PairedEnroll) { b.ExpiryUnix += 60 },
		"paired_enroll_version": func(b *canonical.PairedEnroll) { b.Version = canonical.PairedEnrollVersion + 1 },
		"kind":                  func(b *canonical.PairedEnroll) { b.Kind = "nebula.netbird_offer" },
	}
	for field, mut := range cases {
		t.Run(field, func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			e.openSession()
			b := e.pairedBinding()
			p := e.approvedPaired(b)
			sub := b
			mut(&sub)
			_, err := e.auth.ConsumePaired(p.Digest, sub)
			wantCode(t, err, CodeBindingMismatch)
			if !strings.HasPrefix(err.(*Error).Detail, field+" ") {
				t.Fatalf("detail %q does not name %s", err.(*Error).Detail, field)
			}
			_, err = e.auth.ConsumePaired(p.Digest, b)
			wantCode(t, err, CodeReplay)
		})
	}
}

// TestPairedCommitRejectsOtherDigest: the presented binding is the one of
// another live permit (substitution of the whole permit).
func TestPairedCommitRejectsOtherPermitsBinding(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b1 := e.pairedBinding()
	p1 := e.approvedPaired(b1)
	b2 := e.pairedBinding()
	b2.HostKeyFingerprint = fpB
	e.approvedPaired(b2)
	_, err := e.auth.ConsumePaired(p1.Digest, b2)
	wantCode(t, err, CodeBindingMismatch)
}

func TestPairedCommitIsSingleUse(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.pairedBinding()
	p := e.approvedPaired(b)
	if _, err := e.auth.ConsumePaired(p.Digest, b); err != nil {
		t.Fatal(err)
	}
	_, err := e.auth.ConsumePaired(p.Digest, b)
	wantCode(t, err, CodeReplay)
	// The offer cannot get a second permit, neither the same binding nor
	// a fresh one.
	_, err = e.auth.ProposePaired(b)
	wantCode(t, err, CodeReplay)
	b2 := b
	b2.ExpiryUnix = e.clk.Now().Add(5 * time.Minute).Unix()
	_, err = e.auth.ProposePaired(b2)
	wantCode(t, err, CodeReplay)
}

func TestPairedOfferGetsOnePermit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.pairedBinding()
	p := e.proposePaired(b)
	// Identical proposal while pending: the same permit.
	again := e.proposePaired(b)
	if again.Digest != p.Digest || string(again.Challenge) != string(p.Challenge) {
		t.Fatal("identical proposal returned another permit")
	}
	// Another binding for the same offer (another key): refused.
	sub := b
	sub.HostKeyFingerprint = fpB
	_, err := e.auth.ProposePaired(sub)
	wantCode(t, err, CodeReplay)
	// After approval even the identical proposal is refused.
	if _, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge)); err != nil {
		t.Fatal(err)
	}
	_, err = e.auth.ProposePaired(b)
	wantCode(t, err, CodeReplay)
}

func TestPairedCommitBeforeApprovalRefused(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	b := e.pairedBinding()
	p := e.proposePaired(b)
	_, err := e.auth.ConsumePaired(p.Digest, b)
	wantCode(t, err, CodeWrongState)
}

func TestPairedPermitExpiryEndsCommit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.pairedBinding()
	p := e.approvedPaired(b)
	e.clk.Add(canonical.MaxPairedEnrollLifetime)
	_, err := e.auth.ConsumePaired(p.Digest, b)
	wantCode(t, err, CodeExpired)
	_, err = e.auth.ConsumePaired(p.Digest, b)
	wantCode(t, err, CodeNotFound)
	// The offer stays spent.
	b.ExpiryUnix = e.clk.Now().Add(time.Minute).Unix()
	_, err = e.auth.ProposePaired(b)
	wantCode(t, err, CodeReplay)
}

func TestPairedApprovalStartedBeforeExpiryFinishesWithinLifetime(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.pairedBinding()
	p := e.approvedPaired(b)
	e.clk.Add(canonical.MaxPairedEnrollLifetime - time.Second)
	e.openSession()
	if _, err := e.auth.ConsumePaired(p.Digest, b); err != nil {
		t.Fatalf("commit within the lifetime: %v", err)
	}
}

func TestPairedApprovalWindowExpires(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.proposePaired(e.pairedBinding())
	e.clk.Add(ApprovalWindow)
	_, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeExpired)
	_, err = e.auth.ApprovePairedCLI(p.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	if n := len(e.auth.PendingPaired()); n != 0 {
		t.Fatalf("%d pending after the window", n)
	}
}

func TestPairedApprovalWindowCappedByExpiry(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	b := e.pairedBinding()
	b.ExpiryUnix = e.clk.Now().Add(time.Minute).Unix()
	p := e.proposePaired(b)
	if !p.ApprovalExpiry.Equal(time.Unix(b.ExpiryUnix, 0)) {
		t.Fatalf("approval expiry %v beyond permit expiry", p.ApprovalExpiry)
	}
}

func TestPairedTooManyFailedAssertionsDiscardPermit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.proposePaired(e.pairedBinding())
	for range MaxFailedAssertions {
		_, err := e.auth.SubmitPairedAssertion(p.Digest, []byte(`{"bogus":true}`))
		wantCode(t, err, CodeAssertionRejected)
	}
	_, err := e.auth.SubmitPairedAssertion(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeNotFound)
}

func TestPairedLockRevokes(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.pairedBinding()
	p := e.approvedPaired(b)
	pending := e.proposePaired(e.pairedBinding())
	e.auth.Lock("test")
	_, err := e.auth.ConsumePaired(p.Digest, b)
	wantCode(t, err, CodeNotFound)
	_, err = e.auth.ApprovePairedCLI(pending.Digest, "garm")
	wantCode(t, err, CodeNotFound)
	_, err = e.auth.ProposePaired(b)
	wantCode(t, err, CodeReplay)
}

func TestPairedInvalidBindingRejected(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	for name, mut := range map[string]func(*canonical.PairedEnroll){
		"code not matched":   func(b *canonical.PairedEnroll) { b.CodeMatched = false },
		"short fingerprint":  func(b *canonical.PairedEnroll) { b.HostKeyFingerprint = "SHA256:AAAA" },
		"endpoint unchecked": func(b *canonical.PairedEnroll) { b.Endpoint = "evil host" },
		"expiry too far":     func(b *canonical.PairedEnroll) { b.ExpiryUnix += 3600 },
		"expired":            func(b *canonical.PairedEnroll) { b.ExpiryUnix = e.clk.Now().Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			b := e.pairedBinding()
			mut(&b)
			_, err := e.auth.ProposePaired(b)
			wantCode(t, err, CodeInvalidRequest)
		})
	}
	if n := len(e.auth.PendingPaired()); n != 0 {
		t.Fatalf("%d permits from invalid bindings", n)
	}
}

func TestPairedPendingLimit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	for range MaxPendingPaired {
		e.proposePaired(e.pairedBinding())
	}
	_, err := e.auth.ProposePaired(e.pairedBinding())
	wantCode(t, err, CodeLimit)
}

func TestPairedAuditNeverCarriesCodeOrFingerprint(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	b := e.pairedBinding()
	p := e.approvedPaired(b)
	sub := b
	sub.HostKeyFingerprint = fpB
	_, _ = e.auth.ConsumePaired(p.Digest, sub)
	e.evtMu.Lock()
	defer e.evtMu.Unlock()
	for _, ev := range e.evts {
		s := fmt.Sprintf("%+v", ev)
		if strings.Contains(s, b.PairingCode) || strings.Contains(s, fpB) {
			t.Fatalf("event leaks a bound value: %s", s)
		}
	}
}

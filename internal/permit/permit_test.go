// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	rpID   = "nebula.example.org"
	origin = "https://nebula.example.org"
	fpA    = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB    = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

var (
	artifact = []byte("#!/bin/sh\necho hello\n")
	params   = []byte(`{"packages":["openssl"]}`)
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type env struct {
	t     *testing.T
	clk   *clock
	auth  *Authority
	rp    virtualwebauthn.RelyingParty
	dev   virtualwebauthn.Authenticator
	cred  virtualwebauthn.Credential
	evts  []Event
	evtMu sync.Mutex
	risk  *fakePolicy
}

func newEnv(t *testing.T, mode Mode, devOpts virtualwebauthn.AuthenticatorOptions) *env {
	t.Helper()
	return newEnvWithStores(t, mode, devOpts, newMemStore(), newMemCounters())
}

// newEnvWithStores builds an environment on the given persistent stores, so
// that a test can simulate an executor restart by building a second
// environment on the same stores.
func newEnvWithStores(t *testing.T, mode Mode, devOpts virtualwebauthn.AuthenticatorOptions, store *memStore, counters *memCounters) *env {
	t.Helper()
	e := &env{
		t:    t,
		clk:  &clock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)},
		rp:   virtualwebauthn.RelyingParty{Name: "Nebula", ID: rpID, Origin: origin},
		dev:  virtualwebauthn.NewAuthenticatorWithOptions(devOpts),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
		risk: newFakePolicy(),
	}
	e.dev.AddCredential(e.cred)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: counters},
		[]webauthnverify.Credential{{ID: e.cred.ID, PublicKey: e.cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	e.auth, err = New(Options{
		Mode: mode, Verifier: v, Now: e.clk.Now, Store: store, RiskPolicy: e.risk,
		Audit: func(ev Event) { e.evtMu.Lock(); e.evts = append(e.evts, ev); e.evtMu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) sign(challenge []byte) []byte {
	return []byte(virtualwebauthn.CreateAssertionResponse(e.rp, e.dev, e.cred,
		virtualwebauthn.AssertionOptions{Challenge: challenge, RelyingPartyID: rpID}))
}

func (e *env) openSession() {
	e.t.Helper()
	ch, _, err := e.auth.BeginSession()
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.auth.CompleteSession(e.sign(ch)); err != nil {
		e.t.Fatalf("open session: %v", err)
	}
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var execSeq int

func (e *env) request(risk canonical.Risk) canonical.Request {
	ph, err := canonical.HashParameters(params)
	if err != nil {
		e.t.Fatal(err)
	}
	execSeq++
	return canonical.Request{
		ExecutionID:    fmt.Sprintf("00000000-0000-4000-8000-%012d", execSeq),
		ActionID:       "patching.install_security",
		ModuleVersion:  "1.0.0",
		ArtifactSHA256: hexSum(artifact),
		ParametersHash: ph,
		CredentialRefs: []string{"nebula-default"},
		RiskClass:      risk,
		StagePlanHash:  strings.Repeat("c", 64),
		ExpiryUnix:     e.clk.Now().Add(2 * time.Hour).Unix(),
		ResolvedTargets: []canonical.Target{
			{HostID: "dockerflux", HostKeyFingerprint: fpA},
			{HostID: "strompi", HostKeyFingerprint: fpB},
		},
	}
}

func (e *env) propose(r canonical.Request) Permit {
	e.t.Helper()
	res, err := e.auth.Propose(r, params)
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	return res.Permit
}

func goodRun(host, fp string) Run {
	return Run{HostID: host, HostKeyFingerprint: fp, ActionID: "patching.install_security",
		ModuleVersion: "1.0.0", Artifact: artifact, ParametersJSON: params, CredentialRef: "nebula-default"}
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if got := CodeOf(err); got != code {
		t.Fatalf("want code %q, got %v", code, err)
	}
}

func TestRequirementTable(t *testing.T) {
	cases := []struct {
		risk     canonical.Risk
		standard Requirement
		hardened Requirement
	}{
		{canonical.RiskLow, RequireNone, RequireNone},
		{canonical.RiskMedium, RequireAssertionPresence, RequireAssertionPresence},
		{canonical.RiskHigh, RequireAssertionVerified, RequireCLI},
		{canonical.RiskCritical, RequireAssertionVerifiedTypedCount, RequireCLI},
		{"BOGUS", RequireCLI, RequireCLI},
	}
	for _, c := range cases {
		if got := RequirementFor(c.risk, ModeStandard); got != c.standard {
			t.Errorf("%s standard: got %v", c.risk, got)
		}
		if got := RequirementFor(c.risk, ModeHardened); got != c.hardened {
			t.Errorf("%s hardened: got %v", c.risk, got)
		}
	}
}

func TestLowNeedsSession(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	_, err := e.auth.Propose(e.request(canonical.RiskLow), params)
	wantCode(t, err, CodeSessionRequired)
	e.openSession()
	p := e.propose(e.request(canonical.RiskLow))
	if p.State != StateApproved || p.ApprovedBy != "privileged-session" {
		t.Fatalf("LOW in session should be approved, got %+v", p)
	}
	if len(p.Challenge) != 0 {
		t.Fatal("approved permit must not carry a challenge")
	}
}

func TestMediumAssertionFlow(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := e.propose(e.request(canonical.RiskMedium))
	if p.State != StatePending || len(p.Challenge) != 32 {
		t.Fatalf("expected pending permit with 32-byte challenge, got %+v", p)
	}
	// Without a privileged session the browser path is closed.
	_, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0)
	wantCode(t, err, CodeSessionRequired)

	e.openSession()
	assertion := e.sign(p.Challenge)
	got, err := e.auth.SubmitAssertion(p.Digest, assertion, 0)
	if err != nil || got.State != StateApproved {
		t.Fatalf("approve: %v %+v", err, got)
	}
	// Replay of the identical assertion.
	_, err = e.auth.SubmitAssertion(p.Digest, assertion, 0)
	wantCode(t, err, CodeWrongState)
}

func TestAssertionForOtherPermitRejected(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	a := e.propose(e.request(canonical.RiskMedium))
	b := e.propose(e.request(canonical.RiskMedium))
	_, err := e.auth.SubmitAssertion(b.Digest, e.sign(a.Challenge), 0)
	wantCode(t, err, CodeAssertionRejected)
	// The legitimate assertion for b still works afterwards.
	if _, err := e.auth.SubmitAssertion(b.Digest, e.sign(b.Challenge), 0); err != nil {
		t.Fatal(err)
	}
}

func TestChallengeIsUniquePerProposal(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	r1 := e.request(canonical.RiskMedium)
	r2 := r1
	r2.ExecutionID = "00000000-0000-4000-8000-999999999999"
	p1, p2 := e.propose(r1), e.propose(r2)
	if hex.EncodeToString(p1.Challenge) == hex.EncodeToString(p2.Challenge) {
		t.Fatal("challenges must differ")
	}
}

func TestHighNeedsUserVerification(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession() // session opened with a UV-capable authenticator
	e.dev.Options.UserNotVerified = true
	p := e.propose(e.request(canonical.RiskHigh))
	_, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0)
	wantCode(t, err, CodeAssertionRejected)
	e.dev.Options.UserNotVerified = false
	if _, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0); err != nil {
		t.Fatal(err)
	}
}

func TestCriticalTypedCount(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.propose(e.request(canonical.RiskCritical))
	_, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 1)
	wantCode(t, err, CodeTypedCountMismatch)
	if _, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 2); err != nil {
		t.Fatal(err)
	}
}

func TestHardenedModeForcesCLI(t *testing.T) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	for _, risk := range []canonical.Risk{canonical.RiskHigh, canonical.RiskCritical} {
		p := e.propose(e.request(risk))
		if p.Requirement != RequireCLI {
			t.Fatalf("%s: want CLI requirement, got %v", risk, p.Requirement)
		}
		_, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), p.TargetCount())
		wantCode(t, err, CodeCLIRequired)
		if risk == canonical.RiskCritical {
			_, err := e.auth.ApproveCLI(p.Digest, 0, "garm")
			wantCode(t, err, CodeTypedCountMismatch)
		}
		got, err := e.auth.ApproveCLI(p.Digest, p.TargetCount(), "garm")
		if err != nil || got.State != StateApproved || got.ApprovedBy != "cli:garm" {
			t.Fatalf("%s: cli approve: %v %+v", risk, err, got)
		}
	}
}

func TestTooManyFailuresDiscardsPermit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.propose(e.request(canonical.RiskMedium))
	for range MaxFailedAssertions {
		_, err := e.auth.SubmitAssertion(p.Digest, []byte(`{"bogus":true}`), 0)
		wantCode(t, err, CodeAssertionRejected)
	}
	_, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0)
	wantCode(t, err, CodeNotFound)
}

func TestApprovalWindowExpires(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.propose(e.request(canonical.RiskMedium))
	e.clk.Add(ApprovalWindow)
	_, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0)
	if c := CodeOf(err); c != CodeNotFound && c != CodeExpired {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func approved(t *testing.T, e *env, r canonical.Request) Permit {
	t.Helper()
	p := e.propose(r)
	if p.State == StatePending {
		var err error
		p, err = e.auth.ApproveCLI(p.Digest, p.TargetCount(), "test")
		if err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestAuthorizeEachHostOnce(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := approved(t, e, e.request(canonical.RiskMedium))
	if err := e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)), CodeHostAlreadyRun)
	if err := e.auth.Authorize(p.Digest, goodRun("strompi", fpB)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeRejectsSubstitution(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Run)
		code   Code
	}{
		"other host":          {func(r *Run) { r.HostID = "netbird-vps" }, CodeTargetNotPermitted},
		"other host key":      {func(r *Run) { r.HostKeyFingerprint = fpB }, CodeTargetNotPermitted},
		"swapped script":      {func(r *Run) { r.Artifact = []byte("#!/bin/sh\nrm -rf /\n") }, CodeArtifactMismatch},
		"empty script":        {func(r *Run) { r.Artifact = nil }, CodeArtifactMismatch},
		"swapped parameters":  {func(r *Run) { r.ParametersJSON = []byte(`{"packages":["openssh-server"]}`) }, CodeParametersMismatch},
		"duplicate key trick": {func(r *Run) { r.ParametersJSON = []byte(`{"packages":["openssl"],"packages":["x"]}`) }, CodeParametersMismatch},
		"other action":        {func(r *Run) { r.ActionID = "patching.install_all" }, CodeActionMismatch},
		"other version":       {func(r *Run) { r.ModuleVersion = "1.0.1" }, CodeActionMismatch},
		"other credential":    {func(r *Run) { r.CredentialRef = "root-key" }, CodeCredentialMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			p := approved(t, e, e.request(canonical.RiskMedium))
			run := goodRun("dockerflux", fpA)
			c.mutate(&run)
			wantCode(t, e.auth.Authorize(p.Digest, run), c.code)
			// A rejected attempt must not consume the host.
			if err := e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)); err != nil {
				t.Fatalf("legitimate run after rejected one: %v", err)
			}
		})
	}
}

func TestAuthorizeEquivalentParametersAccepted(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := approved(t, e, e.request(canonical.RiskMedium))
	run := goodRun("dockerflux", fpA)
	run.ParametersJSON = []byte("{ \"packages\" : [ \"openssl\" ] }")
	if err := e.auth.Authorize(p.Digest, run); err != nil {
		t.Fatalf("whitespace-only difference must be accepted: %v", err)
	}
}

func TestAuthorizeRequiresApprovedUnexpiredPermit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	pending := e.propose(e.request(canonical.RiskMedium))
	wantCode(t, e.auth.Authorize(pending.Digest, goodRun("dockerflux", fpA)), CodeWrongState)
	wantCode(t, e.auth.Authorize(canonical.Digest{1}, goodRun("dockerflux", fpA)), CodeNotFound)

	p := approved(t, e, e.request(canonical.RiskMedium))
	e.clk.Add(3 * time.Hour)
	if c := CodeOf(e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA))); c != CodeNotFound && c != CodeExpired {
		t.Fatalf("expired permit authorized: %v", c)
	}
}

func TestExecutionIDCannotBeRebound(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	r := e.request(canonical.RiskMedium)
	first := e.propose(r)
	again := e.propose(r)
	if first.Digest != again.Digest {
		t.Fatal("identical proposal must be idempotent")
	}
	r.ResolvedTargets = append(r.ResolvedTargets, canonical.Target{HostID: "netbird-vps", HostKeyFingerprint: fpA})
	_, err := e.auth.Propose(r, params)
	wantCode(t, err, CodeExecutionIDReused)
}

func TestEndedExecutionCannotBeProposedAgain(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	r := e.request(canonical.RiskLow)
	p := e.propose(r)
	if err := e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)); err != nil {
		t.Fatal(err)
	}
	e.auth.Lock("test")
	e.openSession()
	// Identical request after Lock: would otherwise get a fresh "used" set
	// and run dockerflux a second time under the same execution ID.
	_, err := e.auth.Propose(r, params)
	wantCode(t, err, CodeExecutionIDReused)

	// Discarded after too many failures: the failure budget is per execution.
	m := e.request(canonical.RiskMedium)
	pm := e.propose(m)
	for range MaxFailedAssertions {
		_, _ = e.auth.SubmitAssertion(pm.Digest, []byte(`{}`), 0)
	}
	_, err = e.auth.Propose(m, params)
	wantCode(t, err, CodeExecutionIDReused)
}

func TestParametersMustMatchHash(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	_, err := e.auth.Propose(e.request(canonical.RiskMedium), []byte(`{"packages":["openssh-server"]}`))
	wantCode(t, err, CodeInvalidRequest)
	_, err = e.auth.Propose(e.request(canonical.RiskMedium), []byte(`{"n":1.0}`))
	wantCode(t, err, CodeInvalidRequest)
	p := e.propose(e.request(canonical.RiskMedium))
	if string(p.Parameters) != `{"packages":["openssl"]}` {
		t.Fatalf("stored parameters %q", p.Parameters)
	}
}

func TestLockRevokesEverything(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	low := e.propose(e.request(canonical.RiskLow))
	med := e.propose(e.request(canonical.RiskMedium))
	e.auth.Lock("test")
	if ok, _ := e.auth.Session(); ok {
		t.Fatal("session survived lock")
	}
	wantCode(t, e.auth.Authorize(low.Digest, goodRun("dockerflux", fpA)), CodeNotFound)
	_, err := e.auth.SubmitAssertion(med.Digest, e.sign(med.Challenge), 0)
	wantCode(t, err, CodeNotFound)
}

func TestSessionChallengeRules(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	_, err := e.auth.CompleteSession([]byte("{}"))
	wantCode(t, err, CodeNoChallenge)

	// Consumed even on failure.
	ch, _, _ := e.auth.BeginSession()
	_, err = e.auth.CompleteSession([]byte(`{"bogus":1}`))
	wantCode(t, err, CodeAssertionRejected)
	_, err = e.auth.CompleteSession(e.sign(ch))
	wantCode(t, err, CodeNoChallenge)

	// Expired.
	ch, _, _ = e.auth.BeginSession()
	e.clk.Add(SessionChallengeTTL)
	_, err = e.auth.CompleteSession(e.sign(ch))
	wantCode(t, err, CodeExpired)

	// User verification required.
	e.dev.Options.UserNotVerified = true
	ch, _, _ = e.auth.BeginSession()
	_, err = e.auth.CompleteSession(e.sign(ch))
	wantCode(t, err, CodeAssertionRejected)

	// Session ends after its length.
	e.dev.Options.UserNotVerified = false
	e.openSession()
	e.clk.Add(DefaultSessionLength)
	if ok, _ := e.auth.Session(); ok {
		t.Fatal("session outlived its length")
	}
}

func TestPendingLimit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	for range MaxPending {
		e.propose(e.request(canonical.RiskMedium))
	}
	_, err := e.auth.Propose(e.request(canonical.RiskMedium), params)
	wantCode(t, err, CodeLimit)
}

func TestInvalidRequestRejected(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	r := e.request(canonical.RiskMedium)
	r.ArtifactSHA256 = "nope"
	_, err := e.auth.Propose(r, params)
	wantCode(t, err, CodeInvalidRequest)
}

func TestAuditTrailRecordsDecisions(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := approved(t, e, e.request(canonical.RiskMedium))
	_ = e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA))
	_ = e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA))
	kinds := map[string]int{}
	for _, ev := range e.evts {
		kinds[ev.Kind]++
	}
	for _, k := range []string{"proposed", "approved", "authorized", "denied"} {
		if kinds[k] == 0 {
			t.Errorf("no %q event recorded: %v", k, kinds)
		}
	}
}

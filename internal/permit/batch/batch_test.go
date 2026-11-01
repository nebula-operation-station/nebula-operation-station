// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

var ctx = context.Background()

type counters struct {
	saves atomic.Int32
	fail  atomic.Bool
}

func (*counters) LoadCounters() (map[string]uint32, error) { return nil, nil }
func (c *counters) SaveCounter([]byte, uint32) error {
	if c.fail.Load() {
		return errors.New("counter storage unavailable")
	}
	c.saves.Add(1)
	return nil
}

type policy struct {
	mu     sync.Mutex
	states map[string]Snapshot
	err    error
	hook   func()
	n      int
}

func (p *policy) reads() int { p.mu.Lock(); defer p.mu.Unlock(); return p.n }

func (p *policy) Evaluate(_ context.Context, m canonical.BatchMember) (Snapshot, error) {
	p.mu.Lock()
	s, err, hook := p.states[m.MemberID], p.err, p.hook
	p.n++
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	return s, err
}
func (p *policy) set(id string, s Snapshot) { p.mu.Lock(); p.states[id] = s; p.mu.Unlock() }

type environment struct {
	a        *Authority
	options  Options
	policy   *policy
	store    *fakeStore
	active   atomic.Bool
	unix     atomic.Int64
	rp       virtualwebauthn.RelyingParty
	dev      virtualwebauthn.Authenticator
	cred     virtualwebauthn.Credential
	counters *counters
	events   []permit.Event
}

func setup(t *testing.T, mode permit.Mode) *environment {
	t.Helper()
	e := &environment{policy: &policy{states: map[string]Snapshot{}},
		rp:  virtualwebauthn.RelyingParty{Name: "Nebula", ID: "nebula.example.org", Origin: "https://nebula.example.org"},
		dev: virtualwebauthn.NewAuthenticator(), cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), counters: &counters{}}
	e.dev.AddCredential(e.cred)
	e.unix.Store(1791630000)
	e.active.Store(true)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: e.rp.ID, Origins: []string{e.rp.Origin}, Counters: e.counters},
		[]webauthnverify.Credential{{ID: e.cred.ID, PublicKey: e.cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	e.options = Options{Mode: mode, Verifier: v, Policy: e.policy, AdminUID: 1000,
		Now:     func() time.Time { return time.Unix(e.unix.Load(), 0) },
		Session: func() (bool, time.Time) { return e.active.Load(), time.Unix(e.unix.Load(), 0).Add(time.Hour) },
		Audit:   func(ev permit.Event) { e.events = append(e.events, ev) }}
	e.store = newFakeStore()
	e.options.Store = e.store
	e.a, err = New(e.options)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func (e *environment) sign(ch []byte) []byte {
	e.cred.Counter++
	return []byte(virtualwebauthn.CreateAssertionResponse(e.rp, e.dev, e.cred, virtualwebauthn.AssertionOptions{Challenge: ch, RelyingPartyID: e.rp.ID}))
}
func (e *environment) plan(t *testing.T, risks ...canonical.Risk) ([]byte, []MemberInput) {
	t.Helper()
	b := canonical.Batch{BatchVersion: canonical.BatchVersion, BatchID: "00000000-0000-4000-8000-000000000001", ExpiryUnix: e.unix.Load() + 3600,
		StagePlan: canonical.BatchStagePlan{Stages: []canonical.BatchStage{{StageID: "first", Gate: canonical.BatchGateManual, RequiredPostchecks: []string{}}}, Dependencies: []canonical.BatchDependency{}}}
	var inputs []MemberInput
	for i, r := range risks {
		id := fmt.Sprintf("member-%d", i)
		art := []byte("#!/bin/sh\necho ready\n")
		params := []byte(`{"approved":true}`)
		ph, err := canonical.HashParameters(params)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(art)
		b.Members = append(b.Members, canonical.BatchMember{MemberID: id, Request: canonical.Request{
			RequestVersion: canonical.RequestVersion, ExecutionID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10), ActionID: "package.upgrade", ModuleVersion: "1.0.0",
			ArtifactSHA256: canonical.Digest(h).String(), ParametersHash: ph, CredentialRefs: []string{"admin-key"}, RiskClass: r, ExpiryUnix: b.ExpiryUnix,
			ResolvedTargets: []canonical.Target{{HostID: fmt.Sprintf("host-%d", i), HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}},
			CredentialVersions: []canonical.CredentialVersion{{Reference: "admin-key", Version: 1}}, PreconditionHashes: []string{}})
		b.StagePlan.Stages[0].MemberIDs = append(b.StagePlan.Stages[0].MemberIDs, id)
		inputs = append(inputs, MemberInput{MemberID: id, Artifact: art, ParametersJSON: params})
		e.policy.set(id, Snapshot{Risk: r, Trust: sha256.Sum256([]byte(id))})
	}
	h, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash = h.String()
	for i := range b.Members {
		b.Members[i].Request.StagePlanHash = h.String()
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw, inputs
}
func propose(t *testing.T, e *environment, risks ...canonical.Risk) Approval {
	t.Helper()
	raw, in := e.plan(t, risks...)
	p, err := e.a.Propose(ctx, raw, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func wantCode(t *testing.T, err error, code permit.Code) {
	t.Helper()
	if permit.CodeOf(err) != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestStrictestMemberSetsOneApproval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		risks   []canonical.Risk
		require permit.Requirement
	}{
		{"low", []canonical.Risk{canonical.RiskLow, canonical.RiskLow}, permit.RequireNone},
		{"medium", []canonical.Risk{canonical.RiskLow, canonical.RiskMedium}, permit.RequireAssertionPresence},
		{"high", []canonical.Risk{canonical.RiskMedium, canonical.RiskHigh, canonical.RiskLow}, permit.RequireAssertionVerified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			p := propose(t, e, tc.risks...)
			if p.Requirement != tc.require || len(p.Plan.Members) != len(tc.risks) {
				t.Fatalf("wrong approval: %+v", p)
			}
			if tc.require == permit.RequireNone {
				if p.State != permit.StateApproved || len(p.Challenge) != 0 {
					t.Fatal("LOW not approved by session")
				}
				return
			}
			e.dev.Options.UserNotVerified = tc.require == permit.RequireAssertionPresence
			signed := e.sign(p.Challenge)
			approved, err := e.a.SubmitAssertion(ctx, p.Digest, signed)
			if err != nil || approved.State != permit.StateApproved || len(approved.Challenge) != 0 {
				t.Fatalf("approve: %v", err)
			}
			if e.counters.saves.Load() != 1 {
				t.Fatal("approval did not use exactly one assertion")
			}
			_, err = e.a.SubmitAssertion(ctx, p.Digest, signed)
			wantCode(t, err, permit.CodeWrongState)
			if _, err = e.a.Check(ctx, p.Digest); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestCriticalRejectsWholePlanAndNamesEveryMember(t *testing.T) {
	for _, mode := range []permit.Mode{permit.ModeStandard, permit.ModeHardened} {
		e := setup(t, mode)
		raw, in := e.plan(t, canonical.RiskCritical, canonical.RiskLow, canonical.RiskCritical)
		_, err := e.a.Propose(ctx, raw, in)
		var critical *CriticalError
		if !errors.Is(err, ErrCritical) || !errors.As(err, &critical) || fmt.Sprint(critical.MemberIDs) != "[member-0 member-2]" {
			t.Fatalf("critical refusal: %v", err)
		}
		if len(e.a.entries) != 0 {
			t.Fatal("part of rejected plan retained")
		}
	}
}
func TestExecutorDerivesRiskBeforeDigest(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	raw, in := e.plan(t, canonical.RiskLow, canonical.RiskLow)
	e.policy.set("member-1", Snapshot{Risk: canonical.RiskHigh, Trust: sha256.Sum256([]byte("trusted"))})
	p, err := e.a.Propose(ctx, raw, in)
	if err != nil {
		t.Fatal(err)
	}
	_, _, original, err := canonical.ParseBatch(raw, e.options.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest == original || p.Risk != canonical.RiskHigh || p.Plan.Members[1].Request.RiskClass != canonical.RiskHigh {
		t.Fatal("executor floor not bound into plan")
	}
	e.dev.Options.UserNotVerified = true
	_, err = e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, permit.CodeAssertionRejected)
}
func TestDerivedCriticalRejectsProposal(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	raw, in := e.plan(t, canonical.RiskLow)
	e.policy.set("member-0", Snapshot{Risk: canonical.RiskCritical, Trust: sha256.Sum256([]byte("trust"))})
	_, err := e.a.Propose(ctx, raw, in)
	if !errors.Is(err, ErrCritical) {
		t.Fatalf("got %v", err)
	}
}
func TestHardenedHighRequiresLocalAdminReviewAndConfirmation(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	e.active.Store(false)
	p := propose(t, e, canonical.RiskHigh, canonical.RiskLow)
	if p.Requirement != permit.RequireCLI || len(p.Challenge) != 0 {
		t.Fatal("hardened HIGH exposed browser challenge")
	}
	_, err := e.a.SubmitAssertion(ctx, p.Digest, nil)
	wantCode(t, err, permit.CodeCLIRequired)
	for _, uid := range []uint32{0, 1001} {
		_, err = e.a.ReviewCLI(ctx, p.Digest, uid)
		if !errors.Is(err, ErrAdminRequired) {
			t.Fatalf("review: %v", err)
		}
		_, err = e.a.ApproveCLI(ctx, p.Digest, uid)
		if !errors.Is(err, ErrAdminRequired) {
			t.Fatalf("approve: %v", err)
		}
	}
	review, err := e.a.ReviewCLI(ctx, p.Digest, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Plan.Members) != 2 || len(review.Parameters) != 2 || len(review.Findings) != 2 || !bytes.Equal(review.Canonical, p.Canonical) {
		t.Fatal("CLI view incomplete")
	}
	approved, err := e.a.ApproveCLI(ctx, p.Digest, 1000)
	if err != nil || approved.State != permit.StateApproved || approved.ApprovedBy != "cli:1000" {
		t.Fatalf("CLI: %v", err)
	}
	_, err = e.a.ApproveCLI(ctx, p.Digest, 1000)
	wantCode(t, err, permit.CodeWrongState)
}
func TestHardenedMediumStillUsesBrowserSession(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	p := propose(t, e, canonical.RiskMedium)
	if p.Requirement != permit.RequireAssertionPresence {
		t.Fatal("MEDIUM requires CLI")
	}
	e.active.Store(false)
	_, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, permit.CodeSessionRequired)
	e.active.Store(true)
	if _, err = e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge)); err != nil {
		t.Fatal(err)
	}
}
func TestLowNeedsSession(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	e.active.Store(false)
	raw, in := e.plan(t, canonical.RiskLow)
	_, err := e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeSessionRequired)
}
func TestTrustOrRiskChangeInvalidatesWholeBatch(t *testing.T) {
	for _, when := range []string{"pending-browser", "pending-cli", "approved"} {
		for _, change := range []string{"risk", "trust"} {
			t.Run(when+"/"+change, func(t *testing.T) {
				e := setup(t, permit.ModeStandard)
				if when == "pending-cli" {
					e = setup(t, permit.ModeHardened)
				}
				p := propose(t, e, canonical.RiskHigh, canonical.RiskLow)
				if when == "approved" {
					if _, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge)); err != nil {
						t.Fatal(err)
					}
				}
				s := Snapshot{Risk: canonical.RiskLow, Trust: sha256.Sum256([]byte("member-1"))}
				if change == "risk" {
					s.Risk = canonical.RiskMedium
				} else {
					s.Trust = sha256.Sum256([]byte("replacement trust"))
				}
				e.policy.set("member-1", s)
				var err error
				switch when {
				case "pending-browser":
					_, err = e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
				case "pending-cli":
					_, err = e.a.ApproveCLI(ctx, p.Digest, 1000)
				default:
					_, err = e.a.Check(ctx, p.Digest)
				}
				if !errors.Is(err, ErrInvalidated) {
					t.Fatalf("got %v", err)
				}
				e.policy.set("member-1", Snapshot{Risk: canonical.RiskLow, Trust: sha256.Sum256([]byte("member-1"))})
				_, err = e.a.Check(ctx, p.Digest)
				wantCode(t, err, permit.CodeNotFound)
			})
		}
	}
}
func TestConcurrentApprovalCannotPreserveBatchAfterObservedCriticalRisk(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode permit.Mode
	}{
		{"browser", permit.ModeStandard},
		{"cli", permit.ModeHardened},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t, tc.mode)
			p := propose(t, e, canonical.RiskHigh, canonical.RiskLow)
			assertion := e.sign(p.Challenge)
			approve := func() error {
				if tc.mode == permit.ModeHardened {
					_, err := e.a.ApproveCLI(ctx, p.Digest, 1000)
					return err
				}
				_, err := e.a.SubmitAssertion(ctx, p.Digest, assertion)
				return err
			}
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			var reads atomic.Int32
			e.policy.hook = func() {
				if reads.Add(1) == 1 {
					close(entered)
					<-release
				}
			}
			original := Snapshot{Risk: canonical.RiskHigh, Trust: sha256.Sum256([]byte("member-0"))}
			critical := original
			critical.Risk = canonical.RiskCritical
			e.policy.set("member-0", critical)
			done := make(chan error, 1)
			go func() { done <- approve() }()
			// The first read captured CRITICAL before blocking. Restore risk so
			// another request can approve while that observation is in flight.
			<-entered
			e.policy.set("member-0", original)
			if err := approve(); err != nil {
				t.Fatal(err)
			}
			unblock()
			observedErr := <-done
			_, err := e.a.Check(ctx, p.Digest)
			wantCode(t, err, permit.CodeNotFound)
			if !errors.Is(observedErr, ErrInvalidated) {
				t.Fatalf("observed risk change: got %v, want %v", observedErr, ErrInvalidated)
			}
		})
	}
}

func TestPolicyFailureDeniesWithoutLeakingDetails(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskHigh)
	e.policy.err = errors.New("private policy storage detail")
	_, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, permit.CodeStorage)
	if bytes.Contains([]byte(err.Error()), []byte("private")) {
		t.Fatal("storage detail leaked")
	}
}
func TestChallengesAreDomainSeparatedFreshAndBound(t *testing.T) {
	d := sha256.Sum256([]byte("plan"))
	nonce := bytes.Repeat([]byte{7}, 32)
	expiry := time.Unix(1791630300, 0)
	got := challengeFor(d, nonce, expiry)
	// The exact versioned domain is a protocol binding, independent of sessions,
	// individual permits, read grants and future batch stage-gate assertions.
	var data bytes.Buffer
	data.WriteString("nebula:batch-approval:v1\x00")
	data.Write(d[:])
	data.Write(nonce)
	for i := 7; i >= 0; i-- {
		data.WriteByte(byte(uint64(expiry.Unix()) >> uint(i*8)))
	}
	expected := sha256.Sum256(data.Bytes())
	if !bytes.Equal(got, expected[:]) {
		t.Fatal("wrong challenge domain/binding")
	}
	e := setup(t, permit.ModeStandard)
	raw, in := e.plan(t, canonical.RiskHigh)
	p, err := e.a.Propose(ctx, raw, in)
	if err != nil {
		t.Fatal(err)
	}
	other := setup(t, permit.ModeStandard)
	other.plan(t, canonical.RiskHigh)
	q, err := other.a.Propose(ctx, raw, in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p.Challenge, q.Challenge) {
		t.Fatal("nonce reused")
	}
	_, err = e.a.SubmitAssertion(ctx, p.Digest, e.sign(q.Challenge))
	wantCode(t, err, permit.CodeAssertionRejected)
}
func TestApprovalAndExecutionExpiry(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(fmt.Sprint(approved), func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			p := propose(t, e, canonical.RiskHigh)
			if p.ApprovalExpiry.Sub(e.options.Now()) != permit.ApprovalWindow {
				t.Fatal("wrong approval window")
			}
			if approved {
				if _, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge)); err != nil {
					t.Fatal(err)
				}
				e.unix.Add(3600)
			} else {
				e.unix.Add(300)
			}
			var err error
			if approved {
				_, err = e.a.Check(ctx, p.Digest)
			} else {
				_, err = e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
			}
			wantCode(t, err, permit.CodeExpired)
		})
	}
}
func TestLockAndRestartRevokeApproval(t *testing.T) {
	for _, approved := range []bool{false, true} {
		e := setup(t, permit.ModeStandard)
		p := propose(t, e, canonical.RiskHigh)
		if approved {
			if _, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge)); err != nil {
				t.Fatal(err)
			}
		}
		e.a.Lock()
		_, err := e.a.Check(ctx, p.Digest)
		wantCode(t, err, permit.CodeNotFound)
		restarted, err := New(e.options)
		if err != nil {
			t.Fatal(err)
		}
		_, err = restarted.Check(ctx, p.Digest)
		wantCode(t, err, permit.CodeNotFound)
	}
}
func TestLockDuringPolicyReadCannotApproveStalePlan(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	p := propose(t, e, canonical.RiskHigh)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.policy.hook = func() { once.Do(func() { close(entered); <-release }) }
	done := make(chan error, 1)
	go func() { _, err := e.a.ApproveCLI(ctx, p.Digest, 1000); done <- err }()
	<-entered
	e.a.Lock()
	close(release)
	wantCode(t, <-done, permit.CodeNotFound)
}

func TestProposalRejectsMalformedOrSubstitutedInputs(t *testing.T) {
	for _, name := range []string{"malformed", "unknown", "duplicate-key", "artifact", "empty-artifact", "large-artifact", "parameters", "duplicate-parameters", "secret-refs", "missing-input", "extra-input", "wrong-member", "unknown-risk", "missing-trust"} {
		t.Run(name, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			raw, in := e.plan(t, canonical.RiskMedium)
			switch name {
			case "malformed":
				raw = []byte("\xff")
			case "unknown":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate-key":
				raw = append([]byte(`{"batch_version":"batch-v1",`), raw[1:]...)
			case "artifact":
				in[0].Artifact = []byte("substitution")
			case "empty-artifact":
				in[0].Artifact = nil
			case "large-artifact":
				in[0].Artifact = make([]byte, permit.MaxArtifactSize+1)
			case "parameters":
				in[0].ParametersJSON = []byte(`{"approved":false}`)
			case "duplicate-parameters":
				in[0].ParametersJSON = []byte(`{"approved":true,"approved":true}`)
			case "secret-refs":
				in[0].ParametersJSON = []byte(`{"nebula_secrets":{"invalid slot":"opaque-reference"}}`)
				var b canonical.Batch
				if err := json.Unmarshal(raw, &b); err != nil {
					t.Fatal(err)
				}
				h, err := canonical.HashParameters(in[0].ParametersJSON)
				if err != nil {
					t.Fatal(err)
				}
				b.Members[0].Request.ParametersHash = h
				raw, _ = json.Marshal(b)
			case "missing-input":
				in = nil
			case "extra-input":
				in = append(in, in[0])
			case "wrong-member":
				in[0].MemberID = "other"
			case "unknown-risk":
				e.policy.set("member-0", Snapshot{Risk: "UNKNOWN", Trust: sha256.Sum256([]byte("trust"))})
			case "missing-trust":
				e.policy.set("member-0", Snapshot{Risk: canonical.RiskMedium})
			}
			if _, err := e.a.Propose(ctx, raw, in); err == nil {
				t.Fatal("invalid input accepted")
			}
			if len(e.a.entries) != 0 {
				t.Fatal("invalid proposal retained")
			}
		})
	}
}
func TestScannerAndSecretFloorsCannotBeBypassed(t *testing.T) {
	for _, kind := range []string{"scanner", "secrets"} {
		t.Run(kind, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			raw, in := e.plan(t, canonical.RiskLow)
			var b canonical.Batch
			if err := json.Unmarshal(raw, &b); err != nil {
				t.Fatal(err)
			}
			want := canonical.RiskHigh
			if kind == "scanner" {
				in[0].Artifact = []byte("#!/bin/sh\neval value\n")
				h := sha256.Sum256(in[0].Artifact)
				b.Members[0].Request.ArtifactSHA256 = canonical.Digest(h).String()
			} else {
				want = canonical.RiskMedium
				in[0].ParametersJSON = []byte(`{"nebula_secrets":{"token":"opaque-reference"}}`)
				h, err := canonical.HashParameters(in[0].ParametersJSON)
				if err != nil {
					t.Fatal(err)
				}
				b.Members[0].Request.ParametersHash = h
			}
			raw, _ = json.Marshal(b)
			p, err := e.a.Propose(ctx, raw, in)
			if err != nil {
				t.Fatal(err)
			}
			if p.Risk != want {
				t.Fatalf("floor %s, want %s", p.Risk, want)
			}
			if kind == "scanner" && len(p.Findings[0]) == 0 {
				t.Fatal("scanner findings missing from review")
			}
		})
	}
}
func TestReturnedReviewCannotMutateFrozenPlan(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	p := propose(t, e, canonical.RiskHigh)
	original := bytes.Clone(p.Canonical)
	p.Plan.Members[0].Request.ActionID = "attacker.action"
	p.Plan.Members[0].CredentialVersions[0].Version = 99
	p.Plan.StagePlan.Stages[0].MemberIDs[0] = "other"
	p.Canonical[0] = '!'
	p.Parameters[0][0] = '!'
	view, err := e.a.ReviewCLI(ctx, p.Digest, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(view.Canonical, original) || view.Plan.Members[0].Request.ActionID != "package.upgrade" || view.Plan.Members[0].CredentialVersions[0].Version != 1 || view.Parameters[0][0] != '{' {
		t.Fatal("mutable frozen plan")
	}
}
func TestHighCannotAutomaticallyContinueStages(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	raw, in := e.plan(t, canonical.RiskHigh)
	var b canonical.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.StagePlan.Stages[0].Gate = canonical.BatchGateAutomatic
	h, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash = h.String()
	b.Members[0].Request.StagePlanHash = h.String()
	raw, _ = json.Marshal(b)
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeStagePlan)
}
func TestCounterStorageFailureCannotApprove(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskHigh)
	e.counters.fail.Store(true)
	_, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, permit.CodeStorage)
	_, err = e.a.Check(ctx, p.Digest)
	wantCode(t, err, permit.CodeWrongState)
}
func TestRepeatedBadAssertionsDiscardPendingApproval(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskHigh)
	for range permit.MaxFailedAssertions {
		_, err := e.a.SubmitAssertion(ctx, p.Digest, []byte(`{}`))
		wantCode(t, err, permit.CodeAssertionRejected)
	}
	_, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
	wantCode(t, err, permit.CodeNotFound)
}
func TestConcurrentConfirmationApprovesOnlyOnce(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	p := propose(t, e, canonical.RiskHigh)
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := e.a.ApproveCLI(ctx, p.Digest, 1000); results <- err }()
	}
	successes := 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else {
			wantCode(t, err, permit.CodeWrongState)
		}
	}
	if successes != 1 {
		t.Fatalf("%d approvals", successes)
	}
}
func TestNewRequiresSecurityDependencies(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	for _, field := range []string{"verifier", "policy", "session", "mode"} {
		t.Run(field, func(t *testing.T) {
			o := e.options
			switch field {
			case "verifier":
				o.Verifier = nil
			case "policy":
				o.Policy = nil
			case "session":
				o.Session = nil
			case "mode":
				o.Mode = permit.Mode(99)
			}
			if _, err := New(o); err == nil {
				t.Fatal("missing dependency accepted")
			}
		})
	}
}
func TestProposalLimitsAndDuplicateBatchID(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	raw, in := e.plan(t, canonical.RiskHigh)
	if _, err := e.a.Propose(ctx, raw, in); err != nil {
		t.Fatal(err)
	}
	_, err := e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeWrongState)
	e.a.Lock()
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeWrongState)
	// Capacity is process bounded even after revocation.
	for len(e.a.seen) < permit.MaxExecutionIDs {
		e.a.seen[fmt.Sprint(len(e.a.seen))] = struct{}{}
	}
	var b canonical.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.BatchID = "00000000-0000-4000-8000-000000000002"
	raw, _ = json.Marshal(b)
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeLimit)
}

func TestApprovalAuditRecordsApproverWithoutPlanContents(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	p := propose(t, e, canonical.RiskHigh)
	if _, err := e.a.ApproveCLI(ctx, p.Digest, 1000); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range e.events {
		if ev.Kind == "batch_approved" {
			found = true
			if ev.Detail != "cli:1000" || ev.Digest != p.Digest.String() {
				t.Fatalf("missing approval identity: %+v", ev)
			}
		}
		if bytes.Contains([]byte(ev.Detail), p.Parameters[0]) {
			t.Fatal("parameters in audit")
		}
	}
	if !found {
		t.Fatal("missing approval audit")
	}
}
func TestPresenceAndOriginChecksApplyToBatchAssertion(t *testing.T) {
	for _, kind := range []string{"presence", "origin", "rp"} {
		t.Run(kind, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			p := propose(t, e, canonical.RiskMedium)
			switch kind {
			case "presence":
				e.dev.Options.UserNotPresent = true
			case "origin":
				e.rp.Origin = "https://wrong.example.org"
			case "rp":
				e.rp.ID = "wrong.example.org"
			}
			_, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
			wantCode(t, err, permit.CodeAssertionRejected)
		})
	}
}
func TestZeroCounterAssertionStillSingleUse(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskHigh)
	assertion := []byte(virtualwebauthn.CreateAssertionResponse(e.rp, e.dev, e.cred, virtualwebauthn.AssertionOptions{Challenge: p.Challenge, RelyingPartyID: e.rp.ID}))
	if _, err := e.a.SubmitAssertion(ctx, p.Digest, assertion); err != nil {
		t.Fatal(err)
	}
	if e.counters.saves.Load() != 0 {
		t.Fatal("expected zero-counter authenticator")
	}
	_, err := e.a.SubmitAssertion(ctx, p.Digest, assertion)
	wantCode(t, err, permit.CodeWrongState)
}
func TestSessionAndApprovalExpiryAreRecheckedAfterPolicyRead(t *testing.T) {
	for _, kind := range []string{"session", "approval"} {
		t.Run(kind, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			p := propose(t, e, canonical.RiskHigh)
			e.policy.hook = func() {
				if kind == "session" {
					e.active.Store(false)
				} else {
					e.unix.Add(300)
				}
			}
			_, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
			if kind == "session" {
				wantCode(t, err, permit.CodeSessionRequired)
			} else {
				wantCode(t, err, permit.CodeExpired)
			}
			if e.counters.saves.Load() != 0 {
				t.Fatal("assertion verified after expiry")
			}
		})
	}
}
func TestProposalDuringLockIsDiscarded(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	raw, in := e.plan(t, canonical.RiskHigh)
	e.policy.hook = func() { e.a.Lock() }
	_, err := e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeWrongState)
}
func TestCanceledContextCannotApprove(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	p := propose(t, e, canonical.RiskHigh)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := e.a.ApproveCLI(canceled, p.Digest, 1000)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
func TestPolicyFailureAtDispatchCheckDeniesAuthority(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	p := propose(t, e, canonical.RiskHigh)
	if _, err := e.a.ApproveCLI(ctx, p.Digest, 1000); err != nil {
		t.Fatal(err)
	}
	e.policy.err = errors.New("unavailable")
	_, err := e.a.Check(ctx, p.Digest)
	wantCode(t, err, permit.CodeStorage)
}

// Review PR #128: retained plan bytes are bounded across all entries, and the
// budget is returned when entries go away.
func TestRetainedBytesBudgetBoundsMemoryAndIsReleased(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskHigh)
	e.a.mu.Lock()
	got := e.a.retained
	e.a.mu.Unlock()
	if got <= 0 || got != retainedSize(p) {
		t.Fatalf("retained = %d, want %d", got, retainedSize(p))
	}
	// Fill the budget: the next proposal is refused before any scan or policy read.
	e.a.mu.Lock()
	e.a.retained = MaxRetainedBytes
	e.a.mu.Unlock()
	var b canonical.Batch
	raw, in := e.plan(t, canonical.RiskHigh)
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.BatchID = "00000000-0000-4000-8000-000000000003"
	raw, _ = json.Marshal(b)
	reads := e.policy.reads()
	_, err := e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeLimit)
	if e.policy.reads() != reads {
		t.Fatal("over-budget proposal still read policy state")
	}
	// Budget just below the limit: storing the plan would exceed it.
	e.a.mu.Lock()
	e.a.retained = MaxRetainedBytes - 1
	e.a.mu.Unlock()
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeLimit)
	// Lock releases everything.
	e.a.Lock()
	e.a.mu.Lock()
	defer e.a.mu.Unlock()
	if e.a.retained != 0 || len(e.a.entries) != 0 {
		t.Fatalf("after Lock retained=%d entries=%d", e.a.retained, len(e.a.entries))
	}
}

// Review PR #128: expiry returns the entry's bytes to the budget.
func TestExpiredEntryReleasesRetainedBytes(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskHigh)
	e.unix.Add(4000)
	_, err := e.a.Check(ctx, p.Digest)
	wantCode(t, err, permit.CodeExpired)
	e.a.mu.Lock()
	defer e.a.mu.Unlock()
	if e.a.retained != 0 {
		t.Fatalf("retained = %d after expiry, want 0", e.a.retained)
	}
}

// Review PR #128: duplicates are refused before scanning, and batch scans
// share the executor-wide scan limit (a canceled wait does not scan).
func TestDuplicateRefusedBeforeScanAndScanWaitHonoursContext(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	raw, in := e.plan(t, canonical.RiskHigh)
	if _, err := e.a.Propose(ctx, raw, in); err != nil {
		t.Fatal(err)
	}
	reads := e.policy.reads()
	_, err := e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeWrongState)
	if e.policy.reads() != reads {
		t.Fatal("duplicate proposal did per-member work before refusal")
	}
	// A scanner whose slot never frees: the proposal must give up with ctx.
	e.options.Scan = func(c context.Context, _ []byte) ([]scanner.Finding, canonical.Risk, error) {
		<-c.Done()
		return nil, "", c.Err()
	}
	a, err := New(e.options)
	if err != nil {
		t.Fatal(err)
	}
	e.a = a
	var b canonical.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.BatchID = "00000000-0000-4000-8000-000000000004"
	raw, _ = json.Marshal(b)
	c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err = e.a.Propose(c, raw, in)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline while all scan slots are busy", err)
	}
}

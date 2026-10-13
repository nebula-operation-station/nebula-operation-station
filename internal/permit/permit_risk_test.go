// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// fakePolicy is a RiskPolicy for tests: a base floor plus per-host floors.
// internal/riskpolicy tests the real rules.
type fakePolicy struct {
	mu    sync.Mutex
	base  canonical.Risk
	hosts map[string]canonical.Risk
	err   error
	bogus bool       // return an unknown risk class
	calls [][]string // hostIDs of every call
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{base: canonical.RiskLow, hosts: map[string]canonical.Risk{}}
}

func (f *fakePolicy) MinimumRisk(_ canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var hostIDs []string
	for _, t := range targets {
		hostIDs = append(hostIDs, t.HostID)
	}
	f.calls = append(f.calls, hostIDs)
	if f.err != nil {
		return "", "", f.err
	}
	if f.bogus {
		return "", "", nil
	}
	floor, why := f.base, "base floor"
	for _, h := range hostIDs {
		if c, ok := f.hosts[h]; ok && c.Rank() > floor.Rank() {
			floor, why = c, "host "+h
		}
	}
	return floor, why, nil
}

func (f *fakePolicy) set(base canonical.Risk) { f.mu.Lock(); f.base = base; f.mu.Unlock() }
func (f *fakePolicy) setHost(h string, c canonical.Risk) {
	f.mu.Lock()
	f.hosts[h] = c
	f.mu.Unlock()
}
func (f *fakePolicy) setErr(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }
func (f *fakePolicy) lastCall() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func TestNewRequiresRiskPolicy(t *testing.T) {
	v, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: newMemCounters()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Verifier: v, Store: newMemStore()}); err == nil {
		t.Fatal("authority without a risk policy accepted")
	}
}

// H01 core: a compromised server labels a HIGH action LOW inside an active
// session. The executor rejects it and binds nothing.
func TestProposalBelowExecutorFloorIsRejected(t *testing.T) {
	store := newMemStore()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, newMemCounters())
	e.openSession()
	e.risk.set(canonical.RiskHigh)

	for _, risk := range []canonical.Risk{canonical.RiskLow, canonical.RiskMedium} {
		r := e.request(risk)
		_, err := e.auth.Propose(r, params)
		wantCode(t, err, CodeInvalidRequest)
		if !strings.Contains(err.Error(), "below the executor's minimum HIGH") {
			t.Fatalf("error does not name the minimum: %v", err)
		}
		if _, ok, _ := store.LookupExecution(r.ExecutionID); ok {
			t.Fatal("rejected proposal consumed its execution ID")
		}
	}
	if p, a := e.auth.Counts(); p != 0 || a != 0 {
		t.Fatalf("permit created below the floor: %d pending, %d approved", p, a)
	}
}

func TestProposalAtOrAboveFloorIsAccepted(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.risk.set(canonical.RiskMedium)
	if p := e.propose(e.request(canonical.RiskMedium)); p.Requirement != RequireAssertionPresence {
		t.Fatalf("MEDIUM at floor MEDIUM: requirement %v", p.Requirement)
	}
	// The server may always ask for stronger approval than the floor.
	if p := e.propose(e.request(canonical.RiskCritical)); p.Requirement != RequireAssertionVerifiedTypedCount {
		t.Fatalf("CRITICAL above floor: requirement %v", p.Requirement)
	}
}

func TestProposalFloorCoversEveryTarget(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.risk.setHost("strompi", canonical.RiskCritical)
	_, err := e.auth.Propose(e.request(canonical.RiskHigh), params)
	wantCode(t, err, CodeInvalidRequest)
	if got := e.risk.lastCall(); !slices.Equal(got, []string{"dockerflux", "strompi"}) {
		t.Fatalf("policy asked for hosts %v, want every target", got)
	}
}

func TestRiskPolicyErrorFailsClosedOnProposal(t *testing.T) {
	store := newMemStore()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, newMemCounters())
	e.risk.setErr(errors.New("read /var/lib/nebula/executor/executor.db: input/output error"))
	r := e.request(canonical.RiskCritical)
	_, err := e.auth.Propose(r, params)
	wantCode(t, err, CodeStorage)
	if strings.Contains(err.Error(), "executor.db") {
		t.Fatalf("store detail leaked to the caller: %v", err)
	}
	if _, ok, _ := store.LookupExecution(r.ExecutionID); ok {
		t.Fatal("execution ID bound although the floor was unknown")
	}
}

func approveMedium(t *testing.T, e *env) Permit {
	t.Helper()
	p := e.propose(e.request(canonical.RiskMedium))
	if _, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return p
}

// Trust withdrawn or criticality raised after approval stops the affected
// host runs; the check uses only the host being run.
func TestAuthorizeRechecksFloorPerHost(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := approveMedium(t, e)

	e.risk.setHost("dockerflux", canonical.RiskHigh)
	wantCode(t, e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)), CodeRiskAboveApproval)
	if got := e.risk.lastCall(); !slices.Equal(got, []string{"dockerflux"}) {
		t.Fatalf("policy asked for hosts %v, want only the host being run", got)
	}
	// Another host of the same permit is unaffected.
	if err := e.auth.Authorize(p.Digest, goodRun("strompi", fpB)); err != nil {
		t.Fatalf("unaffected host denied: %v", err)
	}
	// The denied host was not marked as run: once the floor is back, it runs.
	e.risk.setHost("dockerflux", canonical.RiskLow)
	if err := e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)); err != nil {
		t.Fatalf("host denied after floor restored: %v", err)
	}
}

func TestAuthorizeFailsClosedWhenFloorUnknown(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := approveMedium(t, e)
	e.risk.setErr(errors.New("disk gone"))
	err := e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA))
	wantCode(t, err, CodeStorage)
	if strings.Contains(err.Error(), "disk gone") {
		t.Fatalf("store detail leaked to the caller: %v", err)
	}
	e.risk.setErr(nil)
	if err := e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)); err != nil {
		t.Fatalf("host was marked as run although the check failed: %v", err)
	}
}

// A policy that answers with an unknown risk class is treated like an
// unreadable store: fail closed, on proposal and on run.
func TestUnknownFloorFailsClosed(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := approveMedium(t, e)
	e.risk.mu.Lock()
	e.risk.bogus = true
	e.risk.mu.Unlock()
	_, err := e.auth.Propose(e.request(canonical.RiskCritical), params)
	wantCode(t, err, CodeStorage)
	wantCode(t, e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)), CodeStorage)
}

// The reason names hosts and trust entries; it goes to the audit log only.
func TestFloorReasonStaysInTheAuditLog(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := approveMedium(t, e)
	e.risk.setHost("strompi", canonical.RiskCritical)
	_, err := e.auth.Propose(e.request(canonical.RiskMedium), params)
	wantCode(t, err, CodeInvalidRequest)
	if strings.Contains(err.Error(), "strompi") {
		t.Fatalf("proposal error names the host: %v", err)
	}
	err = e.auth.Authorize(p.Digest, goodRun("strompi", fpB))
	wantCode(t, err, CodeRiskAboveApproval)
	if strings.Contains(err.Error(), "host strompi") {
		t.Fatalf("run error names the reason: %v", err)
	}
	found := 0
	e.evtMu.Lock()
	for _, ev := range e.evts {
		if strings.Contains(ev.Detail, "host strompi") {
			found++
		}
	}
	e.evtMu.Unlock()
	if found != 2 {
		t.Fatalf("reason in %d audit events, want 2", found)
	}
}

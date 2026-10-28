// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	// during, if set, is invoked (with mu released) at the start of each
	// MinimumRisk call, so a test can observe the read in flight and change
	// the floor while it runs; the read then sees the new value.
	during func()
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{base: canonical.RiskLow, hosts: map[string]canonical.Risk{}}
}

func (f *fakePolicy) MinimumRisk(_ canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	f.mu.Lock()
	during := f.during
	f.mu.Unlock()
	if during != nil {
		during() // mu released: a test may change the floor while the read runs
	}
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
func (f *fakePolicy) setDuring(fn func())     { f.mu.Lock(); f.during = fn; f.mu.Unlock() }
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

// When the executor's floor rises after the proposal (a host becomes more
// critical, trust is withdrawn, or the scanner), both approval paths reject
// with a message naming the new floor instead of approving and failing at
// run time.
func TestApprovalRejectedWhenTheFloorRose(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()

	// ApproveCLI path: a MEDIUM permit (pending), then the floor rises to HIGH.
	p := e.propose(e.request(canonical.RiskMedium))
	if p.State != StatePending {
		t.Fatal(p.State)
	}
	e.risk.set(canonical.RiskHigh)
	_, err := e.auth.ApproveCLI(p.Digest, 0, "admin")
	wantCode(t, err, CodeRiskAboveApproval)
	if !strings.Contains(err.Error(), "executor minimum is now HIGH") {
		t.Fatalf("error does not name the new floor: %v", err)
	}
	// Still pending: not approved, not discarded, not counted as a failure.
	if pend, appr := e.auth.Counts(); pend != 1 || appr != 0 {
		t.Fatalf("permit after floor rise: %d pending, %d approved", pend, appr)
	}
	// A matching floor approves.
	e.risk.set(canonical.RiskMedium)
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		t.Fatalf("approval at the floor: %v", err)
	}

	// SubmitAssertion path: a MEDIUM permit, then the floor rises to HIGH.
	e2 := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e2.openSession()
	q := e2.propose(e2.request(canonical.RiskMedium))
	e2.risk.set(canonical.RiskHigh)
	_, err = e2.auth.SubmitAssertion(q.Digest, e2.sign(q.Challenge), 0)
	wantCode(t, err, CodeRiskAboveApproval)
	if !strings.Contains(err.Error(), "executor minimum is now HIGH") {
		t.Fatalf("assertion error does not name the new floor: %v", err)
	}
}

func TestApprovalFailsClosedWhenTheFloorIsUnknown(t *testing.T) {
	for name, broken := range map[string]func(*fakePolicy){
		"policy error":  func(f *fakePolicy) { f.setErr(errors.New("disk gone")) },
		"unknown class": func(f *fakePolicy) { f.mu.Lock(); f.bogus = true; f.mu.Unlock() },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			e.openSession()
			p := e.propose(e.request(canonical.RiskMedium))
			q := e.propose(e.request(canonical.RiskMedium))
			broken(e.risk)
			_, err := e.auth.ApproveCLI(p.Digest, 0, "admin")
			wantCode(t, err, CodeStorage)
			_, err = e.auth.SubmitAssertion(q.Digest, e.sign(q.Challenge), 0)
			wantCode(t, err, CodeStorage)
			// Neither is approved; both stay pending for a later attempt.
			if pend, appr := e.auth.Counts(); pend != 2 || appr != 0 {
				t.Fatalf("after an unknown floor: %d pending, %d approved", pend, appr)
			}
		})
	}
}

// The per-target risk read must not hold the global authority lock: while
// the read is in flight, other operations (session, propose, approve) must
// still run, and a floor change made during the read is reflected in the
// decision (fail closed, as if the check had run under the lock).
func TestFloorRiseReleasesTheGlobalLock(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.propose(e.request(canonical.RiskMedium))
	assertion := e.sign(p.Challenge)

	inside := make(chan struct{})
	release := make(chan struct{})
	e.risk.setDuring(func() {
		close(inside)
		<-release
	})
	done := make(chan error, 1)
	go func() {
		_, err := e.auth.SubmitAssertion(p.Digest, assertion, 0)
		done <- err
	}()
	<-inside // the floor read is in flight
	// The global lock must be free while the read runs: this must not block.
	sessOK := make(chan bool, 1)
	go func() {
		ok, _ := e.auth.Session()
		sessOK <- ok
	}()
	select {
	case ok := <-sessOK:
		if !ok {
			t.Fatal("session lost while the floor read was in flight")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Session() blocked while the floor read was in flight: a.mu was not released")
	}
	// Raise the floor while the read is in flight; the decision must see it.
	e.risk.set(canonical.RiskHigh)
	close(release)
	wantCode(t, <-done, CodeRiskAboveApproval)
	// Rejected, not approved: still pending for a later attempt.
	if pend, appr := e.auth.Counts(); pend != 1 || appr != 0 {
		t.Fatalf("after a mid-read floor rise: %d pending, %d approved", pend, appr)
	}
}

// Approvals race a floor change: under -race the decision must stay correct —
// no data race, at most one approval succeeds, and the permit ends in one
// consistent state matching the outcome.
func TestApproveConcurrentWithFloorChange(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.propose(e.request(canonical.RiskMedium))
	assertion := e.sign(p.Challenge)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				e.risk.set(canonical.RiskHigh) // above MEDIUM: would reject
				e.risk.set(canonical.RiskLow)  // at/below MEDIUM: would approve
			}
		}
	}()

	const approvers = 16
	var wg sync.WaitGroup
	errs := make([]error, approvers)
	for i := 0; i < approvers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.auth.SubmitAssertion(p.Digest, assertion, 0)
		}(i)
	}
	wg.Wait()

	approved := 0
	for _, err := range errs {
		if err == nil {
			approved++
		}
	}
	if approved > 1 {
		t.Fatalf("%d approvals succeeded, want at most 1", approved)
	}
	pend, appr := e.auth.Counts()
	if approved == 1 {
		if appr != 1 || pend != 0 {
			t.Fatalf("after one approval: %d pending, %d approved", pend, appr)
		}
	} else if pend != 1 || appr != 0 {
		// No approval succeeded: a floor rise or a consumed challenge
		// rejects; it does not discard the permit.
		t.Fatalf("after no approvals: %d pending, %d approved", pend, appr)
	}
}

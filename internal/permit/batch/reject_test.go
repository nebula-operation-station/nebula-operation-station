// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

// memRejections is an in-memory rejected_proposals table with the
// transaction contract of permit.RejectionStore: it checks the bindings
// against the execution ID store, then writes the row and the event
// together or nothing.
type memRejections struct {
	mu        sync.Mutex
	ids       permit.Store
	rows      map[canonical.Digest]permit.Rejection
	batchIDs  map[string]bool
	events    []map[string]string
	failRead  error
	failWrite error
}

func newMemRejections(ids permit.Store) *memRejections {
	return &memRejections{ids: ids, rows: map[canonical.Digest]permit.Rejection{}, batchIDs: map[string]bool{}}
}

func (m *memRejections) RejectedProposal(d canonical.Digest) (permit.Rejection, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead != nil {
		return permit.Rejection{}, false, m.failRead
	}
	r, ok := m.rows[d]
	return r, ok, nil
}

func (m *memRejections) RejectedBatchID(id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead != nil {
		return false, m.failRead
	}
	return m.batchIDs[id], nil
}

func (m *memRejections) CommitRejection(r permit.Rejection, bindings []permit.ExecutionBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWrite != nil {
		return m.failWrite
	}
	for _, b := range bindings {
		d, ok, err := m.ids.LookupExecution(b.ExecutionID)
		if err != nil {
			return err
		}
		if !ok || d != b.Digest {
			return permit.ErrBindingMismatch
		}
	}
	if _, dup := m.rows[r.Digest]; dup {
		return errors.New("duplicate digest")
	}
	if r.Kind == permit.ProposalBatch && m.batchIDs[r.ID] {
		return errors.New("duplicate batch ID")
	}
	m.rows[r.Digest] = r
	if r.Kind == permit.ProposalBatch {
		m.batchIDs[r.ID] = true
	}
	m.events = append(m.events, r.EventAttrs())
	return nil
}

func (m *memRejections) eventCount() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.events) }

type lowFloor struct{}

func (lowFloor) MinimumRisk(canonical.Request, []canonical.Target) (canonical.Risk, string, error) {
	return canonical.RiskLow, "test", nil
}

// rejectEnv is a batch environment plus an execution permit authority on
// the same stores and clock, wired as in production: the batch authority's
// Session is the permit authority's Session (lock order batch, then permit).
type rejectEnv struct {
	*environment
	exec *permit.Authority
	rej  *memRejections
}

func newRejectEnv(t *testing.T, mode permit.Mode) *rejectEnv {
	t.Helper()
	e := setup(t, mode)
	rej := newMemRejections(e.store)
	var auditMu sync.Mutex
	exec, err := permit.New(permit.Options{
		Mode: mode, Verifier: e.options.Verifier, Store: e.store, RiskPolicy: lowFloor{}, Rejections: rej,
		Now:   e.options.Now,
		Audit: func(permit.Event) { auditMu.Lock(); auditMu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.options.Session = exec.Session
	e.options.Rejections = rej
	e.options.Audit = func(permit.Event) { auditMu.Lock(); auditMu.Unlock() }
	e.a, err = New(e.options)
	if err != nil {
		t.Fatal(err)
	}
	return &rejectEnv{environment: e, exec: exec, rej: rej}
}

// restart builds fresh authorities on the same persistent stores.
func (r *rejectEnv) restart(t *testing.T) {
	t.Helper()
	exec, err := permit.New(permit.Options{
		Verifier: r.options.Verifier, Store: r.store, RiskPolicy: lowFloor{}, Rejections: r.rej, Now: r.options.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.exec = exec
	r.options.Session = exec.Session
	if r.a, err = New(r.options); err != nil {
		t.Fatal(err)
	}
}

func (r *rejectEnv) openSession(t *testing.T) {
	t.Helper()
	ch, _, err := r.exec.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.exec.CompleteSession(r.sign(ch)); err != nil {
		t.Fatalf("open session: %v", err)
	}
}

var rejectSeq int

func (r *rejectEnv) proposeExec(t *testing.T, risk canonical.Risk) permit.Permit {
	t.Helper()
	rejectSeq++
	params := []byte(`{"approved":true}`)
	ph, err := canonical.HashParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("#!/bin/sh\necho ready\n"))
	req := canonical.Request{
		ExecutionID: fmt.Sprintf("00000000-0000-4000-9000-%012d", rejectSeq), ActionID: "package.upgrade", ModuleVersion: "1.0.0",
		ArtifactSHA256: canonical.Digest(h).String(), ParametersHash: ph, CredentialRefs: []string{"admin-key"}, RiskClass: risk,
		StagePlanHash: stageplan.SingleStageHash, ExpiryUnix: r.unix.Load() + 3600,
		ResolvedTargets: []canonical.Target{{HostID: "host-x", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
	}
	res, err := r.exec.Propose(req, params)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	return res.Permit
}

func (r *rejectEnv) reject(d canonical.Digest, role permit.RejectRole, user, reason string) (permit.Rejection, error) {
	return RejectPending(r.exec, r.a, permit.RejectRequest{Digest: d, Role: role, RelayedUser: user, Reason: reason, Who: string(role)})
}

func adminReject(r *rejectEnv, d canonical.Digest) error {
	_, err := r.reject(d, permit.RejectRoleAdmin, "", "")
	return err
}

func TestRejectPendingExecutionIsFinalAndNeverApprovable(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	p := r.proposeExec(t, canonical.RiskMedium)
	reason := "wrong host — planned again"
	got, err := r.reject(p.Digest, permit.RejectRoleAdmin, "", reason)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if got.Kind != permit.ProposalExecution || got.ID != p.Request.ExecutionID || got.Role != permit.RejectRoleAdmin {
		t.Fatalf("rejection = %+v", got)
	}
	// Approval paths refuse with permit_rejected, in memory and after the
	// window, a lock and a restart.
	_, err = r.exec.ApproveCLI(p.Digest, 0, "admin")
	wantCode(t, err, permit.CodeRejected)
	_, err = r.exec.SubmitAssertion(p.Digest, r.sign(p.Challenge), 0)
	wantCode(t, err, permit.CodeRejected)
	if _, live := r.exec.PermitState(p.Digest); live {
		t.Fatal("rejected permit still in memory")
	}
	// Idempotent: a second rejection changes nothing and writes no event.
	wantCode(t, adminReject(r, p.Digest), permit.CodeAlreadyRejected)
	r.unix.Add(int64(permit.ApprovalWindow/time.Second) + 60)
	wantCode(t, adminReject(r, p.Digest), permit.CodeAlreadyRejected)
	r.exec.Lock("test")
	r.a.Lock()
	wantCode(t, adminReject(r, p.Digest), permit.CodeAlreadyRejected)
	r.restart(t)
	wantCode(t, adminReject(r, p.Digest), permit.CodeAlreadyRejected)
	_, err = r.exec.ApproveCLI(p.Digest, 0, "admin")
	wantCode(t, err, permit.CodeRejected)
	if n := r.rej.eventCount(); n != 1 {
		t.Fatalf("events = %d, want exactly 1", n)
	}
	// Re-proposal of the same request: its execution ID stays bound.
	_, err = r.exec.Propose(p.Request, []byte(`{"approved":true}`))
	wantCode(t, err, permit.CodeExecutionIDReused)
}

func TestRejectedEventCarriesLengthNotText(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	r.openSession(t)
	p := r.proposeExec(t, canonical.RiskMedium)
	reason := "secret-looking reason ä"
	if _, err := r.reject(p.Digest, permit.RejectRoleServer, "alice admin", reason); err != nil {
		t.Fatal(err)
	}
	ev := r.rej.events[0]
	for k, v := range ev {
		if strings.Contains(v, "secret-looking") {
			t.Fatalf("event attribute %s carries the reason text", k)
		}
	}
	want := map[string]string{
		"digest": p.Digest.String(), "proposal_kind": "execution", "proposal_id": p.Request.ExecutionID,
		"role": "server", "relayed_user_server_claim": "alice admin", "reason_len": "23",
	}
	for k, v := range want {
		if ev[k] != v {
			t.Errorf("event %s = %q, want %q", k, ev[k], v)
		}
	}
	if len(ev["session_credential_id"]) == 0 {
		t.Error("event lacks the executor-known session credential")
	}
}

func TestRejectPendingRoleAndInputChecks(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	p := r.proposeExec(t, canonical.RiskMedium)
	for _, tc := range []struct {
		name         string
		role         permit.RejectRole
		user, reason string
		want         permit.Code
	}{
		{"server without session", permit.RejectRoleServer, "alice", "", permit.CodeSessionRequired},
		{"server without relayed user", permit.RejectRoleServer, "", "", permit.CodeInvalidRequest},
		{"admin with relayed user", permit.RejectRoleAdmin, "alice", "", permit.CodeInvalidRequest},
		{"other role", permit.RejectRole("pve-collector"), "", "", permit.CodeInvalidRequest},
		{"empty role", permit.RejectRole(""), "", "", permit.CodeInvalidRequest},
		{"reason too long", permit.RejectRoleAdmin, "", strings.Repeat("x", 201), permit.CodeInvalidRequest},
		{"reason with control", permit.RejectRoleAdmin, "", "a\nb", permit.CodeInvalidRequest},
		{"reason with bidi", permit.RejectRoleAdmin, "", "a‮b", permit.CodeInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.reject(p.Digest, tc.role, tc.user, tc.reason)
			wantCode(t, err, tc.want)
		})
	}
	// Nothing changed: still pending and approvable.
	if st, ok := r.exec.PermitState(p.Digest); !ok || st != permit.StatePending {
		t.Fatalf("state = %v %v, want pending", st, ok)
	}
	if r.rej.eventCount() != 0 {
		t.Fatal("refused rejection wrote an event")
	}
	r.openSession(t)
	if _, err := r.reject(p.Digest, permit.RejectRoleServer, "alice", "dup"); err != nil {
		t.Fatalf("server with session: %v", err)
	}
}

func TestRejectPendingErrorCodes(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	wantCode(t, adminReject(r, canonical.Digest{1}), permit.CodeNotFound)

	approved := r.proposeExec(t, canonical.RiskMedium)
	if _, err := r.exec.ApproveCLI(approved.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, adminReject(r, approved.Digest), permit.CodeAlreadyApproved)

	ended := r.proposeExec(t, canonical.RiskMedium)
	r.unix.Add(int64(permit.ApprovalWindow/time.Second) + 1)
	wantCode(t, adminReject(r, ended.Digest), permit.CodeNotFound)

	// A lock drops pending permits: not found, not rejected.
	locked := r.proposeExec(t, canonical.RiskMedium)
	r.exec.Lock("test")
	wantCode(t, adminReject(r, locked.Digest), permit.CodeNotFound)
	if r.rej.eventCount() != 0 {
		t.Fatal("refused rejection wrote an event")
	}
}

func TestRejectStorageFailureLeavesPermitPendingAndApprovable(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	p := r.proposeExec(t, canonical.RiskMedium)
	r.rej.failWrite = errors.New("disk full")
	wantCode(t, adminReject(r, p.Digest), permit.CodeStorage)
	r.rej.failWrite = nil
	r.rej.failRead = errors.New("disk gone")
	wantCode(t, adminReject(r, p.Digest), permit.CodeStorage)
	// A failed marker read also refuses approval (fail closed).
	_, err := r.exec.ApproveCLI(p.Digest, 0, "admin")
	wantCode(t, err, permit.CodeStorage)
	r.rej.failRead = nil
	if r.rej.eventCount() != 0 {
		t.Fatal("failed rejection wrote an event")
	}
	if _, err := r.exec.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		t.Fatalf("still pending permit not approvable: %v", err)
	}
}

func TestRejectWithoutStoreFailsClosed(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	exec, err := permit.New(permit.Options{Verifier: e.options.Verifier, Store: e.store, RiskPolicy: lowFloor{}, Now: e.options.Now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = RejectPending(exec, nil, permit.RejectRequest{Digest: canonical.Digest{2}, Role: permit.RejectRoleAdmin})
	wantCode(t, err, permit.CodeStorage)
}

func TestRejectedSlotHeldUntilWindowEnd(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	for range permit.MaxPending {
		r.proposeExec(t, canonical.RiskMedium)
	}
	pending := r.exec.Pending()
	if err := adminReject(r, pending[0].Digest); err != nil {
		t.Fatal(err)
	}
	// The slot is still taken: rejecting frees no capacity early.
	rejectSeq++
	_, err := r.exec.Propose(canonical.Request{}, nil)
	if err == nil {
		t.Fatal("malformed request accepted")
	}
	params := []byte(`{"approved":true}`)
	req := pending[1].Request
	req.ExecutionID = fmt.Sprintf("00000000-0000-4000-a000-%012d", rejectSeq)
	_, err = r.exec.Propose(req, params)
	wantCode(t, err, permit.CodeLimit)
	// After the window both the permits and the placeholder are gone.
	r.unix.Add(int64(permit.ApprovalWindow/time.Second) + 1)
	if _, err := r.exec.Propose(req, params); err != nil {
		t.Fatalf("propose after window: %v", err)
	}
}

// --- batches ---

func TestRejectPendingBatchAsWhole(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	raw, in := r.plan(t, canonical.RiskMedium, canonical.RiskHigh)
	ap, err := r.a.Propose(ctx, raw, in)
	if err != nil {
		t.Fatal(err)
	}
	retainedBefore := r.a.retained
	got, err := r.reject(ap.Digest, permit.RejectRoleAdmin, "", "no")
	if err != nil {
		t.Fatalf("reject batch: %v", err)
	}
	if got.Kind != permit.ProposalBatch || got.ID != ap.Plan.BatchID {
		t.Fatalf("rejection = %+v", got)
	}
	if r.a.retained != 0 || retainedBefore == 0 {
		t.Fatalf("plan bytes not released: %d -> %d", retainedBefore, r.a.retained)
	}
	if r.a.countLocked() != 1 {
		t.Fatal("rejected plan does not hold its pending slot")
	}
	_, err = r.a.SubmitAssertion(ctx, ap.Digest, r.sign(ap.Challenge))
	wantCode(t, err, permit.CodeRejected)
	_, err = r.a.ApproveCLI(ctx, ap.Digest, 1000)
	wantCode(t, err, permit.CodeRejected)
	wantCode(t, adminReject(r, ap.Digest), permit.CodeAlreadyRejected)

	// Re-proposal of the identical plan: the batch ID check (seen, then the
	// marker) runs before bindExecutionIDs, so the answer is
	// permit_wrong_state, not execution_id_reused; after lock (seen kept)
	// and after restart (marker only).
	_, err = r.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeWrongState)
	r.a.Lock()
	_, err = r.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeWrongState)
	r.restart(t)
	_, err = r.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeWrongState)
	if st, ok := r.a.PlanState(ap.Digest); ok {
		t.Fatalf("rejected plan live after restart: %v", st)
	}
}

func TestBatchRejectThenLockDropsPlaceholder(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	ap := propose(t, r.environment, canonical.RiskMedium)
	if err := adminReject(r, ap.Digest); err != nil {
		t.Fatal(err)
	}
	r.a.Lock()
	if n := r.a.countLocked(); n != 0 {
		t.Fatalf("count after lock = %d", n)
	}
}

func TestRejectApprovedBatchIsAlreadyApproved(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	r.openSession(t)
	ap := propose(t, r.environment, canonical.RiskMedium)
	if _, err := r.a.SubmitAssertion(ctx, ap.Digest, r.sign(ap.Challenge)); err != nil {
		t.Fatal(err)
	}
	wantCode(t, adminReject(r, ap.Digest), permit.CodeAlreadyApproved)
}

// --- race of approval and rejection ---

func TestApproveThenRejectAndRejectThenApprove(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	a := r.proposeExec(t, canonical.RiskMedium)
	if _, err := r.exec.ApproveCLI(a.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, adminReject(r, a.Digest), permit.CodeAlreadyApproved)

	b := r.proposeExec(t, canonical.RiskMedium)
	if err := adminReject(r, b.Digest); err != nil {
		t.Fatal(err)
	}
	_, err := r.exec.ApproveCLI(b.Digest, 0, "admin")
	wantCode(t, err, permit.CodeRejected)
}

// Concurrent approval and rejection of one digest: exactly one wins and the
// loser gets the code for its order. Run with -race.
func TestConcurrentApproveAndRejectExactlyOneWins(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	for i := range 40 {
		p := r.proposeExec(t, canonical.RiskMedium)
		var wg sync.WaitGroup
		var approveErr, rejectErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, approveErr = r.exec.ApproveCLI(p.Digest, 0, "admin") }()
		go func() { defer wg.Done(); rejectErr = adminReject(r, p.Digest) }()
		wg.Wait()
		switch {
		case approveErr == nil && rejectErr != nil:
			wantCode(t, rejectErr, permit.CodeAlreadyApproved)
		case rejectErr == nil && approveErr != nil:
			wantCode(t, approveErr, permit.CodeRejected)
		default:
			t.Fatalf("round %d: approve=%v reject=%v", i, approveErr, rejectErr)
		}
	}
}

func TestConcurrentBatchApproveAndRejectExactlyOneWins(t *testing.T) {
	r := newRejectEnv(t, permit.ModeHardened)
	for i := range 20 {
		raw, in := r.plan(t, canonical.RiskHigh)
		// A fresh batch ID per round.
		raw = []byte(strings.Replace(string(raw), "00000000-0000-4000-8000-000000000001", fmt.Sprintf("00000000-0000-4000-8000-%012d", 100+i), 1))
		raw = []byte(strings.Replace(string(raw), "00000000-0000-4000-8000-000000000010", fmt.Sprintf("00000000-0000-4000-8000-%012d", 500+i), 1))
		ap, err := r.a.Propose(ctx, raw, in)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var approveErr, rejectErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, approveErr = r.a.ApproveCLI(ctx, ap.Digest, 1000) }()
		go func() { defer wg.Done(); rejectErr = adminReject(r, ap.Digest) }()
		wg.Wait()
		switch {
		case approveErr == nil && rejectErr != nil:
			wantCode(t, rejectErr, permit.CodeAlreadyApproved)
		case rejectErr == nil && approveErr != nil:
			wantCode(t, approveErr, permit.CodeRejected)
		default:
			t.Fatalf("round %d: approve=%v reject=%v", i, approveErr, rejectErr)
		}
	}
}

// Lock order batch.mu -> permit.mu: rejections run concurrently with batch
// proposals and browser approvals, which take the batch mutex and then the
// permit mutex through Options.Session. An inverted order would deadlock
// here; the test fails instead of hanging.
func TestRejectLockOrderMatchesBatchSessionPath(t *testing.T) {
	r := newRejectEnv(t, permit.ModeStandard)
	r.openSession(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := range 10 {
			wg.Add(3)
			go func() {
				defer wg.Done()
				raw, in := r.plan(t, canonical.RiskMedium)
				raw = []byte(strings.Replace(string(raw), "00000000-0000-4000-8000-000000000001", fmt.Sprintf("00000000-0000-4000-8000-%012d", 200+i), 1))
				raw = []byte(strings.Replace(string(raw), "00000000-0000-4000-8000-000000000010", fmt.Sprintf("00000000-0000-4000-8000-%012d", 700+i), 1))
				if ap, err := r.a.Propose(ctx, raw, in); err == nil {
					_, _ = r.a.SubmitAssertion(ctx, ap.Digest, []byte("{}"))
					_ = adminReject(r, ap.Digest)
				}
			}()
			go func() { defer wg.Done(); _ = adminReject(r, canonical.Digest{byte(i)}) }()
			go func() { defer wg.Done(); r.exec.Session() }()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("rejection and batch paths deadlocked (lock order inversion)")
	}
}

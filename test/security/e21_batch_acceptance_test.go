// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// E21 (ADR 0007 "One approval for an exact change plan"): batch substitution
// and replay, lock races and crash reconciliation, with the batch authority
// and member dispatcher wired to the real executor.db (durable spent
// execution IDs), the real WebAuthn verifier and real executor restarts.
//
// The executor has no production batch Policy or dispatch Recorder yet (only
// the internal/permit/batch and internal/executor/dispatch libraries exist);
// e21Policy derives risk and trust from the real riskpolicy over executor.db,
// and e21Recorder is a file-backed intent/outcome log that "dies" with its
// simulated process.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
)

var (
	e21UpgradeArtifact = []byte("#!/bin/sh\nset -eu\necho upgrade\n")
	e21UpgradeParams   = []byte(`{"packages":["openssl"]}`)
)

const e21UpgradeAction = "package.upgrade"

// e21Policy is the executor verdict for a member: the real risk floor over
// executor.db, and a trust digest that changes whenever the artifact's trust
// entry changes.
type e21Policy struct {
	db   *executordb.DB
	risk *riskpolicy.Policy
}

func (p *e21Policy) Evaluate(_ context.Context, m canonical.BatchMember) (batch.Snapshot, error) {
	floor, _, err := p.risk.MinimumRisk(m.Request, m.Request.ResolvedTargets)
	if err != nil {
		return batch.Snapshot{}, err
	}
	declared, trusted, err := p.db.ArtifactRisk(m.Request.ArtifactSHA256, m.Request.ActionID, m.Request.ModuleVersion)
	if err != nil {
		return batch.Snapshot{}, err
	}
	return batch.Snapshot{Risk: floor, Trust: sha256.Sum256(fmt.Appendf(nil, "%s|%s|%s|%t|%s",
		m.Request.ArtifactSHA256, m.Request.ActionID, m.Request.ModuleVersion, trusted, declared))}, nil
}

// e21Recorder is a durable dispatch.Recorder backed by one JSON file. A
// crashed process's recorder is marked dead: it writes nothing afterwards.
type e21Recorder struct {
	mu    sync.Mutex
	path  string
	dead  bool
	State map[string]string // execution ID -> "intent" or the terminal outcome
}

func openE21Recorder(t *testing.T, dir string) *e21Recorder {
	t.Helper()
	r := &e21Recorder{path: filepath.Join(dir, "e21-dispatch.json"), State: map[string]string{}}
	raw, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return r
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &r.State); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *e21Recorder) saveLocked() error {
	raw, err := json.Marshal(r.State)
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func (r *e21Recorder) RecordIntent(_ context.Context, run dispatch.Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dead {
		return errors.New("process is dead")
	}
	if _, ok := r.State[run.ExecutionID]; ok {
		return dispatch.ErrIntentRecorded
	}
	r.State[run.ExecutionID] = "intent"
	return r.saveLocked()
}

func (r *e21Recorder) RecordOutcome(_ context.Context, run dispatch.Run, o dispatch.Outcome) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dead {
		return errors.New("process is dead")
	}
	r.State[run.ExecutionID] = string(o)
	return r.saveLocked()
}

func (r *e21Recorder) crash() { r.mu.Lock(); r.dead = true; r.mu.Unlock() }

func (r *e21Recorder) get(id string) string { r.mu.Lock(); defer r.mu.Unlock(); return r.State[id] }

// e21Batch is one executor process's batch authority.
type e21Batch struct {
	a       *batch.Authority
	session atomic.Bool
}

func newE21Batch(t *testing.T, h *harness) *e21Batch {
	t.Helper()
	risk, err := riskpolicy.New(h.db)
	if err != nil {
		t.Fatal(err)
	}
	b := &e21Batch{}
	b.session.Store(true)
	b.a, err = batch.New(batch.Options{
		Mode: permit.ModeStandard, Verifier: h.verifier, Store: h.db, AdminUID: 4242,
		Policy:  &e21Policy{db: h.db, risk: risk},
		Session: func() (bool, time.Time) { return b.session.Load(), time.Now().Add(time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func e21UUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// e21TrustUpgrade trusts the upgrade artifact as MEDIUM: batches of it need
// one presence assertion inside a privileged session.
func e21TrustUpgrade(t *testing.T, h *harness) {
	t.Helper()
	if err := h.db.TrustArtifact(executordb.TrustedArtifact{SHA256: hexSum(e21UpgradeArtifact), ActionID: e21UpgradeAction, ModuleVersion: "1.0.0", Risk: canonical.RiskMedium, TrustedBy: "acceptance"}); err != nil {
		t.Fatal(err)
	}
}

type e21Member struct{ id, host, fp, execID string }

// e21Plan builds a single-stage batch-v1 plan of upgrade members, in order.
func e21Plan(t *testing.T, batchID string, members []e21Member) ([]byte, []batch.MemberInput) {
	t.Helper()
	ph, err := canonical.HashParameters(e21UpgradeParams)
	if err != nil {
		t.Fatal(err)
	}
	b := canonical.Batch{BatchVersion: canonical.BatchVersion, BatchID: batchID, ExpiryUnix: time.Now().Add(2 * time.Hour).Unix(),
		StagePlan: canonical.BatchStagePlan{Stages: []canonical.BatchStage{{StageID: "only", Gate: canonical.BatchGateManual, RequiredPostchecks: []string{}}}, Dependencies: []canonical.BatchDependency{}}}
	var inputs []batch.MemberInput
	for _, m := range members {
		b.Members = append(b.Members, canonical.BatchMember{MemberID: m.id, Request: canonical.Request{
			RequestVersion: canonical.RequestVersion, ExecutionID: m.execID, ActionID: e21UpgradeAction, ModuleVersion: "1.0.0",
			ArtifactSHA256: hexSum(e21UpgradeArtifact), ParametersHash: ph, CredentialRefs: []string{credRef}, RiskClass: canonical.RiskLow, ExpiryUnix: b.ExpiryUnix,
			ResolvedTargets: []canonical.Target{{HostID: m.host, HostKeyFingerprint: m.fp}}},
			CredentialVersions: []canonical.CredentialVersion{{Reference: credRef, Version: 1}}, PreconditionHashes: []string{}})
		b.StagePlan.Stages[0].MemberIDs = append(b.StagePlan.Stages[0].MemberIDs, m.id)
		inputs = append(inputs, batch.MemberInput{MemberID: m.id, Artifact: e21UpgradeArtifact, ParametersJSON: e21UpgradeParams})
	}
	sh, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash = sh.String()
	for i := range b.Members {
		b.Members[i].Request.StagePlanHash = sh.String()
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw, inputs
}

func e21TwoMembers(t *testing.T) []e21Member {
	return []e21Member{
		{id: "upgrade-dockerflux", host: "dockerflux", fp: fpA, execID: e21UUID(t)},
		{id: "upgrade-strompi", host: "strompi", fp: fpB, execID: e21UUID(t)},
	}
}

func e21Approved(t *testing.T, h *harness, b *e21Batch, raw []byte, in []batch.MemberInput) batch.Approval {
	t.Helper()
	p, err := b.a.Propose(context.Background(), raw, in)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if p.Risk != canonical.RiskMedium || p.Requirement != permit.RequireAssertionPresence {
		t.Fatalf("executor-derived risk %s / %s, want MEDIUM presence", p.Risk, p.Requirement)
	}
	a, err := b.a.SubmitAssertion(context.Background(), p.Digest, h.sign(p.Challenge))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return a
}

func wantPermitCode(t *testing.T, err error, codes ...permit.Code) {
	t.Helper()
	for _, c := range codes {
		if permit.CodeOf(err) == c {
			return
		}
	}
	t.Fatalf("got %v, want one of %v", err, codes)
}

// TestE21BatchSubstitutionAndReplayFail: an assertion for one plan cannot
// approve another (reordered) plan, a used assertion cannot be replayed, a
// child that differs from its frozen parent member in any binding is not
// claimable, members cannot be claimed under another parent, concurrent
// claims of one member yield exactly one permit, and a re-proposed plan with
// already spent execution IDs is refused durably.
func TestE21BatchSubstitutionAndReplayFail(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	e21TrustUpgrade(t, h)
	b := newE21Batch(t, h)
	ctx := context.Background()
	members := e21TwoMembers(t)
	rawP, inP := e21Plan(t, e21UUID(t), members)
	// Q: the same members reordered under a fresh batch and execution IDs.
	reordered := []e21Member{members[1], members[0]}
	reordered[0].execID, reordered[1].execID = e21UUID(t), e21UUID(t)
	rawQ, inQ := e21Plan(t, e21UUID(t), reordered)

	p, err := b.a.Propose(ctx, rawP, inP)
	if err != nil {
		t.Fatal(err)
	}
	q, err := b.a.Propose(ctx, rawQ, inQ)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest == q.Digest {
		t.Fatal("reordering did not change the digest")
	}
	assertionP := h.sign(p.Challenge)
	// The server shows plan P and submits the approval for Q.
	_, err = b.a.SubmitAssertion(ctx, q.Digest, assertionP)
	wantPermitCode(t, err, permit.CodeAssertionRejected)
	approved, err := b.a.SubmitAssertion(ctx, p.Digest, assertionP)
	if err != nil {
		t.Fatalf("approve P: %v", err)
	}
	// Replaying the used assertion approves nothing more.
	if _, err := b.a.SubmitAssertion(ctx, p.Digest, assertionP); err == nil {
		t.Fatal("replayed assertion accepted for approved plan")
	}
	if _, err := b.a.SubmitAssertion(ctx, q.Digest, assertionP); err == nil {
		t.Fatal("replayed assertion approved Q")
	}
	if _, err := b.a.Check(ctx, q.Digest); err == nil {
		t.Fatal("Q became approved")
	}

	frozen := approved.Plan.Members
	substitute := func(f func(*canonical.BatchMember)) canonical.BatchMember {
		raw, err := json.Marshal(frozen[0])
		if err != nil {
			t.Fatal(err)
		}
		var m canonical.BatchMember
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		f(&m)
		return m
	}
	for _, tc := range []struct {
		name   string
		parent canonical.Digest
		index  int
		member canonical.BatchMember
	}{
		{"other target", p.Digest, 0, substitute(func(m *canonical.BatchMember) {
			m.Request.ResolvedTargets = []canonical.Target{{HostID: "strompi", HostKeyFingerprint: fpB}}
		})},
		{"other host key", p.Digest, 0, substitute(func(m *canonical.BatchMember) { m.Request.ResolvedTargets[0].HostKeyFingerprint = fpB })},
		{"other action", p.Digest, 0, substitute(func(m *canonical.BatchMember) { m.Request.ActionID = "package.remove" })},
		{"other artifact", p.Digest, 0, substitute(func(m *canonical.BatchMember) { m.Request.ArtifactSHA256 = hexSum([]byte("evil")) })},
		{"other parameters", p.Digest, 0, substitute(func(m *canonical.BatchMember) { m.Request.ParametersHash = hexSum([]byte("{}")) })},
		{"downgraded risk", p.Digest, 0, substitute(func(m *canonical.BatchMember) { m.Request.RiskClass = canonical.RiskLow })},
		{"other execution ID", p.Digest, 0, substitute(func(m *canonical.BatchMember) { m.Request.ExecutionID = e21UUID(t) })},
		{"other credential version", p.Digest, 0, substitute(func(m *canonical.BatchMember) { m.CredentialVersions[0].Version = 2 })},
		{"member at another index", p.Digest, 1, frozen[0]},
		{"inserted member index", p.Digest, 2, frozen[0]},
		{"unapproved parent", q.Digest, 1, frozen[0]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.a.ClaimMember(ctx, tc.parent, tc.index, tc.member); err == nil {
				t.Fatal("substituted member claimed")
			}
		})
	}
	// Concurrent claims of the exact member: exactly one permit.
	const racers = 16
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			if _, err := b.a.ClaimMember(ctx, p.Digest, 0, frozen[0]); err == nil {
				wins.Add(1)
			} else if permit.CodeOf(err) != permit.CodeWrongState {
				t.Errorf("losing claim: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent claims succeeded, want 1", wins.Load())
	}
	// The same plan bytes under a new batch ID reuse spent execution IDs.
	var plan canonical.Batch
	if err := json.Unmarshal(rawP, &plan); err != nil {
		t.Fatal(err)
	}
	plan.BatchID = e21UUID(t)
	again, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.a.Propose(ctx, again, inP)
	wantPermitCode(t, err, permit.CodeExecutionIDReused)
	// Proposing P again verbatim is refused as well.
	if _, err := b.a.Propose(ctx, rawP, inP); err == nil {
		t.Fatal("verbatim re-proposal accepted")
	}
}

// TestE21BatchLockRacesDoNotLetQueuedWorkEscape: a lock between the durable
// dispatch intent and the transport call ends the claimed member as
// not_executed, without reaching the target, and revokes every remaining
// claim and approval. A trust change does the same for an unlocked batch.
func TestE21BatchLockRacesDoNotLetQueuedWorkEscape(t *testing.T) {
	for _, change := range []string{"lock", "untrust"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
			e21TrustUpgrade(t, h)
			b := newE21Batch(t, h)
			ctx := context.Background()
			members := e21TwoMembers(t)
			raw, in := e21Plan(t, e21UUID(t), members)
			approved := e21Approved(t, h, b, raw, in)
			if _, err := b.a.ClaimMember(ctx, approved.Digest, 0, approved.Plan.Members[0]); err != nil {
				t.Fatal(err)
			}
			rec := &pausingRecorder{e21Recorder: openE21Recorder(t, h.dataDir), reached: make(chan struct{}), resume: make(chan struct{})}
			var calls atomic.Int32
			d, err := dispatch.New(dispatch.Options{Permits: b.a, Recorder: rec,
				Transport: func(context.Context, dispatch.Run) (dispatch.Outcome, error) {
					calls.Add(1)
					return dispatch.OutcomeSuccess, nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				o   dispatch.Outcome
				err error
			}
			done := make(chan result, 1)
			go func() {
				o, err := d.Dispatch(ctx, approved.Digest, members[0].id)
				done <- result{o, err}
			}()
			select {
			case <-rec.reached:
			case <-time.After(10 * time.Second):
				t.Fatal("dispatch did not record intent")
			}
			switch change {
			case "lock":
				b.a.Lock()
			case "untrust":
				if ok, err := h.db.UntrustArtifact(hexSum(e21UpgradeArtifact), e21UpgradeAction, "1.0.0"); err != nil || !ok {
					t.Fatalf("untrust: %v %v", ok, err)
				}
				// The executor rechecks before any further authority use.
				if _, err := b.a.Check(ctx, approved.Digest); err == nil {
					t.Fatal("approval survived a trust withdrawal")
				}
			}
			close(rec.resume)
			var r result
			select {
			case r = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("dispatch did not finish")
			}
			if r.o != dispatch.OutcomeNotExecuted || !errors.Is(r.err, dispatch.ErrNotClaimed) {
				t.Fatalf("queued member after %s: %s, %v", change, r.o, r.err)
			}
			if calls.Load() != 0 {
				t.Fatalf("queued member reached the target after %s", change)
			}
			if got := rec.get(members[0].execID); got != string(dispatch.OutcomeNotExecuted) {
				t.Fatalf("recorded outcome %q, want not_executed", got)
			}
			// Nothing else of the batch can be claimed or dispatched.
			if _, err := b.a.ClaimMember(ctx, approved.Digest, 1, approved.Plan.Members[1]); err == nil {
				t.Fatalf("member claimed after %s", change)
			}
			if _, err := d.Dispatch(ctx, approved.Digest, members[0].id); !errors.Is(err, dispatch.ErrNotClaimed) {
				t.Fatalf("redispatch after %s: %v", change, err)
			}
			if calls.Load() != 0 {
				t.Fatalf("target reached after %s", change)
			}
		})
	}
}

// pausingRecorder stops the first dispatch right after its intent is durable.
type pausingRecorder struct {
	*e21Recorder
	reached, resume chan struct{}
	once            sync.Once
}

func (r *pausingRecorder) RecordIntent(ctx context.Context, run dispatch.Run) error {
	err := r.e21Recorder.RecordIntent(ctx, run)
	if err == nil {
		r.once.Do(func() { close(r.reached); <-r.resume })
	}
	return err
}

// TestE21BatchCrashReconciliationNeverRedispatches: an uncertain member is
// terminal and never dispatched twice; after a crash mid-dispatch the
// restarted executor holds no approval or member permit, the stale intent
// stays visible for reconciliation, and neither the old plan nor a new plan
// reusing its execution IDs can be approved again.
func TestE21BatchCrashReconciliationNeverRedispatches(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	e21TrustUpgrade(t, h)
	b := newE21Batch(t, h)
	ctx := context.Background()
	members := e21TwoMembers(t)
	raw, in := e21Plan(t, e21UUID(t), members)
	approved := e21Approved(t, h, b, raw, in)
	rec := openE21Recorder(t, h.dataDir)

	var calls sync.Map // execution ID -> *atomic.Int32
	count := func(id string) *atomic.Int32 {
		v, _ := calls.LoadOrStore(id, new(atomic.Int32))
		return v.(*atomic.Int32)
	}
	inTransport, never := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(never) })
	d, err := dispatch.New(dispatch.Options{Permits: b.a, Recorder: rec,
		Transport: func(ctx context.Context, run dispatch.Run) (dispatch.Outcome, error) {
			count(run.ExecutionID).Add(1)
			if run.MemberID == members[0].id {
				return "", errors.New("connection reset after command start")
			}
			close(inTransport)
			<-never // the process dies while the remote operation runs
			return dispatch.OutcomeSuccess, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	// Member 0: the connection breaks mid-run. The outcome is unknown and
	// the run is consumed; the claim cannot be dispatched again.
	if _, err := b.a.ClaimMember(ctx, approved.Digest, 0, approved.Plan.Members[0]); err != nil {
		t.Fatal(err)
	}
	if o, err := d.Dispatch(ctx, approved.Digest, members[0].id); o != dispatch.OutcomeUnknown || err == nil {
		t.Fatalf("broken connection: %s, %v", o, err)
	}
	if o, err := d.Dispatch(ctx, approved.Digest, members[0].id); !errors.Is(err, dispatch.ErrAlreadyDispatched) || o == dispatch.OutcomeSuccess {
		t.Fatalf("uncertain member redispatched: %s, %v", o, err)
	}
	// A second claim of the uncertain member is refused too.
	if _, err := b.a.ClaimMember(ctx, approved.Digest, 0, approved.Plan.Members[0]); err == nil {
		t.Fatal("uncertain member claimed again")
	}
	b.a.RecordOutcome(members[0].execID, members[0].id, permit.OutcomeUnreachable)

	// Member 1: the executor crashes while the command runs.
	if _, err := b.a.ClaimMember(ctx, approved.Digest, 1, approved.Plan.Members[1]); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = d.Dispatch(ctx, approved.Digest, members[1].id) }()
	select {
	case <-inTransport:
	case <-time.After(10 * time.Second):
		t.Fatal("member 1 did not reach the transport")
	}
	rec.crash()
	h.stop()

	// Restart on the same data directory.
	h2 := newHarness(t, harnessOptions{mode: permit.ModeStandard, dataDir: h.dataDir, identity: h.id})
	b2 := newE21Batch(t, h2)
	rec2 := openE21Recorder(t, h2.dataDir)
	if got := rec2.get(members[0].execID); got != string(dispatch.OutcomeUnknown) {
		t.Fatalf("member 0 after restart: %q, want unknown", got)
	}
	if got := rec2.get(members[1].execID); got != "intent" {
		t.Fatalf("member 1 after restart: %q, want a dangling intent to reconcile", got)
	}
	d2, err := dispatch.New(dispatch.Options{Permits: b2.a, Recorder: rec2,
		Transport: func(_ context.Context, run dispatch.Run) (dispatch.Outcome, error) {
			count(run.ExecutionID).Add(1)
			return dispatch.OutcomeSuccess, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	// Approval and permits were memory-only.
	if _, err := b2.a.Check(ctx, approved.Digest); err == nil {
		t.Fatal("approval survived restart")
	}
	for i, m := range members {
		if _, ok := b2.a.Member(approved.Digest, m.id); ok {
			t.Fatalf("member %d permit survived restart", i)
		}
		if _, err := d2.Dispatch(ctx, approved.Digest, m.id); !errors.Is(err, dispatch.ErrNotClaimed) {
			t.Fatalf("member %d dispatched after restart: %v", i, err)
		}
		if _, err := b2.a.ClaimMember(ctx, approved.Digest, i, approved.Plan.Members[i]); err == nil {
			t.Fatalf("member %d claimed after restart", i)
		}
	}
	// The restarted executor cannot be talked into re-approving the plan:
	// its execution IDs are durably spent.
	_, err = b2.a.Propose(ctx, raw, in)
	wantPermitCode(t, err, permit.CodeExecutionIDReused)
	var plan canonical.Batch
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	plan.BatchID = e21UUID(t)
	fresh, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b2.a.Propose(ctx, fresh, in)
	wantPermitCode(t, err, permit.CodeExecutionIDReused)
	// Even if a dispatcher somehow held a permit for the same execution ID,
	// the durable intent refuses it (simulated by a fake permit source).
	d3, err := dispatch.New(dispatch.Options{Permits: stalePermits{approved}, Recorder: rec2,
		Transport: func(_ context.Context, run dispatch.Run) (dispatch.Outcome, error) {
			count(run.ExecutionID).Add(1)
			return dispatch.OutcomeSuccess, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d3.Dispatch(ctx, approved.Digest, members[1].id); !errors.Is(err, dispatch.ErrAlreadyDispatched) {
		t.Fatalf("dangling intent redispatched: %v", err)
	}
	for i, m := range members {
		if n := count(m.execID).Load(); n != 1 {
			t.Fatalf("member %d reached the target %d times, want exactly 1", i, n)
		}
	}
}

// stalePermits pretends a member permit still exists, as a buggy or
// resurrected authority would.
type stalePermits struct{ approval batch.Approval }

func (s stalePermits) Member(parent canonical.Digest, memberID string) (batch.MemberPermit, bool) {
	for i, m := range s.approval.Plan.Members {
		if m.MemberID == memberID && parent == s.approval.Digest {
			return batch.MemberPermit{ParentDigest: parent, Index: i, Member: m, Parameters: s.approval.Parameters[i], Expiry: time.Now().Add(time.Hour)}, true
		}
	}
	return batch.MemberPermit{}, false
}

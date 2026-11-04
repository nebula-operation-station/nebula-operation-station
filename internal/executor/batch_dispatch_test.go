// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// attachedCall is one script the fake attached runner received.
type attachedCall struct {
	executionID string
	params      []byte
	script      []byte
}

// fakeAttached replaces hostrun.Attached (which needs sudo on the target)
// behind a real SSH connection to the loopback test host. It records every
// script handed to the host; block, when set, holds the run until closed.
type fakeAttached struct {
	mu      sync.Mutex
	calls   []attachedCall
	class   string
	started chan string
	block   chan struct{}
	// mayRun makes the next runs return like hostrun.Attached after a
	// timeout: no exit status, the remote process may still run.
	mayRun bool
}

// fakeVisible replaces hostrun.RunVisible: running is what the target
// reports about the run.
type fakeVisible struct {
	mu      sync.Mutex
	running bool
	checks  int
}

func (f *fakeVisible) run(_ context.Context, client *ssh.Client, _ string) (bool, error) {
	if client == nil {
		return true, fmt.Errorf("no connection")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	return f.running, nil
}

func (f *fakeVisible) set(running bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = running
}

func (f *fakeVisible) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks
}

func (f *fakeAttached) run(ctx context.Context, client *ssh.Client, executionID string, params, script []byte, _ time.Duration, _ ...hostrun.Secret) (hostrun.Result, error) {
	if client == nil {
		return hostrun.Result{}, fmt.Errorf("no connection")
	}
	f.mu.Lock()
	f.calls = append(f.calls, attachedCall{executionID: executionID, params: bytes.Clone(params), script: bytes.Clone(script)})
	class, started, block, mayRun := f.class, f.started, f.block, f.mayRun
	f.mu.Unlock()
	if started != nil {
		started <- executionID
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
		}
	}
	if mayRun {
		return hostrun.Result{Class: hostrun.ClassExecutionTimeout, Detail: "no result within 1m0s", ExitCode: -1, RemoteMayRun: true}, nil
	}
	if class == "" {
		class = hostrun.ClassSuccess
	}
	exit := 0
	if class != hostrun.ClassSuccess {
		exit = 3
	}
	return hostrun.Result{Class: class, ExitCode: exit, Result: []byte(`{"ok":true}`)}, nil
}

func (f *fakeAttached) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// dispatchMember is one member of a dispatch test plan.
type dispatchMember struct {
	host      string
	stage     int
	dependsOn []string
}

// dispatchEnv is a batch environment with the production batch authority,
// the production dispatcher and pinned loopback SSH hosts.
type dispatchEnv struct {
	*batchRPCEnv
	ssh      map[string]*testSSH
	attached *fakeAttached
	visible  *fakeVisible
	admin    pb.ExecutorServiceClient
	server   pb.ExecutorServiceClient
	next     int
	// failureThreshold is the failure threshold of the stages of plans
	// proposed from now on (capped at each stage's size).
	failureThreshold int
}

func newDispatchEnv(t *testing.T, hosts ...string) *dispatchEnv {
	t.Helper()
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	env.usePrivateKeyring()
	env.productionBatchAuthority(t)
	if err := env.svc.EnableBatchExecution(); err != nil {
		t.Fatal(err)
	}
	f := &fakeAttached{}
	env.svc.batchRun.attached = f.run
	v := &fakeVisible{}
	env.svc.batchRun.visible = v.run
	env.svc.batchRun.holdWait, env.svc.batchRun.holdPoll = 300*time.Millisecond, 20*time.Millisecond
	e := &dispatchEnv{batchRPCEnv: env, ssh: map[string]*testSSH{}, attached: f, visible: v,
		admin: readRPCClient(t, env.svc, peercred.RoleAdmin), server: readRPCClient(t, env.svc, peercred.RoleServer)}
	for _, h := range hosts {
		srv := startTestSSH(t, env.userPub, sshModeNormal)
		pin, err := env.db.PinHostKey(executordb.HostKey{HostID: h, PublicKey: srv.hostKey.PublicKey().Marshal(), User: "test",
			CredentialRef: "cred", Source: executordb.SourceProbe, PinnedBy: "test"})
		if err != nil {
			t.Fatal(err)
		}
		// A recorded criticality lets trusted MEDIUM members stay MEDIUM.
		if _, err := env.db.SetHostCriticality(h, pin.Fingerprint, canonical.RiskMedium, "test"); err != nil {
			t.Fatal(err)
		}
		e.ssh[h] = srv
	}
	return e
}

// artifact is the exact script of member i of plan n.
func dispatchArtifact(n, i int) []byte {
	return fmt.Appendf(nil, "#!/bin/sh\necho plan %d member %d\n", n, i)
}

// propose builds, proposes and (unless approve is false) locally approves a
// plan whose stages use gate. It returns the digest and the members in
// plan order.
func (e *dispatchEnv) propose(t *testing.T, gate string, approve bool, members ...dispatchMember) (string, []canonical.BatchMember, int) {
	t.Helper()
	e.next++
	n := e.next
	expiry := e.clock.Now().Unix() + 3600
	b := canonical.Batch{BatchVersion: canonical.BatchVersion, BatchID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), ExpiryUnix: expiry,
		StagePlan: canonical.BatchStagePlan{Dependencies: []canonical.BatchDependency{}}}
	req := &pb.ProposeBatchRequest{}
	for i, m := range members {
		for len(b.StagePlan.Stages) <= m.stage {
			b.StagePlan.Stages = append(b.StagePlan.Stages, canonical.BatchStage{StageID: fmt.Sprintf("stage-%d", len(b.StagePlan.Stages)+1),
				Gate: gate, MemberIDs: []string{}, RequiredPostchecks: []string{}})
		}
		id := fmt.Sprintf("member-%d", i)
		art := dispatchArtifact(n, i)
		params := fmt.Appendf(nil, `{"step":%d}`, i)
		ph, err := canonical.HashParameters(params)
		if err != nil {
			t.Fatal(err)
		}
		hk, ok, err := e.db.HostKey(m.host)
		if err != nil || !ok {
			t.Fatalf("host %s not pinned: %v", m.host, err)
		}
		h := sha256.Sum256(art)
		// Automatic gates (as in the deployment plan) need a plan below
		// HIGH: the artifacts are trusted as MEDIUM. Manual-gate plans use
		// untrusted artifacts, which the production policy makes HIGH.
		risk := canonical.RiskHigh
		if gate == canonical.BatchGateAutomatic {
			risk = canonical.RiskMedium
			if err := e.db.TrustArtifact(executordb.TrustedArtifact{SHA256: canonical.Digest(h).String(), ActionID: "package.upgrade",
				ModuleVersion: "1.0.0", Risk: risk, TrustedBy: "test"}); err != nil {
				t.Fatal(err)
			}
		}
		b.Members = append(b.Members, canonical.BatchMember{MemberID: id, Request: canonical.Request{
			RequestVersion: canonical.RequestVersion, ExecutionID: fmt.Sprintf("00000000-0000-4000-8%03d-%012d", n, i+100), ActionID: "package.upgrade",
			ModuleVersion: "1.0.0", ArtifactSHA256: canonical.Digest(h).String(), ParametersHash: ph, CredentialRefs: []string{"cred"},
			RiskClass: risk, ExpiryUnix: expiry,
			ResolvedTargets: []canonical.Target{{HostID: m.host, HostKeyFingerprint: hk.Fingerprint}}},
			CredentialVersions: []canonical.CredentialVersion{{Reference: "cred", Version: CredentialVersionOf(e.userPub)}}, PreconditionHashes: []string{}})
		b.StagePlan.Stages[m.stage].MemberIDs = append(b.StagePlan.Stages[m.stage].MemberIDs, id)
		if len(m.dependsOn) > 0 {
			b.StagePlan.Dependencies = append(b.StagePlan.Dependencies, canonical.BatchDependency{MemberID: id, DependsOn: m.dependsOn})
		}
		req.Members = append(req.Members, &pb.BatchMemberInput{MemberId: id, Artifact: art, ParametersJson: params})
		// Only used when a test swaps in the stub policy.
		e.policy.mu.Lock()
		e.policy.states[id] = batch.Snapshot{Risk: risk, Trust: sha256.Sum256([]byte(id))}
		e.policy.mu.Unlock()
	}
	for i := range b.StagePlan.Stages {
		b.StagePlan.Stages[i].FailureThreshold = min(e.failureThreshold, len(b.StagePlan.Stages[i].MemberIDs))
	}
	h, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash = h.String()
	for i := range b.Members {
		b.Members[i].Request.StagePlanHash = h.String()
	}
	if req.BatchJson, err = json.Marshal(b); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	prop, err := e.server.ProposeBatch(ctx, req)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if approve {
		if _, err := e.admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: prop.GetBatchDigest()}); err != nil {
			t.Fatalf("approve: %v", err)
		}
	}
	plan, _, _, err := canonical.ParseBatch(prop.GetCanonicalBatch(), e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return prop.GetBatchDigest(), plan.Members, n
}

// runReq is the server's request for member i of plan n on its host.
func (e *dispatchEnv) runReq(digest string, n, i int, host string) *pb.RunBatchMemberRequest {
	return &pb.RunBatchMemberRequest{BatchDigest: digest, MemberId: fmt.Sprintf("member-%d", i), Endpoints: []string{e.ssh[host].addr},
		Artifact: dispatchArtifact(n, i), TimeoutSeconds: 60}
}

// requireRefused asserts a refusal before the claim with code: nothing was
// handed to a host and no run was recorded.
func (e *dispatchEnv) requireRefused(t *testing.T, err error, code codes.Code, member canonical.BatchMember, calls int) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("err = %v, want %s", err, code)
	}
	if e.attached.count() != calls {
		t.Fatalf("%d scripts handed to hosts, want %d", e.attached.count(), calls)
	}
	host := member.Request.ResolvedTargets[0].HostID
	if _, err := e.db.GetRun(member.Request.ExecutionID, host); err == nil {
		t.Fatal("a refused member left a run record")
	}
}

// An approved two-stage plan on one host runs member by member: each
// member exactly once, with exactly the frozen script, parameters and
// execution ID; a member behind its stage or dependency is refused before
// anything runs; a spent member is never run again; the capability is
// advertised only with the dispatcher wired.
func TestRunBatchMemberRunsApprovedMembersInOrder(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	caps, err := e.server.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{})
	if err != nil || !caps.GetBatchExecutionAvailable() {
		t.Fatalf("execution not advertised with the dispatcher wired: %v %v", caps, err)
	}

	pending, pm, pn := e.propose(t, canonical.BatchGateAutomatic, false, dispatchMember{host: "web-1"})
	_, err = e.server.RunBatchMember(ctx, e.runReq(pending, pn, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, pm[0], 0)

	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true,
		dispatchMember{host: "web-1"}, dispatchMember{host: "web-1", stage: 1, dependsOn: []string{"member-0"}})
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1"))
	e.requireRefused(t, err, codes.PermissionDenied, members[1], 0)

	for i := range members {
		resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, i, "web-1"))
		if err != nil {
			t.Fatalf("member %d: %v", i, err)
		}
		if resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS || resp.GetClass() != hostrun.ClassSuccess ||
			resp.GetExecutionId() != members[i].Request.ExecutionID || resp.GetEndpoint() != e.ssh["web-1"].addr {
			t.Fatalf("member %d: %+v", i, resp)
		}
		got := e.attached.calls[i]
		if got.executionID != members[i].Request.ExecutionID || !bytes.Equal(got.script, dispatchArtifact(n, i)) ||
			string(got.params) != fmt.Sprintf(`{"step":%d}`, i) {
			t.Fatalf("member %d ran %+v", i, got)
		}
		run, err := e.db.GetRun(members[i].Request.ExecutionID, "web-1")
		if err != nil || run.State != executordb.RunFinished || run.Class != hostrun.ClassSuccess || run.Digest != d {
			t.Fatalf("member %d run record %+v %v", i, run, err)
		}
	}
	// Spent: a replay is refused and nothing runs again.
	for i := range members {
		_, err := e.server.RunBatchMember(ctx, e.runReq(d, n, i, "web-1"))
		if status.Code(err) != codes.FailedPrecondition || e.attached.count() != len(members) {
			t.Fatalf("replay of member %d: %v, %d runs", i, err, e.attached.count())
		}
	}
	if len(e.logs.find("batch_member_finished", members[0].Request.ExecutionID)) != 1 {
		t.Error("member run not audited")
	}
}

// Every refusal before the claim leaves the member unspent and nothing
// runs: wrong artifact bytes, unknown member, unknown batch, malformed
// requests, a host whose pin changed or is blocked, a locked keyring and a
// service without the dispatcher.
func TestRunBatchMemberRefusesBeforeClaim(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})

	cases := []struct {
		name string
		mut  func(*pb.RunBatchMemberRequest)
		code codes.Code
	}{
		{"artifact differs", func(r *pb.RunBatchMemberRequest) { r.Artifact = []byte("#!/bin/sh\nrm -rf /\n") }, codes.InvalidArgument},
		{"artifact missing", func(r *pb.RunBatchMemberRequest) { r.Artifact = nil }, codes.InvalidArgument},
		{"unknown member", func(r *pb.RunBatchMemberRequest) { r.MemberId = "member-9" }, codes.NotFound},
		{"oversize member", func(r *pb.RunBatchMemberRequest) { r.MemberId = strings.Repeat("m", maxBatchMemberIDBytes+1) }, codes.InvalidArgument},
		{"unknown batch", func(r *pb.RunBatchMemberRequest) { r.BatchDigest = strings.Repeat("0", 64) }, codes.NotFound},
		{"bad digest", func(r *pb.RunBatchMemberRequest) { r.BatchDigest = "x" }, codes.InvalidArgument},
		{"no endpoints", func(r *pb.RunBatchMemberRequest) { r.Endpoints = nil }, codes.InvalidArgument},
		{"timeout too long", func(r *pb.RunBatchMemberRequest) { r.TimeoutSeconds = 3600 }, codes.InvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := e.runReq(d, n, 0, "web-1")
			c.mut(req)
			_, err := e.server.RunBatchMember(ctx, req)
			e.requireRefused(t, err, c.code, members[0], 0)
		})
	}

	t.Run("member not UTF-8", func(t *testing.T) {
		// gRPC refuses it on the wire; a direct call is refused too.
		req := e.runReq(d, n, 0, "web-1")
		req.MemberId = "\xff"
		_, err := e.svc.RunBatchMember(ctx, req)
		e.requireRefused(t, err, codes.InvalidArgument, members[0], 0)
	})

	t.Run("blocked host", func(t *testing.T) {
		if _, err := e.db.BlockHost("web-1", "SHA256:other", "127.0.0.1:22"); err != nil {
			t.Fatal(err)
		}
		_, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
		e.requireRefused(t, err, codes.FailedPrecondition, members[0], 0)
	})

	t.Run("no dispatcher", func(t *testing.T) {
		env := newBatchRPCEnv(t, uint32(os.Getuid()))
		_, err := env.svc.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("err = %v", err)
		}
		if caps, err := env.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{}); err != nil || caps.GetBatchExecutionAvailable() {
			t.Fatalf("execution advertised without a dispatcher: %v %v", caps, err)
		}
	})
}

// The member is unspent after a refusal: once the cause is gone the same
// member runs (exactly once).
func TestRunBatchMemberRefusalLeavesMemberUnspent(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	bad := e.runReq(d, n, 0, "web-1")
	bad.Artifact = []byte("#!/bin/sh\necho substituted\n")
	_, err := e.server.RunBatchMember(ctx, bad)
	e.requireRefused(t, err, codes.InvalidArgument, members[0], 0)
	resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS || e.attached.count() != 1 {
		t.Fatalf("after refusal: %v %v, %d runs", resp, err, e.attached.count())
	}
}

// Fail closed after the claim: a key rotated between approval and dispatch
// ends the member as not executed (nothing reaches the host, the run
// record says so, the member is spent and the rollout stops); a locked
// executor refuses.
func TestRunBatchMemberFailsClosedAfterApproval(t *testing.T) {
	t.Run("credential rotated", func(t *testing.T) {
		e := newDispatchEnv(t, "web-1")
		ctx := context.Background()
		d, members, n := e.propose(t, canonical.BatchGateAutomatic, true,
			dispatchMember{host: "web-1"}, dispatchMember{host: "web-1", stage: 1})
		kr, _ := rotatedTestKeyring(t)
		e.svc.keys = kr
		resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
		// The batch policy notices the rotation first (revalidation
		// revokes the batch) or the dispatcher's own credential check
		// does; either way it is an error status before the claim or a
		// not-executed response after it, and nothing ran.
		if err == nil && resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED {
			t.Fatalf("rotated: %+v", resp)
		}
		if e.attached.count() != 0 {
			t.Fatal("a member ran with a rotated credential")
		}
		if run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err == nil && run.Class != classBatchNotExecuted {
			t.Fatalf("run record %+v", run)
		}
		_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1"))
		if err == nil || e.attached.count() != 0 {
			t.Fatalf("the next member ran after a rotation: %v", err)
		}
	})
	t.Run("locked", func(t *testing.T) {
		e := newDispatchEnv(t, "web-1")
		ctx := context.Background()
		d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
		if _, err := e.svc.Lock(ctx, &pb.LockRequest{}); err != nil {
			t.Fatal(err)
		}
		_, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
		e.requireRefused(t, err, codes.FailedPrecondition, members[0], 0)
	})
}

// The dispatcher's own credential check (Options.Credentials) runs after
// the claim, immediately before the target, independent of the batch
// policy: with a policy that does not look at credentials, a key rotated
// after approval still ends the claimed member as not executed; its run
// record says so, it is spent and nothing reached the host.
func TestRunBatchMemberCredentialCheckAtDispatch(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	// The stub policy of newBatchRPCEnv never reads credentials.
	stub, err := batch.New(batch.Options{
		Mode: permit.ModeStandard, Verifier: e.verifier, Policy: e.policy, AdminUIDs: e.adminUIDs, Now: e.clock.Now, Store: e.db,
		Session: func() (bool, time.Time) { return true, e.clock.Now().Add(time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetBatchAuthority(stub)
	if err := e.svc.EnableBatchExecution(); err != nil {
		t.Fatal(err)
	}
	e.svc.batchRun.attached = e.attached.run
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	kr, _ := rotatedTestKeyring(t)
	e.svc.keys = kr
	resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED || e.attached.count() != 0 {
		t.Fatalf("rotated after approval: %+v %v, %d runs", resp, err, e.attached.count())
	}
	if !strings.Contains(resp.GetDetail(), "credential") || strings.Contains(resp.GetDetail(), "PRIVATE") {
		t.Errorf("detail = %q", resp.GetDetail())
	}
	if run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err != nil || run.Class != classBatchNotExecuted || run.State != executordb.RunFinished {
		t.Fatalf("run record %+v %v", run, err)
	}
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err == nil || e.attached.count() != 0 {
		t.Fatalf("spent member ran again: %v", err)
	}
}

// A script failure is a definitive failure: recorded, the member is spent,
// and the default zero threshold stops the rollout so the next stage never
// runs.
func TestRunBatchMemberFailureStopsRollout(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	e.attached.class = hostrun.ClassScriptFailed
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true,
		dispatchMember{host: "web-1"}, dispatchMember{host: "web-1", stage: 1})
	resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || resp.GetExitCode() != 3 {
		t.Fatalf("failed member: %+v %v", resp, err)
	}
	if run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err != nil || run.Class != hostrun.ClassScriptFailed {
		t.Fatalf("run record %+v %v", run, err)
	}
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1"))
	e.requireRefused(t, err, codes.PermissionDenied, members[1], 1)
}

// An unreachable target is a definitive failure flagged unreachable:
// nothing reached the host.
func TestRunBatchMemberUnreachable(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	req := e.runReq(d, n, 0, "web-1")
	req.Endpoints = []string{closedAddr(t)}
	resp, err := e.server.RunBatchMember(ctx, req)
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || !resp.GetUnreachable() || e.attached.count() != 0 {
		t.Fatalf("unreachable: %+v %v", resp, err)
	}
	if run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err != nil || run.Class != classNetworkUnreachable {
		t.Fatalf("run record %+v %v", run, err)
	}
}

// A run record for the member's execution ID that outlived a restart (the
// intent was recorded before a crash) means the member is never dispatched
// again: its outcome is unknown and nothing runs.
func TestRunBatchMemberNeverRedispatchesRecordedIntent(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	if err := e.db.CreateRun(executordb.Run{ExecutionID: members[0].Request.ExecutionID, HostID: "web-1", Digest: d,
		Endpoints: []string{e.ssh["web-1"].addr}, Fingerprint: members[0].Request.ResolvedTargets[0].HostKeyFingerprint, Timeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_UNKNOWN || e.attached.count() != 0 {
		t.Fatalf("recorded intent: %+v %v, %d runs", resp, err, e.attached.count())
	}
}

// At most one batch member runs on a target at a time, across batches: a
// second batch's member for the same host is refused while the first runs
// (nothing claimed), and runs once the host is free; another host is not
// held up.
func TestRunBatchMemberOneAtATimePerTarget(t *testing.T) {
	e := newDispatchEnv(t, "web-1", "web-2")
	ctx := context.Background()
	dA, _, nA := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	dB, membersB, nB := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	dC, _, nC := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-2"})

	e.attached.mu.Lock()
	e.attached.started = make(chan string, 4)
	e.attached.block = make(chan struct{})
	e.attached.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := e.server.RunBatchMember(ctx, e.runReq(dA, nA, 0, "web-1"))
		done <- err
	}()
	<-e.attached.started

	_, err := e.server.RunBatchMember(ctx, e.runReq(dB, nB, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, membersB[0], 1)
	if !strings.Contains(status.Convert(err).Message(), "batch_host_busy") {
		t.Errorf("refusal = %v", err)
	}
	// Another target runs concurrently.
	otherDone := make(chan error, 1)
	go func() {
		_, err := e.server.RunBatchMember(ctx, e.runReq(dC, nC, 0, "web-2"))
		otherDone <- err
	}()
	<-e.attached.started
	close(e.attached.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-otherDone; err != nil {
		t.Fatal(err)
	}
	resp, err := e.server.RunBatchMember(ctx, e.runReq(dB, nB, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("after the host is free: %+v %v", resp, err)
	}
}

// Concurrent requests for the same member run it at most once.
func TestRunBatchMemberConcurrentReplayRunsOnce(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, _, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1")); err == nil && resp.GetOutcome() == pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 || e.attached.count() != 1 {
		t.Fatalf("%d successes, %d runs; want exactly one", ok, e.attached.count())
	}
}

// A HIGH plan has manual stage gates: the second stage's member is refused
// (nothing runs) until the local admin opens the stage, then runs once.
func TestRunBatchMemberWaitsForManualGate(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateManual, true,
		dispatchMember{host: "web-1"}, dispatchMember{host: "web-1", stage: 1})
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("stage 1: %+v %v", resp, err)
	}
	_, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1"))
	e.requireRefused(t, err, codes.PermissionDenied, members[1], 1)
	if _, err := e.admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d,
		Gate: &pb.Gate{Kind: pb.GateKind_GATE_KIND_OPEN_STAGE, Stage: 2}}); err != nil {
		t.Fatalf("open stage 2: %v", err)
	}
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("stage 2: %+v %v", resp, err)
	}
	if e.attached.count() != 2 {
		t.Fatalf("%d runs, want 2", e.attached.count())
	}
}

// A crash after the script was handed over leaves the run marked running;
// an attached run leaves no job on the host, so reconciliation ends it as
// unknown (never not executed, never rerun). A crash before that leaves it
// dispatching, which reconciles as not executed.
func TestBatchMemberCrashReconciles(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(map[bool]string{true: "running", false: "dispatching"}[running], func(t *testing.T) {
			e := newDispatchEnv(t, "web-1")
			hk, _, err := e.db.HostKey("web-1")
			if err != nil {
				t.Fatal(err)
			}
			id := newTestUUID()
			if err := e.db.CreateRun(executordb.Run{ExecutionID: id, HostID: "web-1", Digest: strings.Repeat("a", 64),
				Endpoints: []string{e.ssh["web-1"].addr}, Fingerprint: hk.Fingerprint, Timeout: time.Minute}); err != nil {
				t.Fatal(err)
			}
			want := classNotExecuted
			if running {
				if err := e.db.MarkRunRunning(id, "web-1", e.ssh["web-1"].addr); err != nil {
					t.Fatal(err)
				}
				want = classUnknown
			}
			e.svc.ReconcileOnce(context.Background())
			run, err := e.db.GetRun(id, "web-1")
			if err != nil || run.State != executordb.RunFinished || run.Class != want {
				t.Fatalf("reconciled run %+v %v, want class %s", run, err, want)
			}
		})
	}
}

// A member whose attached run returned without an exit status (timeout,
// cancelled request) may still be running on its target: its outcome is
// unknown, never a definitive failure, and while the target reports the
// run, no other batch member starts there, even when the stage's
// threshold lets the rollout go on and even from another batch. The
// target is freed once it shows the run gone.
func TestRunBatchMemberTimeoutHoldsTarget(t *testing.T) {
	e := newDispatchEnv(t, "web-1", "web-2")
	ctx := context.Background()
	e.failureThreshold = 1
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true,
		dispatchMember{host: "web-1"}, dispatchMember{host: "web-1"}, dispatchMember{host: "web-2"})
	dB, membersB, nB := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})

	e.visible.set(true)
	e.attached.mu.Lock()
	e.attached.mayRun = true
	e.attached.mu.Unlock()
	resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_UNKNOWN || resp.GetClass() != classUnknown ||
		!strings.Contains(resp.GetDetail(), hostrun.ClassExecutionTimeout) || !strings.Contains(resp.GetDetail(), "held") {
		t.Fatalf("timed-out member: %+v %v", resp, err)
	}
	if run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err != nil || run.Class != classUnknown || run.State != executordb.RunFinished {
		t.Fatalf("run record %+v %v", run, err)
	}
	if e.visible.count() == 0 {
		t.Fatal("the target was never asked whether the run is gone")
	}
	e.attached.mu.Lock()
	e.attached.mayRun = false
	e.attached.mu.Unlock()

	// The threshold lets the rollout go on, but the next member on the
	// same target must not start while the run may still be there.
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[1], 1)
	if !strings.Contains(status.Convert(err).Message(), "batch_host_busy") {
		t.Errorf("refusal = %v", err)
	}
	_, err = e.server.RunBatchMember(ctx, e.runReq(dB, nB, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, membersB[0], 1)
	// Another target is not held up.
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 2, "web-2")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("other target: %+v %v", resp, err)
	}

	// The run ended on the target: the refused member was never claimed
	// and now runs.
	e.visible.set(false)
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("after the run is gone: %+v %v", resp, err)
	}
	if e.attached.count() != 3 {
		t.Fatalf("%d runs, want 3", e.attached.count())
	}
}

// A timed-out member whose run the target already shows gone frees the
// target before its response: the next member runs at once.
func TestRunBatchMemberTimeoutReleasesWhenGone(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	e.failureThreshold = 1
	d, _, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"}, dispatchMember{host: "web-1"})
	e.attached.mu.Lock()
	e.attached.mayRun = true
	e.attached.mu.Unlock()
	resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_UNKNOWN || strings.Contains(resp.GetDetail(), "held") {
		t.Fatalf("timed-out member: %+v %v", resp, err)
	}
	e.attached.mu.Lock()
	e.attached.mayRun = false
	e.attached.mu.Unlock()
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("next member: %+v %v", resp, err)
	}
}

// A target that cannot be asked (unreachable) stays held: fail closed.
func TestRunBatchMemberHeldTargetUnreachableStaysHeld(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	e.failureThreshold = 1
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"}, dispatchMember{host: "web-1"})
	e.attached.mu.Lock()
	e.attached.mayRun = true
	e.attached.mu.Unlock()
	e.visible.set(true)
	if _, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1")); err != nil {
		t.Fatal(err)
	}
	e.attached.mu.Lock()
	e.attached.mayRun = false
	e.attached.mu.Unlock()
	// The target is gone from the network: no answer is not "finished",
	// although the host would say so if it could be reached.
	eps, err := parseEndpoints([]string{closedAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.batchRun.mu.Lock()
	e.svc.batchRun.held["web-1"].call.eps = eps
	e.svc.batchRun.mu.Unlock()
	e.visible.set(false)
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[1], 1)
}

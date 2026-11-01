// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// The server proposes and relays assertions; only the admin reviews and
// approves; both may read status. No other role reaches the batch surface.
func TestBatchMethodRoles(t *testing.T) {
	methods := map[string][]peercred.Role{
		pb.ExecutorService_ProposeBatch_FullMethodName:    {peercred.RoleServer},
		pb.ExecutorService_CommitBatch_FullMethodName:     {peercred.RoleServer},
		pb.ExecutorService_ReviewBatch_FullMethodName:     {peercred.RoleAdmin},
		pb.ExecutorService_ApproveBatchCLI_FullMethodName: {peercred.RoleAdmin},
		pb.ExecutorService_GetBatchStatus_FullMethodName:  {peercred.RoleServer, peercred.RoleAdmin},
	}
	roles := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector, peercred.Role("discovery")}
	uids := map[uint32][]peercred.Role{}
	for i, r := range roles {
		uids[uint32(i+1)] = []peercred.Role{r}
	}
	policy := peercred.NewPolicy(uids, MethodRoles())
	for method, want := range methods {
		t.Run(method, func(t *testing.T) {
			if got := MethodRoles()[method]; len(got) != len(want) {
				t.Errorf("roles = %v, want %v", got, want)
			}
			for i, role := range roles {
				allowed := false
				for _, r := range want {
					allowed = allowed || r == role
				}
				if _, ok := policy.Allowed(uint32(i+1), method); ok != allowed {
					t.Errorf("role %s allowed=%v, want %v", role, ok, allowed)
				}
			}
			if _, ok := policy.Allowed(999, method); ok {
				t.Error("unknown UID allowed")
			}
		})
	}
}

func validProposeBatchRequest() *pb.ProposeBatchRequest {
	return &pb.ProposeBatchRequest{
		BatchJson: []byte(`{}`),
		Members:   []*pb.BatchMemberInput{{MemberId: "member-0", Artifact: []byte("#!/bin/sh\n"), ParametersJson: []byte(`{}`)}},
	}
}

// Oversize and malformed requests are rejected before the authority is
// touched: the Service below has no authority, so reaching it would panic or
// answer Unimplemented instead of InvalidArgument.
func TestBatchRPCRejectsOversizeAndMalformedBeforeAuthority(t *testing.T) {
	tooMany := make([]*pb.BatchMemberInput, canonical.MaxBatchMembers+1)
	for i := range tooMany {
		tooMany[i] = &pb.BatchMemberInput{MemberId: fmt.Sprintf("m-%d", i), Artifact: []byte("x"), ParametersJson: []byte(`{}`)}
	}
	proposals := map[string]func(*pb.ProposeBatchRequest){
		"missing plan": func(r *pb.ProposeBatchRequest) { r.BatchJson = nil },
		"oversize plan": func(r *pb.ProposeBatchRequest) {
			r.BatchJson = bytes.Repeat([]byte(" "), canonical.MaxBatchInputSize+1)
		},
		"invalid UTF8 plan":  func(r *pb.ProposeBatchRequest) { r.BatchJson = []byte{'{', 0xff, '}'} },
		"no members":         func(r *pb.ProposeBatchRequest) { r.Members = nil },
		"too many members":   func(r *pb.ProposeBatchRequest) { r.Members = tooMany },
		"missing member ID":  func(r *pb.ProposeBatchRequest) { r.Members[0].MemberId = "" },
		"oversize member ID": func(r *pb.ProposeBatchRequest) { r.Members[0].MemberId = strings.Repeat("a", maxBatchMemberIDBytes+1) },
		"missing artifact":   func(r *pb.ProposeBatchRequest) { r.Members[0].Artifact = nil },
		"oversize artifact":  func(r *pb.ProposeBatchRequest) { r.Members[0].Artifact = make([]byte, permit.MaxArtifactSize+1) },
		"missing parameters": func(r *pb.ProposeBatchRequest) { r.Members[0].ParametersJson = nil },
		"oversize parameters": func(r *pb.ProposeBatchRequest) {
			r.Members[0].ParametersJson = make([]byte, canonical.MaxParametersSize+1)
		},
		"invalid UTF8 params": func(r *pb.ProposeBatchRequest) { r.Members[0].ParametersJson = []byte{'{', 0xff, '}'} },
	}
	s := &Service{}
	ctx := context.Background()
	if _, err := s.ProposeBatch(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil: %v", err)
	}
	for name, mutate := range proposals {
		t.Run(name, func(t *testing.T) {
			r := validProposeBatchRequest()
			mutate(r)
			if _, err := s.ProposeBatch(ctx, r); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("want InvalidArgument, got %v", err)
			}
		})
	}

	digest := strings.Repeat("a", 64)
	for _, d := range []string{"", "bad", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 1000)} {
		if _, err := s.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: d, AssertionJson: []byte(`{}`)}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("commit digest %q: %v", d, err)
		}
		if _, err := s.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: d}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("review digest %q: %v", d, err)
		}
		if _, err := s.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("approve digest %q: %v", d, err)
		}
		if _, err := s.GetBatchStatus(ctx, &pb.GetBatchStatusRequest{BatchDigest: d}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("status digest %q: %v", d, err)
		}
	}
	for _, a := range [][]byte{nil, []byte(`broken`), {0xff}, make([]byte, webauthnverify.MaxAssertionSize+1)} {
		if _, err := s.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: digest, AssertionJson: a}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("assertion %d bytes: %v", len(a), err)
		}
	}
	if _, err := s.CommitBatch(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil commit: %v", err)
	}
}

// Without a wired authority every well-formed batch request is
// Unimplemented: nothing is approved by default.
func TestBatchRPCUnconfiguredIsUnimplemented(t *testing.T) {
	s := &Service{}
	ctx := context.Background()
	d := strings.Repeat("a", 64)
	calls := map[string]func() error{
		"propose": func() error { _, err := s.ProposeBatch(ctx, validProposeBatchRequest()); return err },
		"commit": func() error {
			_, err := s.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: d, AssertionJson: []byte(`{}`)})
			return err
		},
		"review":  func() error { _, err := s.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: d}); return err },
		"approve": func() error { _, err := s.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d}); return err },
		"status":  func() error { _, err := s.GetBatchStatus(ctx, &pb.GetBatchStatusRequest{BatchDigest: d}); return err },
	}
	for name, call := range calls {
		if err := call(); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s: want Unimplemented, got %v", name, err)
		}
	}
}

// Direct calls without authenticated peer credentials cannot review or
// approve: the admin identity never comes from a request field.
func TestBatchCLIRequiresPeerCredentials(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	ctx := context.Background()
	d := strings.Repeat("a", 64)
	if _, err := env.svc.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: d}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("review: %v", err)
	}
	if _, err := env.svc.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("approve: %v", err)
	}
}

type batchRPCPolicy struct {
	mu     sync.Mutex
	states map[string]batch.Snapshot
}

func (p *batchRPCPolicy) Evaluate(_ context.Context, m canonical.BatchMember) (batch.Snapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.states[m.MemberID], nil
}

type batchRPCEnv struct {
	*reconcileEnv
	policy *batchRPCPolicy
	sign   func([]byte) []byte
}

func newBatchRPCEnv(t *testing.T, adminUID uint32) *batchRPCEnv {
	t.Helper()
	e := newReconcileEnv(t)
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	dev := virtualwebauthn.NewAuthenticator()
	dev.AddCredential(cred)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db},
		[]webauthnverify.Credential{{ID: cred.ID, PublicKey: cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.reg, err = webauthnreg.New(webauthnreg.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}}, v, e.db)
	if err != nil {
		t.Fatal(err)
	}
	p := &batchRPCPolicy{states: map[string]batch.Snapshot{}}
	a, err := batch.New(batch.Options{
		Mode: permit.ModeStandard, Verifier: v, Policy: p, AdminUID: adminUID, Now: e.clock.Now,
		Session: func() (bool, time.Time) { return true, e.clock.Now().Add(time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetBatchAuthority(a)
	sign := func(ch []byte) []byte {
		cred.Counter++
		return []byte(virtualwebauthn.CreateAssertionResponse(virtualwebauthn.RelyingParty{Name: "Reconcile", ID: "reconcile.test", Origin: "https://reconcile.test"}, dev, cred,
			virtualwebauthn.AssertionOptions{Challenge: ch, RelyingPartyID: "reconcile.test"}))
	}
	return &batchRPCEnv{reconcileEnv: e, policy: p, sign: sign}
}

// plan builds a complete two-stage plan with a dependency, one member per risk.
func (e *batchRPCEnv) plan(t *testing.T, risks ...canonical.Risk) *pb.ProposeBatchRequest {
	t.Helper()
	expiry := e.clock.Now().Unix() + 3600
	b := canonical.Batch{BatchVersion: canonical.BatchVersion, BatchID: "00000000-0000-4000-8000-000000000001", ExpiryUnix: expiry,
		StagePlan: canonical.BatchStagePlan{Stages: []canonical.BatchStage{
			{StageID: "first", Gate: canonical.BatchGateManual, RequiredPostchecks: []string{}},
			{StageID: "second", Gate: canonical.BatchGateManual, FailureThreshold: 1, RequiredPostchecks: []string{}},
		}, Dependencies: []canonical.BatchDependency{}}}
	req := &pb.ProposeBatchRequest{}
	for i, r := range risks {
		id := fmt.Sprintf("member-%d", i)
		art := []byte("#!/bin/sh\necho ready " + strconv.Itoa(i) + "\n")
		params := []byte(`{"approved":true}`)
		ph, err := canonical.HashParameters(params)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(art)
		b.Members = append(b.Members, canonical.BatchMember{MemberID: id, Request: canonical.Request{
			RequestVersion: canonical.RequestVersion, ExecutionID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10), ActionID: "package.upgrade", ModuleVersion: "1.0.0",
			ArtifactSHA256: canonical.Digest(h).String(), ParametersHash: ph, CredentialRefs: []string{"admin-key"}, RiskClass: r, ExpiryUnix: expiry,
			ResolvedTargets: []canonical.Target{{HostID: fmt.Sprintf("host-%d", i), HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43)}}},
			CredentialVersions: []canonical.CredentialVersion{{Reference: "admin-key", Version: 1}}, PreconditionHashes: []string{}})
		stage := 0
		if i > 0 {
			stage = 1
			b.StagePlan.Dependencies = append(b.StagePlan.Dependencies, canonical.BatchDependency{MemberID: id, DependsOn: []string{"member-0"}})
		}
		b.StagePlan.Stages[stage].MemberIDs = append(b.StagePlan.Stages[stage].MemberIDs, id)
		req.Members = append(req.Members, &pb.BatchMemberInput{MemberId: id, Artifact: art, ParametersJson: params})
		e.policy.mu.Lock()
		e.policy.states[id] = batch.Snapshot{Risk: r, Trust: sha256.Sum256([]byte(id))}
		e.policy.mu.Unlock()
	}
	if len(b.StagePlan.Stages[1].MemberIDs) == 0 {
		b.StagePlan.Stages = b.StagePlan.Stages[:1]
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
	return req
}

// checkCompletePlan asserts the typed view carries every member and the full
// graph, each member linked to the parent stage plan hash, and matches the
// authoritative canonical bytes.
func checkCompletePlan(t *testing.T, plan *pb.BatchPlan, canonicalBatch []byte, members int) {
	t.Helper()
	var want canonical.Batch
	if err := json.Unmarshal(canonicalBatch, &want); err != nil {
		t.Fatalf("canonical batch: %v", err)
	}
	if plan.GetBatchId() != want.BatchID || plan.GetStagePlanHash() != want.StagePlanHash || plan.GetBatchVersion() != want.BatchVersion || plan.GetExpiryUnix() != want.ExpiryUnix {
		t.Fatalf("parent mismatch: %+v", plan)
	}
	if len(plan.GetMembers()) != members || len(want.Members) != members {
		t.Fatalf("members = %d/%d, want %d", len(plan.GetMembers()), len(want.Members), members)
	}
	for i, m := range plan.GetMembers() {
		w := want.Members[i]
		if m.GetMemberId() != w.MemberID || m.GetExecutionId() != w.Request.ExecutionID || m.GetArtifactSha256() != w.Request.ArtifactSHA256 ||
			m.GetParametersHash() != w.Request.ParametersHash || m.GetStagePlanHash() != plan.GetStagePlanHash() || len(m.GetHostIds()) != 1 {
			t.Errorf("member %d not linked to parent: %+v", i, m)
		}
	}
	if len(plan.GetStages()) != len(want.StagePlan.Stages) || len(plan.GetDependencies()) != len(want.StagePlan.Dependencies) {
		t.Fatalf("graph truncated: %d stages, %d dependencies", len(plan.GetStages()), len(plan.GetDependencies()))
	}
	seen := 0
	for i, st := range plan.GetStages() {
		w := want.StagePlan.Stages[i]
		if st.GetStageId() != w.StageID || st.GetGate() != w.Gate || int(st.GetFailureThreshold()) != w.FailureThreshold || len(st.GetMemberIds()) != len(w.MemberIDs) {
			t.Errorf("stage %d: %+v", i, st)
		}
		seen += len(st.GetMemberIds())
	}
	if seen != members {
		t.Errorf("stages assign %d members, want %d", seen, members)
	}
}

// The server proposes and reads status but can never review or approve; the
// configured local admin reviews the complete plan and approves it.
func TestBatchServerProposesAdminApproves(t *testing.T) {
	uid := uint32(os.Getuid())
	env := newBatchRPCEnv(t, uid)
	server := readRPCClient(t, env.svc, peercred.RoleServer)
	admin := readRPCClient(t, env.svc, peercred.RoleAdmin)
	ctx := context.Background()

	prop, err := server.ProposeBatch(ctx, env.plan(t, canonical.RiskLow, canonical.RiskHigh, canonical.RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	if prop.GetState() != pb.PermitState_PERMIT_STATE_PENDING || prop.GetRisk() != pb.RiskClass_RISK_CLASS_HIGH || len(prop.GetChallenge()) == 0 {
		t.Fatalf("propose: state %v risk %v", prop.GetState(), prop.GetRisk())
	}
	checkCompletePlan(t, prop.GetPlan(), prop.GetCanonicalBatch(), 3)
	d := prop.GetBatchDigest()

	// Server approval separation: the role table refuses review and CLI
	// approval, and status reports nothing approved.
	if _, err := server.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: d}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server review: %v", err)
	}
	if _, err := server.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server approve: %v", err)
	}
	if _, err := server.GetBatchStatus(ctx, &pb.GetBatchStatusRequest{BatchDigest: d}); status.Code(err) == codes.OK {
		t.Fatal("pending batch reported as approved")
	}
	// The admin role cannot propose or relay assertions.
	if _, err := admin.ProposeBatch(ctx, validProposeBatchRequest()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin propose: %v", err)
	}
	if _, err := admin.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: d, AssertionJson: []byte(`{}`)}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin commit: %v", err)
	}

	rev, err := admin.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: d})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rev.GetCanonicalBatch(), prop.GetCanonicalBatch()) || len(rev.GetMemberParameters()) != 3 || len(rev.GetMemberFindings()) != 3 ||
		rev.GetApprovedBy() != "" || rev.GetApprovalExpiryUnix() == 0 {
		t.Fatalf("review incomplete: %+v", rev)
	}
	checkCompletePlan(t, rev.GetPlan(), rev.GetCanonicalBatch(), 3)

	ok, err := admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d})
	if err != nil {
		t.Fatal(err)
	}
	if ok.GetState() != pb.PermitState_PERMIT_STATE_APPROVED || ok.GetApprovedBy() != "cli:"+strconv.FormatUint(uint64(uid), 10) {
		t.Fatalf("approve: %+v", ok)
	}
	for name, c := range map[string]pb.ExecutorServiceClient{"server": server, "admin": admin} {
		st, err := c.GetBatchStatus(ctx, &pb.GetBatchStatusRequest{BatchDigest: d})
		if err != nil {
			t.Fatalf("%s status: %v", name, err)
		}
		if st.GetState() != pb.PermitState_PERMIT_STATE_APPROVED || st.GetBatchId() != prop.GetPlan().GetBatchId() ||
			st.GetStagePlanHash() != prop.GetPlan().GetStagePlanHash() || len(st.GetMemberIds()) != 3 || len(st.GetMemberExecutionIds()) != 3 {
			t.Fatalf("%s status: %+v", name, st)
		}
		for i, m := range prop.GetPlan().GetMembers() {
			if st.GetMemberIds()[i] != m.GetMemberId() || st.GetMemberExecutionIds()[i] != m.GetExecutionId() {
				t.Errorf("%s status member %d linkage: %s/%s", name, i, st.GetMemberIds()[i], st.GetMemberExecutionIds()[i])
			}
		}
	}
	// A second approval of the same digest is refused.
	if _, err := admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d}); status.Code(err) == codes.OK {
		t.Fatal("approved twice")
	}
}

// An admin-role peer that is not the configured executor-local admin UID can
// neither review nor approve.
func TestBatchCLIRejectsOtherAdminUID(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid())+1)
	server := readRPCClient(t, env.svc, peercred.RoleServer)
	admin := readRPCClient(t, env.svc, peercred.RoleAdmin)
	ctx := context.Background()
	prop, err := server.ProposeBatch(ctx, env.plan(t, canonical.RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: prop.GetBatchDigest()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("review: %v", err)
	}
	if _, err := admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: prop.GetBatchDigest()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("approve: %v", err)
	}
}

// The server's relayed assertion is verified by the executor: a forged
// assertion is rejected, a user-verified one approves the whole batch.
func TestBatchCommitVerifiesRelayedAssertion(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	server := readRPCClient(t, env.svc, peercred.RoleServer)
	ctx := context.Background()
	prop, err := server.ProposeBatch(ctx, env.plan(t, canonical.RiskMedium, canonical.RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	if prop.GetApprovalRequirement() == pb.ApprovalRequirement_APPROVAL_REQUIREMENT_UNSPECIFIED || len(prop.GetRequestOptionsJson()) == 0 {
		t.Fatalf("no browser challenge: %+v", prop)
	}
	forged := env.sign(bytes.Repeat([]byte{1}, len(prop.GetChallenge())))
	if _, err := server.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: prop.GetBatchDigest(), AssertionJson: forged}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forged assertion: %v", err)
	}
	ok, err := server.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: prop.GetBatchDigest(), AssertionJson: env.sign(prop.GetChallenge())})
	if err != nil {
		t.Fatal(err)
	}
	if ok.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		t.Fatalf("commit state %v", ok.GetState())
	}
}

// Plans beyond the canonical bounds, mismatched member inputs and CRITICAL
// members are rejected as a whole; nothing is recorded.
func TestBatchProposeRejectsOversizeOrIncompletePlans(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	server := readRPCClient(t, env.svc, peercred.RoleServer)
	ctx := context.Background()

	// One member per stage, every member valid: only the stage bound fails.
	tooManyStages := env.stagePerMember(t, canonical.MaxBatchStages+1)

	missingInput := env.plan(t, canonical.RiskMedium, canonical.RiskMedium)
	missingInput.Members = missingInput.Members[:1]

	swapped := env.plan(t, canonical.RiskMedium, canonical.RiskMedium)
	swapped.Members[0], swapped.Members[1] = swapped.Members[1], swapped.Members[0]

	substituted := env.plan(t, canonical.RiskMedium)
	substituted.Members[0].Artifact = []byte("#!/bin/sh\nrm -rf /\n")

	padded := env.plan(t, canonical.RiskMedium)
	padded.BatchJson = append(padded.BatchJson, bytes.Repeat([]byte(" "), canonical.MaxBatchInputSize)...)

	for name, tc := range map[string]struct {
		req  *pb.ProposeBatchRequest
		code codes.Code
	}{
		"too many stages":      {tooManyStages, codes.InvalidArgument},
		"missing member input": {missingInput, codes.InvalidArgument},
		"reordered inputs":     {swapped, codes.InvalidArgument},
		"substituted artifact": {substituted, codes.PermissionDenied},
		"oversize padded plan": {padded, codes.InvalidArgument},
		"critical member":      {env.plan(t, canonical.RiskMedium, canonical.RiskCritical), codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := server.ProposeBatch(ctx, tc.req); status.Code(err) != tc.code {
				t.Fatalf("want %v, got %v", tc.code, err)
			}
		})
	}
	// After every rejection the same batch ID can still be proposed (nothing
	// was recorded), and a plan exactly at the stage bound is complete.
	prop, err := server.ProposeBatch(ctx, env.stagePerMember(t, canonical.MaxBatchStages))
	if err != nil {
		t.Fatalf("plan at the stage bound: %v", err)
	}
	checkCompletePlan(t, prop.GetPlan(), prop.GetCanonicalBatch(), canonical.MaxBatchStages)
}

// stagePerMember builds a plan of n MEDIUM members, each in its own stage,
// with the stage plan hash recomputed where the graph is still hashable.
func (e *batchRPCEnv) stagePerMember(t *testing.T, n int) *pb.ProposeBatchRequest {
	t.Helper()
	risks := make([]canonical.Risk, n)
	for i := range risks {
		risks[i] = canonical.RiskMedium
	}
	req := e.plan(t, risks...)
	var b canonical.Batch
	if err := json.Unmarshal(req.BatchJson, &b); err != nil {
		t.Fatal(err)
	}
	b.StagePlan = canonical.BatchStagePlan{Dependencies: []canonical.BatchDependency{}}
	for _, m := range b.Members {
		b.StagePlan.Stages = append(b.StagePlan.Stages, canonical.BatchStage{StageID: "stage-" + m.MemberID, Gate: canonical.BatchGateManual, MemberIDs: []string{m.MemberID}, RequiredPostchecks: []string{}})
	}
	if h, err := canonical.BatchStagePlanHash(b.StagePlan); err == nil {
		b.StagePlanHash = h.String()
		for i := range b.Members {
			b.Members[i].Request.StagePlanHash = h.String()
		}
	} else if n <= canonical.MaxBatchStages {
		t.Fatalf("stage plan within bounds not hashable: %v", err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	req.BatchJson = raw
	return req
}

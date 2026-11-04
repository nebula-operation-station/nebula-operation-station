// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"os"
	"strconv"
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
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// newHardenedBatchEnv is newBatchRPCEnv with a hardened-mode batch authority
// and an active privileged session, so only the mode decides the refusal.
func newHardenedBatchEnv(t *testing.T, adminUID uint32) *batchRPCEnv {
	t.Helper()
	env := newBatchRPCEnv(t, adminUID)
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: env.db},
		[]webauthnverify.Credential{{ID: cred.ID, PublicKey: cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := batch.New(batch.Options{
		Mode: permit.ModeHardened, Verifier: v, Policy: env.policy, AdminUIDs: []uint32{adminUID}, Now: env.clock.Now, Store: env.db,
		Session: func() (bool, time.Time) { return true, env.clock.Now().Add(time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	env.svc.SetBatchAuthority(a)
	return env
}

func openStage(n uint32) *pb.Gate { return &pb.Gate{Kind: pb.GateKind_GATE_KIND_OPEN_STAGE, Stage: n} }

func skipMember(id string) *pb.Gate {
	return &pb.Gate{Kind: pb.GateKind_GATE_KIND_SKIP_HOST, HostId: id}
}

// In hardened mode a HIGH batch cannot be approved from the browser, even
// with a privileged session and a relayed assertion; the executor-local admin
// approves it after the full executor view, and the browser cannot open its
// stage gates either.
func TestHardenedHighBatchRefusedFromBrowserApprovedByCLI(t *testing.T) {
	uid := uint32(os.Getuid())
	env := newHardenedBatchEnv(t, uid)
	server := readRPCClient(t, env.svc, peercred.RoleServer)
	admin := readRPCClient(t, env.svc, peercred.RoleAdmin)
	ctx := context.Background()

	prop, err := server.ProposeBatch(ctx, env.plan(t, canonical.RiskHigh, canonical.RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	if prop.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY || len(prop.GetChallenge()) != 0 {
		t.Fatalf("hardened HIGH batch offered a browser path: %v challenge=%d", prop.GetApprovalRequirement(), len(prop.GetChallenge()))
	}
	d := prop.GetBatchDigest()
	if _, err := server.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: d, AssertionJson: env.sign([]byte("any challenge"))}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("browser commit of hardened HIGH batch: %v", err)
	}
	if _, err := server.GetBatchStatus(ctx, &pb.GetBatchStatusRequest{BatchDigest: d}); status.Code(err) == codes.OK {
		t.Fatal("browser commit approved the batch")
	}

	rev, err := admin.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: d})
	if err != nil {
		t.Fatal(err)
	}
	checkCompletePlan(t, rev.GetPlan(), rev.GetCanonicalBatch(), 2)
	if rev.GetRisk() != pb.RiskClass_RISK_CLASS_HIGH || rev.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
		t.Fatalf("review: risk %v state %v", rev.GetRisk(), rev.GetState())
	}
	// Gates of a pending batch are refused: approval comes first.
	if _, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: skipMember("member-0")}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("gate on pending batch: %v", err)
	}
	ok, err := admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d})
	if err != nil {
		t.Fatal(err)
	}
	if ok.GetApprovedBy() != "cli:"+strconv.FormatUint(uint64(uid), 10) {
		t.Fatalf("approved by %q", ok.GetApprovedBy())
	}

	// The browser gate path does not reach a batch: nothing opens.
	if _, err := server.BeginGate(ctx, &pb.BeginGateRequest{ExecutionDigest: d, Gate: skipMember("member-0")}); status.Code(err) == codes.OK {
		t.Fatal("browser began a batch gate")
	}
	if _, err := server.CommitGate(ctx, &pb.CommitGateRequest{ExecutionDigest: d, Gate: skipMember("member-0")}); status.Code(err) == codes.OK {
		t.Fatal("browser committed a batch gate")
	}
	r, err := admin.GetRollout(ctx, &pb.GetRolloutRequest{ExecutionDigest: d})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.GetRollout().GetStages()[0].GetOutcomes()) != 0 {
		t.Fatalf("browser gate changed the rollout: %+v", r.GetRollout())
	}
	if r.GetRollout().GetGateRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY {
		t.Fatalf("gate requirement %v, want CLI", r.GetRollout().GetGateRequirement())
	}
}

// The local admin opens batch stages in order: the next stage only after the
// open one passed, a skip is a recorded outcome, and stage numbers and member
// IDs outside the plan are refused.
func TestBatchStageGatesFromCLI(t *testing.T) {
	env := newHardenedBatchEnv(t, uint32(os.Getuid()))
	server := readRPCClient(t, env.svc, peercred.RoleServer)
	admin := readRPCClient(t, env.svc, peercred.RoleAdmin)
	ctx := context.Background()
	prop, err := server.ProposeBatch(ctx, env.plan(t, canonical.RiskHigh, canonical.RiskHigh, canonical.RiskLow))
	if err != nil {
		t.Fatal(err)
	}
	d := prop.GetBatchDigest()
	if _, err := admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: d}); err != nil {
		t.Fatal(err)
	}

	for name, r := range map[string]pb.ExecutorServiceClient{"admin": admin, "server": server} {
		got, err := r.GetRollout(ctx, &pb.GetRolloutRequest{ExecutionDigest: d})
		if err != nil {
			t.Fatalf("%s rollout: %v", name, err)
		}
		ro := got.GetRollout()
		if ro.GetOpenStage() != 1 || len(ro.GetStages()) != 2 {
			t.Fatalf("%s rollout: open %d, %d stages", name, ro.GetOpenStage(), len(ro.GetStages()))
		}
		first, second := ro.GetStages()[0].GetStage(), ro.GetStages()[1].GetStage()
		if first.GetName() != "first" || len(first.GetHostIds()) != 1 || first.GetHostIds()[0] != "member-0" ||
			second.GetName() != "second" || len(second.GetHostIds()) != 2 || second.GetMaxFailed() != 1 || second.GetContinueMode() != canonical.BatchGateManual {
			t.Fatalf("%s rollout stages: %+v / %+v", name, first, second)
		}
	}

	refused := []struct {
		name string
		gate *pb.Gate
		code codes.Code
	}{
		{"stage 2 before stage 1 passed", openStage(2), codes.FailedPrecondition},
		{"stage 3 does not exist", openStage(3), codes.InvalidArgument},
		{"stage 1 is no gate", openStage(1), codes.InvalidArgument},
		{"skip of a later stage", skipMember("member-1"), codes.PermissionDenied},
		{"skip of an unknown member", skipMember("member-9"), codes.InvalidArgument},
		{"skip with a stage", &pb.Gate{Kind: pb.GateKind_GATE_KIND_SKIP_HOST, Stage: 1, HostId: "member-0"}, codes.InvalidArgument},
		{"open with a member", &pb.Gate{Kind: pb.GateKind_GATE_KIND_OPEN_STAGE, Stage: 2, HostId: "member-0"}, codes.InvalidArgument},
		{"no gate", nil, codes.InvalidArgument},
		{"unknown kind", &pb.Gate{Stage: 2}, codes.InvalidArgument},
	}
	for _, tc := range refused {
		if _, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: tc.gate}); status.Code(err) != tc.code {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.code)
		}
	}

	res, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: skipMember("member-0")})
	if err != nil {
		t.Fatal(err)
	}
	if o := res.GetRollout().GetStages()[0].GetOutcomes(); len(o) != 1 || o[0].GetHostId() != "member-0" || o[0].GetOutcome() != string(permit.OutcomeSkipped) {
		t.Fatalf("skip outcome: %+v", o)
	}
	if _, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: skipMember("member-0")}); status.Code(err) == codes.OK {
		t.Fatal("member skipped twice")
	}
	res, err = admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: openStage(2)})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetRollout().GetOpenStage() != 2 || !res.GetRollout().GetStages()[0].GetPassed() {
		t.Fatalf("stage 2 not open: %+v", res.GetRollout())
	}
	if _, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: openStage(2)}); status.Code(err) == codes.OK {
		t.Fatal("stage 2 opened twice")
	}
}

// Only the configured executor-local admin UID applies batch gates: an
// admin-role peer with another UID and a direct call without peer
// credentials are refused, and the rollout is unchanged.
func TestBatchGateCLIRequiresAdminUID(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid())+1)
	server := readRPCClient(t, env.svc, peercred.RoleServer)
	admin := readRPCClient(t, env.svc, peercred.RoleAdmin)
	ctx := context.Background()
	prop, err := server.ProposeBatch(ctx, env.plan(t, canonical.RiskMedium, canonical.RiskMedium))
	if err != nil {
		t.Fatal(err)
	}
	d := prop.GetBatchDigest()
	if _, err := server.CommitBatch(ctx, &pb.CommitBatchRequest{BatchDigest: d, AssertionJson: env.sign(prop.GetChallenge())}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: skipMember("member-0")}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other admin UID: %v", err)
	}
	if _, err := env.svc.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: skipMember("member-0")}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no peer credentials: %v", err)
	}
	// The server role never reaches the CLI gate method.
	if _, err := server.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: skipMember("member-0")}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server CLI gate: %v", err)
	}
	r, err := server.GetRollout(ctx, &pb.GetRolloutRequest{ExecutionDigest: d})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.GetRollout().GetStages()[0].GetOutcomes()) != 0 {
		t.Fatalf("refused gate changed the rollout: %+v", r.GetRollout())
	}
}

// A digest the batch authority does not hold still reaches the host stage
// engine unchanged (NotFound there), and a batch digest never falls through
// to it.
func TestGateCLIUnknownDigestKeepsHostEngine(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	admin := readRPCClient(t, env.svc, peercred.RoleAdmin)
	ctx := context.Background()
	d := canonical.Digest{1}.String()
	if _, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: openStage(2)}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown digest gate: %v", err)
	}
	if _, err := admin.GetRollout(ctx, &pb.GetRolloutRequest{ExecutionDigest: d}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown digest rollout: %v", err)
	}
	if _, err := admin.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: "nothex", Gate: openStage(2)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed digest: %v", err)
	}
}

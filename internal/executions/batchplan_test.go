// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

var batchNow = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

// batchFP returns a well-formed SSH host key fingerprint unique to i.
func batchFP(i int) string {
	return "SHA256:" + strings.Repeat("A", 40) + fmt.Sprintf("%03d", i)
}

func containerID(i int) string { return fmt.Sprintf("%064x", 0xc0+i) }

// fakeBatchExec freezes a proposal the way the executor does: it parses
// the canonical plan, checks every member's artifact and parameters,
// raises each member to at least MEDIUM, and answers the canonical bytes.
type fakeBatchExec struct {
	mu        sync.Mutex
	pins      []*pb.HostKeyPin
	proposed  []*pb.ProposeBatchRequest
	critical  []string // member IDs the executor rates CRITICAL
	tamper    func(*canonical.Batch)
	state     pb.PermitState
	commitErr error
	statusErr error
	statusAns *pb.GetBatchStatusResponse
	frozen    canonical.Batch
	digest    string
	// proposeErr, when set, is returned by ProposeBatch after recording
	// the request.
	proposeErr error
}

func (f *fakeBatchExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{Hosts: f.pins}, nil
}

func (f *fakeBatchExec) ProposeBatch(_ context.Context, in *pb.ProposeBatchRequest, _ ...grpc.CallOption) (*pb.ProposeBatchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proposed = append(f.proposed, in)
	if f.proposeErr != nil {
		return nil, f.proposeErr
	}
	plan, _, _, err := canonical.ParseBatch(in.GetBatchJson(), batchNow)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid canonical batch")
	}
	if len(in.GetMembers()) != len(plan.Members) {
		return nil, status.Error(codes.InvalidArgument, "member inputs")
	}
	for i, m := range plan.Members {
		sum := sha256.Sum256(in.GetMembers()[i].GetArtifact())
		if in.GetMembers()[i].GetMemberId() != m.MemberID || hex.EncodeToString(sum[:]) != m.Request.ArtifactSHA256 {
			return nil, status.Error(codes.InvalidArgument, "artifact")
		}
		if _, h, err := canonical.CanonicalParameters(in.GetMembers()[i].GetParametersJson()); err != nil || h != m.Request.ParametersHash {
			return nil, status.Error(codes.InvalidArgument, "parameters")
		}
		if m.Request.RiskClass == canonical.RiskLow {
			plan.Members[i].Request.RiskClass = canonical.RiskMedium
		}
	}
	if len(f.critical) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "CRITICAL members cannot be approved in a batch: [%s]", strings.Join(f.critical, " "))
	}
	if f.tamper != nil {
		f.tamper(&plan)
	}
	frozen, canon, digest, err := canonical.CanonicalizeBatch(plan, batchNow)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "derived")
	}
	f.frozen, f.digest = frozen, digest.String()
	st := f.state
	if st == pb.PermitState_PERMIT_STATE_UNSPECIFIED {
		st = pb.PermitState_PERMIT_STATE_PENDING
	}
	return &pb.ProposeBatchResponse{BatchDigest: digest.String(), CanonicalBatch: canon, Risk: pb.RiskClass_RISK_CLASS_MEDIUM,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE, Challenge: []byte("c"),
		ChallengeExpiryUnix: batchNow.Add(5 * time.Minute).Unix(), RequestOptionsJson: []byte(`{"challenge":"c"}`), State: st}, nil
}

func (f *fakeBatchExec) CommitBatch(_ context.Context, in *pb.CommitBatchRequest, _ ...grpc.CallOption) (*pb.CommitBatchResponse, error) {
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	if in.GetBatchDigest() != f.digest || string(in.GetAssertionJson()) != `{"ok":true}` {
		return nil, status.Error(codes.PermissionDenied, "assertion")
	}
	return &pb.CommitBatchResponse{State: pb.PermitState_PERMIT_STATE_APPROVED}, nil
}

func (f *fakeBatchExec) GetBatchStatus(_ context.Context, in *pb.GetBatchStatusRequest, _ ...grpc.CallOption) (*pb.GetBatchStatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if f.statusAns != nil {
		return f.statusAns, nil
	}
	out := &pb.GetBatchStatusResponse{BatchDigest: f.digest, BatchId: f.frozen.BatchID, State: pb.PermitState_PERMIT_STATE_APPROVED, ApprovedBy: "admin-cli"}
	for _, m := range f.frozen.Members {
		out.MemberIds = append(out.MemberIds, m.MemberID)
		out.MemberExecutionIds = append(out.MemberExecutionIds, m.Request.ExecutionID)
	}
	return out, nil
}

type fakeContainers struct{ err error }

func (f fakeContainers) ContainerBinding(_ context.Context, _, id string) (canonical.BatchContainer, error) {
	if f.err != nil {
		return canonical.BatchContainer{}, f.err
	}
	img := "sha256:" + strings.Repeat("e", 64)
	return canonical.BatchContainer{ContainerID: id, ConfigurationHash: strings.Repeat("f", 64), OldImageDigest: img, NewImageDigest: img}, nil
}

// batchSetup makes 15 enrolled hosts h01..h15 and a planner.
func batchSetup(t *testing.T, f *fakeBatchExec, mod func(*BatchOptions)) (*Batches, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	hosts := fakeHosts{}
	for i := 1; i <= 15; i++ {
		id := fmt.Sprintf("h%02d", i)
		hosts[id] = inventory.Host{ID: id, Endpoints: []inventory.Endpoint{{Address: fmt.Sprintf("10.0.0.%d", i), Port: 22}}}
		f.pins = append(f.pins, &pb.HostKeyPin{HostId: id, Fingerprint: batchFP(i), CredentialRef: "nebula-default"})
	}
	hosts["blocked"] = inventory.Host{ID: "blocked", Endpoints: []inventory.Endpoint{{Address: "10.0.1.1"}}}
	f.pins = append(f.pins, &pb.HostKeyPin{HostId: "blocked", Fingerprint: batchFP(99), CredentialRef: "nebula-default", Blocked: true})
	hosts["unpinned"] = inventory.Host{ID: "unpinned", Endpoints: []inventory.Endpoint{{Address: "10.0.1.2"}}}
	o := BatchOptions{Exec: f, DB: db, Hosts: hosts, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:               func() time.Time { return batchNow },
		CredentialVersion: func(context.Context, string) (uint64, error) { return 7, nil },
		Containers:        fakeContainers{}}
	if mod != nil {
		mod(&o)
	}
	b, err := NewBatches(o)
	if err != nil {
		t.Fatal(err)
	}
	return b, db
}

// twelveUpdatesThreeRestarts is the ADR's example: 12 hosts updated in
// stage 1, then 3 containers restarted in stage 2.
func twelveUpdatesThreeRestarts() BatchRequest {
	var updates, restarts []BatchMemberSpec
	for i := 1; i <= 12; i++ {
		updates = append(updates, BatchMemberSpec{ActionID: "package.install_all", HostID: fmt.Sprintf("h%02d", i)})
	}
	for i := 13; i <= 15; i++ {
		restarts = append(restarts, BatchMemberSpec{ActionID: "docker.restart", HostID: fmt.Sprintf("h%02d", i), Params: map[string]string{"container": containerID(i)}})
	}
	return BatchRequest{Stages: []BatchStageSpec{
		{Gate: canonical.BatchGateManual, Members: updates},
		{Gate: canonical.BatchGateManual, Members: restarts},
	}}
}

func TestBatchTwelveUpdatesThreeRestartsAreFifteenListedMembers(t *testing.T) {
	f := &fakeBatchExec{}
	b, _ := batchSetup(t, f, nil)
	ctx := context.Background()
	c, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts())
	if err != nil {
		t.Fatal(err)
	}
	if c.State != "pending" || c.Risk != "MEDIUM" || c.Digest != f.digest || string(c.Options) == "" {
		t.Fatalf("created %+v", c)
	}
	// The executor received 15 expanded members with exact inputs.
	in := f.proposed[0]
	if len(in.GetMembers()) != 15 {
		t.Fatalf("proposed %d member inputs, want 15", len(in.GetMembers()))
	}
	v, err := b.Batch(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Members) != 15 || v.Counts.Total != 15 || v.Counts.Planned != 15 || len(v.Stages) != 2 {
		t.Fatalf("view: %d members, counts %+v, %d stages", len(v.Members), v.Counts, len(v.Stages))
	}
	if v.Stages[0].Members != 12 || v.Stages[1].Members != 3 || v.Stages[0].Gate != "manual" {
		t.Errorf("stages %+v", v.Stages)
	}
	seenExec := map[string]bool{}
	for i, m := range v.Members {
		host := fmt.Sprintf("h%02d", i+1)
		wantAction, wantStage := "package.install_all", 1
		if i >= 12 {
			wantAction, wantStage = "docker.restart", 2
		}
		if m.Index != i+1 || m.MemberID != fmt.Sprintf("m-%03d", i+1) || m.HostID != host || m.ActionID != wantAction || m.Stage != wantStage ||
			m.Fingerprint != batchFP(i+1) || m.CredentialRef != "nebula-default" || m.Risk != "MEDIUM" || m.Outcome != OutcomePlanned ||
			len(m.ArtifactSHA256) != 64 || len(m.ParametersHash) != 64 || m.ModuleVersion != "1.0.0" || m.ActionTitle == "" {
			t.Errorf("member %d: %+v", i+1, m)
		}
		if i >= 12 && (m.ContainerID != containerID(i+1) || !strings.Contains(m.Params, containerID(i+1))) {
			t.Errorf("restart member %d lacks its container: %+v", i+1, m)
		}
		if seenExec[m.ExecutionID] || len(m.ExecutionID) != 36 {
			t.Errorf("member %d execution ID %q reused or malformed", i+1, m.ExecutionID)
		}
		seenExec[m.ExecutionID] = true
	}
	// The stored canonical plan is the executor's, member for member.
	for i, m := range f.frozen.Members {
		if v.Members[i].ExecutionID != m.Request.ExecutionID {
			t.Errorf("member %d not linked to the frozen plan", i+1)
		}
		if i >= 12 && (m.Container == nil || m.Container.ContainerID != containerID(i+1)) {
			t.Errorf("frozen restart %d without its incarnation binding", i+1)
		}
		if len(m.CredentialVersions) != 1 || m.CredentialVersions[0].Version != 7 {
			t.Errorf("member %d credential versions %+v", i+1, m.CredentialVersions)
		}
	}
	if v.Summary != "waiting for approval" {
		t.Errorf("summary %q", v.Summary)
	}
}

func TestBatchPlanRefusesInvalidRequests(t *testing.T) {
	ctx := context.Background()
	member := func(action, host string, params map[string]string) BatchMemberSpec {
		return BatchMemberSpec{ActionID: action, HostID: host, Params: params}
	}
	one := func(ms ...BatchMemberSpec) BatchRequest {
		return BatchRequest{Stages: []BatchStageSpec{{Gate: "manual", Members: ms}}}
	}
	tooMany := BatchRequest{Stages: []BatchStageSpec{{Gate: "manual"}}}
	for i := 0; i < 101; i++ {
		tooMany.Stages[0].Members = append(tooMany.Stages[0].Members, member("core.facts", "h01", nil))
	}
	tooManyStages := BatchRequest{}
	for i := 0; i < 21; i++ {
		tooManyStages.Stages = append(tooManyStages.Stages, BatchStageSpec{Gate: "manual", Members: []BatchMemberSpec{member("core.facts", "h01", nil)}})
	}
	var tooLong BatchRequest
	for i := 0; i < 12; i++ {
		tooLong.Stages = append(tooLong.Stages, BatchStageSpec{Gate: "manual", Members: []BatchMemberSpec{member("package.install_all", fmt.Sprintf("h%02d", i+1), nil)}})
	}
	cases := map[string]struct {
		req  BatchRequest
		want string
	}{
		"empty":            {BatchRequest{}, "at least one member"},
		"empty stage":      {BatchRequest{Stages: []BatchStageSpec{{Gate: "manual"}}}, "at least one member"},
		"101 members":      {tooMany, "split the work"},
		"21 stages":        {tooManyStages, "split the work"},
		"over 24 hours":    {tooLong, "24 hours"},
		"unknown action":   {one(member("nope.nope", "h01", nil)), "unknown action"},
		"logs excluded":    {one(member("docker.logs", "h01", map[string]string{"container": containerID(1)})), "logs"},
		"compose excluded": {one(member("docker.compose_update", "h01", map[string]string{"project": "web"})), "Compose"},
		"preview excluded": {one(member("docker.update_preview", "h01", map[string]string{"target_tags": ""})), "durable job"},
		"bad gate":         {BatchRequest{Stages: []BatchStageSpec{{Gate: "auto", Members: []BatchMemberSpec{member("core.facts", "h01", nil)}}}}, "gate"},
		"threshold":        {BatchRequest{Stages: []BatchStageSpec{{Gate: "manual", FailureThreshold: 2, Members: []BatchMemberSpec{member("core.facts", "h01", nil)}}}}, "thresholds"},
		"bad parameter":    {one(member("service.restart", "h01", map[string]string{"unit": "-x"})), "service.restart"},
		"short container":  {one(member("docker.restart", "h01", map[string]string{"container": "web"})), "full 64-character ID"},
		"duplicate tuple":  {one(member("core.facts", "h01", nil), member("core.facts", "h01", nil)), "repeats member 1"},
	}
	for name, c := range cases {
		f := &fakeBatchExec{}
		b, _ := batchSetup(t, f, nil)
		_, err := b.ProposeBatch(ctx, "axel", c.req)
		var ie *BatchInputError
		if !errors.As(err, &ie) || !strings.Contains(ie.Reason, c.want) {
			t.Errorf("%s: %v, want input error containing %q", name, err, c.want)
		}
		if len(f.proposed) != 0 {
			t.Errorf("%s: proposed to the executor", name)
		}
	}
}

func TestBatchPlanRefusesUnusableHosts(t *testing.T) {
	ctx := context.Background()
	for host, want := range map[string]string{"ghost": "not in the inventory", "unpinned": "not enrolled", "blocked": "blocked"} {
		f := &fakeBatchExec{}
		b, _ := batchSetup(t, f, nil)
		_, err := b.ProposeBatch(ctx, "axel", BatchRequest{Stages: []BatchStageSpec{{Gate: "manual", Members: []BatchMemberSpec{{ActionID: "core.facts", HostID: host}}}}})
		var he *HostError
		if !errors.As(err, &he) || !strings.Contains(he.Reason, want) || len(f.proposed) != 0 {
			t.Errorf("%s: %v", host, err)
		}
	}
}

func TestBatchPlanFailsClosedWithoutCredentialVersionsOrContainerDetails(t *testing.T) {
	ctx := context.Background()
	f := &fakeBatchExec{}
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.CredentialVersion = nil })
	if _, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts()); !errors.Is(err, ErrBatchCredentials) {
		t.Errorf("no credential versions: %v", err)
	}
	b, _ = batchSetup(t, &fakeBatchExec{}, func(o *BatchOptions) {
		o.CredentialVersion = func(context.Context, string) (uint64, error) { return 0, errors.New("locked") }
	})
	if _, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts()); !errors.Is(err, ErrBatchCredentials) {
		t.Errorf("credential version error: %v", err)
	}
	f = &fakeBatchExec{}
	b, _ = batchSetup(t, f, func(o *BatchOptions) { o.Containers = fakeContainers{err: ErrBatchContainer} })
	if _, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts()); !errors.Is(err, ErrBatchContainer) || len(f.proposed) != 0 {
		t.Errorf("no container details: %v", err)
	}
}

func TestBatchCriticalMembersRejectWholeProposalAndAreNamed(t *testing.T) {
	f := &fakeBatchExec{critical: []string{"m-003", "m-014"}}
	b, db := batchSetup(t, f, nil)
	_, err := b.ProposeBatch(context.Background(), "axel", twelveUpdatesThreeRestarts())
	var ce *BatchCriticalError
	if !errors.As(err, &ce) || !errors.Is(err, ErrBatchCritical) {
		t.Fatalf("got %v", err)
	}
	if len(ce.Members) != 2 || ce.Members[0].MemberID != "m-003" || ce.Members[0].HostID != "h03" ||
		ce.Members[1].MemberID != "m-014" || ce.Members[1].ActionID != "docker.restart" {
		t.Fatalf("critical members %+v", ce.Members)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM batches`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused batch was stored: %d %v", n, err)
	}
}

func TestBatchAnswerThatDiffersFromProposalIsRefused(t *testing.T) {
	tampers := map[string]func(*canonical.Batch){
		"member dropped": func(p *canonical.Batch) {
			p.Members = p.Members[:14]
			p.StagePlan.Stages[1].MemberIDs = p.StagePlan.Stages[1].MemberIDs[:2]
			h, _ := canonical.BatchStagePlanHash(p.StagePlan)
			p.StagePlanHash = h.String()
			for i := range p.Members {
				p.Members[i].Request.StagePlanHash = h.String()
			}
		},
		"target swapped": func(p *canonical.Batch) {
			p.Members[0].Request.ResolvedTargets[0] = canonical.Target{HostID: "evil", HostKeyFingerprint: batchFP(50)}
		},
		"parameters changed": func(p *canonical.Batch) { p.Members[13].Request.ParametersHash = strings.Repeat("0", 64) },
		"container changed":  func(p *canonical.Batch) { p.Members[13].Container.NewImageDigest = "sha256:" + strings.Repeat("1", 64) },
		"risk lowered":       func(p *canonical.Batch) { p.Members[0].Request.RiskClass = canonical.RiskLow },
	}
	for name, tamper := range tampers {
		f := &fakeBatchExec{tamper: tamper}
		b, db := batchSetup(t, f, nil)
		if _, err := b.ProposeBatch(context.Background(), "axel", twelveUpdatesThreeRestarts()); !errors.Is(err, ErrBatchAnswer) {
			t.Errorf("%s: %v", name, err)
		}
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM batch_members`).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: stored %d members", name, n)
		}
	}
}

func TestBatchApproveRelaysAssertionOnlyWhilePending(t *testing.T) {
	f := &fakeBatchExec{}
	b, _ := batchSetup(t, f, nil)
	ctx := context.Background()
	c, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ApproveBatch(ctx, "axel", c.ID, []byte(`{"bad":1}`)); status.Code(errors.Unwrap(err)) != codes.PermissionDenied {
		t.Fatalf("bad assertion: %v", err)
	}
	if v, _ := b.Batch(ctx, c.ID); v.State != "pending" {
		t.Fatalf("state after refusal %q", v.State)
	}
	if err := b.ApproveBatch(ctx, "axel", c.ID, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	v, _ := b.Batch(ctx, c.ID)
	if v.State != "approved" || v.ApprovedBy != "axel" || len(v.Options) != 0 || v.Summary != "approved, not started" {
		t.Fatalf("after approval %+v", v)
	}
	if err := b.ApproveBatch(ctx, "axel", c.ID, []byte(`{"ok":true}`)); !errors.Is(err, ErrBatchNotPending) {
		t.Fatalf("second approval: %v", err)
	}
	if err := b.ApproveBatch(ctx, "axel", strings.Repeat("0", 36), []byte(`{"ok":true}`)); !errors.Is(err, ErrBatchNotFound) {
		t.Fatalf("unknown batch: %v", err)
	}
}

// approvedBatch proposes the ADR example and approves it.
func approvedBatch(t *testing.T) (*Batches, *fakeBatchExec, string) {
	t.Helper()
	f := &fakeBatchExec{state: pb.PermitState_PERMIT_STATE_APPROVED}
	b, _ := batchSetup(t, f, nil)
	c, err := b.ProposeBatch(context.Background(), "axel", twelveUpdatesThreeRestarts())
	if err != nil || c.State != "approved" {
		t.Fatalf("%+v %v", c, err)
	}
	return b, f, c.ID
}

func mid(i int) string { return fmt.Sprintf("m-%03d", i) }

func TestBatchPartialFailureStopsUndispatchedWorkWithoutRetryOrRollback(t *testing.T) {
	b, _, id := approvedBatch(t)
	ctx := context.Background()
	// Stage 1: members 1..4 dispatched; 1..3 succeed, 4 fails.
	for i := 1; i <= 4; i++ {
		if err := b.MarkDispatched(ctx, id, mid(i)); err != nil {
			t.Fatalf("dispatch %d: %v", i, err)
		}
	}
	// Stage 2 cannot start while stage 1 is open.
	if err := b.MarkDispatched(ctx, id, mid(13)); !errors.Is(err, ErrBatchNotDispatchable) {
		t.Fatalf("stage 2 before stage 1 finished: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if err := b.RecordOutcome(ctx, id, mid(i), MemberResult{Outcome: OutcomeSuccess}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.RecordOutcome(ctx, id, mid(4), MemberResult{Outcome: OutcomeFailed, Detail: "dpkg was interrupted"}); err != nil {
		t.Fatal(err)
	}
	v, err := b.Batch(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := BatchCounts{Total: 15, Success: 3, Failed: 1, NotExecuted: 11}
	if v.Counts != want {
		t.Fatalf("counts %+v, want %+v", v.Counts, want)
	}
	if v.Summary != "partially failed" {
		t.Errorf("summary %q", v.Summary)
	}
	for _, m := range v.Members {
		switch {
		case m.Index <= 3 && m.Outcome != OutcomeSuccess, m.Index == 4 && m.Outcome != OutcomeFailed:
			t.Errorf("member %d outcome %s", m.Index, m.Outcome)
		case m.Index > 4 && (m.Outcome != OutcomeNotExecuted || !strings.Contains(m.Detail, "nothing is retried or rolled back")):
			t.Errorf("member %d: %s %q", m.Index, m.Outcome, m.Detail)
		}
	}
	// No retry, redispatch or rollback of any member under this batch.
	for i := 1; i <= 15; i++ {
		if err := b.MarkDispatched(ctx, id, mid(i)); !errors.Is(err, ErrBatchMemberFinal) {
			t.Errorf("redispatch %d: %v", i, err)
		}
		for _, o := range []string{OutcomeSuccess, OutcomeFailed, OutcomeUnknown} {
			if err := b.RecordOutcome(ctx, id, mid(i), MemberResult{Outcome: o}); !errors.Is(err, ErrBatchMemberFinal) {
				t.Errorf("rewrite %d to %s: %v", i, o, err)
			}
		}
		if err := b.SkipMember(ctx, "axel", id, mid(i)); !errors.Is(err, ErrBatchMemberFinal) {
			t.Errorf("skip %d: %v", i, err)
		}
	}
	for _, o := range []string{OutcomePlanned, OutcomeDispatched, OutcomeSkipped, OutcomeNotExecuted, "rolled_back", "retry"} {
		if err := b.RecordOutcome(ctx, id, mid(4), MemberResult{Outcome: o}); !errors.Is(err, ErrBatchOutcome) {
			t.Errorf("outcome %q accepted: %v", o, err)
		}
	}
}

func TestBatchApprovedThresholdLetsIndependentMembersContinue(t *testing.T) {
	f := &fakeBatchExec{state: pb.PermitState_PERMIT_STATE_APPROVED}
	b, _ := batchSetup(t, f, nil)
	ctx := context.Background()
	req := twelveUpdatesThreeRestarts()
	req.Stages[0].FailureThreshold, req.Stages[0].UnreachableThreshold = 1, 1
	c, err := b.ProposeBatch(ctx, "axel", req)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := b.MarkDispatched(ctx, c.ID, mid(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.RecordOutcome(ctx, c.ID, mid(1), MemberResult{Outcome: OutcomeFailed}); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordOutcome(ctx, c.ID, mid(2), MemberResult{Outcome: OutcomeFailed, Unreachable: true, Detail: "all endpoints failed"}); err != nil {
		t.Fatal(err)
	}
	v, _ := b.Batch(ctx, c.ID)
	if v.Counts.Planned != 12 || v.Counts.NotExecuted != 0 {
		t.Fatalf("within thresholds the plan continues: %+v", v.Counts)
	}
	// An unknown outcome counts as a failure: the threshold is exceeded.
	if err := b.RecordOutcome(ctx, c.ID, mid(3), MemberResult{Outcome: OutcomeUnknown}); err != nil {
		t.Fatal(err)
	}
	v, _ = b.Batch(ctx, c.ID)
	if v.Counts.Planned != 0 || v.Counts.NotExecuted != 12 || v.Counts.Unknown != 1 || v.Summary != "failed" {
		t.Fatalf("after exceeding: %+v %q", v.Counts, v.Summary)
	}
}

func TestBatchAllSucceed(t *testing.T) {
	b, _, id := approvedBatch(t)
	ctx := context.Background()
	for stage := 0; stage < 2; stage++ {
		lo, hi := 1, 12
		if stage == 1 {
			lo, hi = 13, 15
		}
		for i := lo; i <= hi; i++ {
			if err := b.MarkDispatched(ctx, id, mid(i)); err != nil {
				t.Fatal(err)
			}
		}
		for i := lo; i <= hi; i++ {
			if err := b.RecordOutcome(ctx, id, mid(i), MemberResult{Outcome: OutcomeSuccess}); err != nil {
				t.Fatal(err)
			}
		}
	}
	v, _ := b.Batch(ctx, id)
	if v.Counts.Success != 15 || v.Summary != "succeeded" {
		t.Fatalf("%+v %q", v.Counts, v.Summary)
	}
}

func TestBatchDispatchNeedsApprovedUnexpiredBatch(t *testing.T) {
	f := &fakeBatchExec{}
	now := batchNow
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.Now = func() time.Time { return now } })
	ctx := context.Background()
	c, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.MarkDispatched(ctx, c.ID, mid(1)); !errors.Is(err, ErrBatchNotDispatchable) {
		t.Fatalf("pending batch dispatched: %v", err)
	}
	if err := b.ApproveBatch(ctx, "axel", c.ID, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	if err := b.MarkDispatched(ctx, c.ID, mid(1)); !errors.Is(err, ErrBatchNotDispatchable) {
		t.Fatalf("expired batch dispatched: %v", err)
	}
	if err := b.MarkDispatched(ctx, c.ID, "m-999"); !errors.Is(err, ErrBatchMemberNotFound) {
		t.Fatalf("unknown member: %v", err)
	}
}

func TestBatchSkipIsFinalAndAudited(t *testing.T) {
	b, _, id := approvedBatch(t)
	ctx := context.Background()
	if err := b.SkipMember(ctx, "axel", id, mid(5)); err != nil {
		t.Fatal(err)
	}
	if err := b.MarkDispatched(ctx, id, mid(5)); !errors.Is(err, ErrBatchMemberFinal) {
		t.Fatalf("skipped member dispatched: %v", err)
	}
	v, _ := b.Batch(ctx, id)
	if v.Members[4].Outcome != OutcomeSkipped || !strings.Contains(v.Members[4].Detail, "axel") {
		t.Fatalf("%+v", v.Members[4])
	}
}

func TestBatchReconcileMarksDispatchedUnknownAndNeverRedispatches(t *testing.T) {
	b, _, id := approvedBatch(t)
	ctx := context.Background()
	if err := b.MarkDispatched(ctx, id, mid(1)); err != nil {
		t.Fatal(err)
	}
	n, err := b.ReconcileBatches(ctx)
	if err != nil || n != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	v, _ := b.Batch(ctx, id)
	if v.Members[0].Outcome != OutcomeUnknown || !strings.Contains(v.Members[0].Detail, "never redispatched") {
		t.Fatalf("%+v", v.Members[0])
	}
	if err := b.MarkDispatched(ctx, id, mid(1)); !errors.Is(err, ErrBatchMemberFinal) {
		t.Fatalf("unknown member redispatched: %v", err)
	}
	if err := b.RecordOutcome(ctx, id, mid(1), MemberResult{Outcome: OutcomeSuccess}); !errors.Is(err, ErrBatchMemberFinal) {
		t.Fatalf("unknown outcome rewritten: %v", err)
	}
}

func TestBatchReconcileExpiresPendingAndUnrunMembers(t *testing.T) {
	f := &fakeBatchExec{}
	now := batchNow
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.Now = func() time.Time { return now } })
	ctx := context.Background()
	c, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Minute)
	n, err := b.ReconcileBatches(ctx)
	if err != nil || n != 15 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	v, _ := b.Batch(ctx, c.ID)
	if v.State != "expired" || v.Counts.NotExecuted != 15 || v.Summary != "not executed" || len(v.Options) != 0 {
		t.Fatalf("%+v", v)
	}
}

func TestBatchRefreshFollowsTheExecutor(t *testing.T) {
	ctx := context.Background()
	// A CLI approval on the executor shows up as approved.
	f := &fakeBatchExec{}
	b, _ := batchSetup(t, f, nil)
	c, err := b.ProposeBatch(ctx, "axel", twelveUpdatesThreeRestarts())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshBatch(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if v, _ := b.Batch(ctx, c.ID); v.State != "approved" || v.ApprovedBy != "admin-cli" {
		t.Fatalf("%+v", v)
	}
	// A different member list is refused.
	f.statusAns = &pb.GetBatchStatusResponse{BatchDigest: f.digest, BatchId: c.ID, State: pb.PermitState_PERMIT_STATE_APPROVED, MemberIds: []string{"m-001"}}
	if err := b.RefreshBatch(ctx, c.ID); !errors.Is(err, ErrBatchAnswer) {
		t.Fatalf("mismatched status: %v", err)
	}
	// Lock or restart: the approval is gone; undispatched members end.
	f.statusAns = nil
	if err := b.MarkDispatched(ctx, c.ID, mid(1)); err != nil {
		t.Fatal(err)
	}
	f.statusErr = status.Error(codes.NotFound, "unknown batch")
	if err := b.RefreshBatch(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	v, _ := b.Batch(ctx, c.ID)
	if v.Counts.Dispatched != 1 || v.Counts.NotExecuted != 14 || !strings.Contains(v.Detail, "plan a fresh batch") {
		t.Fatalf("%+v %q", v.Counts, v.Detail)
	}
	// Other errors change nothing.
	f.statusErr = status.Error(codes.Unavailable, "down")
	if err := b.RefreshBatch(ctx, c.ID); err == nil {
		t.Fatal("unavailable executor ignored")
	}
}

func TestBatchListCountsOutcomes(t *testing.T) {
	b, _, id := approvedBatch(t)
	ctx := context.Background()
	if err := b.MarkDispatched(ctx, id, mid(1)); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordOutcome(ctx, id, mid(1), MemberResult{Outcome: OutcomeFailed}); err != nil {
		t.Fatal(err)
	}
	list, err := b.ListBatches(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("%+v %v", list, err)
	}
	if list[0].ID != id || list[0].Counts.Total != 15 || list[0].Counts.Failed != 1 || list[0].Counts.NotExecuted != 14 || list[0].Summary != "failed" {
		t.Fatalf("%+v", list[0])
	}
}

func TestBatchOutcomeDetailIsBoundedUTF8(t *testing.T) {
	b, _, id := approvedBatch(t)
	ctx := context.Background()
	if err := b.MarkDispatched(ctx, id, mid(1)); err != nil {
		t.Fatal(err)
	}
	detail := strings.Repeat("ä", 600) + "\xff"
	if err := b.RecordOutcome(ctx, id, mid(1), MemberResult{Outcome: OutcomeSuccess, Detail: detail}); err != nil {
		t.Fatal(err)
	}
	v, _ := b.Batch(ctx, id)
	if d := v.Members[0].Detail; len(d) > maxBatchDetail || !utf8Valid(d) {
		t.Fatalf("detail %d bytes", len(d))
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

func TestInspectBindingsUseFreshInspectOfThatContainer(t *testing.T) {
	_, db := setup(t, &fakeExec{})
	id := containerID(1)
	inner, _ := json.Marshal(map[string]any{"id": id, "name": "/web", "image_id": "sha256:" + strings.Repeat("e", 64)})
	result, _ := json.Marshal(map[string]string{"format": "docker-inspect-v1", "phase": "done", "container": id,
		"inspect": base64.StdEncoding.EncodeToString(inner)})
	params, _ := json.Marshal(map[string]string{"container": id})
	seedExecution(t, db, strings.Repeat("1", 36), "docker.inspect", "h01", "success", result, batchNow.Unix()-60, batchNow.Unix()-60)
	if _, err := db.Exec(`UPDATE executions SET params = ? WHERE id = ?`, string(params), strings.Repeat("1", 36)); err != nil {
		t.Fatal(err)
	}
	now := batchNow
	ib := &InspectBindings{DB: db, Now: func() time.Time { return now }}
	c, err := ib.ContainerBinding(context.Background(), "h01", id)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(result)
	if c.ContainerID != id || c.ConfigurationHash != hex.EncodeToString(sum[:]) || c.OldImageDigest != "sha256:"+strings.Repeat("e", 64) || c.NewImageDigest != c.OldImageDigest {
		t.Fatalf("%+v", c)
	}
	if _, err := ib.ContainerBinding(context.Background(), "h02", id); !errors.Is(err, ErrBatchContainer) {
		t.Errorf("other host: %v", err)
	}
	if _, err := ib.ContainerBinding(context.Background(), "h01", containerID(2)); !errors.Is(err, ErrBatchContainer) {
		t.Errorf("other container: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := ib.ContainerBinding(context.Background(), "h01", id); !errors.Is(err, ErrBatchContainer) {
		t.Errorf("stale inspect: %v", err)
	}
}

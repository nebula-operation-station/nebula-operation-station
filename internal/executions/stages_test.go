// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

// stagedExec is a fake executor that keeps a rollout like the executor
// does (the rules themselves are tested in internal/permit): hosts of a
// closed stage are refused, a stage over max_failed stops the rollout.
type stagedExec struct {
	fakeExec
	plan    []stageplan.Stage
	open    int
	outcome map[string]string
	stopped string
	aborted bool
	gateReq pb.ApprovalRequirement
	commits []*pb.CommitGateRequest
	onRun   func(host string) // called before a run, without the lock
}

func (f *stagedExec) ProposeExecution(ctx context.Context, in *pb.ProposeExecutionRequest, o ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	var hosts []string
	for _, t := range in.GetRequest().GetResolvedTargets() {
		hosts = append(hosts, t.GetHostId())
	}
	p, err := stageplan.Parse(in.GetStagePlanJson(), hosts)
	if err != nil || p.Hash != in.GetRequest().GetStagePlanHash() {
		return nil, status.Error(codes.InvalidArgument, "stage_plan_invalid")
	}
	f.mu.Lock()
	f.plan, f.outcome = p.Stages, map[string]string{}
	f.mu.Unlock()
	return f.fakeExec.ProposeExecution(ctx, in, o...)
}

func (f *stagedExec) stageOf(host string) int {
	for i, st := range f.plan {
		for _, h := range st.Hosts {
			if h == host {
				return i
			}
		}
	}
	return -1
}

func (f *stagedExec) RunAttached(ctx context.Context, in *pb.RunAttachedRequest, o ...grpc.CallOption) (*pb.RunAttachedResponse, error) {
	host := in.GetRun().GetHostId()
	if f.onRun != nil {
		f.onRun(host)
	}
	f.mu.Lock()
	switch {
	case f.outcome[host] == "skipped":
		f.mu.Unlock()
		return nil, status.Error(codes.PermissionDenied, "host_already_run: host was skipped")
	case f.aborted:
		f.mu.Unlock()
		return nil, status.Error(codes.PermissionDenied, "rollout_aborted")
	case f.stopped != "":
		f.mu.Unlock()
		return nil, status.Error(codes.PermissionDenied, "rollout_stopped")
	case f.stageOf(host) > f.open:
		f.mu.Unlock()
		return nil, status.Error(codes.PermissionDenied, "stage_not_open")
	}
	f.mu.Unlock()
	r, err := f.fakeExec.RunAttached(ctx, in, o...)
	if err != nil {
		return r, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o2 := "failed"
	switch r.GetClass() {
	case "success":
		o2 = "succeeded"
	case "network_unreachable":
		o2 = "unreachable"
	}
	f.outcome[host] = o2
	i := f.stageOf(host)
	failed := 0
	for _, h := range f.plan[i].Hosts {
		if f.outcome[h] == "failed" {
			failed++
		}
	}
	if failed > f.plan[i].MaxFailed {
		f.stopped = "stage " + f.plan[i].Name + " failed"
	}
	return r, nil
}

func (f *stagedExec) GetRollout(context.Context, *pb.GetRolloutRequest, ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &pb.Rollout{OpenStage: uint32(f.open + 1), Stopped: f.stopped, Aborted: f.aborted}
	for i, st := range f.plan {
		ss := &pb.StageStatus{Stage: &pb.PlanStage{Name: st.Name, HostIds: st.Hosts}, Open: i <= f.open}
		done, bad := 0, 0
		for _, h := range st.Hosts {
			if o := f.outcome[h]; o != "" {
				ss.Outcomes = append(ss.Outcomes, &pb.HostOutcome{HostId: h, Outcome: o})
				done++
				if o == "failed" || o == "unreachable" {
					bad++
				}
			}
		}
		ss.Passed = done == len(st.Hosts) && bad <= st.MaxFailed
		r.Stages = append(r.Stages, ss)
	}
	return &pb.GetRolloutResponse{Rollout: r}, nil
}

func (f *stagedExec) BeginGate(context.Context, *pb.BeginGateRequest, ...grpc.CallOption) (*pb.BeginGateResponse, error) {
	r := &pb.BeginGateResponse{ApprovalRequirement: f.gateReq}
	if f.gateReq == pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		r.Challenge, r.RequestOptionsJson = []byte("c"), []byte(`{"publicKey":{"challenge":"gate"}}`)
	}
	return r, nil
}

func (f *stagedExec) CommitGate(_ context.Context, in *pb.CommitGateRequest, _ ...grpc.CallOption) (*pb.CommitGateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits = append(f.commits, in)
	if f.gateReq == pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED && string(in.GetAssertionJson()) != "good" {
		return nil, status.Error(codes.PermissionDenied, "assertion_rejected")
	}
	switch in.GetGate().GetKind() {
	case pb.GateKind_GATE_KIND_OPEN_STAGE:
		f.open = int(in.GetGate().GetStage()) - 1
	case pb.GateKind_GATE_KIND_SKIP_HOST:
		f.outcome[in.GetGate().GetHostId()] = "skipped"
	}
	return &pb.CommitGateResponse{}, nil
}

func (f *stagedExec) AbortRollout(context.Context, *pb.AbortRolloutRequest, ...grpc.CallOption) (*pb.AbortRolloutResponse, error) {
	f.mu.Lock()
	f.aborted = true
	f.mu.Unlock()
	return &pb.AbortRolloutResponse{}, nil
}

func stagedSetup(t *testing.T, f *stagedExec) *Service {
	t.Helper()
	savedRetry := retryDelays
	pollInterval = 20 * time.Millisecond
	retryDelays = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() { pollInterval, retryDelays = 5*time.Second, savedRetry })
	f.approved = true
	f.risk = pb.RiskClass_RISK_CLASS_MEDIUM
	if f.gateReq == 0 {
		f.gateReq = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_NONE
	}
	s, _ := setup(t, &f.fakeExec)
	// setup wired the embedded fake; use the staged one.
	s.exec = f
	f.pins = append(f.pins, &pb.HostKeyPin{HostId: "db", Fingerprint: "SHA256:db", CredentialRef: "nebula-default"},
		&pb.HostKeyPin{HostId: "new", Fingerprint: "SHA256:new", CredentialRef: "nebula-default"})
	return s
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hostsOf(t *testing.T, s *Service, id string) map[string]Host {
	t.Helper()
	e, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Host{}
	for _, h := range e.Hosts {
		out[h.HostID] = h
	}
	return out
}

func TestCanaryPlanIsProposedAndFollowed(t *testing.T) {
	f := &stagedExec{}
	s := stagedSetup(t, f)
	ctx := context.Background()
	c, err := s.CreateStaged(ctx, "axel", "core.facts", []string{"web", "db", "new"}, nil,
		Plan{Preset: PresetCanary, Size: 1, Continue: stageplan.ContinueManual, MaxFailed: 1})
	if err != nil {
		t.Fatal(err)
	}
	req := f.proposed.GetRequest()
	want, _ := canonical.HashParameters(f.proposed.GetStagePlanJson())
	if req.GetStagePlanHash() != want || len(f.plan) != 2 || f.plan[0].Name != "canary" || strings.Join(f.plan[0].Hosts, ",") != "web" ||
		f.plan[1].MaxFailed != 1 || time.Until(time.Unix(req.GetExpiryUnix(), 0)) < time.Hour {
		t.Fatalf("%v %+v", req, f.plan)
	}
	// The canary runs; the rest waits at the gate.
	waitFor(t, "the gate", func() bool { e, _ := s.Get(ctx, c.ID); return strings.Contains(e.Waiting, "continue to stage 2") })
	if h := hostsOf(t, s, c.ID); h["web"].Class != "success" || h["db"].State != "waiting" || h["db"].Stage != 2 {
		t.Fatalf("%+v", h)
	}
	r, err := s.BeginGate(ctx, "axel", c.ID, Gate{Kind: "open", Stage: 2})
	if err != nil || !r.Done {
		t.Fatalf("%+v %v", r, err)
	}
	waitState(t, s, c.ID, "finished")
	if h := hostsOf(t, s, c.ID); h["db"].Class != "success" || h["new"].Class != "success" {
		t.Fatalf("%+v", h)
	}
	for _, a := range f.attached {
		if a.GetRun().GetHostId() != "web" && len(f.commits) == 0 {
			t.Fatal("a stage-2 host ran before the gate")
		}
	}
}

func TestFailingCanaryEndsTheExecution(t *testing.T) {
	f := &stagedExec{}
	f.failHost = "web"
	s := stagedSetup(t, f)
	c, err := s.CreateStaged(context.Background(), "axel", "core.facts", []string{"web", "db"}, nil,
		Plan{Preset: PresetCanary, Size: 1, Continue: stageplan.ContinueAuto})
	if err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	h := hostsOf(t, s, c.ID)
	if h["web"].Class != "script_failed" || h["db"].Class != "not_run" || !strings.Contains(h["db"].Detail, "stopped") {
		t.Fatalf("%+v", h)
	}
	if len(f.attached) != 1 {
		t.Fatalf("%d runs", len(f.attached))
	}
}

func TestHighGateNeedsTheBrowserAssertion(t *testing.T) {
	f := &stagedExec{gateReq: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED}
	s := stagedSetup(t, f)
	ctx := context.Background()
	c, err := s.CreateStaged(ctx, "axel", "core.facts", []string{"web", "db"}, nil, Plan{Preset: PresetWaves, Size: 1, Continue: stageplan.ContinueManual})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the gate", func() bool { e, _ := s.Get(ctx, c.ID); return e.Waiting != "" })
	r, err := s.BeginGate(ctx, "axel", c.ID, Gate{Kind: "open", Stage: 2})
	if err != nil || r.Done || !strings.Contains(string(r.Options), "gate") {
		t.Fatalf("%+v %v", r, err)
	}
	if err := s.CommitGate(ctx, "axel", c.ID, Gate{Kind: "open", Stage: 2}, []byte("bad")); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	if err := s.CommitGate(ctx, "axel", c.ID, Gate{Kind: "open", Stage: 2}, []byte("good")); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	if g := f.commits[len(f.commits)-1].GetGate(); g.GetKind() != pb.GateKind_GATE_KIND_OPEN_STAGE || g.GetStage() != 2 {
		t.Fatalf("%v", g)
	}
}

func TestAbortAndSkipAndRetry(t *testing.T) {
	f := &stagedExec{}
	f.unreachable = 1 // the canary is unreachable once
	s := stagedSetup(t, f)
	ctx := context.Background()
	c, err := s.CreateStaged(ctx, "axel", "core.facts", []string{"web", "db", "new"}, nil, Plan{Preset: PresetWaves, Size: 1, Continue: stageplan.ContinueManual})
	if err != nil {
		t.Fatal(err)
	}
	// core.facts is a safe action: the server retries it by itself.
	waitFor(t, "the gate", func() bool { e, _ := s.Get(ctx, c.ID); return strings.Contains(e.Waiting, "continue to stage 2") })
	if _, err := s.BeginGate(ctx, "axel", c.ID, Gate{Kind: "skip", Host: "db"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the skip", func() bool { return hostsOf(t, s, c.ID)["db"].Class == "skipped" })
	if err := s.Abort(ctx, "axel", c.ID); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	if h := hostsOf(t, s, c.ID); h["new"].Class != "not_run" || h["web"].Class != "success" {
		t.Fatalf("%+v", h)
	}
	if err := s.RetryHost(ctx, "axel", c.ID, "web"); !errors.Is(err, ErrNotRunning) {
		t.Fatal(err)
	}
	if err := s.Abort(ctx, "axel", c.ID); !errors.Is(err, ErrNotRunning) {
		t.Fatal(err)
	}
}

func TestBuildStagesRefusesUnusablePlans(t *testing.T) {
	a, _ := actions.Lookup("core.facts")
	ts := []target{{host: "a"}, {host: "b"}, {host: "c"}}
	env := map[string]inventory.Environment{"a": inventory.EnvProd, "b": inventory.EnvDev, "c": inventory.EnvProd}
	st, err := buildStages(Plan{Preset: PresetEnvironments, Continue: stageplan.ContinueAuto}, a, ts, env)
	if err != nil || len(st) != 2 || st[0].Name != "dev" || strings.Join(st[1].Hosts, ",") != "a,c" || st[0].Continue != "auto" || st[1].Continue != "manual" {
		t.Fatalf("%+v %v", st, err)
	}
	st, err = buildStages(Plan{Preset: PresetWaves, Size: 2, Continue: "manual", MaxFailed: 5}, a, ts, env)
	if err != nil || len(st) != 2 || st[0].MaxFailed != 2 || st[1].MaxFailed != 1 || st[0].TimeoutS < stageplan.MinTimeout {
		t.Fatalf("%+v %v", st, err)
	}
	for name, p := range map[string]Plan{
		"canary too big":  {Preset: PresetCanary, Size: 3, Continue: "manual"},
		"canary zero":     {Preset: PresetCanary, Size: 0, Continue: "manual"},
		"wave zero":       {Preset: PresetWaves, Size: 0, Continue: "manual"},
		"continue":        {Preset: PresetWaves, Size: 1, Continue: "later"},
		"negative failed": {Preset: PresetWaves, Size: 1, Continue: "manual", MaxFailed: -1},
		"unknown":         {Preset: "random", Continue: "manual"},
	} {
		var pe *PlanError
		if _, err := buildStages(p, a, ts, env); !errors.As(err, &pe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var pe *PlanError
	if _, err := buildStages(Plan{Preset: PresetEnvironments, Continue: "manual"}, a, ts, map[string]inventory.Environment{}); !errors.As(err, &pe) {
		t.Fatal(err)
	}
	many := make([]target, 21)
	for i := range many {
		many[i] = target{host: string(rune('a' + i))}
	}
	if _, err := buildStages(Plan{Preset: PresetWaves, Size: 1, Continue: "manual"}, a, many, env); !errors.As(err, &pe) {
		t.Fatal(err)
	}
}

// Review m63 finding 1: an unreachable host in the last stage leaves every
// host with an outcome but the stage not passed. The execution keeps
// running and waits for a retry or a skip instead of finishing.
func TestUnreachableHostInTheLastStageWaits(t *testing.T) {
	f := &stagedExec{}
	s := stagedSetup(t, f)
	ctx := context.Background()
	c, err := s.CreateStaged(ctx, "axel", "core.facts", []string{"web", "db"}, nil, Plan{Preset: PresetWaves, Size: 1, Continue: stageplan.ContinueManual})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the gate", func() bool { e, _ := s.Get(ctx, c.ID); return strings.Contains(e.Waiting, "continue to stage 2") })
	unreachable := func(n int) {
		f.mu.Lock()
		f.unreachable = n
		f.mu.Unlock()
	}
	unreachable(1 + len(retryDelays)) // db stays unreachable through the safe retries
	if _, err := s.BeginGate(ctx, "axel", c.ID, Gate{Kind: "open", Stage: 2}); err != nil {
		t.Fatal(err)
	}
	notPassed := func() bool {
		e, _ := s.Get(ctx, c.ID)
		return strings.Contains(e.Waiting, "stage 2 (wave-2) has not passed")
	}
	waitFor(t, "the wait for stage 2", notPassed)
	if e, _ := s.Get(ctx, c.ID); e.State != "running" || hostsOf(t, s, c.ID)["db"].Class != "network_unreachable" {
		t.Fatalf("%+v", e)
	}

	// A retry that is unreachable again: still waiting.
	unreachable(1 + len(retryDelays))
	if err := s.RetryHost(ctx, "axel", c.ID, "db"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the retry", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.unreachable == 0
	})
	waitFor(t, "the wait after the retry", func() bool { return hostsOf(t, s, c.ID)["db"].State == "finished" && notPassed() })
	if e, _ := s.Get(ctx, c.ID); e.State != "running" {
		t.Fatalf("%+v", e)
	}

	// Skipped: it no longer counts as a failure, and the execution ends.
	if _, err := s.BeginGate(ctx, "axel", c.ID, Gate{Kind: "skip", Host: "db"}); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	if h := hostsOf(t, s, c.ID); h["db"].Class != "skipped" || h["web"].Class != "success" {
		t.Fatalf("%+v", h)
	}
	if err := s.RetryHost(ctx, "axel", c.ID, "db"); err == nil {
		t.Fatal("retry of a finished execution")
	}
}

// Review f63 F1: a retry that loses the race to a skip is refused by the
// executor; the host still ends as skipped, not as a failure.
func TestRetryThatLosesToASkipEndsSkipped(t *testing.T) {
	f := &stagedExec{}
	s := stagedSetup(t, f)
	ctx := context.Background()
	c, err := s.CreateStaged(ctx, "axel", "core.facts", []string{"web", "db"}, nil, Plan{Preset: PresetWaves, Size: 1, Continue: stageplan.ContinueManual})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the gate", func() bool { e, _ := s.Get(ctx, c.ID); return strings.Contains(e.Waiting, "continue to stage 2") })
	f.mu.Lock()
	f.unreachable = 1 + len(retryDelays)
	f.mu.Unlock()
	if _, err := s.BeginGate(ctx, "axel", c.ID, Gate{Kind: "open", Stage: 2}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the wait for stage 2", func() bool { e, _ := s.Get(ctx, c.ID); return strings.Contains(e.Waiting, "has not passed") })
	// The skip lands while the retried run is on its way to the executor.
	f.onRun = func(host string) {
		if host == "db" {
			f.mu.Lock()
			f.outcome["db"] = "skipped"
			f.mu.Unlock()
		}
	}
	if err := s.RetryHost(ctx, "axel", c.ID, "db"); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	if h := hostsOf(t, s, c.ID); h["db"].Class != "skipped" {
		t.Fatalf("%+v", h["db"])
	}
}

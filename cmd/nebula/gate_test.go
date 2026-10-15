// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeGates struct {
	pb.ExecutorServiceClient
	rollout  *pb.Rollout
	approved *pb.ApproveGateCLIRequest
}

func (f *fakeGates) GetRollout(context.Context, *pb.GetRolloutRequest, ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	return &pb.GetRolloutResponse{Rollout: f.rollout}, nil
}

func (f *fakeGates) ApproveGateCLI(_ context.Context, in *pb.ApproveGateCLIRequest, _ ...grpc.CallOption) (*pb.ApproveGateCLIResponse, error) {
	f.approved = in
	return &pb.ApproveGateCLIResponse{Rollout: &pb.Rollout{OpenStage: 2, Stages: f.rollout.GetStages()}}, nil
}

func TestApproveGateShowsTheExecutorsRolloutAndAsks(t *testing.T) {
	d := strings.Repeat("ab", 32)
	f := &fakeGates{rollout: &pb.Rollout{OpenStage: 1, Stages: []*pb.StageStatus{
		{Stage: &pb.PlanStage{Name: "canary", HostIds: []string{"web-01"}, ContinueMode: "manual"}, Open: true, Passed: true,
			Outcomes: []*pb.HostOutcome{{HostId: "web-01", Outcome: "succeeded"}}},
		{Stage: &pb.PlanStage{Name: "rest\x1b[2J", HostIds: []string{"web-02"}, MaxFailed: 1, ContinueMode: "manual"}},
	}}}
	var out bytes.Buffer
	if err := gateCmd(context.Background(), f, []string{"--stage", "2", d}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if f.approved.GetGate().GetKind() != pb.GateKind_GATE_KIND_OPEN_STAGE || f.approved.GetGate().GetStage() != 2 || f.approved.GetExecutionDigest() != d {
		t.Fatalf("%v", f.approved)
	}
	for _, want := range []string{"Open stage 2", "web-01", "succeeded", "passed", `rest\u001b[2J`, "stage 2 of 2 is open"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output misses %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Fatal("terminal escape reached the screen")
	}

	f.approved = nil
	if err := gateCmd(context.Background(), f, []string{"--skip", "web-02", d}, strings.NewReader("no\n"), &out); err == nil || f.approved != nil {
		t.Fatal("approved without yes")
	}
	if err := gateCmd(context.Background(), f, []string{"--skip", "web-02", d}, strings.NewReader("yes\n"), &out); err != nil ||
		f.approved.GetGate().GetKind() != pb.GateKind_GATE_KIND_SKIP_HOST || f.approved.GetGate().GetHostId() != "web-02" {
		t.Fatalf("%v %v", f.approved, err)
	}
	for _, bad := range [][]string{{"--stage", "2"}, {"--stage", "2", "--skip", "x", d}, {"--stage", "2", "abc"}, {"--skip", "-x", d}, {d}} {
		if err := gateCmd(context.Background(), f, bad, strings.NewReader("yes\n"), &out); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

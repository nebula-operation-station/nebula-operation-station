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

type fakeSchedules struct {
	pb.ExecutorServiceClient
	pending  []*pb.PendingScheduleGrant
	approved string
	revoked  string
}

func (f *fakeSchedules) ListPendingScheduleGrants(context.Context, *pb.ListPendingScheduleGrantsRequest, ...grpc.CallOption) (*pb.ListPendingScheduleGrantsResponse, error) {
	return &pb.ListPendingScheduleGrantsResponse{Grants: f.pending}, nil
}

func (f *fakeSchedules) ApproveScheduleGrantCLI(_ context.Context, in *pb.ApproveScheduleGrantCLIRequest, _ ...grpc.CallOption) (*pb.ApproveScheduleGrantCLIResponse, error) {
	f.approved = in.GetGrantDigest()
	return &pb.ApproveScheduleGrantCLIResponse{Grant: &pb.ScheduleGrant{GrantId: "g1"}}, nil
}

func (f *fakeSchedules) RevokeScheduleGrant(_ context.Context, in *pb.RevokeScheduleGrantRequest, _ ...grpc.CallOption) (*pb.RevokeScheduleGrantResponse, error) {
	f.revoked = in.GetGrantId()
	return &pb.RevokeScheduleGrantResponse{}, nil
}

func TestScheduleApproveShowsTheExecutorsGrant(t *testing.T) {
	d := strings.Repeat("ab", 32)
	f := &fakeSchedules{pending: []*pb.PendingScheduleGrant{{GrantDigest: d, CanonicalGrant: []byte("{\"grant\":\"read-schedule-v1\",\"id\":\"x\x1b[2J\"}")}}}
	var out bytes.Buffer
	if err := scheduleCmd(context.Background(), f, []string{"approve", d[:8]}, strings.NewReader("no\n"), &out); err == nil || f.approved != "" {
		t.Fatal("approved without yes")
	}
	if err := scheduleCmd(context.Background(), f, []string{"approve", d[:8]}, strings.NewReader("yes\n"), &out); err != nil || f.approved != d {
		t.Fatalf("%v %q", err, f.approved)
	}
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "read-schedule-v1") {
		t.Fatalf("%q", out.String())
	}
	if err := scheduleCmd(context.Background(), f, []string{"revoke", "g1"}, nil, &out); err != nil || f.revoked != "g1" {
		t.Fatal(err)
	}
	for _, bad := range [][]string{nil, {"approve"}, {"approve", "abc"}, {"revoke"}, {"other"}} {
		if err := scheduleCmd(context.Background(), f, bad, strings.NewReader("yes\n"), &out); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

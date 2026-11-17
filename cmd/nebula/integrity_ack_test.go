// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeIntegrity struct {
	pb.ExecutorServiceClient
	status *pb.GetIntegrityStatusResponse
	acked  []string
}

func (f *fakeIntegrity) GetIntegrityStatus(context.Context, *pb.GetIntegrityStatusRequest, ...grpc.CallOption) (*pb.GetIntegrityStatusResponse, error) {
	return f.status, nil
}

func (f *fakeIntegrity) AckIntegrityFinding(_ context.Context, in *pb.AckIntegrityFindingRequest, _ ...grpc.CallOption) (*pb.AckIntegrityFindingResponse, error) {
	f.acked = append(f.acked, in.GetFindingId())
	var kept []*pb.IntegrityFinding
	var acked *pb.IntegrityFinding
	for _, x := range f.status.Findings {
		if x.Id == in.GetFindingId() {
			acked = x
			continue
		}
		kept = append(kept, x)
	}
	return &pb.AckIntegrityFindingResponse{Finding: acked, Remaining: int32(len(kept)), Locked: len(kept) > 0}, nil
}

func lockedStatus() *pb.GetIntegrityStatusResponse {
	return &pb.GetIntegrityStatusResponse{
		Configured: true, Locked: true, LockedSinceUnix: 1794560400, TotalRuns: 3,
		LastRun: &pb.IntegrityRun{StartedUnix: 1794564000, State: "deviations", Complete: true, ReleaseVersion: "1.4.0",
			Files: 3, Different: 1, Locking: 1,
			Deviations: []*pb.IntegrityDeviation{{Path: "/usr/bin/nebula-server", Class: "binary", Status: "different", Reason: "sha256", Locks: true}}},
		Findings: []*pb.IntegrityFinding{
			{Id: "i1-0123456789abcdef", Cause: "deviation", Path: "/usr/bin/nebula-server", Class: "binary", Status: "different", Reason: "sha256"},
			{Id: "i1-fedcba9876543210", Cause: "deviation", Path: "/usr/bin/nebula-\x1b[31mevil", Class: "binary", Status: "extra"},
		},
		Note: integrity.RootCompromiseNote,
	}
}

func TestIntegrityStatusPrintsLockFindingsAndNote(t *testing.T) {
	f := &fakeIntegrity{status: lockedStatus()}
	var out bytes.Buffer
	if err := integrityExecutorCmd(context.Background(), f, []string{"status"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"LOCKED", "i1-0123456789abcdef", "/usr/bin/nebula-server", "last run:", "deviations",
		"note: NOS checks cannot detect a root compromise of the NOS machine; see ADR 0015"} {
		if !strings.Contains(s, want) {
			t.Fatalf("status lacks %q:\n%s", want, s)
		}
	}
	// Host-controlled names are printed as text only.
	if strings.Contains(s, "\x1b") || !strings.Contains(s, `\x1b[31mevil`) {
		t.Fatalf("control byte not escaped:\n%q", s)
	}
	if len(f.acked) != 0 {
		t.Fatal("status acknowledged something")
	}
}

func TestIntegrityStatusUnlockedStillShowsNote(t *testing.T) {
	f := &fakeIntegrity{status: &pb.GetIntegrityStatusResponse{Configured: true, Note: integrity.RootCompromiseNote}}
	var out bytes.Buffer
	if err := integrityExecutorCmd(context.Background(), f, []string{"status"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "no open locking finding") || !strings.Contains(s, "last run: none") ||
		!strings.Contains(s, integrity.RootCompromiseNote) {
		t.Fatalf("status:\n%s", s)
	}
}

func TestIntegrityAckShowsFindingAndClearsExactlyIt(t *testing.T) {
	f := &fakeIntegrity{status: lockedStatus()}
	var out bytes.Buffer
	if err := integrityExecutorCmd(context.Background(), f, []string{"ack", "i1-0123456789abcdef"}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if len(f.acked) != 1 || f.acked[0] != "i1-0123456789abcdef" {
		t.Fatalf("acked = %v", f.acked)
	}
	s := out.String()
	for _, want := range []string{"/usr/bin/nebula-server", "binary different (sha256)", "rolls back nothing", "1 findings still open", integrity.RootCompromiseNote} {
		if !strings.Contains(s, want) {
			t.Fatalf("ack output lacks %q:\n%s", want, s)
		}
	}
}

func TestIntegrityAckNeedsConfirmationAndAnOpenFinding(t *testing.T) {
	cases := []struct {
		name, id, input string
	}{
		{"no confirmation", "i1-0123456789abcdef", "no\n"},
		{"empty input", "i1-0123456789abcdef", ""},
		{"unknown finding", "i1-aaaaaaaaaaaaaaaa", "yes\n"},
		{"prefix only", "i1-0123", "yes\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeIntegrity{status: lockedStatus()}
			var out bytes.Buffer
			if err := integrityExecutorCmd(context.Background(), f, []string{"ack", tc.id}, strings.NewReader(tc.input), &out); err == nil {
				t.Fatal("ack succeeded")
			}
			if len(f.acked) != 0 {
				t.Fatalf("acked = %v", f.acked)
			}
		})
	}
}

func TestIntegrityExecutorCmdUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"ack"}, {"ack", "a", "b"}, {"status", "x"}, {"approve"}} {
		f := &fakeIntegrity{status: lockedStatus()}
		if err := integrityExecutorCmd(context.Background(), f, args, strings.NewReader("yes\n"), &bytes.Buffer{}); err == nil {
			t.Fatalf("%v accepted", args)
		}
		if len(f.acked) != 0 {
			t.Fatalf("%v acked", args)
		}
	}
	if isOfflineIntegrityCmd([]string{"status"}) || isOfflineIntegrityCmd([]string{"ack", "x"}) || !isOfflineIntegrityCmd([]string{"verify"}) {
		t.Fatal("offline dispatch")
	}
}

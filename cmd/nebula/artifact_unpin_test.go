// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeUnpinClient struct {
	reqs []*pb.UnpinBuiltinVersionRequest
	res  *pb.UnpinBuiltinVersionResponse
	err  error
}

func (f *fakeUnpinClient) UnpinBuiltinVersion(_ context.Context, r *pb.UnpinBuiltinVersionRequest, _ ...grpc.CallOption) (*pb.UnpinBuiltinVersionResponse, error) {
	f.reqs = append(f.reqs, r)
	return f.res, f.err
}

// `nebula artifact unpin MODULE@VERSION` sends exactly that version and
// prints the executor's record (admin UID, generation, remaining pins).
func TestArtifactUnpinSendsVersionAndPrintsRecord(t *testing.T) {
	f := &fakeUnpinClient{res: &pb.UnpinBuiltinVersionResponse{Version: "docker@1.0.0", Generation: 7, AdminUid: 1000,
		RemainingPins: []string{"core@0.9.0\x1b[2J"}}}
	var out bytes.Buffer
	if err := artifactUnpinIO(context.Background(), f, []string{"docker@1.0.0"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 1 || f.reqs[0].GetVersion() != "docker@1.0.0" {
		t.Fatalf("requests = %v", f.reqs)
	}
	s := out.String()
	for _, want := range []string{"version:    docker@1.0.0", "admin uid:  1000", "generation: 7", "still pinned: core@0.9.0"} {
		if !strings.Contains(s, want) {
			t.Fatalf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b") {
		t.Fatalf("output carries a raw escape: %q", s)
	}
}

// A version the executor reports as not pinned is a clear error; malformed
// arguments never reach the executor.
func TestArtifactUnpinRejections(t *testing.T) {
	f := &fakeUnpinClient{err: grpcstatus.Error(codes.NotFound, "trust: the version is not pinned")}
	err := artifactUnpinIO(context.Background(), f, []string{"docker@9.9.9"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "docker@9.9.9 is not pinned") {
		t.Fatalf("unknown pin: %v", err)
	}
	f.reqs = nil
	for _, args := range [][]string{nil, {}, {"docker"}, {"@1.0.0"}, {"docker@"}, {"a@1", "b@1"}, {strings.Repeat("a", 300) + "@1"}, {"d\xff@1"}} {
		if err := artifactUnpinIO(context.Background(), f, args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("args %q: %v, want usage", args, err)
		}
	}
	if len(f.reqs) != 0 {
		t.Fatalf("malformed arguments reached the executor: %v", f.reqs)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const testRGID = "11111111-2222-4333-8444-555555555555"

// fakeRevoke is an executor that lists stored read grants and records
// revocations.
type fakeRevoke struct {
	pb.ExecutorServiceClient
	grants    []*pb.ReadGrant
	listErr   error
	revokeErr error
	revoked   []string
}

func (f *fakeRevoke) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &pb.ListReadGrantsResponse{Grants: f.grants}, nil
}

func (f *fakeRevoke) RevokeReadGrant(_ context.Context, in *pb.RevokeReadGrantRequest, _ ...grpc.CallOption) (*pb.RevokeReadGrantResponse, error) {
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	f.revoked = append(f.revoked, in.GetGrantId())
	return &pb.RevokeReadGrantResponse{}, nil
}

// fixRevokeClock pins readGrantNow for one test.
func fixRevokeClock(t *testing.T, now time.Time) {
	t.Helper()
	old := readGrantNow
	readGrantNow = func() time.Time { return now }
	t.Cleanup(func() { readGrantNow = old })
}

func activeGrant(id string) *pb.ReadGrant {
	return &pb.ReadGrant{GrantId: id, GrantDigest: testRGDigest, ApprovedBy: "alice", CreatedUnix: 1800000000, ExpiryUnix: testRGExpiry}
}

// TestReadGrantRevokeRevokesActiveGrant: `nebula read-grant revoke <id>`
// revokes an active read lease through RevokeReadGrant, as the web lease
// page does.
func TestReadGrantRevokeRevokesActiveGrant(t *testing.T) {
	fixRevokeClock(t, time.Unix(1850000000, 0))
	f := &fakeRevoke{grants: []*pb.ReadGrant{activeGrant("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), activeGrant(testRGID)}}
	var out bytes.Buffer
	if err := readGrantCmd(context.Background(), f, []string{"revoke", testRGID}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != testRGID {
		t.Fatalf("revoked %v, want [%s]", f.revoked, testRGID)
	}
	if !strings.Contains(out.String(), "revoked: read grant "+testRGID) {
		t.Fatalf("output %q", out.String())
	}
}

// TestReadGrantRevokeRejects: a malformed, unknown, already revoked or
// expired grant is refused before RevokeReadGrant is called; the web page
// refuses the same cases.
func TestReadGrantRevokeRejects(t *testing.T) {
	now := time.Unix(1850000000, 0)
	revoked := activeGrant(testRGID)
	revoked.RevokedUnix = 1840000000
	expired := activeGrant(testRGID)
	expired.ExpiryUnix = now.Unix()
	for _, tc := range []struct {
		name   string
		args   []string
		grants []*pb.ReadGrant
		want   string
	}{
		{"no id", []string{"revoke"}, nil, "usage"},
		{"two ids", []string{"revoke", testRGID, testRGID}, nil, "usage"},
		{"uppercase", []string{"revoke", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"}, nil, "UUID"},
		{"not v4", []string{"revoke", "11111111-2222-1333-8444-555555555555"}, nil, "UUID"},
		{"path", []string{"revoke", "../grant"}, nil, "UUID"},
		{"too long", []string{"revoke", testRGID + "0"}, nil, "UUID"},
		{"unknown", []string{"revoke", testRGID}, []*pb.ReadGrant{activeGrant("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")}, "no read grant with that id"},
		{"revoked", []string{"revoke", testRGID}, []*pb.ReadGrant{revoked}, "already revoked"},
		{"expired", []string{"revoke", testRGID}, []*pb.ReadGrant{expired}, "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixRevokeClock(t, now)
			f := &fakeRevoke{grants: tc.grants}
			err := readGrantCmd(context.Background(), f, tc.args, nil, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if len(f.revoked) != 0 {
				t.Fatalf("revoked %v", f.revoked)
			}
		})
	}
}

// TestReadGrantRevokeExecutorErrors: executor refusals map to fixed
// messages; the executor's own text is never echoed.
func TestReadGrantRevokeExecutorErrors(t *testing.T) {
	fixRevokeClock(t, time.Unix(1850000000, 0))
	const secretish = "internal detail \x1b[2J from executor"
	for _, tc := range []struct {
		name string
		f    *fakeRevoke
		want string
	}{
		{"list denied", &fakeRevoke{listErr: grpcstatus.Error(codes.PermissionDenied, secretish)}, "permission denied"},
		{"revoke raced", &fakeRevoke{grants: []*pb.ReadGrant{activeGrant(testRGID)}, revokeErr: grpcstatus.Error(codes.NotFound, secretish)}, "no active read grant"},
		{"revoke unavailable", &fakeRevoke{grants: []*pb.ReadGrant{activeGrant(testRGID)}, revokeErr: grpcstatus.Error(codes.FailedPrecondition, secretish)}, "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := readGrantCmd(context.Background(), tc.f, []string{"revoke", testRGID}, nil, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "internal detail") || strings.Contains(err.Error(), "\x1b") {
				t.Fatalf("executor text echoed: %q", err)
			}
		})
	}
}

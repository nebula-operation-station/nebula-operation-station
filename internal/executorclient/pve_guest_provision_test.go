// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestCommitPVEGuestProvisionDeadlineCoversTheRun: the commit wait is the
// executor's whole run bound, which covers the task wait of every step,
// not one step's wait (the 30 min wait before covered only one).
func TestCommitPVEGuestProvisionDeadlineCoversTheRun(t *testing.T) {
	if pveGuestProvisionCommitWait < executor.PveGuestProvisionRunBound {
		t.Fatalf("commit wait %v shorter than the executor run bound %v", pveGuestProvisionCommitWait, executor.PveGuestProvisionRunBound)
	}
	if pveGuestProvisionCommitWait < 4*30*time.Minute {
		t.Fatalf("commit wait %v does not cover four 30 min task waits", pveGuestProvisionCommitWait)
	}
}

func TestProposePVEGuestProvisionForwardsWithDefaultTimeout(t *testing.T) {
	checkPVEAdminRPC(t, "ProposePVEGuestProvision", (*Client).ProposePVEGuestProvision)
}

// TestCommitPVEGuestProvisionForwardsWithLongTimeout: the commit is
// forwarded once with request and options, gets the default timeout plus
// the provisioning wait, and maps errors like every other call.
func TestCommitPVEGuestProvisionForwardsWithLongTimeout(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rpcError  error
		wantError error
	}{
		{name: "success"},
		{name: "permission denied", rpcError: status.Error(codes.PermissionDenied, "denied"), wantError: ErrPermissionDenied},
		{name: "unavailable", rpcError: status.Error(codes.Unavailable, "unavailable"), wantError: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := &pb.CommitPVEGuestProvisionRequest{ExecutionDigest: "d"}
			option := grpc.WaitForReady(true)
			var response *pb.CommitPVEGuestProvisionResponse
			calls := 0
			started := time.Now()
			c := &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{
				invoke: func(ctx context.Context, method string, in, out any, opts ...grpc.CallOption) error {
					calls++
					if method != pb.ExecutorService_CommitPVEGuestProvision_FullMethodName {
						t.Errorf("method = %q", method)
					}
					if in != request || len(opts) == 0 || opts[len(opts)-1] != option {
						t.Error("request or option not forwarded")
					}
					deadline, ok := ctx.Deadline()
					if !ok || deadline.Before(started.Add(time.Second+pveGuestProvisionCommitWait)) ||
						deadline.After(time.Now().Add(time.Second+pveGuestProvisionCommitWait)) {
						t.Errorf("deadline %v, want default timeout plus %v", deadline, pveGuestProvisionCommitWait)
					}
					response = out.(*pb.CommitPVEGuestProvisionResponse)
					return tc.rpcError
				},
			})}
			got, err := c.CommitPVEGuestProvision(context.Background(), request, option)
			if calls != 1 {
				t.Fatalf("calls = %d, want 1", calls)
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("error = %v, want %v", err, tc.wantError)
			}
			if tc.rpcError == nil && got != response {
				t.Error("response not forwarded")
			}
		})
	}
}

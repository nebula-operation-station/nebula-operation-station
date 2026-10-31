// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestReadGrantRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProposeReadGrant", func(t *testing.T) { checkPVEAdminRPC(t, "ProposeReadGrant", (*Client).ProposeReadGrant) })
	t.Run("CommitReadGrant", func(t *testing.T) { checkPVEAdminRPC(t, "CommitReadGrant", (*Client).CommitReadGrant) })
	t.Run("ListPendingReadGrants", func(t *testing.T) { checkPVEAdminRPC(t, "ListPendingReadGrants", (*Client).ListPendingReadGrants) })
	t.Run("ApproveReadGrantCLI", func(t *testing.T) { checkPVEAdminRPC(t, "ApproveReadGrantCLI", (*Client).ApproveReadGrantCLI) })
	t.Run("ListReadGrants", func(t *testing.T) { checkPVEAdminRPC(t, "ListReadGrants", (*Client).ListReadGrants) })
	t.Run("RevokeReadGrant", func(t *testing.T) { checkPVEAdminRPC(t, "RevokeReadGrant", (*Client).RevokeReadGrant) })
}

func TestReadGrantErrorsPreserveCodes(t *testing.T) {
	for _, tc := range []struct {
		code    permit.Code
		status  codes.Code
		blocked bool
	}{
		{permit.CodeLeaseInvalid, codes.InvalidArgument, false},
		{permit.CodeLeaseUnavailable, codes.Unimplemented, false},
		{permit.CodeLeaseInactive, codes.PermissionDenied, true},
		{permit.CodeLeaseNotCovered, codes.PermissionDenied, true},
		{permit.CodeLeaseBudget, codes.ResourceExhausted, false},
	} {
		t.Run(string(tc.code), func(t *testing.T) {
			err := mapError(status.Error(tc.status, string(tc.code)+": bounded denial"))
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != string(tc.code) {
				t.Fatalf("lost read-grant code: %v", err)
			}
			if errors.Is(err, ErrPolicyBlocked) != tc.blocked {
				t.Fatalf("policy classification: %v", err)
			}
		})
	}
}

func TestRunReadGrantTimeoutAndForwarding(t *testing.T) {
	for _, seconds := range []uint32{0, 1, 600, 601} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			for _, trigger := range []pb.ReadGrantTrigger{pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED, pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND} {
				req := &pb.RunReadGrantRequest{TimeoutSeconds: seconds, Trigger: trigger}
				runTimeout := time.Duration(seconds) * time.Second
				if runTimeout <= 0 || runTimeout > 10*time.Minute {
					runTimeout = 10 * time.Minute
				}
				var callCtx context.Context
				c := &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{invoke: func(ctx context.Context, method string, in, out any, opts ...grpc.CallOption) error {
					callCtx = ctx
					if method != pb.ExecutorService_RunReadGrant_FullMethodName || in != req {
						t.Fatal("wrong method or request")
					}
					deadline, ok := ctx.Deadline()
					remaining := time.Until(deadline)
					if !ok || remaining > runTimeout+time.Second || remaining < runTimeout+900*time.Millisecond {
						t.Fatalf("run deadline: %s", remaining)
					}
					if len(opts) < 1 || opts[len(opts)-1] != grpc.WaitForReady(true) {
						t.Fatal("lost call option")
					}
					return status.Error(codes.PermissionDenied, "denied")
				}})}
				if _, err := c.RunReadGrant(context.Background(), req, grpc.WaitForReady(true)); !errors.Is(err, ErrPermissionDenied) {
					t.Fatal(err)
				}
				if !errors.Is(callCtx.Err(), context.Canceled) {
					t.Fatal("call context was not canceled")
				}
			}
		})
	}
}

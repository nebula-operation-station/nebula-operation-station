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

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type pveAdminConn struct {
	grpc.ClientConnInterface
	invoke func(context.Context, string, any, any, ...grpc.CallOption) error
}

func (c pveAdminConn) Invoke(ctx context.Context, method string, in, out any, opts ...grpc.CallOption) error {
	return c.invoke(ctx, method, in, out, opts...)
}

func checkPVEAdminRPC[Request, Response any](t *testing.T, name string, call func(*Client, context.Context, *Request, ...grpc.CallOption) (*Response, error)) {
	t.Helper()
	for _, tc := range []struct {
		name      string
		rpcError  error
		wantError error
	}{
		{name: "success"},
		{name: "permission denied", rpcError: status.Error(codes.PermissionDenied, "denied"), wantError: ErrPermissionDenied},
		{name: "unavailable", rpcError: status.Error(codes.Unavailable, "unavailable"), wantError: ErrUnavailable},
		{name: "deadline exceeded", rpcError: status.Error(codes.DeadlineExceeded, "deadline exceeded"), wantError: ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := new(Request)
			option := grpc.WaitForReady(true)
			var callCtx context.Context
			var response *Response
			calls := 0
			started := time.Now()
			c := &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{
				invoke: func(ctx context.Context, method string, in, out any, opts ...grpc.CallOption) error {
					calls++
					callCtx = ctx
					if method != "/nebula.executor.v1.ExecutorService/"+name {
						t.Errorf("method = %q, want RPC %s", method, name)
					}
					if in != request {
						t.Error("request was not forwarded")
					}
					if len(opts) == 0 || opts[len(opts)-1] != option {
						t.Error("call option was not forwarded")
					}
					deadline, ok := ctx.Deadline()
					if !ok || deadline.Before(started.Add(time.Second)) || deadline.After(time.Now().Add(time.Second)) {
						t.Error("call does not use the default timeout")
					}
					response = out.(*Response)
					return tc.rpcError
				},
			})}
			got, err := call(c, context.Background(), request, option)
			if calls != 1 {
				t.Fatalf("RPC calls = %d, want 1", calls)
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("error = %v, want %v", err, tc.wantError)
			}
			if tc.rpcError == nil && got != response {
				t.Error("response was not forwarded")
			}
			if !errors.Is(callCtx.Err(), context.Canceled) {
				t.Error("call context was not canceled")
			}
		})
	}
}

func TestPVEAdminRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProbePVERemote", func(t *testing.T) { checkPVEAdminRPC(t, "ProbePVERemote", (*Client).ProbePVERemote) })
	t.Run("AddPVERemote", func(t *testing.T) { checkPVEAdminRPC(t, "AddPVERemote", (*Client).AddPVERemote) })
	t.Run("RotatePVEToken", func(t *testing.T) { checkPVEAdminRPC(t, "RotatePVEToken", (*Client).RotatePVEToken) })
	t.Run("RemovePVERemote", func(t *testing.T) { checkPVEAdminRPC(t, "RemovePVERemote", (*Client).RemovePVERemote) })
	t.Run("ListPVEAdminRemotes", func(t *testing.T) { checkPVEAdminRPC(t, "ListPVEAdminRemotes", (*Client).ListPVEAdminRemotes) })
	t.Run("ProposePVERepin", func(t *testing.T) { checkPVEAdminRPC(t, "ProposePVERepin", (*Client).ProposePVERepin) })
	t.Run("CommitPVERepin", func(t *testing.T) { checkPVEAdminRPC(t, "CommitPVERepin", (*Client).CommitPVERepin) })
}

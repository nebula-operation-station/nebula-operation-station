// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// pveGuestTestDefaultTimeout is the client default timeout the guest wrapper
// tests use; the propose calls must carry exactly this bound.
const pveGuestTestDefaultTimeout = time.Second

// pveGuestCallerDeadline is the caller's own deadline in the caller-context
// tests. It is far shorter than any call deadline, so the caller's context
// is what ends the call.
const pveGuestCallerDeadline = 20 * time.Millisecond

// pveGuestHangLimit bounds how long a fake RPC waits for the caller's context.
// A wrapper that ignores the caller's context fails after this time instead
// of hanging for the full commit deadline.
const pveGuestHangLimit = 5 * time.Second

// pveGuestErrorCases are the RPC failures a guest power or snapshot call can
// return. Each maps through mapCallError to the sentinel in wantError; the
// server message becomes the Detail unchanged.
var pveGuestErrorCases = []struct {
	name      string
	code      codes.Code
	message   string
	wantError error
}{
	{name: "permission denied", code: codes.PermissionDenied, message: "denied", wantError: ErrPermissionDenied},
	{name: "not found", code: codes.NotFound, message: "no such permit", wantError: ErrPermitNotFound},
	{name: "failed precondition", code: codes.FailedPrecondition, message: "wrong state", wantError: ErrPrecondition},
	{name: "unavailable", code: codes.Unavailable, message: "socket down", wantError: ErrUnavailable},
	{name: "deadline exceeded", code: codes.DeadlineExceeded, message: "task timed out", wantError: ErrDeadlineExceeded},
}

// checkPVEGuestRPC checks one guest wrapper call. It forwards the request and
// the call option once to method, gives the call the default timeout plus
// extra, returns the response, and maps every failure in pveGuestErrorCases
// like the other wrappers. canary is a value from the request that must not
// show up in any error text.
func checkPVEGuestRPC[Request, Response any](t *testing.T, method string, extra time.Duration, request *Request, canary string, call func(*Client, context.Context, *Request, ...grpc.CallOption) (*Response, error)) {
	t.Helper()
	t.Run("success", func(t *testing.T) {
		option := grpc.WaitForReady(true)
		var response *Response
		calls := 0
		started := time.Now()
		c := &Client{defaultTimeout: pveGuestTestDefaultTimeout, rpc: pb.NewExecutorServiceClient(pveAdminConn{
			invoke: func(ctx context.Context, m string, in, out any, opts ...grpc.CallOption) error {
				calls++
				checkPVEGuestCall(t, ctx, started, method, extra, m, in, request, opts, option)
				response = out.(*Response)
				return nil
			},
		})}
		got, err := call(c, context.Background(), request, option)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if calls != 1 {
			t.Fatalf("RPC calls = %d, want 1", calls)
		}
		if got != response {
			t.Error("response was not returned unchanged")
		}
	})
	for _, tc := range pveGuestErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			option := grpc.WaitForReady(true)
			calls := 0
			started := time.Now()
			c := &Client{defaultTimeout: pveGuestTestDefaultTimeout, rpc: pb.NewExecutorServiceClient(pveAdminConn{
				invoke: func(ctx context.Context, m string, in, out any, opts ...grpc.CallOption) error {
					calls++
					checkPVEGuestCall(t, ctx, started, method, extra, m, in, request, opts, option)
					return status.Error(tc.code, tc.message)
				},
			})}
			got, err := call(c, context.Background(), request, option)
			if calls != 1 {
				t.Fatalf("RPC calls = %d, want 1", calls)
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("error = %v, want %v", err, tc.wantError)
			}
			if got != nil {
				t.Error("a response was returned together with an error")
			}
			var execErr *Error
			if !errors.As(err, &execErr) || execErr.Detail != tc.message {
				t.Errorf("error detail = %v, want the server message %q", err, tc.message)
			}
			if canary != "" && strings.Contains(err.Error(), canary) {
				t.Errorf("error %q contains request content %q", err, canary)
			}
		})
	}
}

// checkPVEGuestCall asserts what the fake RPC receives: the method, the
// request pointer (unchanged), the call option as the last option, and the
// deadline, which must be the default timeout plus extra.
func checkPVEGuestCall(t *testing.T, ctx context.Context, started time.Time, method string, extra time.Duration, gotMethod string, in any, request any, opts []grpc.CallOption, option grpc.CallOption) {
	t.Helper()
	if gotMethod != method {
		t.Errorf("method = %q, want %q", gotMethod, method)
	}
	if in != request {
		t.Error("request was not forwarded unchanged")
	}
	if len(opts) == 0 || opts[len(opts)-1] != option {
		t.Error("call option was not forwarded")
	}
	want := pveGuestTestDefaultTimeout + extra
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(started.Add(want)) || deadline.After(time.Now().Add(want)) {
		t.Errorf("deadline = %v (set: %t), want %v from the call start", deadline, ok, want)
	}
}

// checkPVEGuestCallerContext checks that a call ends as soon as the caller's
// own context is canceled or expires, even when the call has a long deadline
// (the commit waits for the PVE task). The fake RPC blocks until the call's
// context is done and then returns the status a transport reports for it.
func checkPVEGuestCallerContext[Request, Response any](t *testing.T, request *Request, call func(*Client, context.Context, *Request, ...grpc.CallOption) (*Response, error)) {
	t.Helper()
	// hang blocks like a real transport until the call context is done and
	// reports Canceled, as gRPC does when the client gives up.
	hang := func(ctx context.Context, _ string, _, _ any, _ ...grpc.CallOption) error {
		select {
		case <-ctx.Done():
			return status.Error(codes.Canceled, ctx.Err().Error())
		case <-time.After(pveGuestHangLimit):
			t.Error("call kept waiting after the caller's context ended")
			return nil
		}
	}
	t.Run("caller canceled", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		defer cancel()
		timer := time.AfterFunc(pveGuestCallerDeadline, cancel)
		defer timer.Stop()
		c := &Client{defaultTimeout: pveGuestTestDefaultTimeout, rpc: pb.NewExecutorServiceClient(pveAdminConn{invoke: hang})}
		started := time.Now()
		_, err := call(c, parent, request)
		if elapsed := time.Since(started); elapsed >= pveGuestHangLimit {
			t.Fatalf("call returned after %v, want it to end with the caller's context", elapsed)
		}
		if !errors.Is(err, ErrCanceled) {
			t.Fatalf("error = %v, want %v", err, ErrCanceled)
		}
	})
	t.Run("caller deadline expired", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), pveGuestCallerDeadline)
		defer cancel()
		c := &Client{defaultTimeout: pveGuestTestDefaultTimeout, rpc: pb.NewExecutorServiceClient(pveAdminConn{invoke: hang})}
		started := time.Now()
		_, err := call(c, parent, request)
		if elapsed := time.Since(started); elapsed >= pveGuestHangLimit {
			t.Fatalf("call returned after %v, want it to end with the caller's deadline", elapsed)
		}
		if !errors.Is(err, ErrDeadlineExceeded) {
			t.Fatalf("error = %v, want %v", err, ErrDeadlineExceeded)
		}
	})
}

// pveGuestPowerTestRequest is a propose request with a recognizable node name,
// which the error text must never contain.
func pveGuestPowerTestRequest() (*pb.ProposePVEGuestPowerRequest, string) {
	const node = "node-canary-power"
	return &pb.ProposePVEGuestPowerRequest{Target: &pb.PVEGuestPowerTarget{
		RemoteId: "remote-1", Kind: "qemu", Node: node, Vmid: 101, Verb: "stop",
	}}, node
}

func TestProposePVEGuestPowerForwardsWithDefaultTimeout(t *testing.T) {
	request, canary := pveGuestPowerTestRequest()
	checkPVEGuestRPC(t, pb.ExecutorService_ProposePVEGuestPower_FullMethodName, 0, request, canary, (*Client).ProposePVEGuestPower)
}

func TestProposePVEGuestPowerCallerContextEndsCall(t *testing.T) {
	request, _ := pveGuestPowerTestRequest()
	checkPVEGuestCallerContext(t, request, (*Client).ProposePVEGuestPower)
}

func TestCommitPVEGuestPowerForwardsWithLongTimeout(t *testing.T) {
	request, canary := pveGuestPowerTestRequest()
	commit := &pb.CommitPVEGuestPowerRequest{Target: request.Target, ExecutionDigest: "digest-power"}
	checkPVEGuestRPC(t, pb.ExecutorService_CommitPVEGuestPower_FullMethodName, pveGuestPowerCommitWait, commit, canary, (*Client).CommitPVEGuestPower)
}

func TestCommitPVEGuestPowerCallerContextEndsCall(t *testing.T) {
	request, _ := pveGuestPowerTestRequest()
	commit := &pb.CommitPVEGuestPowerRequest{Target: request.Target, ExecutionDigest: "digest-power"}
	checkPVEGuestCallerContext(t, commit, (*Client).CommitPVEGuestPower)
}

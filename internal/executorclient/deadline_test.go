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

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// lateStatusRPC is a fake transport for ProposeExecution: it waits until
// the call context is done and then returns err, as gRPC does when the
// transport's status races with the client's own per-call deadline. This
// forces the race seen in CI (TestPerCallTimeoutFires reported
// "canceled: context canceled") deterministically.
type lateStatusRPC struct {
	pb.ExecutorServiceClient
	err  error
	resp *pb.ProposeExecutionResponse
}

func (f *lateStatusRPC) ProposeExecution(ctx context.Context, _ *pb.ProposeExecutionRequest, _ ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	<-ctx.Done()
	return f.resp, f.err
}

func TestPerCallDeadlineWinsOverTransportStatus(t *testing.T) {
	statuses := map[string]error{
		"canceled":          status.Error(codes.Canceled, "context canceled"),
		"deadline exceeded": status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
		"unavailable":       status.Error(codes.Unavailable, "transport is closing"),
		"unknown":           status.Error(codes.Unknown, "context canceled"),
		"plain context err": context.Canceled,
	}
	for name, transportErr := range statuses {
		t.Run(name, func(t *testing.T) {
			c := &Client{rpc: &lateStatusRPC{err: transportErr}, defaultTimeout: time.Millisecond}
			_, err := c.ProposeExecution(context.Background(), &pb.ProposeExecutionRequest{})
			if !errors.Is(err, ErrDeadlineExceeded) {
				t.Fatalf("want ErrDeadlineExceeded, got %v", err)
			}
			if errors.Is(err, ErrCanceled) {
				t.Fatalf("deadline error also matches ErrCanceled: %v", err)
			}
			if !errors.Is(err, transportErr) {
				t.Fatalf("transport error %v not kept as cause of %v", transportErr, err)
			}
		})
	}
}

func TestCallerCancelStaysCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Client{rpc: &lateStatusRPC{err: status.Error(codes.Canceled, "context canceled")}, defaultTimeout: time.Hour}
	_, err := c.ProposeExecution(ctx, &pb.ProposeExecutionRequest{})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("want ErrCanceled, got %v", err)
	}
}

func TestCallerDeadlineMapsToDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	c := &Client{rpc: &lateStatusRPC{err: status.Error(codes.Canceled, "context canceled")}, defaultTimeout: time.Hour}
	_, err := c.ProposeExecution(ctx, &pb.ProposeExecutionRequest{})
	if !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("want ErrDeadlineExceeded, got %v", err)
	}
}

// An answer the executor actually sent (a coded failure) is not hidden
// behind a deadline that expired after it arrived.
func TestExecutorCodeKeptAfterDeadline(t *testing.T) {
	c := &Client{rpc: &lateStatusRPC{err: status.Error(codes.FailedPrecondition, "vault_locked: run `nebula unlock`")}, defaultTimeout: time.Millisecond}
	_, err := c.ProposeExecution(context.Background(), &pb.ProposeExecutionRequest{})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

// A success that arrives as the deadline fires stays a success.
func TestSuccessNotMaskedByDeadline(t *testing.T) {
	want := &pb.ProposeExecutionResponse{}
	c := &Client{rpc: &lateStatusRPC{resp: want}, defaultTimeout: time.Millisecond}
	resp, err := c.ProposeExecution(context.Background(), &pb.ProposeExecutionRequest{})
	if err != nil || resp != want {
		t.Fatalf("want response and nil error, got %v, %v", resp, err)
	}
}

func TestMapCallErrorTable(t *testing.T) {
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelExpired()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	live := context.Background()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want *Error
	}{
		{"expired+canceled status", expired, status.Error(codes.Canceled, "context canceled"), ErrDeadlineExceeded},
		{"expired+internal status", expired, status.Error(codes.Internal, "boom"), ErrDeadlineExceeded},
		{"expired+executor code", expired, status.Error(codes.PermissionDenied, string(permit.CodeTargetNotPermitted)+": x"), ErrPolicyBlocked},
		{"canceled+canceled status", canceled, status.Error(codes.Canceled, "context canceled"), ErrCanceled},
		{"live+canceled status", live, status.Error(codes.Canceled, "context canceled"), ErrCanceled},
		{"live+deadline status", live, status.Error(codes.DeadlineExceeded, "x"), ErrDeadlineExceeded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := mapCallError(tc.ctx, tc.err); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	if err := mapCallError(expired, nil); err != nil {
		t.Fatalf("mapCallError(expired, nil) = %v, want nil", err)
	}
}

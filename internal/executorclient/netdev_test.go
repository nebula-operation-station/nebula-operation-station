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

const netDevMethodPrefix = "/nebula.executor.v1.ExecutorService/"

// netDevErrorCases are the outcomes every netdev wrapper must map like the
// PVE wrappers: success, a role refusal, the ND-12 Unimplemented answer and
// a transport deadline.
var netDevErrorCases = []struct {
	name     string
	rpcError error
	want     error
	wantCode codes.Code
}{
	{name: "success"},
	{name: "permission denied", rpcError: status.Error(codes.PermissionDenied, "role not allowed"), want: ErrPermissionDenied, wantCode: codes.PermissionDenied},
	{name: "unimplemented", rpcError: status.Error(codes.Unimplemented, "device reads not implemented"), want: ErrInternal, wantCode: codes.Unimplemented},
	{name: "not found", rpcError: status.Error(codes.NotFound, "unknown device"), want: ErrPermitNotFound, wantCode: codes.NotFound},
	{name: "deadline exceeded", rpcError: status.Error(codes.DeadlineExceeded, "deadline exceeded"), want: ErrDeadlineExceeded, wantCode: codes.DeadlineExceeded},
}

// checkNetDevError asserts that err is the typed mapping of rpcError and
// keeps the gRPC status as cause.
func checkNetDevError(t *testing.T, err, rpcError, want error, wantCode codes.Code) {
	t.Helper()
	if rpcError == nil {
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		return
	}
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("error %v (%T) is not a typed *Error", err, err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if got := status.Code(errors.Unwrap(err)); got != wantCode {
		t.Fatalf("cause code = %v, want %v", got, wantCode)
	}
}

func checkNetDevRPC[Request, Response any](t *testing.T, name string, call func(*Client, context.Context, *Request, ...grpc.CallOption) (*Response, error)) {
	t.Helper()
	for _, tc := range netDevErrorCases {
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
					if method != netDevMethodPrefix+name {
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
			checkNetDevError(t, err, tc.rpcError, tc.want, tc.wantCode)
			if tc.rpcError == nil && got != response {
				t.Error("response was not forwarded")
			}
			if !errors.Is(callCtx.Err(), context.Canceled) {
				t.Error("call context was not canceled")
			}
		})
	}
}

func TestNetDevRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProbeNetDevice", func(t *testing.T) { checkNetDevRPC(t, "ProbeNetDevice", (*Client).ProbeNetDevice) })
	t.Run("RegisterNetDevice", func(t *testing.T) { checkNetDevRPC(t, "RegisterNetDevice", (*Client).RegisterNetDevice) })
	t.Run("SetNetDeviceCredential", func(t *testing.T) {
		checkNetDevRPC(t, "SetNetDeviceCredential", (*Client).SetNetDeviceCredential)
	})
	t.Run("RotateNetDeviceCredential", func(t *testing.T) {
		checkNetDevRPC(t, "RotateNetDeviceCredential", (*Client).RotateNetDeviceCredential)
	})
	t.Run("ProposeNetDeviceRepin", func(t *testing.T) {
		checkNetDevRPC(t, "ProposeNetDeviceRepin", (*Client).ProposeNetDeviceRepin)
	})
	t.Run("CommitNetDeviceRepin", func(t *testing.T) { checkNetDevRPC(t, "CommitNetDeviceRepin", (*Client).CommitNetDeviceRepin) })
	t.Run("BlockNetDevice", func(t *testing.T) { checkNetDevRPC(t, "BlockNetDevice", (*Client).BlockNetDevice) })
	t.Run("UnblockNetDevice", func(t *testing.T) { checkNetDevRPC(t, "UnblockNetDevice", (*Client).UnblockNetDevice) })
	t.Run("RemoveNetDevice", func(t *testing.T) { checkNetDevRPC(t, "RemoveNetDevice", (*Client).RemoveNetDevice) })
	t.Run("ListNetDevices", func(t *testing.T) { checkNetDevRPC(t, "ListNetDevices", (*Client).ListNetDevices) })
	t.Run("ReadNetDevice", func(t *testing.T) { checkNetDevRPC(t, "ReadNetDevice", (*Client).ReadNetDevice) })
}

// netDevFake returns a client whose transport answers one method with
// reply (copied into the generated response) or rpcError.
func netDevFake(t *testing.T, wantMethod string, check func(in any), reply func(out any), rpcError error) (*Client, *int) {
	t.Helper()
	calls := new(int)
	c := &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{
		invoke: func(ctx context.Context, method string, in, out any, _ ...grpc.CallOption) error {
			*calls++
			if method != netDevMethodPrefix+wantMethod {
				t.Errorf("method = %q, want %s", method, wantMethod)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("call has no deadline")
			}
			if check != nil {
				check(in)
			}
			if rpcError != nil {
				return rpcError
			}
			if reply != nil {
				reply(out)
			}
			return nil
		},
	})}
	return c, calls
}

func TestListNetDeviceInfosReturnsDevicesAndMapsErrors(t *testing.T) {
	devices := []*pb.NetDeviceInfo{
		{DeviceId: "sw-core", Family: "cbs", TrustGeneration: 3},
		{DeviceId: "fw-edge", Family: "panos", TrustGeneration: 1, Blocked: true},
	}
	for _, tc := range netDevErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			c, calls := netDevFake(t, "ListNetDevices",
				func(in any) {
					if _, ok := in.(*pb.ListNetDevicesRequest); !ok {
						t.Errorf("request type = %T", in)
					}
				},
				func(out any) { out.(*pb.ListNetDevicesResponse).Devices = devices },
				tc.rpcError)
			got, err := c.ListNetDeviceInfos(context.Background())
			if *calls != 1 {
				t.Fatalf("RPC calls = %d, want 1", *calls)
			}
			checkNetDevError(t, err, tc.rpcError, tc.want, tc.wantCode)
			if tc.rpcError != nil {
				if got != nil {
					t.Fatalf("devices = %v on error, want nil", got)
				}
				return
			}
			if len(got) != len(devices) || got[0] != devices[0] || got[1] != devices[1] {
				t.Fatalf("devices = %v, want %v", got, devices)
			}
		})
	}
}

func TestListNetDeviceInfosEmptyRegistry(t *testing.T) {
	c, _ := netDevFake(t, "ListNetDevices", nil, nil, nil)
	got, err := c.ListNetDeviceInfos(context.Background())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("devices = %v, want none", got)
	}
}

func TestReadNetDeviceByIDBuildsRequestAndMapsErrors(t *testing.T) {
	const deviceID = "sw-core"
	read := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS
	for _, tc := range netDevErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			var reply *pb.ReadNetDeviceResponse
			c, calls := netDevFake(t, "ReadNetDevice",
				func(in any) {
					req, ok := in.(*pb.ReadNetDeviceRequest)
					if !ok {
						t.Fatalf("request type = %T", in)
					}
					if req.GetDeviceId() != deviceID || req.GetRead() != read {
						t.Errorf("request = (%q, %v), want (%q, %v)", req.GetDeviceId(), req.GetRead(), deviceID, read)
					}
				},
				func(out any) {
					reply = out.(*pb.ReadNetDeviceResponse)
					reply.DeviceId = deviceID
					reply.TrustGeneration = 3
				},
				tc.rpcError)
			got, err := c.ReadNetDeviceByID(context.Background(), deviceID, read)
			if *calls != 1 {
				t.Fatalf("RPC calls = %d, want 1", *calls)
			}
			checkNetDevError(t, err, tc.rpcError, tc.want, tc.wantCode)
			if tc.rpcError == nil && (got != reply || got.GetTrustGeneration() != 3) {
				t.Fatalf("response = %v, want %v", got, reply)
			}
		})
	}
}

// lateNetDevRPC waits for the per-call context to end and then answers
// with err, forcing the race between the transport status and the
// client's own deadline (see deadline_test.go).
type lateNetDevRPC struct {
	pb.ExecutorServiceClient
	err error
}

func (f *lateNetDevRPC) ListNetDevices(ctx context.Context, _ *pb.ListNetDevicesRequest, _ ...grpc.CallOption) (*pb.ListNetDevicesResponse, error) {
	<-ctx.Done()
	return nil, f.err
}

func (f *lateNetDevRPC) ReadNetDevice(ctx context.Context, _ *pb.ReadNetDeviceRequest, _ ...grpc.CallOption) (*pb.ReadNetDeviceResponse, error) {
	<-ctx.Done()
	return nil, f.err
}

func TestNetDevPerCallDeadlineWinsOverTransportStatus(t *testing.T) {
	transportErr := status.Error(codes.Canceled, "context canceled")
	c := &Client{rpc: &lateNetDevRPC{err: transportErr}, defaultTimeout: time.Millisecond}
	calls := map[string]func() error{
		"ListNetDeviceInfos": func() error {
			_, err := c.ListNetDeviceInfos(context.Background())
			return err
		},
		"ReadNetDeviceByID": func() error {
			_, err := c.ReadNetDeviceByID(context.Background(), "sw-core", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION)
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			if !errors.Is(err, ErrDeadlineExceeded) {
				t.Fatalf("want ErrDeadlineExceeded, got %v", err)
			}
			if errors.Is(err, ErrCanceled) {
				t.Fatalf("deadline error also matches ErrCanceled: %v", err)
			}
			if !errors.Is(err, transportErr) {
				t.Fatalf("transport error not kept as cause of %v", err)
			}
		})
	}
}

func TestNetDevCallerCancelStaysCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Client{rpc: &lateNetDevRPC{err: status.Error(codes.Canceled, "context canceled")}, defaultTimeout: time.Hour}
	_, err := c.ReadNetDeviceByID(ctx, "sw-core", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION)
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("want ErrCanceled, got %v", err)
	}
}

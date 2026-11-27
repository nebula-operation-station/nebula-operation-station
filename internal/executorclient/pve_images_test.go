// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestPVEImageRPCsForwardWithTimeoutAndMapErrors: the propose and list image
// pass-throughs (ADR 0008 amendment 2, PV-03f) each call their own generated
// method once, forward request, options and response, carry the default
// timeout and map errors like every other executor call. The commit has its
// own longer timeout (TestCommitPVEImagePrepareForwardsWithLongTimeout).
func TestPVEImageRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProposePVEImagePrepare", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ProposePVEImagePrepare_FullMethodName), (*Client).ProposePVEImagePrepare)
	})
	t.Run("ListPVEImages", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ListPVEImages_FullMethodName), (*Client).ListPVEImages)
	})
}

// TestCommitPVEImagePrepareForwardsWithLongTimeout: the commit is forwarded
// once with request and options, gets the default timeout plus the image
// preparation wait (the executor runs the download, the import and the
// template conversion, each up to its task wait), and maps errors like every
// other call. A default-length deadline would cancel a real preparation.
func TestCommitPVEImagePrepareForwardsWithLongTimeout(t *testing.T) {
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
			request := &pb.CommitPVEImagePrepareRequest{ExecutionDigest: "d"}
			option := grpc.WaitForReady(true)
			var response *pb.CommitPVEImagePrepareResponse
			calls := 0
			started := time.Now()
			c := &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{
				invoke: func(ctx context.Context, method string, in, out any, opts ...grpc.CallOption) error {
					calls++
					if method != pb.ExecutorService_CommitPVEImagePrepare_FullMethodName {
						t.Errorf("method = %q", method)
					}
					if in != request || len(opts) == 0 || opts[len(opts)-1] != option {
						t.Error("request or option not forwarded")
					}
					deadline, ok := ctx.Deadline()
					if !ok || deadline.Before(started.Add(time.Second+pveImagePrepareCommitWait)) ||
						deadline.After(time.Now().Add(time.Second+pveImagePrepareCommitWait)) {
						t.Errorf("deadline %v, want default timeout plus %v", deadline, pveImagePrepareCommitWait)
					}
					response = out.(*pb.CommitPVEImagePrepareResponse)
					return tc.rpcError
				},
			})}
			got, err := c.CommitPVEImagePrepare(context.Background(), request, option)
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

// TestLocalImageRPCsAreNotForwarded: AddPVELocalImage and RemovePVELocalImage
// (PV-03f: local-entry RPCs are not forwarded) never reach the executor from
// this client. Each returns ErrPermissionDenied without a call, so a server
// caller cannot write local catalog entries through executorclient.
func TestLocalImageRPCsAreNotForwarded(t *testing.T) {
	t.Run("AddPVELocalImage", func(t *testing.T) {
		checkLocalImageRPCNotForwarded(t, func(c *Client) error {
			resp, err := c.AddPVELocalImage(context.Background(), &pb.AddPVELocalImageRequest{})
			if resp != nil {
				t.Error("response is not nil")
			}
			return err
		})
	})
	t.Run("RemovePVELocalImage", func(t *testing.T) {
		checkLocalImageRPCNotForwarded(t, func(c *Client) error {
			resp, err := c.RemovePVELocalImage(context.Background(), &pb.RemovePVELocalImageRequest{})
			if resp != nil {
				t.Error("response is not nil")
			}
			return err
		})
	})
}

func checkLocalImageRPCNotForwarded(t *testing.T, call func(*Client) error) {
	t.Helper()
	calls := 0
	c := &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{
		invoke: func(context.Context, string, any, any, ...grpc.CallOption) error {
			calls++
			return nil
		},
	})}
	err := call(c)
	if calls != 0 {
		t.Fatalf("RPC calls = %d, want 0: local-entry RPCs must not be forwarded", calls)
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("error = %v, want ErrPermissionDenied", err)
	}
}

// imageSocketService is an in-process executor for the image RPCs. It
// records which handler was reached and returns err (if set) from each. The
// local-entry handlers are present so that a call that reaches them is
// counted, not answered as Unimplemented.
type imageSocketService struct {
	pb.UnimplementedExecutorServiceServer
	err   error
	calls map[string]int
}

// GetStatus answers the probe that New sends before it returns a client.
func (s *imageSocketService) GetStatus(_ context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (s *imageSocketService) ProposePVEImagePrepare(_ context.Context, _ *pb.ProposePVEImagePrepareRequest) (*pb.ProposePVEImagePrepareResponse, error) {
	s.calls["propose"]++
	if s.err != nil {
		return nil, s.err
	}
	return &pb.ProposePVEImagePrepareResponse{}, nil
}

func (s *imageSocketService) CommitPVEImagePrepare(_ context.Context, _ *pb.CommitPVEImagePrepareRequest) (*pb.CommitPVEImagePrepareResponse, error) {
	s.calls["commit"]++
	if s.err != nil {
		return nil, s.err
	}
	return &pb.CommitPVEImagePrepareResponse{}, nil
}

func (s *imageSocketService) ListPVEImages(_ context.Context, _ *pb.ListPVEImagesRequest) (*pb.ListPVEImagesResponse, error) {
	s.calls["list"]++
	if s.err != nil {
		return nil, s.err
	}
	return &pb.ListPVEImagesResponse{}, nil
}

func (s *imageSocketService) AddPVELocalImage(_ context.Context, _ *pb.AddPVELocalImageRequest) (*pb.AddPVELocalImageResponse, error) {
	s.calls["add"]++
	return &pb.AddPVELocalImageResponse{}, nil
}

func (s *imageSocketService) RemovePVELocalImage(_ context.Context, _ *pb.RemovePVELocalImageRequest) (*pb.RemovePVELocalImageResponse, error) {
	s.calls["remove"]++
	return &pb.RemovePVELocalImageResponse{}, nil
}

// startRolesSocket serves svc on a real peercred Unix socket in a temporary
// directory. The current UID gets exactly roles, and the real method-role
// table from the executor decides what it may call.
func startRolesSocket(t *testing.T, svc pb.ExecutorServiceServer, roles ...peercred.Role) string {
	t.Helper()
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): roles}, executor.MethodRoles())
	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(peercred.Credentials{Policy: policy}),
		grpc.UnaryInterceptor(policy.UnaryInterceptor(nil)),
		grpc.StreamInterceptor(policy.StreamInterceptor(nil)),
	)
	pb.RegisterExecutorServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return socket
}

// TestPVEImageRPCsReachExecutorOverSocket: the three image RPCs travel over
// a real verified socket to the matching executor handler, the server role
// is allowed to call them, and gRPC error codes come back as the client's
// typed errors.
func TestPVEImageRPCsReachExecutorOverSocket(t *testing.T) {
	type rpcCase struct {
		name    string
		handler string
		call    func(*Client, context.Context) error
	}
	rpcs := []rpcCase{
		{"ProposePVEImagePrepare", "propose", func(c *Client, ctx context.Context) error {
			_, err := c.ProposePVEImagePrepare(ctx, &pb.ProposePVEImagePrepareRequest{})
			return err
		}},
		{"CommitPVEImagePrepare", "commit", func(c *Client, ctx context.Context) error {
			_, err := c.CommitPVEImagePrepare(ctx, &pb.CommitPVEImagePrepareRequest{})
			return err
		}},
		{"ListPVEImages", "list", func(c *Client, ctx context.Context) error {
			_, err := c.ListPVEImages(ctx, &pb.ListPVEImagesRequest{})
			return err
		}},
	}
	errCases := []struct {
		name      string
		rpcErr    error
		wantError error
	}{
		{name: "success"},
		{name: "permission denied", rpcErr: status.Error(codes.PermissionDenied, "denied"), wantError: ErrPermissionDenied},
		{name: "failed precondition", rpcErr: status.Error(codes.FailedPrecondition, "not approved"), wantError: ErrPrecondition},
		{name: "unavailable", rpcErr: status.Error(codes.Unavailable, "down"), wantError: ErrUnavailable},
	}
	for _, rpc := range rpcs {
		for _, ec := range errCases {
			t.Run(rpc.name+"/"+ec.name, func(t *testing.T) {
				svc := &imageSocketService{err: ec.rpcErr, calls: map[string]int{}}
				// Server role only: the server must be allowed to call the
				// three RPCs (the executor method-role table decides).
				socket := startRolesSocket(t, svc, peercred.RoleServer)
				c, err := New(testCtx(t), Options{SocketPath: socket, ExecutorUser: currentUser(t)})
				if err != nil {
					t.Fatalf("new client: %v", err)
				}
				defer c.Close()
				err = rpc.call(c, testCtx(t))
				if svc.calls[rpc.handler] != 1 {
					t.Fatalf("handler %q reached %d times, want 1 (calls: %v)", rpc.handler, svc.calls[rpc.handler], svc.calls)
				}
				if ec.wantError == nil {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				if !errors.Is(err, ec.wantError) {
					t.Fatalf("error = %v, want %v", err, ec.wantError)
				}
			})
		}
	}
}

// TestLocalImageRPCsDeniedForServerRoleOverSocket: a server-role caller that
// sends AddPVELocalImage or RemovePVELocalImage over the real peercred socket
// (through the raw generated client on the same connection, since
// executorclient does not forward them) gets PermissionDenied from the
// executor's role table, and the handler is never reached. A later change to
// the role table or the client that lets the server write local catalog
// entries fails here.
func TestLocalImageRPCsDeniedForServerRoleOverSocket(t *testing.T) {
	svc := &imageSocketService{calls: map[string]int{}}
	socket := startRolesSocket(t, svc, peercred.RoleServer)
	c, err := New(testCtx(t), Options{SocketPath: socket, ExecutorUser: currentUser(t)})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	if _, err := c.rpc.AddPVELocalImage(testCtx(t), &pb.AddPVELocalImageRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("AddPVELocalImage code = %v (err %v), want PermissionDenied", status.Code(err), err)
	}
	if _, err := c.rpc.RemovePVELocalImage(testCtx(t), &pb.RemovePVELocalImageRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("RemovePVELocalImage code = %v (err %v), want PermissionDenied", status.Code(err), err)
	}
	if svc.calls["add"] != 0 || svc.calls["remove"] != 0 {
		t.Fatalf("local-entry handlers reached (calls: %v), want none", svc.calls)
	}
}

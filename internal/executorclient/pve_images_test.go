// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestPVEImageRPCsForwardWithTimeoutAndMapErrors: each of the five image
// pass-throughs (ADR 0008 amendment 2, PV-03a) calls its own generated
// method once, forwards request, options and response, carries the default
// timeout and maps errors like every other executor call.
//
// CommitPVEImagePrepare is pinned to the default timeout on purpose: the
// executor handler and its run bound do not exist yet. The ticket that adds
// them has to replace this case with a long-timeout test like
// TestCommitPVEGuestProvisionForwardsWithLongTimeout.
func TestPVEImageRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProposePVEImagePrepare", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ProposePVEImagePrepare_FullMethodName), (*Client).ProposePVEImagePrepare)
	})
	t.Run("CommitPVEImagePrepare", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_CommitPVEImagePrepare_FullMethodName), (*Client).CommitPVEImagePrepare)
	})
	t.Run("ListPVEImages", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ListPVEImages_FullMethodName), (*Client).ListPVEImages)
	})
	t.Run("AddPVELocalImage", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_AddPVELocalImage_FullMethodName), (*Client).AddPVELocalImage)
	})
	t.Run("RemovePVELocalImage", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_RemovePVELocalImage_FullMethodName), (*Client).RemovePVELocalImage)
	})
}

// imageSocketService is an in-process executor for the image RPCs. It
// records which handler was reached and returns err (if set) from each.
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

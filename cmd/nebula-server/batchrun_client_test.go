// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeExecutorServer serves a fakeBatchRPC as a gRPC executor, so the
// batch runner talks to it through the real executor client and its error
// mapping (executorclient.Client), over a Unix socket in a temporary
// directory.
type fakeExecutorServer struct {
	pb.UnimplementedExecutorServiceServer
	f *fakeBatchRPC
}

func (s fakeExecutorServer) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (s fakeExecutorServer) ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest) (*pb.ListHostKeysResponse, error) {
	return s.f.ListHostKeys(ctx, in)
}

func (s fakeExecutorServer) GetBatchCredentialVersions(ctx context.Context, in *pb.GetBatchCredentialVersionsRequest) (*pb.GetBatchCredentialVersionsResponse, error) {
	return s.f.GetBatchCredentialVersions(ctx, in)
}

func (s fakeExecutorServer) ProposeBatch(ctx context.Context, in *pb.ProposeBatchRequest) (*pb.ProposeBatchResponse, error) {
	return s.f.ProposeBatch(ctx, in)
}

func (s fakeExecutorServer) CommitBatch(ctx context.Context, in *pb.CommitBatchRequest) (*pb.CommitBatchResponse, error) {
	return s.f.CommitBatch(ctx, in)
}

func (s fakeExecutorServer) GetBatchStatus(ctx context.Context, in *pb.GetBatchStatusRequest) (*pb.GetBatchStatusResponse, error) {
	return s.f.GetBatchStatus(ctx, in)
}

func (s fakeExecutorServer) RunBatchMember(ctx context.Context, in *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
	return s.f.RunBatchMember(ctx, in)
}

func (s fakeExecutorServer) GetRollout(ctx context.Context, in *pb.GetRolloutRequest) (*pb.GetRolloutResponse, error) {
	return s.f.GetRollout(ctx, in)
}

// realClient serves f on a Unix socket and returns the real executor
// client connected to it.
func realClient(t *testing.T, f *fakeBatchRPC) *executorclient.Client {
	t.Helper()
	// Short path: Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "nos-exec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterExecutorServiceServer(srv, fakeExecutorServer{f: f})
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c, err := executorclient.New(context.Background(), executorclient.Options{SocketPath: sock, ExecutorUser: u.Username})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

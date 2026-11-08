// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// definitionClient serves the shipped executor service through the real
// gRPC server and role table (as run() does) to the current UID in role.
func definitionClient(t *testing.T, svc *executor.Service, role peercred.Role) pb.ExecutorServiceClient {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "executor.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): {role}}, executor.MethodRoles())
	srv := executor.NewGRPCServer(svc, policy, quietLog)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); _ = ln.Close() })
	conn, err := grpc.NewClient("passthrough:///executor", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, sock, uint32(os.Getuid()))
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewExecutorServiceClient(conn)
}

// The shipped executor serves the container definition RPCs to the admin
// role only: an admin reaches the service (a locked vault refuses the
// write, the metadata list answers), the server role is denied.
func TestShippedExecutorServesContainerDefinitionsToAdminOnly(t *testing.T) {
	e := newExecutorUnderTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	put := &pb.PutContainerDefinitionRequest{HostId: "web-1", ContainerName: "web", Options: []string{"--name=web"}}

	admin := definitionClient(t, e.svc, peercred.RoleAdmin)
	if _, err := admin.ListContainerDefinitions(ctx, &pb.ListContainerDefinitionsRequest{}); err != nil {
		t.Fatalf("admin list: %v", err)
	}
	if _, err := admin.PutContainerDefinition(ctx, put); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("admin put with the vault not unlocked: %v", err)
	}

	server := definitionClient(t, e.svc, peercred.RoleServer)
	if _, err := server.ListContainerDefinitions(ctx, &pb.ListContainerDefinitionsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server list: %v", err)
	}
	if _, err := server.PutContainerDefinition(ctx, put); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server put: %v", err)
	}
	if _, err := server.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "web"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server remove: %v", err)
	}
}

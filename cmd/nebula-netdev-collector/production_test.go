// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// roleStub answers the one method the collector probes. Every other method
// is Unimplemented, so only the role policy decides what a caller may reach.
type roleStub struct {
	pb.UnimplementedExecutorServiceServer
}

func (roleStub) ListNetDevices(context.Context, *pb.ListNetDevicesRequest) (*pb.ListNetDevicesResponse, error) {
	return &pb.ListNetDevicesResponse{}, nil
}

// startRoleExecutor serves roleStub on a real peercred Unix socket with the
// real method-role table (executor.MethodRoles) and the real policy
// interceptors. The test's own UID holds exactly the given role.
func startRoleExecutor(t *testing.T, role peercred.Role) (socket, execUser string) {
	t.Helper()
	uid := uint32(os.Getuid())
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uid: {role}}, executor.MethodRoles())
	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket = filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(peercred.Credentials{Policy: policy}),
		grpc.UnaryInterceptor(policy.UnaryInterceptor(nil)),
		grpc.StreamInterceptor(policy.StreamInterceptor(nil)),
	)
	pb.RegisterExecutorServiceServer(srv, roleStub{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	return socket, u.Username
}

// connectRecorder wraps the real productionDeps().newClient and keeps the
// error it returned, so a refused connect stays visible after run returns.
func connectRecorder(d deps) (deps, *error) {
	var connectErr error
	real := d.newClient
	d.newClient = func(ctx context.Context, o executorclient.Options) (collectorClient, error) {
		c, err := real(ctx, o)
		connectErr = err
		return c, err
	}
	return d, &connectErr
}

// TestProductionCollectorStartsUnderItsRole runs the real productionDeps
// against an executor whose role table is the real one and whose only role
// for the collector UID is netdev-collector. The collector must connect,
// poll an empty registry without a role error and spool nothing.
func TestProductionCollectorStartsUnderItsRole(t *testing.T) {
	socket, user := startRoleExecutor(t, peercred.RoleNetDevCollector)
	spool := filepath.Join(t.TempDir(), "spool")

	d := productionDeps()
	// The test process may run as root; the root refusal is tested
	// separately, so only this check is replaced.
	d.geteuid = func() int { return 1000 }
	d, connectErr := connectRecorder(d)

	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	o := options{socket: socket, executorUser: user, spoolDir: spool, interval: time.Second}
	if err := run(ctx, o, log, d); err != nil {
		t.Fatalf("run under netdev-collector role: %v", err)
	}
	if *connectErr != nil {
		t.Fatalf("connect under netdev-collector role: %v", *connectErr)
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"nebula-netdev-collector: starting"`)) {
		t.Fatalf("collector never reached the poll loop:\n%s", logs.String())
	}
	if entries, err := os.ReadDir(spool); err == nil && len(entries) != 0 {
		t.Fatalf("empty registry spooled %d entries", len(entries))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// TestProductionCollectorRefusedUnderForeignRole is the counter-probe: the
// same wiring with the pve-collector role must not get the collector in.
func TestProductionCollectorRefusedUnderForeignRole(t *testing.T) {
	socket, user := startRoleExecutor(t, peercred.RolePVECollector)
	d := productionDeps()
	d.geteuid = func() int { return 1000 }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o := options{socket: socket, executorUser: user, spoolDir: t.TempDir(), interval: time.Second}
	err := run(ctx, o, slog.New(slog.DiscardHandler), d)
	if !errors.Is(err, executorclient.ErrPermissionDenied) {
		t.Fatalf("run under pve-collector role: want ErrPermissionDenied, got %v", err)
	}
}

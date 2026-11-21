// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// timeoutSlack is how much earlier than the budget the deadline seen by the
// executor may end: the client starts its clock before the call is sent.
const timeoutSlack = time.Second

// readProbe is a pvecollect.Reader that records the deadline the collector
// gives one ReadPVE call. It reads the collector's own per-read budget from
// pvecollect instead of copying the number.
type readProbe struct {
	mu     sync.Mutex
	budget time.Duration
	seen   bool
}

func (p *readProbe) ListPVERemotes(context.Context, *pb.ListPVERemotesRequest, ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
	return &pb.ListPVERemotesResponse{Remotes: []*pb.PVERemoteInfo{
		{RemoteId: "probe", State: pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE},
	}}, nil
}

func (p *readProbe) ReadPVE(ctx context.Context, _ *pb.ReadPVERequest, _ ...grpc.CallOption) (*pb.ReadPVEResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d, ok := ctx.Deadline(); ok && !p.seen {
		p.budget = time.Until(d)
		p.seen = true
	}
	return nil, context.Canceled // the probe only needs the deadline
}

// probePVECollectBudget returns the per-read budget pvecollect applies to a
// default Config, measured through its public behaviour.
func probePVECollectBudget(t *testing.T) time.Duration {
	t.Helper()
	spool, err := pvecollect.NewSpool(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	probe := &readProbe{}
	c, err := pvecollect.New(probe, spool, pvecollect.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if !probe.seen {
		t.Fatal("collector issued no ReadPVE call with a deadline")
	}
	return probe.budget
}

// TestClientOptionsCoverCollectorReadBudget checks the options run() gives
// the executor client against the read budget of pvecollect's defaults.
// With a shorter DefaultTimeout the client would cut every slow read.
func TestClientOptionsCoverCollectorReadBudget(t *testing.T) {
	budget := probePVECollectBudget(t)
	o := clientOptions(options{socket: "/run/nebula/executor.sock", executorUser: "nebula-executor"})
	if o.DefaultTimeout <= 0 {
		t.Fatalf("DefaultTimeout = %v: the client would fall back to %v", o.DefaultTimeout, executorclient.DefaultCallTimeout)
	}
	if o.DefaultTimeout < budget {
		t.Fatalf("DefaultTimeout = %v, below the collector read budget %v: every read slower than %v is cut", o.DefaultTimeout, budget, o.DefaultTimeout)
	}
}

// TestClientOptionsIndependentOfMode checks that -live, -once and the
// interval do not change the client's timeouts: the sampling loop and the
// live watcher share one client built from the same options.
func TestClientOptionsIndependentOfMode(t *testing.T) {
	base := clientOptions(options{socket: "/run/nebula/executor.sock", executorUser: "nebula-executor"})
	for _, o := range []options{
		{socket: "/run/nebula/executor.sock", executorUser: "nebula-executor", live: true, interval: time.Minute},
		{socket: "/run/nebula/executor.sock", executorUser: "nebula-executor", live: false, once: true, interval: time.Second},
	} {
		got := clientOptions(o)
		if got.DefaultTimeout != base.DefaultTimeout || got.AuthorizeRunTimeout != base.AuthorizeRunTimeout {
			t.Fatalf("options for %+v = %+v, want the same timeouts as %+v", o, got, base)
		}
	}
}

// deadlineService is an executor stand-in for the collector role. It records
// the time left on the deadline of every ReadPVE call, as the executor sees
// it on the wire, and answers at once; no call waits for the budget.
type deadlineService struct {
	pb.UnimplementedExecutorServiceServer
	left chan time.Duration
}

func (s *deadlineService) ListPVERemotes(context.Context, *pb.ListPVERemotesRequest) (*pb.ListPVERemotesResponse, error) {
	return &pb.ListPVERemotesResponse{}, nil
}

func (s *deadlineService) ReadPVE(ctx context.Context, _ *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
	left := time.Duration(-1)
	if d, ok := ctx.Deadline(); ok {
		left = time.Until(d)
	}
	select {
	case s.left <- left:
	default:
	}
	return &pb.ReadPVEResponse{}, nil
}

// startCollectorExecutor serves svc on a peercred socket with the real
// method-role table. The calling UID holds only the pve-collector role.
func startCollectorExecutor(t *testing.T, svc pb.ExecutorServiceServer) (socket, username string) {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uid: {peercred.RolePVECollector}}, executor.MethodRoles())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket = filepath.Join(dir, "executor.sock")
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
	return socket, me.Username
}

// readDeadlineOverRPC makes one ReadPVE call through client and returns the
// time left on the deadline the executor saw.
func readDeadlineOverRPC(t *testing.T, client *executorclient.Client, svc *deadlineService) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := client.ReadPVE(ctx, &pb.ReadPVERequest{RemoteId: "probe"}); err != nil {
		t.Fatalf("ReadPVE: %v", err)
	}
	select {
	case left := <-svc.left:
		return left
	case <-time.After(5 * time.Second):
		t.Fatal("executor did not see the call")
		return 0
	}
}

// TestCollectorReadBudgetReachesExecutor runs one read through the real
// chain (clientOptions, executorclient, gRPC, peercred role check) and checks
// the executor sees at least the collector's read budget. A default client
// is cut at executorclient.DefaultCallTimeout, which the second check shows.
func TestCollectorReadBudgetReachesExecutor(t *testing.T) {
	budget := probePVECollectBudget(t)
	svc := &deadlineService{left: make(chan time.Duration, 4)}
	socket, username := startCollectorExecutor(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	o := clientOptions(options{socket: socket, executorUser: username})
	client, err := executorclient.NewPVECollector(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	left := readDeadlineOverRPC(t, client, svc)
	if left < budget-timeoutSlack {
		t.Fatalf("executor saw %v left on the ReadPVE deadline, want at least the collector read budget %v", left, budget)
	}
}

// TestDefaultClientIsCutAtDefaultCallTimeout is the control for the test
// above: a client without DefaultTimeout gets executorclient.DefaultCallTimeout,
// which is shorter than the collector's read budget. This shows that the
// deadline observation tells the two apart.
func TestDefaultClientIsCutAtDefaultCallTimeout(t *testing.T) {
	budget := probePVECollectBudget(t)
	svc := &deadlineService{left: make(chan time.Duration, 4)}
	socket, username := startCollectorExecutor(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := executorclient.NewPVECollector(ctx, executorclient.Options{SocketPath: socket, ExecutorUser: username})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	left := readDeadlineOverRPC(t, client, svc)
	if left > executorclient.DefaultCallTimeout+timeoutSlack {
		t.Fatalf("default client deadline %v, want at most %v", left, executorclient.DefaultCallTimeout)
	}
	if budget <= executorclient.DefaultCallTimeout {
		t.Fatalf("collector read budget %v does not exceed the default call timeout %v; the fix would be moot", budget, executorclient.DefaultCallTimeout)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func dpRun(id, user, state string, now time.Time) *deployRun {
	return &deployRun{id: id, user: user, state: state, created: now, expires: now.Add(deployRunTTL), deadline: now.Add(time.Hour)}
}

func TestDeployRunsGlobalLimitNeverEvictsLiveRuns(t *testing.T) {
	p := newDeployRuns(nil)
	now := time.Unix(1_800_000_000, 0)
	// 8 users with 16 live runs each fill the global limit.
	for u := range maxDeployRuns / maxDeployRunsPerUser {
		for i := range maxDeployRunsPerUser {
			if err := p.put(dpRun(fmt.Sprintf("u%d-%d", u, i), fmt.Sprintf("user%d", u), deployBooting, now), now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := p.room("newcomer", now); !errors.Is(err, errDeployFull) {
		t.Fatalf("room with only live runs = %v", err)
	}
	if err := p.put(dpRun("x", "newcomer", deployProposed, now), now); !errors.Is(err, errDeployFull) {
		t.Fatalf("put evicted a live run: %v", err)
	}
	if err := p.room("user0", now); !errors.Is(err, errDeployUserCap) {
		t.Fatalf("user cap = %v", err)
	}
	// Past their deadline the idle runs fail and stop counting; the
	// finished run that expires first is evicted for a newcomer, a live
	// run of another user never is.
	later := now.Add(2 * time.Hour)
	p.mu.Lock()
	for _, x := range p.runs {
		if x.user != "user7" {
			continue
		}
		x.deadline = later.Add(time.Hour) // user7's runs stay live
	}
	p.mu.Unlock()
	if err := p.room("user0", later); err != nil {
		t.Fatalf("room after the deadline = %v", err)
	}
	if err := p.put(dpRun("y", "newcomer", deployProposed, later), later); err != nil {
		t.Fatalf("put after the deadline = %v", err)
	}
	live := 0
	for _, x := range p.runs {
		if x.user == "user7" {
			if x.final() {
				t.Errorf("run %s of user7 failed before its deadline", x.id)
			}
			live++
		}
		if x.state == deployFailed && (x.failedIn != deployBooting || x.message == "") {
			t.Errorf("expired run %s: failed in %q, reason %q", x.id, x.failedIn, x.message)
		}
	}
	if live != maxDeployRunsPerUser {
		t.Errorf("user7 keeps %d of %d live runs", live, maxDeployRunsPerUser)
	}
}

func TestDeployRunsBusyRunsAreNeverExpired(t *testing.T) {
	p := newDeployRuns(nil)
	now := time.Unix(1_800_000_000, 0)
	creating := dpRun("c", "alice", deployCreating, now)
	joining := dpRun("j", "alice", deployEnrolling, now)
	joining.join = &deployJoin{approving: true}
	planning := dpRun("p", "alice", deployBootstrapping, now)
	planning.approving = true
	for _, x := range []*deployRun{creating, joining, planning} {
		if err := p.put(x, now); err != nil {
			t.Fatal(err)
		}
	}
	later := now.Add(48 * time.Hour)
	p.mu.Lock()
	p.prune(later)
	p.mu.Unlock()
	for _, x := range []*deployRun{creating, joining, planning} {
		if x.final() || p.runs[x.id] == nil {
			t.Errorf("busy run %s (%s) was expired or dropped", x.id, x.state)
		}
	}
}

// TestDeployRunsExpiredProposalKeepsItsAddress: the expiry of a proposal
// with an IPAM reservation marks the address kept ("may be in use"), never
// for release: the execution may have been committed out of band. A
// proposal without a reservation (DHCP) has nothing to keep.
func TestDeployRunsExpiredProposalKeepsItsAddress(t *testing.T) {
	var logBuf bytes.Buffer
	p := newDeployRuns(slog.New(slog.NewTextHandler(&logBuf, nil)))
	now := time.Unix(1_800_000_000, 0)
	x := dpRun("a", "alice", deployProposed, now)
	x.ipam, x.vmid, x.executionID, x.form.Remote = &pb.PVEIPAMBinding{Address: "192.168.10.50"}, 123, "exec-1", "pve1"
	dhcp := dpRun("b", "alice", deployProposed, now)
	for _, r := range []*deployRun{x, dhcp} {
		if err := p.put(r, now); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	p.prune(now.Add(2 * time.Hour))
	p.mu.Unlock()
	if x.state != deployFailed || x.failedIn != deployProposed || x.address != ipamKept {
		t.Fatalf("expired proposal: %s in %s, address %q", x.state, x.failedIn, x.address)
	}
	for _, want := range []string{"may be in use", "192.168.10.50", "VMID 123"} {
		if !strings.Contains(x.message, want) {
			t.Errorf("expired proposal message lacks %q: %s", want, x.message)
		}
	}
	if dhcp.state != deployFailed || dhcp.address != ipamHeld || strings.Contains(dhcp.message, "nothing was created") {
		t.Errorf("expired DHCP proposal: %s, address %q, %q", dhcp.state, dhcp.address, dhcp.message)
	}
	// The audit log keeps the owner of the reservation after the run is
	// pruned; the DHCP proposal kept nothing.
	audit := logBuf.String()
	for _, want := range []string{"kind=deployment_address_kept", "reason=proposal_expired", "address=192.168.10.50",
		"run=a", "execution=exec-1", "remote=pve1", "vmid=123", "user=alice"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit log lacks %q: %s", want, audit)
		}
	}
	if n := strings.Count(audit, "deployment_address_kept"); n != 1 {
		t.Errorf("%d kept-address audit entries, want 1: %s", n, audit)
	}
	// A kept address holds no run: past the TTL both are pruned (the
	// reservation itself stays in the IPAM).
	p.mu.Lock()
	p.prune(now.Add(72 * time.Hour))
	p.mu.Unlock()
	if len(p.runs) != 0 {
		t.Errorf("%d runs left past the TTL", len(p.runs))
	}
}

// TestDeployRunsKeptAddressesNeverBlockTheLimit: finished runs that keep
// their address are evicted like any finished run, so a store full of them
// never refuses a new deployment.
func TestDeployRunsKeptAddressesNeverBlockTheLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := newDeployRuns(nil)
	for i := range maxDeployRuns {
		x := dpRun(fmt.Sprintf("r%d", i), fmt.Sprintf("user%d", i), deployFailed, now)
		x.ipam, x.address = &pb.PVEIPAMBinding{Address: "192.168.10.50"}, ipamKept
		if err := p.put(x, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.room("bob", now); err != nil {
		t.Errorf("room with only kept-address runs = %v", err)
	}
	if err := p.put(dpRun("new", "bob", deployProposed, now), now); err != nil {
		t.Errorf("put with only kept-address runs = %v", err)
	}
	if len(p.runs) != maxDeployRuns {
		t.Errorf("%d runs, want %d", len(p.runs), maxDeployRuns)
	}
}

// proposeExecutor answers ProposePVEGuestProvision with err after delay.
type proposeExecutor struct {
	pb.UnimplementedExecutorServiceServer
	err   error
	delay time.Duration
}

func (proposeExecutor) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (f *proposeExecutor) ProposePVEGuestProvision(_ context.Context, _ *pb.ProposePVEGuestProvisionRequest) (*pb.ProposePVEGuestProvisionResponse, error) {
	// The answer is sent after the delay even when the call's deadline
	// has passed, like a slow executor.
	time.Sleep(f.delay)
	return nil, f.err
}

// clientProposeError returns the error the real executorclient reports
// for a ProposePVEGuestProvision the executor answers as f does.
func clientProposeError(t *testing.T, f *proposeExecutor, timeout time.Duration) error {
	t.Helper()
	dir, err := os.MkdirTemp("", "nosui") // short: a socket path is limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "x.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterExecutorServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c, err := executorclient.New(context.Background(), executorclient.Options{SocketPath: socket, ExecutorUser: u.Username, DefaultTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_, err = c.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{})
	if err == nil {
		t.Fatal("propose succeeded")
	}
	return err
}

// TestProposeRefusedIsAnAllowlist: the wizard releases an address after a
// failed propose only for the executor's spec refusal, which it sends
// before registering a permit. Every other gRPC code (with the same
// message or another), a coded executor refusal, a wrapped or non-status
// error and every executorclient mapping other than that refusal keeps
// the address: the executor may hold an approvable permit.
func TestProposeRefusedIsAnAllowlist(t *testing.T) {
	type tc struct {
		name    string
		err     error
		release bool
	}
	var cases []tc
	for c := codes.Canceled; c <= codes.Unauthenticated; c++ {
		cases = append(cases,
			tc{name: c.String(), err: status.Error(c, proposeSpecRefusal), release: c == codes.InvalidArgument},
			tc{name: c.String() + " other message", err: status.Error(c, "pve guest provision failed")})
	}
	refusal := status.Error(codes.InvalidArgument, proposeSpecRefusal)
	cases = append(cases,
		tc{name: "invalid_request coded", err: status.Error(codes.InvalidArgument, "invalid_request: "+proposeSpecRefusal)},
		tc{name: "wrapped status", err: fmt.Errorf("propose: %w", refusal)},
		tc{name: "non-status", err: errors.New(proposeSpecRefusal)},
		tc{name: "context deadline", err: context.DeadlineExceeded},
		tc{name: "context canceled", err: context.Canceled},
		tc{name: "client sentinel invalid request", err: executorclient.ErrInvalidRequest},
		tc{name: "client sentinel internal", err: executorclient.ErrInternal},
		tc{name: "client sentinel unavailable", err: executorclient.ErrUnavailable},
		tc{name: "client sentinel deadline", err: executorclient.ErrDeadlineExceeded},
		tc{name: "client error without cause", err: &executorclient.Error{Code: "invalid_request", Detail: proposeSpecRefusal}},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := proposeRefused(c.err); got != c.release {
				t.Errorf("proposeRefused(%v) = %v, want %v", c.err, got, c.release)
			}
		})
	}
}

// TestProposeRefusedThroughTheExecutorClient: the same allowlist over the
// errors the production client (executorclient over the executor socket)
// returns, including a refusal that arrives after the call's deadline.
func TestProposeRefusedThroughTheExecutorClient(t *testing.T) {
	type tc struct {
		name    string
		exec    *proposeExecutor
		release bool
	}
	var cases []tc
	for c := codes.Canceled; c <= codes.Unauthenticated; c++ {
		cases = append(cases, tc{name: c.String(), exec: &proposeExecutor{err: status.Error(c, proposeSpecRefusal)}, release: c == codes.InvalidArgument})
	}
	cases = append(cases,
		tc{name: "other invalid argument", exec: &proposeExecutor{err: status.Error(codes.InvalidArgument, "pve guest provision: something else")}},
		tc{name: "permit code invalid_request", exec: &proposeExecutor{err: status.Error(codes.InvalidArgument, "invalid_request: "+proposeSpecRefusal)}},
		tc{name: "permit code storage", exec: &proposeExecutor{err: status.Error(codes.Unavailable, "storage: write failed")}},
		tc{name: "request options", exec: &proposeExecutor{err: status.Error(codes.Internal, "request options")}},
		tc{name: "refusal after the deadline", exec: &proposeExecutor{err: status.Error(codes.InvalidArgument, proposeSpecRefusal), delay: time.Second}},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := clientProposeError(t, c.exec, 200*time.Millisecond)
			if got := proposeRefused(err); got != c.release {
				t.Errorf("proposeRefused(%v) = %v, want %v", err, got, c.release)
			}
		})
	}
}

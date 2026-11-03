// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
)

// blockRecorder records the remotes a client asked to block.
type blockRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (b *blockRecorder) block(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ids = append(b.ids, id)
}

func (b *blockRecorder) take() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.ids
	b.ids = nil
	return out
}

// TestPveMutationClientTrustFailureBlocksRemote: a pin mismatch seen by
// any call of the production client (dispatch, target state, task status,
// task list) or a trust source that reports a changed identity blocks the
// remote; an unreachable remote does not.
func TestPveMutationClientTrustFailureBlocksRemote(t *testing.T) {
	chain, other := makeTestChain(t), makeTestChain(t)
	f := newFakeMutPVE(t, chain.tls, "qemu")
	rm := testMutRemote(f.endpoint())
	read := tokenOf(mutReadToken)
	ctx := context.Background()
	upid := testTaskUPID("pve1", time.Now(), "qmstop", "101", mutActionUser, 1)

	var rec blockRecorder
	c := testMutClient(other)
	c.block = rec.block
	calls := map[string]func() error{
		"dispatch": func() error {
			_, err := c.Dispatch(ctx, rm, "pve1", mkStep("guest.qemu.stop", `{"vmid":101}`), tokenOf(mutActionToken))
			return err
		},
		"target state": func() error { _, err := c.TargetState(ctx, rm, "qemu", "pve1", 101, read); return err },
		"node state":   func() error { _, err := c.TargetState(ctx, rm, "node", "pve1", 0, read); return err },
		"task status":  func() error { _, err := c.TaskStatus(ctx, rm, "pve1", upid, read); return err },
		"task list":    func() error { _, err := c.RecentTasks(ctx, rm, "pve1", time.Time{}, read); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, errPveReadTrust) {
			t.Fatalf("%s: err = %v, want a trust failure", name, err)
		}
		if got := rec.take(); len(got) != 1 || got[0] != mutRemote {
			t.Fatalf("%s: blocked %v, want [%s]", name, got, mutRemote)
		}
	}
	if f.requests != 0 {
		t.Fatalf("requests reached the endpoint: %d", f.requests)
	}

	c.trust = func(context.Context, executordb.PveRemote) (pvetransport.Trust, error) {
		return pvetransport.Trust{}, errPveReadTrust
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, errPveReadTrust) {
			t.Fatalf("%s (trust source): err = %v", name, err)
		}
		if got := rec.take(); len(got) != 1 || got[0] != mutRemote {
			t.Fatalf("%s (trust source): blocked %v", name, got)
		}
	}

	c.trust = func(context.Context, executordb.PveRemote) (pvetransport.Trust, error) {
		return pvetransport.Trust{}, errPveReadUnreachable
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Fatalf("%s (unreachable): succeeded", name)
		}
	}
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("unreachable remote blocked: %v", got)
	}

	// A remote that keeps its pin is never blocked.
	c = testMutClient(chain)
	c.block = rec.block
	for name, call := range calls {
		if name == "task status" {
			continue // no such task on the fake
		}
		if err := call(); err != nil {
			t.Fatalf("%s (pinned): %v", name, err)
		}
	}
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("pinned remote blocked: %v", got)
	}
}

// badDispatchClient is the production client whose writes go over another
// (wrong) pin, while its reads keep the remote's pin: the remote changes
// its identity between the precondition reads and the write.
type badDispatchClient struct {
	*pveMutationClient
	dispatch *pveMutationClient
}

func (c badDispatchClient) Dispatch(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action pveapi.TokenSupplier) (string, error) {
	return c.dispatch.Dispatch(ctx, rm, node, step, action)
}

// adminBlock blocks a remote the way Service.blockPveRead does.
func adminBlock(a *PveAdmin) func(string) {
	return func(id string) { _ = a.blockTrustFailure(id, "executor", errPveReadTrust) }
}

func remoteState(t *testing.T, db *executordb.DB, id string) string {
	t.Helper()
	rm, ok, err := db.GetRemote(id)
	if err != nil || !ok {
		t.Fatalf("remote %s: %v %v", id, ok, err)
	}
	return rm.State
}

// TestGuestPowerPinMismatchDuringDispatchBlocksRemote: a pin mismatch
// seen while dispatching a mutation blocks the remote persistently; the
// step is refused unsent and every further mutation of the remote is
// refused before any write.
func TestGuestPowerPinMismatchDuringDispatchBlocksRemote(t *testing.T) {
	e, f, c := prodPowerEnv(t, "qemu")
	c.block = adminBlock(e.pe.admin)
	bad := testMutClient(makeTestChain(t))
	bad.block = c.block
	e.g.Mutations.Client = badDispatchClient{pveMutationClient: c, dispatch: bad}

	req := e.approve(powerReq("qemu", PveGuestPowerStop))
	next := e.approve(powerReq("qemu", PveGuestPowerShutdown))
	if _, err := e.g.Run(context.Background(), req); err == nil {
		t.Fatal("run over a changed pin succeeded")
	}
	if got := remoteState(t, e.pe.db, mutRemote); got != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", got)
	}
	// Further mutations are refused, also with the correct pin again.
	e.g.Mutations.Client = c
	if _, err := e.g.Run(context.Background(), next); err == nil {
		t.Fatal("approved mutation of a blocked remote ran")
	}
	if _, err := e.propose(powerReq("qemu", PveGuestPowerStop)); err == nil {
		t.Fatal("mutation of a blocked remote proposed")
	}
	if f.writeCount() != 0 || f.badAuth != 0 {
		t.Fatalf("writes %v badAuth %d", f.writes, f.badAuth)
	}
}

// TestGuestPowerPinMismatchDuringReconcileBlocksRemote: a lost response
// leaves the step reconciling; the remote then presents another identity
// to the reconciler's reads. The remote is blocked, the step is not
// decided from the untrusted remote, and further mutations are refused.
func TestGuestPowerPinMismatchDuringReconcileBlocksRemote(t *testing.T) {
	e, f, c := prodPowerEnv(t, "qemu")
	c.block = adminBlock(e.pe.admin)
	f.mu.Lock()
	f.hang = true
	f.mu.Unlock()
	req := e.approve(powerReq("qemu", PveGuestPowerStop))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	res, err := e.g.Run(ctx, req)
	cancel()
	if err == nil || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
	f.mu.Lock()
	f.hang = false
	f.mu.Unlock()

	other := makeTestChain(t)
	c.trust = func(context.Context, executordb.PveRemote) (pvetransport.Trust, error) {
		return pvetransport.Trust{CA: other.ca}, nil
	}
	_ = e.g.Mutations.Reconcile(context.Background())
	if got := remoteState(t, e.pe.db, mutRemote); got != executordb.StateBlocked {
		t.Fatalf("remote state = %s, want blocked", got)
	}
	steps, err := e.pe.db.PveJobSteps(res.ExecutionID)
	if err != nil || len(steps) != 1 || steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("steps %+v %v", steps, err)
	}
	if _, err := e.propose(powerReq("qemu", PveGuestPowerShutdown)); err == nil {
		t.Fatal("mutation of a blocked remote proposed")
	}
	if f.writeCount() != 1 {
		t.Fatalf("writes = %d, want only the first", f.writeCount())
	}
}

// TestPveMutationClientTaskListDedupsShiftedPages: PVE pages the task
// list by offset; a task that starts between two page reads shifts the
// list, so the last entry of the first page reappears on the second. Each
// UPID is returned once, or identify would see two candidates.
func TestPveMutationClientTaskListDedupsShiftedPages(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	var reads atomic.Int64
	var mu sync.Mutex
	var tasks []string
	for i := 0; i < pveMutationTaskPage+20; i++ {
		tasks = append(tasks, testTaskUPID("pve1", time.Now(), "qmstart", "101", mutActionUser, i))
	}
	want := len(tasks)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		body := `{"data":[`
		for i := start; i < len(tasks) && i < start+limit; i++ {
			if i > start {
				body += ","
			}
			body += `{"upid":"` + tasks[i] + `"}`
		}
		body += `]}`
		if reads.Add(1) == 1 {
			// A new task starts after the first page was read; the list
			// is newest first, so everything shifts down by one.
			tasks = append([]string{testTaskUPID("pve1", time.Now(), "qmstop", "101", mutActionUser, 99999)}, tasks...)
		}
		_, _ = w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{chain.tls}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	got, err := c.RecentTasks(context.Background(), testMutRemote(endpointOf(t, srv)), "pve1", time.Time{}, tokenOf(mutReadToken))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, u := range got {
		if seen[u] {
			t.Fatalf("UPID %s returned twice", u)
		}
		seen[u] = true
	}
	if len(got) != want {
		t.Fatalf("tasks = %d, want %d", len(got), want)
	}
}

// TestPveMutationClientRedirectIsUncertainNeverResent: an endpoint that
// answers a write with a redirect received it, so the step is uncertain
// (never refused as unsent) and is not sent to the redirect target or to
// another endpoint.
func TestPveMutationClientRedirectIsUncertainNeverResent(t *testing.T) {
	chain := makeTestChain(t)
	c := testMutClient(chain)
	second := newFakeMutPVE(t, chain.tls, "qemu")
	var hits atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://"+net.JoinHostPort(second.host, strconv.Itoa(int(second.port)))+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{chain.tls}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	rm := testMutRemote(endpointOf(t, srv), second.endpoint())
	_, err := c.Dispatch(context.Background(), rm, "pve1", mkStep("guest.qemu.stop", `{"vmid":101}`), tokenOf(mutActionToken))
	if err == nil || errors.Is(err, ErrPveRejected) {
		t.Fatalf("err = %v, want an uncertain dispatch", err)
	}
	var we *pveapi.WriteError
	if !errors.As(err, &we) || !we.OutcomeUnknown() {
		t.Fatalf("err = %v, want an unknown write outcome", err)
	}
	if hits.Load() != 1 || second.writeCount() != 0 {
		t.Fatalf("hits %d, second endpoint writes %d", hits.Load(), second.writeCount())
	}
}

func endpointOf(t *testing.T, srv *httptest.Server) pvecontract.Endpoint {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return pvecontract.Endpoint{Host: host, Port: uint16(p)}
}

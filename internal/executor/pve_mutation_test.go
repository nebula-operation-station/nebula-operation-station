// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	mutReadToken   = "nosread@pve!read=readsecret0123456789"
	mutActionToken = "nosact@pve!act=actionsecret0123456789"
	mutRemote      = "lab-pve"
)

var mutArtifact = []byte("pve.test.mutation 1.0.0\nTest-only typed mutation.\n")

// fixedRisk is a risk policy whose floor is MEDIUM for every request.
type fixedRisk struct{}

func (fixedRisk) MinimumRisk(canonical.Request, []canonical.Target) (canonical.Risk, string, error) {
	return canonical.RiskMedium, "test", nil
}

type mutDispatch struct {
	node, method, header string
}

// fakeMutClient records every call and the credential it was given.
type fakeMutClient struct {
	mu            sync.Mutex
	db            *executordb.DB
	liveNode      string
	configDigest  string
	dispatches    []mutDispatch
	readHeaders   []string
	onDispatch    func(n int, node string) (string, error)
	status        func(upid string) (PveTaskStatus, error)
	recent        []string
	recentErr     error
	statusQueried []string
}

func header(ctx context.Context, tok pveapi.TokenSupplier) string {
	h, _ := tok(ctx)
	return h
}

func (f *fakeMutClient) Dispatch(ctx context.Context, _ executordb.PveRemote, node string, step PveMutationStep, tok pveapi.TokenSupplier) (string, error) {
	f.mu.Lock()
	f.dispatches = append(f.dispatches, mutDispatch{node: node, method: step.Method, header: header(ctx, tok)})
	n := len(f.dispatches)
	on := f.onDispatch
	f.mu.Unlock()
	if on != nil {
		return on(n, node)
	}
	return testUPIDAt(node, time.Now(), 101, n), nil
}

func (f *fakeMutClient) TaskStatus(ctx context.Context, _ executordb.PveRemote, _, upid string, tok pveapi.TokenSupplier) (PveTaskStatus, error) {
	f.mu.Lock()
	f.readHeaders = append(f.readHeaders, header(ctx, tok))
	f.statusQueried = append(f.statusQueried, upid)
	st := f.status
	f.mu.Unlock()
	if st != nil {
		return st(upid)
	}
	return PveTaskStatus{ExitStatus: "OK"}, nil
}

func (f *fakeMutClient) RecentTasks(ctx context.Context, _ executordb.PveRemote, _ string, _ time.Time, tok pveapi.TokenSupplier) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readHeaders = append(f.readHeaders, header(ctx, tok))
	return f.recent, f.recentErr
}

func (f *fakeMutClient) TargetState(ctx context.Context, _ executordb.PveRemote, _, _ string, _ uint64, tok pveapi.TokenSupplier) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readHeaders = append(f.readHeaders, header(ctx, tok))
	return f.liveNode, f.configDigest, nil
}

func (f *fakeMutClient) dispatchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dispatches)
}

// testUPIDAt is a well-formed UPID for vmid on node started at t.
func testUPIDAt(node string, t time.Time, vmid uint64, seq int) string {
	return fmt.Sprintf("UPID:%s:%08X:0000ABCD:%08X:qmstart:%d:nosact@pve!act:", node, 0x1000+seq, t.Unix(), vmid)
}

type pveMutEnv struct {
	t      *testing.T
	pe     *pveTestEnv
	auth   *permit.Authority
	client *fakeMutClient
	m      *PveMutations
	logs   *bytes.Buffer
}

func newPveMutEnv(t *testing.T, withAction bool) *pveMutEnv {
	t.Helper()
	pe := newPveTestEnv(t)
	chain := makeTestChain(t)
	pe.probe.result = probeResultFrom(chain, "pve1.example.test")
	if _, err := pe.add(t, mutRemote, pvecontract.KindCluster, pveEndpoints("pve1.example.test"), fpHex(chain.ca), []byte(mutReadToken)); err != nil {
		t.Fatal(err)
	}
	if withAction {
		if _, err := pe.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: mutRemote, Purpose: PvePurposeAction, Token: []byte(mutActionToken), By: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	e := &pveMutEnv{t: t, pe: pe, logs: &bytes.Buffer{}}
	e.restart()
	return e
}

// restart replaces the authority and engine as an executor restart does:
// permits are gone, the database and vault stay.
func (e *pveMutEnv) restart() {
	e.t.Helper()
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}, Counters: e.pe.db}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.auth, err = permit.New(permit.Options{Verifier: v, Store: e.pe.db, RiskPolicy: fixedRisk{}})
	if err != nil {
		e.t.Fatal(err)
	}
	if e.client == nil {
		e.client = &fakeMutClient{db: e.pe.db, liveNode: "pve1", configDigest: strings.Repeat("cd", 32)}
	}
	e.m = &PveMutations{DB: e.pe.db, Auth: e.auth, Vault: e.pe.vault, Client: e.client, PollInterval: time.Millisecond,
		MaxWait: 2 * time.Second, Log: slog.New(slog.NewTextHandler(e.logs, nil))}
}

func mutRequest(steps ...string) PveMutationRequest {
	var plan []PveMutationStep
	for _, s := range steps {
		plan = append(plan, PveMutationStep{Method: s, Args: json.RawMessage(`{"vmid":101}`)})
	}
	params, _ := json.Marshal(map[string]any{"steps": plan})
	return PveMutationRequest{RemoteID: mutRemote, Kind: permit.ProviderKindQemu, Node: "pve1", VMID: 101,
		ActionID: "pve.test.mutation", ModuleVersion: "1.0.0", Artifact: mutArtifact, Parameters: params}
}

var mutExecSeq int

// approve proposes req against the current target and approves it.
func (e *pveMutEnv) approve(req PveMutationRequest) PveMutationRequest {
	e.t.Helper()
	mutExecSeq++
	id := fmt.Sprintf("00000000-0000-4000-a000-%012d", mutExecSeq)
	rq, params, err := e.m.ProposalRequest(context.Background(), req, id, canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour))
	if err != nil {
		e.t.Fatal(err)
	}
	res, err := e.auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(res.Permit.Digest, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest = res.Permit.Digest
	return req
}

// noSecrets fails if a token appears in err, the logs or the job records.
func (e *pveMutEnv) noSecrets(err error, executionID string) {
	e.t.Helper()
	for _, secret := range []string{"readsecret0123456789", "actionsecret0123456789"} {
		if err != nil && strings.Contains(err.Error(), secret) {
			e.t.Fatalf("error carries a token: %v", err)
		}
		if strings.Contains(e.logs.String(), secret) {
			e.t.Fatal("log carries a token")
		}
		steps, _ := e.pe.db.PveJobSteps(executionID)
		if strings.Contains(fmt.Sprintf("%+v", steps), secret) {
			e.t.Fatal("job record carries a token")
		}
	}
}

func TestPveMutationUsesActionTokenOnly(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.config", "guest.start"))
	res, err := e.m.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.client.dispatches) != 2 {
		t.Fatalf("dispatches: %+v", e.client.dispatches)
	}
	for _, d := range e.client.dispatches {
		if d.header != "PVEAPIToken="+mutActionToken || d.node != "pve1" {
			t.Fatalf("dispatch used %q on %s", d.header, d.node)
		}
	}
	for _, h := range e.client.readHeaders {
		if h != "PVEAPIToken="+mutReadToken {
			t.Fatalf("observation used %q", h)
		}
	}
	if len(res.Steps) != 2 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[1].State != executordb.PveJobSucceeded {
		t.Fatalf("steps: %+v", res.Steps)
	}
	e.noSecrets(nil, res.ExecutionID)
}

func TestPveMutationReadOnlyRemoteIsRefused(t *testing.T) {
	e := newPveMutEnv(t, false)
	_, _, err := e.m.ProposalRequest(context.Background(), mutRequest("guest.start"), "00000000-0000-4000-a000-999999999999", canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour))
	if !errors.Is(err, ErrPveReadOnly) {
		t.Fatalf("proposal on read-only remote: %v", err)
	}
	if _, err := e.m.Run(context.Background(), mutRequest("guest.start")); !errors.Is(err, ErrPveReadOnly) {
		t.Fatalf("run on read-only remote: %v", err)
	}
	if e.client.dispatchCount() != 0 {
		t.Fatal("read-only remote dispatched")
	}
}

func TestPveMutationStoresIntentAndUPIDAroundDispatch(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.clone", "guest.config", "guest.start"))
	var seen []string
	e.client.onDispatch = func(n int, node string) (string, error) {
		steps, err := e.pe.db.PveJobSteps(e.execID(req))
		if err != nil || len(steps) != n {
			t.Errorf("step %d dispatched without its intent: %+v %v", n, steps, err)
			return "", errors.New("abort")
		}
		cur := steps[n-1]
		if cur.State != executordb.PveJobDispatching || cur.UPID != "" {
			t.Errorf("step %d intent state %s", n, cur.State)
		}
		for _, prev := range steps[:n-1] {
			if prev.UPID == "" || prev.State != executordb.PveJobSucceeded {
				t.Errorf("step %d dispatched before step %d had its UPID and succeeded: %+v", n, prev.Step, prev)
			}
		}
		upid := testUPIDAt(node, time.Now(), 101, n)
		seen = append(seen, upid)
		return upid, nil
	}
	e.client.status = func(upid string) (PveTaskStatus, error) {
		// The task is observed only after its UPID is durable.
		steps, _ := e.pe.db.PveJobSteps(e.execID(req))
		if steps[len(steps)-1].UPID != upid || steps[len(steps)-1].State != executordb.PveJobRunning {
			t.Errorf("task %s observed before its UPID was stored", upid)
		}
		return PveTaskStatus{ExitStatus: "OK"}, nil
	}
	res, err := e.m.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range res.Steps {
		if s.UPID != seen[i] || s.DispatchedAt.IsZero() {
			t.Fatalf("step %d: %+v", i+1, s)
		}
	}
}

// execID returns the execution ID the permit of req binds.
func (e *pveMutEnv) execID(req PveMutationRequest) string {
	e.t.Helper()
	open, _ := e.pe.db.OpenPveJobs()
	for _, j := range open {
		if j.Digest == fmt.Sprintf("%x", req.Digest[:]) {
			return j.ExecutionID
		}
	}
	e.t.Fatal("no job for the permit")
	return ""
}

func TestPveMutationRefusesChangedTarget(t *testing.T) {
	cases := map[string]func(*pveMutEnv){
		"guest moved":       func(e *pveMutEnv) { e.client.liveNode = "pve2" },
		"config changed":    func(e *pveMutEnv) { e.client.configDigest = strings.Repeat("00", 32) },
		"action rotated":    func(e *pveMutEnv) { e.rotateAction() },
		"remote blocked":    func(e *pveMutEnv) { _, _ = e.pe.db.BlockRemote(mutRemote, "test", "admin") },
		"vault locked":      func(e *pveMutEnv) { e.pe.vault.Lock() },
		"executor locked":   func(e *pveMutEnv) { e.auth.Lock("admin") },
		"executor restarts": func(e *pveMutEnv) { e.restart() },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			req := e.approve(mutRequest("guest.start"))
			change(e)
			_, err := e.m.Run(context.Background(), req)
			if err == nil {
				t.Fatal("changed target dispatched")
			}
			if e.client.dispatchCount() != 0 {
				t.Fatal("dispatch after change")
			}
			if open, _ := e.pe.db.OpenPveJobs(); len(open) != 0 {
				t.Fatalf("intent recorded for a refused mutation: %+v", open)
			}
		})
	}
}

func (e *pveMutEnv) rotateAction() {
	e.t.Helper()
	if _, err := e.pe.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: mutRemote, Purpose: PvePurposeAction, Token: []byte("nosact@pve!act=rotatedsecret"), By: "admin"}); err != nil {
		e.t.Fatal(err)
	}
}

func TestPveMutationPermitIsSingleUse(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start"))
	if _, err := e.m.Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("second run: %v", err)
	}
	if e.client.dispatchCount() != 1 {
		t.Fatalf("dispatches: %d", e.client.dispatchCount())
	}
}

func TestPveMutationLostResponseNeverRedispatches(t *testing.T) {
	cases := map[string]struct {
		recent    func(time.Time) []string
		want      error
		wantState string
	}{
		"no task found": {func(time.Time) []string { return nil }, ErrPveDispatchUncertain, executordb.PveJobUnknown},
		"two candidates": {func(at time.Time) []string {
			return []string{testUPIDAt("pve1", at, 101, 7), testUPIDAt("pve1", at, 101, 8)}
		}, ErrPveDispatchUncertain, executordb.PveJobUnknown},
		"other guest only": {func(at time.Time) []string { return []string{testUPIDAt("pve1", at, 999, 7)} }, ErrPveDispatchUncertain, executordb.PveJobUnknown},
		"stale task only": {func(at time.Time) []string {
			return []string{testUPIDAt("pve1", at.Add(-time.Hour), 101, 7)}
		}, ErrPveDispatchUncertain, executordb.PveJobUnknown},
		"exact task identified": {func(at time.Time) []string {
			return []string{testUPIDAt("pve1", at, 999, 6), testUPIDAt("pve1", at, 101, 7), "garbage"}
		}, nil, executordb.PveJobSucceeded},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			req := e.approve(mutRequest("guest.start"))
			// The transport fails after sending; the error text even echoes
			// the credential, which must never surface.
			e.client.onDispatch = func(int, string) (string, error) {
				e.client.mu.Lock()
				e.client.recent = c.recent(time.Now())
				e.client.mu.Unlock()
				return "", errors.New("read tcp: connection reset; Authorization: PVEAPIToken=" + mutActionToken)
			}
			res, err := e.m.Run(context.Background(), req)
			if !errors.Is(err, c.want) && !(c.want == nil && err == nil) {
				t.Fatalf("run: %v, want %v", err, c.want)
			}
			if len(res.Steps) != 1 || res.Steps[0].State != c.wantState {
				t.Fatalf("steps: %+v", res.Steps)
			}
			e.noSecrets(err, res.ExecutionID)
			// Reconciliation and a restart change nothing and never dispatch.
			e.restart()
			if err := e.m.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := e.m.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
				t.Fatalf("run after restart: %v", err)
			}
			if e.client.dispatchCount() != 1 {
				t.Fatalf("redispatched: %d", e.client.dispatchCount())
			}
		})
	}
}

func TestPveMutationTransientLookupFailureStaysReconciling(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start", "guest.resize"))
	e.client.recentErr = errors.New("unreachable")
	e.client.onDispatch = func(int, string) (string, error) { return "", errors.New("timeout") }
	res, err := e.m.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
	// After a restart the task becomes visible: it is adopted and observed,
	// and the job is not continued with its second step.
	e.restart()
	e.client.recentErr = nil
	e.client.recent = []string{testUPIDAt("pve1", time.Now(), 101, 3)}
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(res.ExecutionID)
	if len(steps) != 1 || steps[0].State != executordb.PveJobSucceeded || steps[0].UPID != e.client.recent[0] {
		t.Fatalf("steps after reconcile: %+v", steps)
	}
	if e.client.dispatchCount() != 1 {
		t.Fatalf("redispatched: %d", e.client.dispatchCount())
	}
}

func TestPveMutationRestartReconcilesRunningTask(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start", "guest.resize"))
	e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{Running: true}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res, err := e.m.Run(ctx, req)
	if !errors.Is(err, ErrPveStepRunning) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobRunning || res.Steps[0].UPID == "" {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
	upid := res.Steps[0].UPID
	// Restart: the vault locked again until the operator unlocks it.
	e.pe.vault.Lock()
	e.restart()
	if err := e.m.Reconcile(context.Background()); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("reconcile with locked vault: %v", err)
	}
	if err := e.pe.vault.Unlock([]byte(e.pe.passphrase)); err != nil {
		t.Fatal(err)
	}
	e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{ExitStatus: "OK"}, nil }
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(res.ExecutionID)
	if len(steps) != 1 || steps[0].State != executordb.PveJobSucceeded || steps[0].UPID != upid {
		t.Fatalf("steps: %+v", steps)
	}
	if last := e.client.statusQueried[len(e.client.statusQueried)-1]; last != upid {
		t.Fatalf("reconciled %s, want stored %s", last, upid)
	}
	if e.client.dispatchCount() != 1 {
		t.Fatalf("redispatched: %d", e.client.dispatchCount())
	}
}

func TestPveMutationRestartBeforeUPIDNeverRedispatches(t *testing.T) {
	e := newPveMutEnv(t, true)
	// A crash between the durable intent and the response leaves the step
	// in dispatching without a UPID.
	job := executordb.PveJob{ExecutionID: "00000000-0000-4000-a000-777777777777", Step: 1, Digest: strings.Repeat("a", 64),
		Action: "pve.test.mutation", RemoteID: mutRemote, TrustGeneration: 1, Kind: "qemu", Node: "pve1", VMID: 101,
		RequestDigest: strings.Repeat("b", 64)}
	if err := e.pe.db.CreatePveJobIntent(job); err != nil {
		t.Fatal(err)
	}
	e.restart()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, _, _ := e.pe.db.PveJob(job.ExecutionID, 1)
	if j.State != executordb.PveJobUnknown || e.client.dispatchCount() != 0 {
		t.Fatalf("job %+v, dispatches %d", j, e.client.dispatchCount())
	}
}

func TestPveMutationLockOrRevokeInFlightStopsNextStep(t *testing.T) {
	cases := map[string]func(*pveMutEnv){
		"lock":            func(e *pveMutEnv) { e.auth.Lock("admin") },
		"revoke remote":   func(e *pveMutEnv) { e.auth.RevokeProviderMutations(mutRemote, "admin") },
		"remote blocked":  func(e *pveMutEnv) { _, _ = e.pe.db.BlockRemote(mutRemote, "trust failure", "executor") },
		"action rotation": func(e *pveMutEnv) { e.rotateAction() },
	}
	for name, revoke := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			req := e.approve(mutRequest("guest.config", "guest.start"))
			once := sync.Once{}
			e.client.status = func(string) (PveTaskStatus, error) {
				once.Do(func() { revoke(e) })
				return PveTaskStatus{ExitStatus: "OK"}, nil
			}
			res, err := e.m.Run(context.Background(), req)
			if err == nil {
				t.Fatal("second step ran after " + name)
			}
			if e.client.dispatchCount() != 1 {
				t.Fatalf("dispatches: %d", e.client.dispatchCount())
			}
			// The accepted first task is still observed to completion.
			if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded {
				t.Fatalf("steps: %+v", res.Steps)
			}
		})
	}
}

func TestPveMutationRefusedOrFailedStepStopsJob(t *testing.T) {
	cases := map[string]func(*pveMutEnv){
		"refused": func(e *pveMutEnv) {
			e.client.onDispatch = func(int, string) (string, error) {
				return "", fmt.Errorf("403 forbidden for %s: %w", mutActionToken, ErrPveRejected)
			}
		},
		"task error": func(e *pveMutEnv) {
			e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{ExitStatus: "clone failed"}, nil }
		},
		"warnings are not success": func(e *pveMutEnv) {
			e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{ExitStatus: "WARNINGS: 1"}, nil }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			req := e.approve(mutRequest("guest.clone", "guest.start"))
			setup(e)
			res, err := e.m.Run(context.Background(), req)
			if !errors.Is(err, ErrPveStepFailed) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobFailed {
				t.Fatalf("run: %v %+v", err, res.Steps)
			}
			if e.client.dispatchCount() != 1 {
				t.Fatalf("dispatches: %d", e.client.dispatchCount())
			}
			e.noSecrets(err, res.ExecutionID)
		})
	}
}

func TestPveMutationMalformedUPIDIsReconciled(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start"))
	e.client.onDispatch = func(int, string) (string, error) { return "UPID:pve2:../../etc:", nil }
	res, err := e.m.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) || res.Steps[0].State != executordb.PveJobUnknown || res.Steps[0].UPID != "" {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
}

func TestPveMutationPlanComesFromApproval(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start"))
	// A caller cannot add steps: changed parameters do not match the permit.
	extra := mutRequest("guest.start", "guest.delete")
	extra.Digest = req.Digest
	if _, err := e.m.Run(context.Background(), extra); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("extra step: %v", err)
	}
	for _, bad := range []string{`{}`, `{"steps":[]}`, `{"steps":[{"method":"../x","args":{}}]}`, `{"steps":[{"method":"guest.start","args":[]}]}`} {
		r := mutRequest("guest.start")
		r.Parameters = json.RawMessage(bad)
		if _, _, err := e.m.ProposalRequest(context.Background(), r, "00000000-0000-4000-a000-888888888888", canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveMutationPlan) {
			t.Fatalf("plan %s: %v", bad, err)
		}
	}
	if e.client.dispatchCount() != 0 {
		t.Fatal("dispatched")
	}
}

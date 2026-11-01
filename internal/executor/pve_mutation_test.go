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
	return testTaskUPID(node, time.Now(), mutTaskTypes[step.Method], "101", mutActionUser, n), nil
}

// mutTaskTypes is the fake client's method allowlist and task types.
var mutTaskTypes = map[string]string{
	"guest.start": "qmstart", "guest.resize": "qmresize", "guest.config": "qmconfig",
	"guest.clone": "qmclone", "guest.delete": "qmdestroy", "node.update": "aptupdate",
}

func (f *fakeMutClient) TaskType(method string) (string, bool) {
	tt, ok := mutTaskTypes[method]
	return tt, ok
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

// mutActionUser is the token ID of mutActionToken, as PVE writes it into
// the UPIDs of the tasks it starts.
const mutActionUser = "nosact@pve!act"

// testUPIDAt is a well-formed qmstart UPID of the action token for vmid on
// node started at t.
func testUPIDAt(node string, t time.Time, vmid uint64, seq int) string {
	return testTaskUPID(node, t, "qmstart", fmt.Sprint(vmid), mutActionUser, seq)
}

// testTaskUPID is a well-formed UPID of a task of type typ on id, started
// by user on node at t.
func testTaskUPID(node string, t time.Time, typ, id, user string, seq int) string {
	return fmt.Sprintf("UPID:%s:%08X:0000ABCD:%08X:%s:%s:%s:", node, 0x1000+seq, t.Unix(), typ, id, user)
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
		e.client = &fakeMutClient{liveNode: "pve1", configDigest: strings.Repeat("cd", 32)}
	}
	e.m = &PveMutations{DB: e.pe.db, Auth: e.auth, Vault: e.pe.vault, Client: e.client, PollInterval: time.Millisecond,
		MaxWait: 2 * time.Second, Log: slog.New(slog.NewTextHandler(e.logs, nil))}
}

// passMatchWindow moves the engine clock past the start window of every
// step recorded so far, so an unidentified step can be declared unknown.
func (e *pveMutEnv) passMatchWindow() {
	later := time.Now().Add(pveTaskMatchWindow + pveTaskMatchSkew + time.Minute)
	e.m.Now = func() time.Time { return later }
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
	methods := []string{"guest.clone", "guest.config", "guest.start"}
	req := e.approve(mutRequest(methods...))
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
		upid := testTaskUPID(node, time.Now(), mutTaskTypes[methods[n-1]], "101", mutActionUser, n)
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
		"endpoints changed": func(e *pveMutEnv) { e.setEndpoints("pve1.example.test", "evil.example.test") },
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

// setEndpoints replaces the registry endpoints of the test remote.
func (e *pveMutEnv) setEndpoints(hosts ...string) {
	e.t.Helper()
	if _, err := e.pe.db.SetEndpoints(mutRemote, pveEndpoints(hosts...), "admin"); err != nil {
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
	// wantState is the state after Run; finalState the state after a
	// reconciliation once the task's start window has passed. A step
	// without a candidate stays reconciling while the window is open.
	cases := map[string]struct {
		recent     func(time.Time) []string
		want       error
		wantState  string
		finalState string
	}{
		"no task found": {func(time.Time) []string { return nil }, ErrPveDispatchUncertain, executordb.PveJobReconciling, executordb.PveJobUnknown},
		"two candidates": {func(at time.Time) []string {
			return []string{testUPIDAt("pve1", at, 101, 7), testUPIDAt("pve1", at, 101, 8)}
		}, ErrPveDispatchUncertain, executordb.PveJobUnknown, executordb.PveJobUnknown},
		"other guest only": {func(at time.Time) []string { return []string{testUPIDAt("pve1", at, 999, 7)} }, ErrPveDispatchUncertain, executordb.PveJobReconciling, executordb.PveJobUnknown},
		"stale task only": {func(at time.Time) []string {
			return []string{testUPIDAt("pve1", at.Add(-time.Hour), 101, 7)}
		}, ErrPveDispatchUncertain, executordb.PveJobReconciling, executordb.PveJobUnknown},
		"exact task identified": {func(at time.Time) []string {
			return []string{testUPIDAt("pve1", at, 999, 6), testUPIDAt("pve1", at, 101, 7), "garbage"}
		}, nil, executordb.PveJobSucceeded, executordb.PveJobSucceeded},
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
			// Reconciliation and a restart never dispatch; once the start
			// window has passed, an unidentified step is unknown.
			e.restart()
			if err := e.m.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1); j.State != c.wantState {
				t.Fatalf("job within the window: %+v", j)
			}
			e.passMatchWindow()
			if err := e.m.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1); j.State != c.finalState {
				t.Fatalf("job after the window: %+v", j)
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
		RequestDigest: strings.Repeat("b", 64), TaskType: "qmstart", TaskUser: mutActionUser}
	if err := e.pe.db.CreatePveJobIntent(job); err != nil {
		t.Fatal(err)
	}
	e.restart()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, _, _ := e.pe.db.PveJob(job.ExecutionID, 1)
	if j.State != executordb.PveJobReconciling || e.client.dispatchCount() != 0 {
		t.Fatalf("job within the window %+v, dispatches %d", j, e.client.dispatchCount())
	}
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, _, _ = e.pe.db.PveJob(job.ExecutionID, 1)
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
		"endpoints changed": func(e *pveMutEnv) {
			e.setEndpoints("evil.example.test")
		},
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
	if !errors.Is(err, ErrPveDispatchUncertain) || res.Steps[0].State != executordb.PveJobReconciling || res.Steps[0].UPID != "" {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1); j.State != executordb.PveJobUnknown || j.UPID != "" || e.client.dispatchCount() != 1 {
		t.Fatalf("job after the window: %+v", j)
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
	// A method the client does not allow has no task type to identify.
	r := mutRequest("guest.start", "guest.unknown")
	if _, _, err := e.m.ProposalRequest(context.Background(), r, "00000000-0000-4000-a000-888888888889", canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveMutationPlan) {
		t.Fatalf("unknown method: %v", err)
	}
}

func nodeRequest(steps ...string) PveMutationRequest {
	req := mutRequest(steps...)
	var plan []PveMutationStep
	for _, s := range steps {
		plan = append(plan, PveMutationStep{Method: s, Args: json.RawMessage(`{}`)})
	}
	req.Parameters, _ = json.Marshal(map[string]any{"steps": plan})
	req.Kind, req.VMID = permit.ProviderKindNode, 0
	return req
}

func TestPveMutationLostResponseNeverAdoptsForeignTask(t *testing.T) {
	cases := map[string]struct {
		req    PveMutationRequest
		lost   int // the step whose response is lost
		recent func(at time.Time, earlier []string) []string
	}{
		"earlier step's task": {mutRequest("guest.start", "guest.resize", "guest.config"), 2,
			func(_ time.Time, earlier []string) []string { return earlier }},
		"earlier step's task of the same type": {mutRequest("guest.config", "guest.config", "guest.start"), 2,
			func(_ time.Time, earlier []string) []string { return earlier }},
		"foreign backup of the guest": {mutRequest("guest.start"), 1, func(at time.Time, _ []string) []string {
			return []string{testTaskUPID("pve1", at, "vzdump", "101", "root@pam", 7)}
		}},
		"same task type by another user": {mutRequest("guest.start"), 1, func(at time.Time, _ []string) []string {
			return []string{testTaskUPID("pve1", at, "qmstart", "101", "root@pam", 7)}
		}},
		"same task type by the read token": {mutRequest("guest.start"), 1, func(at time.Time, _ []string) []string {
			return []string{testTaskUPID("pve1", at, "qmstart", "101", "nosread@pve!read", 7)}
		}},
		"node target with unrelated node tasks": {nodeRequest("node.update"), 1, func(at time.Time, _ []string) []string {
			return []string{testTaskUPID("pve1", at, "aptupdate", "", "root@pam", 7), testTaskUPID("pve1", at, "vncproxy", "", mutActionUser, 8)}
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			req := e.approve(c.req)
			var earlier []string
			e.client.onDispatch = func(n int, node string) (string, error) {
				if n < c.lost {
					steps, _ := parsePveSteps(c.req.Parameters)
					upid := testTaskUPID(node, time.Now(), mutTaskTypes[steps[n-1].Method], "101", mutActionUser, n)
					earlier = append(earlier, upid)
					return upid, nil
				}
				e.client.mu.Lock()
				e.client.recent = c.recent(time.Now(), earlier)
				e.client.mu.Unlock()
				return "", errors.New("connection reset")
			}
			res, err := e.m.Run(context.Background(), req)
			if !errors.Is(err, ErrPveDispatchUncertain) {
				t.Fatalf("run: %v", err)
			}
			if len(res.Steps) != c.lost || res.Steps[c.lost-1].State != executordb.PveJobReconciling || res.Steps[c.lost-1].UPID != "" {
				t.Fatalf("steps: %+v", res.Steps)
			}
			// No foreign task is adopted later either: once the window has
			// passed the step is unknown.
			e.passMatchWindow()
			if err := e.m.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if j, _, _ := e.pe.db.PveJob(res.ExecutionID, c.lost); j.State != executordb.PveJobUnknown || j.UPID != "" {
				t.Fatalf("job after the window: %+v", j)
			}
			if e.client.dispatchCount() != c.lost {
				t.Fatalf("a later step was dispatched: %d", e.client.dispatchCount())
			}
		})
	}
}

func TestPveMutationIdentifiesTaskBeyondManyCandidates(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start"))
	var want string
	e.client.onDispatch = func(int, string) (string, error) {
		at := time.Now()
		var recent []string
		for i := range 300 {
			recent = append(recent, testTaskUPID("pve1", at, "vzdump", fmt.Sprint(200+i), "root@pam", 100+i))
		}
		want = testUPIDAt("pve1", at, 101, 7)
		e.client.mu.Lock()
		e.client.recent = append(recent, want)
		e.client.mu.Unlock()
		return "", errors.New("connection reset")
	}
	res, err := e.m.Run(context.Background(), req)
	if err != nil || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[0].UPID != want {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
}

func TestPveMutationReconcileDuringDispatchLeavesStepAlone(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start", "guest.config"))
	e.client.onDispatch = func(n int, node string) (string, error) {
		// A concurrent reconciliation pass sees the step in dispatching
		// without a UPID; it must not take it over.
		if err := e.m.Reconcile(context.Background()); err != nil {
			t.Errorf("reconcile: %v", err)
		}
		steps := []string{"guest.start", "guest.config"}
		return testTaskUPID(node, time.Now(), mutTaskTypes[steps[n-1]], "101", mutActionUser, n), nil
	}
	res, err := e.m.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Steps) != 2 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[1].State != executordb.PveJobSucceeded {
		t.Fatalf("steps: %+v", res.Steps)
	}
	// Once Run returns, its open steps are Reconcile's again.
	req = e.approve(mutRequest("guest.start"))
	e.client.onDispatch = nil
	e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{Running: true}, nil }
	e.m.MaxWait = 10 * time.Millisecond
	res, err = e.m.Run(context.Background(), req)
	if !errors.Is(err, ErrPveStepRunning) {
		t.Fatalf("run: %v", err)
	}
	e.client.status = nil
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1); j.State != executordb.PveJobSucceeded {
		t.Fatalf("job after reconcile: %+v", j)
	}
}

func TestPveMutationTaskRecordGoneIsUnknown(t *testing.T) {
	gone := func(string) (PveTaskStatus, error) {
		return PveTaskStatus{}, fmt.Errorf("404 no such task: %w", ErrPveTaskNotFound)
	}
	t.Run("during run", func(t *testing.T) {
		e := newPveMutEnv(t, true)
		req := e.approve(mutRequest("guest.start", "guest.config"))
		e.client.status = gone
		res, err := e.m.Run(context.Background(), req)
		if !errors.Is(err, ErrPveDispatchUncertain) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobUnknown {
			t.Fatalf("run: %v %+v", err, res.Steps)
		}
		if e.client.dispatchCount() != 1 {
			t.Fatalf("dispatches: %d", e.client.dispatchCount())
		}
	})
	t.Run("during reconcile", func(t *testing.T) {
		e := newPveMutEnv(t, true)
		req := e.approve(mutRequest("guest.start"))
		e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{Running: true}, nil }
		e.m.MaxWait = 10 * time.Millisecond
		res, err := e.m.Run(context.Background(), req)
		if !errors.Is(err, ErrPveStepRunning) {
			t.Fatalf("run: %v", err)
		}
		e.restart()
		e.client.status = gone
		if err := e.m.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1); j.State != executordb.PveJobUnknown {
			t.Fatalf("job: %+v", j)
		}
		if open, _ := e.pe.db.OpenPveJobs(); len(open) != 0 {
			t.Fatalf("open: %+v", open)
		}
	})
	t.Run("transient error keeps the step open", func(t *testing.T) {
		e := newPveMutEnv(t, true)
		req := e.approve(mutRequest("guest.start"))
		e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{}, errors.New("unreachable") }
		e.m.MaxWait = 10 * time.Millisecond
		res, err := e.m.Run(context.Background(), req)
		if !errors.Is(err, ErrPveStepRunning) {
			t.Fatalf("run: %v", err)
		}
		e.restart()
		if err := e.m.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1); j.State != executordb.PveJobRunning {
			t.Fatalf("job: %+v", j)
		}
	})
}

func TestPveMutationWaitUsesInjectedClock(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start"))
	var mu sync.Mutex
	clock := time.Now()
	// Every reading of the clock is an hour later, so the wait bound has
	// passed after the first poll.
	e.m.Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(time.Hour)
		return clock
	}
	e.m.MaxWait = 10 * time.Minute
	e.client.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{Running: true}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := e.m.Run(ctx, req); !errors.Is(err, ErrPveStepRunning) {
		t.Fatalf("run: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the wait ignored the injected clock and ran until the context ended")
	}
	if n := len(e.client.statusQueried); n != 1 {
		t.Fatalf("polls: %d", n)
	}
}

// TestPveMutationLateTaskIsAdoptedWithinWindow: a lost response whose task
// is not yet listed stays reconciling, and the task is adopted once it
// appears inside the start window.
func TestPveMutationLateTaskIsAdoptedWithinWindow(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start"))
	e.client.onDispatch = func(int, string) (string, error) { return "", errors.New("client timeout") }
	res, err := e.m.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
	late := testUPIDAt("pve1", time.Now().Add(time.Minute), 101, 9)
	e.client.mu.Lock()
	e.client.recent = []string{late}
	e.client.mu.Unlock()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1)
	if j.State != executordb.PveJobSucceeded || j.UPID != late || e.client.dispatchCount() != 1 {
		t.Fatalf("job: %+v, dispatches %d", j, e.client.dispatchCount())
	}
}

// TestPveMutationSerializesPerTarget: while one mutation of a guest is
// open, another approved mutation of the same guest is not dispatched, so
// the first job's identification can never adopt the second job's task.
func TestPveMutationSerializesPerTarget(t *testing.T) {
	e := newPveMutEnv(t, true)
	a := e.approve(mutRequest("guest.start"))
	b := e.approve(mutRequest("guest.start"))
	e.client.onDispatch = func(int, string) (string, error) { return "", errors.New("connection reset") }
	resA, err := e.m.Run(context.Background(), a)
	if !errors.Is(err, ErrPveDispatchUncertain) || resA.Steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("run a: %v %+v", err, resA.Steps)
	}
	e.client.onDispatch = nil
	resB, err := e.m.Run(context.Background(), b)
	if !errors.Is(err, ErrPveTargetBusy) || len(resB.Steps) != 0 {
		t.Fatalf("run b: %v %+v", err, resB.Steps)
	}
	if e.client.dispatchCount() != 1 {
		t.Fatalf("dispatches: %d", e.client.dispatchCount())
	}
	// A's step is still reconciling and has adopted nothing.
	if j, _, _ := e.pe.db.PveJob(resA.ExecutionID, 1); j.State != executordb.PveJobReconciling || j.UPID != "" {
		t.Fatalf("job a: %+v", j)
	}
	// Another guest on the same remote is independent.
	other := mutRequest("guest.start")
	other.VMID = 102
	other = e.approve(other)
	e.client.onDispatch = func(n int, node string) (string, error) {
		return testTaskUPID(node, time.Now(), "qmstart", "102", mutActionUser, n), nil
	}
	if _, err := e.m.Run(context.Background(), other); err != nil {
		t.Fatalf("other guest: %v", err)
	}
	// Once A is terminal, the guest takes new mutations again.
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if j, _, _ := e.pe.db.PveJob(resA.ExecutionID, 1); j.State != executordb.PveJobUnknown {
		t.Fatalf("job a after the window: %+v", j)
	}
	e.m.Now = nil
	e.client.onDispatch = nil
	c := e.approve(mutRequest("guest.start"))
	if _, err := e.m.Run(context.Background(), c); err != nil {
		t.Fatalf("after a ended: %v", err)
	}
}

// TestPveMutationNineDigitPstartUPID: a node with more than about 497 days
// of uptime writes nine-digit pstart values; such a UPID is recorded on
// dispatch and identified after a lost response.
func TestPveMutationNineDigitPstartUPID(t *testing.T) {
	upidAt := func(at time.Time) string {
		return fmt.Sprintf("UPID:pve1:00001234:1ABCDEF01:%08X:qmstart:101:%s:", at.Unix(), mutActionUser)
	}
	t.Run("dispatch", func(t *testing.T) {
		e := newPveMutEnv(t, true)
		req := e.approve(mutRequest("guest.start"))
		var upid string
		e.client.onDispatch = func(int, string) (string, error) { upid = upidAt(time.Now()); return upid, nil }
		res, err := e.m.Run(context.Background(), req)
		if err != nil || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[0].UPID != upid {
			t.Fatalf("run: %v %+v", err, res.Steps)
		}
	})
	t.Run("identify", func(t *testing.T) {
		e := newPveMutEnv(t, true)
		req := e.approve(mutRequest("guest.start"))
		var upid string
		e.client.onDispatch = func(int, string) (string, error) {
			upid = upidAt(time.Now())
			e.client.mu.Lock()
			e.client.recent = []string{upid}
			e.client.mu.Unlock()
			return "", errors.New("connection reset")
		}
		res, err := e.m.Run(context.Background(), req)
		if err != nil || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[0].UPID != upid {
			t.Fatalf("run: %v %+v", err, res.Steps)
		}
	})
}

// TestPveMutationOpenStepSurvivesRepin: a step left open when the remote
// is blocked and re-pinned (trust generation bumped) is still reconciled
// through the new pin, read-only and bound to its stored task identity, so
// the guest is not blocked for new mutations forever.
func TestPveMutationOpenStepSurvivesRepin(t *testing.T) {
	cases := map[string]struct {
		visible   bool
		wantState string
	}{
		"task identified after re-pin": {true, executordb.PveJobSucceeded},
		"task never found":             {false, executordb.PveJobUnknown},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			req := e.approve(mutRequest("guest.start"))
			var upid string
			e.client.onDispatch = func(int, string) (string, error) {
				upid = testUPIDAt("pve1", time.Now(), 101, 9)
				return "", errors.New("connection reset")
			}
			res, err := e.m.Run(context.Background(), req)
			if !errors.Is(err, ErrPveDispatchUncertain) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
				t.Fatalf("run: %v %+v", err, res.Steps)
			}
			// Trust failure, then the documented recovery: re-pin.
			if _, err := e.pe.db.BlockRemote(mutRemote, "trust failure", "executor"); err != nil {
				t.Fatal(err)
			}
			rm, _, err := e.pe.db.GetRemote(mutRemote)
			if err != nil {
				t.Fatal(err)
			}
			rm, err = e.pe.db.RepinRemote(mutRemote, rm.TrustPin, fpHex(makeTestChain(t).ca), "admin")
			if err != nil {
				t.Fatal(err)
			}
			if rm.TrustGeneration != res.Steps[0].TrustGeneration+1 {
				t.Fatalf("generation %d, step %d", rm.TrustGeneration, res.Steps[0].TrustGeneration)
			}
			e.restart()
			e.client.onDispatch = nil
			if c.visible {
				e.client.recent = []string{testUPIDAt("pve1", time.Now(), 999, 8), upid}
			} else {
				e.passMatchWindow()
			}
			if err := e.m.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1)
			if j.State != c.wantState || (c.visible && j.UPID != upid) {
				t.Fatalf("job after re-pin: %+v", j)
			}
			if !strings.Contains(e.logs.String(), "pve_mutation_reconcile_repinned") {
				t.Fatal("generation change not audited")
			}
			if e.client.dispatchCount() != 1 {
				t.Fatalf("redispatched: %d", e.client.dispatchCount())
			}
			// The guest takes new mutations again.
			e.m.Now = nil
			next := e.approve(mutRequest("guest.start"))
			if _, err := e.m.Run(context.Background(), next); err != nil {
				t.Fatalf("after re-pin: %v", err)
			}
		})
	}
}

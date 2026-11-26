// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Durable fim.scan runs from a read lease (decisions (b)/(g) option 2,
// docs/implementation/integrity-wiring-decisions.md).

const (
	fimLeaseGrantID = "00000000-0000-4000-8000-0000000000f1"
	fimIncremental  = `{"mode":"incremental","profile":"fim-default-v1"}`
	// promptly bounds a lifecycle call that must not wait for a job.
	promptly = 5 * time.Second
)

// fimLeaseEnv is a read-lease environment whose host is a real (loopback)
// SSH server running /bin/sh, with an approved lease for fim.scan.
// The scan script runs against an empty NEBULA_FIM_TEST_ROOT (never the
// test machine) and is held at its first `id` call until release is called,
// so a test controls when the durable job ends.
type fimLeaseEnv struct {
	*reconcileEnv
	ssh     *testSSH
	gate    string
	client  pb.ExecutorServiceClient
	grantID string
}

func newFimLeaseEnv(t *testing.T, privateKeys bool) *fimLeaseEnv {
	t.Helper()
	e := newReconcileEnv(t)
	if privateKeys {
		e.usePrivateKeyring()
	}
	hk := mustReadSigner(t)
	e.pin(hk)
	srv := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)

	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth, err = permit.New(permit.Options{Mode: permit.ModeHardened, Verifier: v, Store: e.db, RiskPolicy: risk, Schedules: e.db, Leases: e.db, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	if err := e.db.TrustArtifact(executordb.TrustedArtifact{SHA256: permit.FimScanArtifactSHA256, ActionID: permit.FimScanActionID, ModuleVersion: permit.FimScanModuleVersion, Risk: canonical.RiskLow, TrustedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.SetHostCriticality(e.host, e.fp, canonical.RiskLow, "test"); err != nil {
		t.Fatal(err)
	}
	doc := permit.ReadGrantDoc{Grant: permit.ReadGrantFormat, ID: fimLeaseGrantID, Issuer: "test", CreatedUnix: e.clock.Now().Unix(),
		ExpiryUnix: e.clock.Now().Add(7 * 24 * time.Hour).Unix(), Trigger: permit.TriggerBoth, RateProfile: "ordinary", MinIntervalS: 900, RunBudget: 2,
		Actions: []permit.ReadGrantAction{{ActionID: permit.FimScanActionID, ModuleVersion: permit.FimScanModuleVersion,
			ArtifactSHA256: permit.FimScanArtifactSHA256, ParametersHash: permit.FimScanIncrementalParametersHash}},
		Targets:     []canonical.Target{{HostID: e.host, HostKeyFingerprint: e.fp}},
		Credentials: []permit.ReadGrantCredential{{HostID: e.host, CredentialRef: "cred", CredentialVersion: ssh.FingerprintSHA256(e.userPub)}}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	pg, err := e.svc.auth.ProposeReadGrant(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveReadGrantCLI(pg.Digest, "cli:test"); err != nil {
		t.Fatal(err)
	}

	// The gate: a fake `id` first in PATH waits (bounded) for the gate
	// file, then runs the real id. The SSH server's shells inherit the
	// environment, so the detached job does too.
	realID, err := exec.LookPath("id")
	if err != nil {
		t.Fatal(err)
	}
	gateDir := t.TempDir()
	gate := filepath.Join(gateDir, "release")
	bin := filepath.Join(gateDir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/sh\ni=0\nwhile [ ! -e '" + gate + "' ] && [ $i -lt 3000 ]; do sleep 0.02; i=$((i+1)); done\nexec '" + realID + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "id"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NEBULA_FIM_TEST_ROOT", t.TempDir())
	f := &fimLeaseEnv{reconcileEnv: e, ssh: srv, gate: gate, grantID: fimLeaseGrantID}
	// Cleanups run last-in first-out: the job is released before the
	// temporary directories go.
	t.Cleanup(f.release)
	f.client = readRPCClient(t, e.svc, peercred.RoleServer)
	return f
}

func (f *fimLeaseEnv) release() {
	if err := os.WriteFile(f.gate, nil, 0o600); err != nil && !errors.Is(err, os.ErrExist) {
		f.t.Errorf("release gate: %v", err)
	}
}

func (f *fimLeaseEnv) request(timeout time.Duration) *pb.RunReadGrantRequest {
	return &pb.RunReadGrantRequest{
		GrantId: f.grantID,
		Trigger: pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND,
		Run: &pb.AuthorizeRunRequest{HostId: f.host, HostKeyFingerprint: f.fp, ActionId: permit.FimScanActionID, ModuleVersion: permit.FimScanModuleVersion,
			Artifact: fimscan.Script, ParametersJson: []byte(fimIncremental), CredentialRef: "cred"},
		Endpoints:      []string{f.ssh.addr},
		TimeoutSeconds: uint32(timeout / time.Second),
	}
}

// within runs fn and fails the test if it does not return within promptly:
// a lifecycle call that waits for the durable job would block here.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(promptly):
		t.Fatalf("%s did not return within %s while the durable job runs", what, promptly)
	}
}

// jobState reads the state.json the wrapper keeps in the job directory.
func (f *fimLeaseEnv) jobState(id string) string {
	b, err := os.ReadFile(filepath.Join(f.jobs.JobRoot, id, "state.json"))
	if err != nil {
		return ""
	}
	return string(b)
}

// requireHeld checks that the job is stored on the host and has not ended.
func (f *fimLeaseEnv) requireHeld(id string) {
	f.t.Helper()
	if s := f.jobState(id); !strings.Contains(s, `"dispatched"`) && !strings.Contains(s, `"running"`) {
		f.t.Fatalf("job %s state %q, want dispatched or running", id, s)
	}
}

// waitJobFinished waits (bounded) until the host job wrote its final state,
// without the executor looking at it.
func (f *fimLeaseEnv) waitJobFinished(id string) {
	f.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(f.jobState(id), `"finished"`) {
		if time.Now().After(deadline) {
			f.t.Fatalf("job %s did not finish: %q", id, f.jobState(id))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// reconcileUntilFinished runs reconcile passes (bounded) until the run is
// closed and its collect has ended, and returns it.
func (f *fimLeaseEnv) reconcileUntilFinished(id string) executordb.Run {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	deadline := time.Now().Add(60 * time.Second)
	for {
		f.svc.ReconcileOnce(ctx)
		if r := f.getRun(id); r.State == executordb.RunFinished && !f.svc.isCollecting(id+"/"+f.host) {
			return r
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("run %s not closed by reconcile: %+v", id, f.getRun(id))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startHeldScan starts one fim.scan run with the action's own 40 minute
// timeout and checks that it came back as a started durable job while the
// job is still held on the host.
func (f *fimLeaseEnv) startHeldScan(ctx context.Context) string {
	f.t.Helper()
	resp, err := f.client.RunReadGrant(ctx, f.request(40*time.Minute))
	if err != nil {
		f.t.Fatalf("fim.scan read: %v", err)
	}
	id := resp.GetExecutionId()
	if id == "" {
		f.t.Fatal("no execution ID")
	}
	res := resp.GetResult()
	if res.GetClass() != "" || len(res.GetResult()) != 0 || len(res.GetLog()) != 0 || !strings.Contains(res.GetDetail(), "durable job") {
		f.t.Fatalf("durable start response carries more than class and status: %v", res)
	}
	run := f.getRun(id)
	if run.ActionID != permit.FimScanActionID || run.Timeout != 40*time.Minute || run.State == executordb.RunFinished ||
		run.Digest != "grant:"+f.grantID || run.Endpoint != f.ssh.addr {
		f.t.Fatalf("durable run record: %+v", run)
	}
	f.requireHeld(id)
	return id
}

// requireScanCollected checks the run's outcome after the reconciler read
// the result with the fim.scan limit: class and status are kept, the
// document is not.
func (f *fimLeaseEnv) requireScanCollected(ctx context.Context, run executordb.Run) {
	f.t.Helper()
	if run.Class != hostrun.ClassSuccess || run.ExitCode != 0 || len(run.Result) != 0 {
		f.t.Fatalf("collected fim.scan run: class %q exit %d detail %q result %d bytes; log %q", run.Class, run.ExitCode, run.Detail, len(run.Result), run.Log)
	}
	got, err := f.client.GetRun(ctx, &pb.GetRunRequest{ExecutionId: run.ExecutionID, HostId: f.host})
	if err != nil || got.GetRun().GetClass() != hostrun.ClassSuccess || len(got.GetRun().GetResult()) != 0 {
		f.t.Fatalf("GetRun: %v %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(f.jobs.JobRoot, run.ExecutionID)); !errors.Is(err, os.ErrNotExist) {
		f.t.Fatalf("job directory kept after collect: %v", err)
	}
}

func TestFimScanLeaseRunsAsDurableJobOutsideReadGuard(t *testing.T) {
	f := newFimLeaseEnv(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// RunReadGrant returns while the job is held on the host: the read
	// does not wait for the job.
	id := f.startHeldScan(ctx)

	// While the job runs, the authority answers at once, and the
	// reservation of the durable run counts against interval and budget.
	run := permit.Run{HostID: f.host, HostKeyFingerprint: f.fp, ActionID: permit.FimScanActionID, ModuleVersion: permit.FimScanModuleVersion,
		Artifact: fimscan.Script, ParametersJSON: []byte(fimIncremental), CredentialRef: "cred", CredentialVersion: ssh.FingerprintSHA256(f.userPub)}
	within(t, "AuthorizeReadRun", func() {
		if _, err := f.svc.auth.AuthorizeReadRun(f.grantID, newTestUUID(), permit.TriggerOnDemand, run); permit.CodeOf(err) != permit.CodeLeaseBudget {
			t.Errorf("second authorization during the job: %v, want %s", err, permit.CodeLeaseBudget)
		}
	})
	within(t, "RunReadGrant", func() {
		if _, err := f.client.RunReadGrant(ctx, f.request(40*time.Minute)); status.Code(err) != codes.ResourceExhausted {
			t.Errorf("second read during the job: %v, want ResourceExhausted", err)
		}
	})
	f.requireHeld(id)

	f.release()
	f.requireScanCollected(ctx, f.reconcileUntilFinished(id))
	if got := len(f.logs.find("run_dispatched", id)); got != 1 {
		t.Fatalf("run_dispatched audit records = %d, want 1", got)
	}
	// The read that started the job has its own scheduled-read record.
	recs := f.logs.find("read_dispatched_durable", id)
	if len(recs) != 1 || recs[0].attrs["digest"] != "grant:"+f.grantID || recs[0].attrs["endpoint"] != f.ssh.addr {
		t.Fatalf("read_dispatched_durable audit records: %+v", recs)
	}
}

// TestFimScanLeaseRevocationDuringDurableJob: a revocation returns at once
// while the job runs and stops every further run. The running job is not
// cancelled: it runs to its end and the reconciler collects its outcome,
// which is used normally (ADR 0007, decision note 2026-11-26, option (a)).
func TestFimScanLeaseRevocationDuringDurableJob(t *testing.T) {
	f := newFimLeaseEnv(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id := f.startHeldScan(ctx)
	within(t, "RevokeReadGrant", func() {
		if _, err := f.client.RevokeReadGrant(ctx, &pb.RevokeReadGrantRequest{GrantId: f.grantID}); err != nil {
			t.Errorf("revoke: %v", err)
		}
	})
	f.clock.Add(2 * time.Hour) // past interval and budget: only the revocation refuses
	if _, err := f.client.RunReadGrant(ctx, f.request(40*time.Minute)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("read after revocation: %v, want PermissionDenied", err)
	}
	f.requireHeld(id)
	f.release()
	f.requireScanCollected(ctx, f.reconcileUntilFinished(id))
}

// TestFimScanLeaseLockDuringDurableJob: Lock returns at once while the job
// runs and pauses every further run. The running job is not cancelled; its
// outcome is collected once the keyring is unlocked again (ADR 0007,
// decision note 2026-11-26, option (a)).
func TestFimScanLeaseLockDuringDurableJob(t *testing.T) {
	f := newFimLeaseEnv(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id := f.startHeldScan(ctx)
	within(t, "Lock", func() {
		if _, err := f.client.Lock(ctx, &pb.LockRequest{}); err != nil {
			t.Errorf("lock: %v", err)
		}
	})
	f.clock.Add(2 * time.Hour)
	if _, err := f.client.RunReadGrant(ctx, f.request(40*time.Minute)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("read while locked: %v, want FailedPrecondition", err)
	}
	f.requireHeld(id)
	f.release()
	f.waitJobFinished(id)
	f.svc.ReconcileOnce(ctx)
	f.requireOpen(id) // locked: the reconciler does not touch the host
	if _, err := f.svc.keys.Unlock([]byte(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	f.requireScanCollected(ctx, f.reconcileUntilFinished(id))
}

// TestFimScanLeaseUnreachableHostSpendsReservation: the durable branch
// reserves like an attached read. A run whose host cannot be reached still
// uses its interval slot and stores no run.
func TestFimScanLeaseUnreachableHostSpendsReservation(t *testing.T) {
	f := newFimLeaseEnv(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := f.request(40 * time.Minute)
	r.Endpoints = []string{closedAddr(t)}
	one, err := f.client.RunReadGrant(ctx, r)
	if err != nil || one.GetResult().GetClass() != classNetworkUnreachable {
		t.Fatalf("unreachable read: %v %v", one, err)
	}
	if _, err := f.db.GetRun(one.GetExecutionId(), f.host); !errors.Is(err, executordb.ErrNoRun) {
		t.Fatalf("a run was stored for a job never sent: %v", err)
	}
	if _, err := f.client.RunReadGrant(ctx, r); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("interval not spent by the durable branch: %v", err)
	}
	// The fim.scan floor (1 h) lies above the lease's 15 min interval.
	f.clock.Add(30 * time.Minute)
	if _, err := f.client.RunReadGrant(ctx, r); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("fim.scan floor not applied: %v", err)
	}
	f.clock.Add(31 * time.Minute)
	if _, err := f.client.RunReadGrant(ctx, r); err != nil {
		t.Fatalf("read after the floor: %v", err)
	}
}

// stallResult replaces the finished job's result.json with a FIFO that no
// one writes, so a collect blocks in its result read. The returned restore
// (also run at cleanup) unblocks every reader and puts the result back.
func (f *fimLeaseEnv) stallResult(id string) func() {
	f.t.Helper()
	res := filepath.Join(f.jobs.JobRoot, id, "result.json")
	if err := os.Rename(res, res+".held"); err != nil {
		f.t.Fatal(err)
	}
	if err := syscall.Mkfifo(res, 0o600); err != nil {
		f.t.Fatal(err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			// Opening the FIFO for writing and closing it gives every
			// blocked reader EOF.
			if w, err := os.OpenFile(res, os.O_RDWR, 0); err == nil {
				_ = w.Close()
			}
			_ = os.Remove(res)
			if err := os.Rename(res+".held", res); err != nil && !errors.Is(err, os.ErrNotExist) {
				f.t.Errorf("restore result: %v", err)
			}
		})
	}
	f.t.Cleanup(restore)
	return restore
}

// waitLogs waits (bounded) until at least n audit records of kind exist for
// the execution.
func (f *fimLeaseEnv) waitLogs(kind, id string, n int) {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for len(f.logs.find(kind, id)) < n {
		if time.Now().After(deadline) {
			f.t.Fatalf("%d %s audit records for %s, want %d", len(f.logs.find(kind, id)), kind, id, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitCollectEnded waits (bounded) until no collect of the run is in flight.
func (f *fimLeaseEnv) waitCollectEnded(id string) {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for f.svc.isCollecting(id + "/" + f.host) {
		if time.Now().After(deadline) {
			f.t.Fatalf("collect of %s still in flight", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// finishedScan starts a fim.scan run and lets its job finish on the host,
// without the executor looking at it.
func (f *fimLeaseEnv) finishedScan(ctx context.Context) string {
	f.t.Helper()
	id := f.startHeldScan(ctx)
	f.release()
	f.waitJobFinished(id)
	return id
}

// TestFimScanCollectAbortedAtLockResumesAfterUnlock: a Lock aborts a
// collect in progress at once and no collect touches the host while
// locked; the run stays open (not failed) and is collected normally after
// unlock (ADR 0007, decision note 2026-11-26).
func TestFimScanCollectAbortedAtLockResumesAfterUnlock(t *testing.T) {
	f := newFimLeaseEnv(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id := f.finishedScan(ctx)
	restore := f.stallResult(id)

	f.svc.ReconcileOnce(ctx)
	f.waitLogs("reconcile_collect_started", id, 1)
	within(t, "Lock", func() {
		if _, err := f.client.Lock(ctx, &pb.LockRequest{}); err != nil {
			t.Errorf("lock: %v", err)
		}
	})
	f.waitCollectEnded(id)
	f.requireOpen(id)
	f.waitLogs("reconcile_collect_paused", id, 1)
	if n := len(f.logs.find("reconcile_collect_failed", id)); n != 0 {
		t.Fatalf("a Lock abort counted as a failed collect (%d)", n)
	}
	if _, err := os.Stat(filepath.Join(f.jobs.JobRoot, id)); err != nil {
		t.Fatalf("job directory gone after an aborted collect: %v", err)
	}

	// While locked no pass starts a collect.
	f.svc.ReconcileOnce(ctx)
	if n := len(f.logs.find("reconcile_collect_started", id)); n != 1 || f.svc.isCollecting(id+"/"+f.host) {
		t.Fatalf("a collect started while locked (%d started)", n)
	}
	f.requireOpen(id)

	restore()
	if _, err := f.svc.keys.Unlock([]byte(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	f.requireScanCollected(ctx, f.reconcileUntilFinished(id))
	if n := len(f.logs.find("reconcile_collect_started", id)); n != 2 {
		t.Fatalf("collect starts = %d, want 2 (aborted, resumed)", n)
	}
}

// TestFimScanCollectTimeLimitAndAttemptCap: a host that never delivers its
// result neither holds reconcileMu nor the pass over other runs; each
// collect ends at its time limit, and after maxFimCollectAttempts failed
// collects the run is closed as collect_failed and audited.
func TestFimScanCollectTimeLimitAndAttemptCap(t *testing.T) {
	f := newFimLeaseEnv(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id := f.finishedScan(ctx)
	f.stallResult(id)

	for i := 1; i <= maxFimCollectAttempts; i++ {
		within(t, "ReconcileOnce", func() { f.svc.ReconcileOnce(ctx) })
		f.waitLogs("reconcile_collect_started", id, i)
		// The stalled collect holds no reconciliation lock.
		if !f.svc.reconcileMu.TryLock() {
			t.Fatal("reconcileMu held by a stalled collect")
		}
		f.svc.reconcileMu.Unlock()
		// A second pass during the collect starts no second one.
		within(t, "ReconcileOnce", func() { f.svc.ReconcileOnce(ctx) })
		if n := len(f.logs.find("reconcile_collect_started", id)); n != i {
			t.Fatalf("collect starts = %d during attempt %d", n, i)
		}
		f.clock.Add(fimCollectTimeout + time.Minute)
		f.waitCollectEnded(id)
		if i < maxFimCollectAttempts {
			f.requireOpen(id)
			if n := len(f.logs.find("reconcile_collect_failed", id)); n != i {
				t.Fatalf("reconcile_collect_failed records = %d after attempt %d", n, i)
			}
		}
	}
	run := f.getRun(id)
	if run.State != executordb.RunFinished || run.Class != classCollectFailed || run.ExitCode != -1 ||
		!strings.Contains(run.Detail, "3 attempts") || !strings.Contains(run.Detail, "did not finish within") {
		t.Fatalf("capped run: %+v", run)
	}
	if n := len(f.logs.find("reconcile_collect_gave_up", id)); n != 1 {
		t.Fatalf("reconcile_collect_gave_up records = %d, want 1", n)
	}
	if recs := f.logs.find("run_finished", id); len(recs) != 1 || recs[0].attrs["class"] != classCollectFailed {
		t.Fatalf("run_finished audit: %+v", recs)
	}
	// Closed: no further pass collects it.
	f.svc.ReconcileOnce(ctx)
	if n := len(f.logs.find("reconcile_collect_started", id)); n != maxFimCollectAttempts {
		t.Fatalf("collect starts = %d after the cap", n)
	}
}

// holdProxy forwards loopback TCP to target, but holds each connection
// after accepting it until release: the client is then inside Connect,
// after the read was authorized and before the dispatch guard.
type holdProxy struct {
	addr     string
	accepted chan struct{}
	release  func()
}

func startHoldProxy(t *testing.T, target string) *holdProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	var once sync.Once
	p := &holdProxy{addr: ln.Addr().String(), accepted: make(chan struct{}, 1), release: func() { once.Do(func() { close(gate) }) }}
	t.Cleanup(func() { p.release(); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				select {
				case p.accepted <- struct{}{}:
				default:
				}
				<-gate
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, conn); _ = up.Close() }()
				_, _ = io.Copy(conn, up)
			}()
		}
	}()
	return p
}

// TestFimScanLeaseRevokeOrLockBeforeDispatchGuard: a revocation or a Lock
// that lands after the read was authorized and while it connects (before
// the dispatch guard) stops it: no run is stored and no job reaches the
// host.
func TestFimScanLeaseRevokeOrLockBeforeDispatchGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(ctx context.Context, f *fimLeaseEnv) error
	}{
		{"revocation", func(ctx context.Context, f *fimLeaseEnv) error {
			_, err := f.client.RevokeReadGrant(ctx, &pb.RevokeReadGrantRequest{GrantId: f.grantID})
			return err
		}},
		{"lock", func(ctx context.Context, f *fimLeaseEnv) error {
			_, err := f.client.Lock(ctx, &pb.LockRequest{})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFimLeaseEnv(t, tc.name == "lock")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			p := startHoldProxy(t, f.ssh.addr)
			req := f.request(40 * time.Minute)
			req.Endpoints = []string{p.addr}
			type result struct {
				resp *pb.RunReadGrantResponse
				err  error
			}
			done := make(chan result, 1)
			go func() {
				resp, err := f.client.RunReadGrant(ctx, req)
				done <- result{resp, err}
			}()
			select {
			case <-p.accepted:
			case <-time.After(30 * time.Second):
				t.Fatal("the read never connected")
			}
			within(t, tc.name, func() {
				if err := tc.stop(ctx, f); err != nil {
					t.Errorf("%s: %v", tc.name, err)
				}
			})
			p.release()
			var got result
			select {
			case got = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("the read did not return")
			}
			if got.err == nil && got.resp.GetResult().GetClass() == "" {
				t.Fatalf("read dispatched after %s: %v", tc.name, got.resp)
			}
			runs, err := f.db.OpenRuns()
			if err != nil {
				t.Fatal(err)
			}
			if len(runs) != 0 {
				t.Fatalf("runs stored after %s: %+v", tc.name, runs)
			}
			if id := got.resp.GetExecutionId(); id != "" {
				if _, err := f.db.GetRun(id, f.host); !errors.Is(err, executordb.ErrNoRun) {
					t.Fatalf("run stored after %s: %v", tc.name, err)
				}
			}
			if entries, err := os.ReadDir(f.jobs.JobRoot); err == nil && len(entries) != 0 {
				t.Fatalf("a job reached the host after %s: %v", tc.name, entries)
			}
			for _, kind := range []string{"run_dispatching", "run_dispatched", "read_dispatched_durable"} {
				if n := len(f.logs.find(kind, "")); n != 0 {
					t.Fatalf("%d %s audit records after %s", n, kind, tc.name)
				}
			}
		})
	}
}

// TestDurableReadRefusalNamesCause: the refusal of a durable read names its
// actual cause; only a failed run record is reported as such.
func TestDurableReadRefusalNamesCause(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		notRecorded bool
		class       string
		detail      string
	}{
		{"authority", &permit.Error{Code: permit.CodeLeaseBudget}, false, "read_denied", "read authority changed before dispatch"},
		{"not recorded", status.Error(codes.Unavailable, "storage_error: x"), true, classNotExecuted, "the read could not be recorded"},
		{"store error in recheck", status.Error(codes.Unavailable, "storage_error: host key"), false, classNotExecuted, "the read was not dispatched: storage_error: host key"},
		{"pin changed", status.Error(codes.PermissionDenied, "read target pin changed before dispatch"), false, "read_denied", "read target pin changed before dispatch"},
		{"canceled", status.Error(codes.Canceled, "read canceled before dispatch"), false, classNotExecuted, "the read was not dispatched: read canceled before dispatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class, detail := durableReadRefusal(tc.err, tc.notRecorded)
			if class != tc.class || detail != tc.detail {
				t.Fatalf("got %q %q, want %q %q", class, detail, tc.class, tc.detail)
			}
		})
	}
}

// TestReadPathTimeoutAndDurableLimits: only fim.scan may ask for more than
// the attached limit, and only up to its own 40 minutes; any other durable
// catalog action is refused on the read path. Every refusal comes before the
// authority, so no reservation is spent (the authority here has no leases
// and would answer otherwise).
func TestReadPathTimeoutAndDurableLimits(t *testing.T) {
	e := newReconcileEnv(t)
	for _, tc := range []struct {
		name    string
		action  string
		timeout time.Duration
	}{
		{"attached above 10 min", "core.facts", hostrun.MaxTimeout + time.Second},
		{"fim.scan above its own limit", permit.FimScanActionID, 40*time.Minute + time.Second},
		{"fim.scan above the durable maximum", permit.FimScanActionID, hostrun.MaxDurableTimeout + time.Second},
		{"other durable action", "docker.update_preview", time.Minute},
		{"other durable action without timeout", "package.install_security", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := validReadRPCRequest()
			req.Run.ActionId = tc.action
			req.TimeoutSeconds = uint32(tc.timeout / time.Second)
			if _, err := e.svc.RunReadGrant(context.Background(), req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("RunReadGrant: %v, want InvalidArgument", err)
			}
			sched := &pb.RunScheduledRequest{GrantId: req.GrantId, Run: req.Run, Endpoints: req.Endpoints, TimeoutSeconds: req.TimeoutSeconds}
			if _, err := e.svc.RunRead(context.Background(), permit.TriggerOnDemand, sched); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("RunRead: %v, want InvalidArgument", err)
			}
		})
	}
	// At the limits the requests pass the checks and reach the authority.
	for _, tc := range []struct {
		action  string
		timeout time.Duration
	}{{"core.facts", hostrun.MaxTimeout}, {permit.FimScanActionID, 40 * time.Minute}} {
		req := validReadRPCRequest()
		req.Run.ActionId = tc.action
		req.TimeoutSeconds = uint32(tc.timeout / time.Second)
		if _, err := e.svc.RunReadGrant(context.Background(), req); status.Code(err) == codes.InvalidArgument {
			t.Fatalf("%s at %s refused as invalid: %v", tc.action, tc.timeout, err)
		}
	}
}

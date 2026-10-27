// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Test SSH server modes (issue #70).
const (
	sshModeNormal = int32(0) // exec requests run with /bin/sh, like a host
	sshModeReject = int32(1) // authenticates fine, rejects every session channel
)

// testSSH is an in-process SSH server for the reconcile tests. It counts
// accepted connections so backoff behaviour is observable, and can switch
// between serving sessions and rejecting every session channel.
type testSSH struct {
	addr    string
	hostKey ssh.Signer
	mode    atomic.Int32
	conns   atomic.Int64
	mu      sync.Mutex
	cmds    []string
}

func startTestSSH(t *testing.T, user ssh.PublicKey, mode int32) *testSSH {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(user.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSH{addr: ln.Addr().String(), hostKey: hk}
	s.mode.Store(mode)
	var wg sync.WaitGroup
	var conns sync.Map
	t.Cleanup(func() {
		_ = ln.Close()
		conns.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			conns.Store(c, true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.serve(c, cfg)
			}()
		}
	}()
	return s
}

func (s *testSSH) setMode(m int32)      { s.mode.Store(m) }
func (s *testSSH) connections() int64   { return s.conns.Load() }
func (s *testSSH) commands() []string   { s.mu.Lock(); defer s.mu.Unlock(); return append([]string(nil), s.cmds...) }
func (s *testSSH) recordCommand(c string) { s.mu.Lock(); s.cmds = append(s.cmds, c); s.mu.Unlock() }

func (s *testSSH) serve(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		if s.mode.Load() == sshModeReject {
			_ = nc.Reject(ssh.Prohibited, "no sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, creqs)
	}
}

func (s *testSSH) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	var cmd *exec.Cmd
	var once sync.Once
	finished := make(chan struct{})
	for r := range reqs {
		switch r.Type {
		case "exec":
			if len(r.Payload) < 4 {
				_ = r.Reply(false, nil)
				continue
			}
			n := binary.BigEndian.Uint32(r.Payload)
			line := string(r.Payload[4 : 4+n])
			s.recordCommand(line)
			cmd = exec.Command("/bin/sh", "-c", line)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				_ = r.Reply(false, nil)
				return
			}
			_ = r.Reply(true, nil)
			go func() {
				err := cmd.Wait()
				status := 0
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
						msg := ssh.Marshal(struct {
							Signal     string
							CoreDumped bool
							Error      string
							Lang       string
						}{Signal: "KILL"})
						_, _ = ch.SendRequest("exit-signal", false, msg)
						once.Do(func() { close(finished) })
						_ = ch.Close()
						return
					}
					status = ee.ExitCode()
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
				once.Do(func() { close(finished) })
				_ = ch.Close()
			}()
		case "signal":
			if cmd != nil && cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		default:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
	if cmd != nil && cmd.Process != nil {
		select {
		case <-finished:
		default:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	_, _ = io.Copy(io.Discard, ch)
}

// closedAddr returns a loopback address with nothing listening on it.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// fakeClock is the injected service clock for the reconcile tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *fakeClock) Add(d time.Duration) { c.Set(c.Now().Add(d)) }

// logRecord is one captured slog record.
type logRecord struct {
	msg   string
	attrs map[string]any
}

// logBuffer captures log records so tests can assert on audit entries.
type logBuffer struct {
	mu      sync.Mutex
	records []logRecord
}

func (b *logBuffer) Enabled(context.Context, slog.Level) bool { return true }

func (b *logBuffer) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{msg: r.Message, attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool { rec.attrs[a.Key] = a.Value.Any(); return true })
	b.mu.Lock()
	b.records = append(b.records, rec)
	b.mu.Unlock()
	return nil
}

func (b *logBuffer) WithAttrs([]slog.Attr) slog.Handler { return b }
func (b *logBuffer) WithGroup(string) slog.Handler      { return b }

// find returns the records whose attrs contain kind=kind and (when
// execution != "") execution=execution.
func (b *logBuffer) find(kind, execution string) []logRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []logRecord
	for _, r := range b.records {
		if r.attrs["kind"] != kind {
			continue
		}
		if execution != "" && r.attrs["execution"] != execution {
			continue
		}
		out = append(out, r)
	}
	return out
}

// reconcileEnv is a self-contained executor environment: real executor DB,
// a real keyring with one passphrase-protected key, a real permit
// authority, and a Service with an injected clock.
type reconcileEnv struct {
	t        *testing.T
	svc      *Service
	db       *executordb.DB
	logs     *logBuffer
	clock    *fakeClock
	userPub  ssh.PublicKey
	host     string
	fp       string
	jobs     hostrun.JobConfig
	bootFile string
}

const testPassphrase = "reconcile-test-passphrase-0123456789"

func newReconcileEnv(t *testing.T) *reconcileEnv {
	t.Helper()
	dir := t.TempDir()
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "cred.key"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	kr := keyring.New(keysDir)
	if _, err := kr.Unlock([]byte(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	userPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	clk := &fakeClock{t: time.Now()}
	verifier, err := webauthnverify.New(webauthnverify.Config{
		RPID:    "reconcile.test",
		Origins: []string{"https://reconcile.test"},
		Counters: db,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{
		Verifier:   verifier,
		Store:      db,
		RiskPolicy: risk,
		Now:        clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{
		RPID:    "reconcile.test",
		Origins: []string{"https://reconcile.test"},
		Now:     clk.Now,
	}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}

	logs := &logBuffer{}
	svc := NewService(auth, kr, db, reg, slog.New(logs))
	svc.Now = clk.Now
	jobs := hostrun.JobConfig{
		Sudo:         false,
		JobRoot:      filepath.Join(dir, "jobs"),
		RunRoot:      filepath.Join(dir, "run"),
		Systemd:      false,
		BootIDFile:   filepath.Join(dir, "bootid"),
		RequireTmpfs: false,
	}
	svc.SetJobConfig(jobs)
	// The reconcile interval the production loop uses; ReconcileOnce in
	// tests relies on it for backoff.
	svc.reconcileInterval = 75 * time.Second

	e := &reconcileEnv{
		t:        t,
		svc:      svc,
		db:       db,
		logs:     logs,
		clock:    clk,
		userPub:  userPub,
		host:     "reconcile-host",
		jobs:     jobs,
		bootFile: jobs.BootIDFile,
	}
	return e
}

// pin stores the host key for e.host and remembers the fingerprint.
func (e *reconcileEnv) pin(hostKey ssh.Signer) {
	e.t.Helper()
	pk, err := ssh.NewPublicKey(hostKey.PublicKey())
	if err != nil {
		e.t.Fatal(err)
	}
	pin, err := e.db.PinHostKey(executordb.HostKey{
		HostID:        e.host,
		PublicKey:     pk.Marshal(),
		User:          "test",
		CredentialRef: "cred",
		Source:        executordb.SourceProbe,
		PinnedBy:      "test",
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.fp = pin.Fingerprint
}

// createRun stores a fresh open run for e.host and returns its execution ID.
func (e *reconcileEnv) createRun(endpoint string, timeout time.Duration) string {
	e.t.Helper()
	id := newTestUUID()
	if err := e.db.CreateRun(executordb.Run{
		ExecutionID: id,
		HostID:      e.host,
		Digest:      "reconcile-test-digest",
		Endpoints:   []string{endpoint},
		Fingerprint: e.fp,
		Timeout:     timeout,
	}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func newTestUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (e *reconcileEnv) getRun(id string) executordb.Run {
	e.t.Helper()
	r, err := e.db.GetRun(id, e.host)
	if err != nil {
		e.t.Fatalf("get run: %v", err)
	}
	return r
}

func (e *reconcileEnv) requireOpen(id string) {
	e.t.Helper()
	r := e.getRun(id)
	if r.State == executordb.RunFinished {
		e.t.Fatalf("run %s is finished (class %q), want open", id, r.Class)
	}
}

func (e *reconcileEnv) requireFinished(id, class string) executordb.Run {
	e.t.Helper()
	r := e.getRun(id)
	if r.State != executordb.RunFinished {
		e.t.Fatalf("run %s is not finished (state %q)", id, r.State)
	}
	if r.Class != class {
		e.t.Fatalf("run %s class = %q, want %q (detail %q)", id, r.Class, class, r.Detail)
	}
	return r
}

// failAttempts returns the recorded consecutive failure count for a run.
func (e *reconcileEnv) failAttempts(id string) int {
	e.t.Helper()
	e.svc.reconcileBackoffMu.Lock()
	defer e.svc.reconcileBackoffMu.Unlock()
	st, ok := e.svc.reconcileBackoff[id+"/"+e.host]
	if !ok {
		return 0
	}
	return st.attempts
}

func (e *reconcileEnv) backoffEntries() int {
	e.t.Helper()
	e.svc.reconcileBackoffMu.Lock()
	defer e.svc.reconcileBackoffMu.Unlock()
	return len(e.svc.reconcileBackoff)
}

func (e *reconcileEnv) reconcile(ctx context.Context) {
	if err := e.svc.ReconcileOnce(ctx); err != nil {
		e.t.Fatalf("ReconcileOnce: %v", err)
	}
}

// TestReconcileClosesRunAfterDeadlineWhenSessionsFail: the host authenticates
// but rejects every session channel, so hostrun.Check fails forever. Before
// the deadline the run stays open; after it the run is finished as unknown
// and the job is never dispatched again.
func TestReconcileClosesRunAfterDeadlineWhenSessionsFail(t *testing.T) {
	e := newReconcileEnv(t)
	srv := startTestSSH(t, e.userPub, sshModeReject)
	e.pin(srv.hostKey)
	id := e.createRun(srv.addr, 10*time.Minute)
	ctx := context.Background()

	// Before the deadline: still open, failure logged with backoff fields.
	e.clock.Add(time.Hour)
	e.reconcile(ctx)
	e.requireOpen(id)
	recs := e.logs.find("reconcile_check_failed", id)
	if len(recs) != 1 {
		t.Fatalf("reconcile_check_failed records = %d, want 1", len(recs))
	}
	if recs[0].attrs["attempt"] != 1 {
		t.Errorf("attempt = %v, want 1", recs[0].attrs["attempt"])
	}
	if recs[0].attrs["next_try_in"] != 75 {
		t.Errorf("next_try_in = %v, want 75", recs[0].attrs["next_try_in"])
	}

	// Past the deadline (created + 10 min + 24 h grace): finished as
	// unknown, audit recorded, no re-dispatch.
	e.clock.Add(24 * time.Hour)
	e.reconcile(ctx)
	r := e.requireFinished(id, "unknown")
	for _, want := range []string{"reconcile deadline", "may have run", "not re-run"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("detail %q does not contain %q", r.Detail, want)
		}
	}
	audit := e.logs.find("reconcile_deadline_passed", id)
	if len(audit) != 1 {
		t.Fatalf("reconcile_deadline_passed records = %d, want 1", len(audit))
	}
	if audit[0].attrs["host"] != e.host {
		t.Errorf("audit host = %v, want %s", audit[0].attrs["host"], e.host)
	}
	if cmds := srv.commands(); len(cmds) != 0 {
		t.Errorf("server saw %d exec commands after close, want 0 (no re-dispatch)", len(cmds))
	}
}

// TestReconcileClosesRunAfterDeadlineWhenUnreachable: nothing listens on the
// endpoint; the run is finished as unknown once the deadline passes.
func TestReconcileClosesRunAfterDeadlineWhenUnreachable(t *testing.T) {
	e := newReconcileEnv(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	e.pin(hk)
	addr := closedAddr(t)
	id := e.createRun(addr, 10*time.Minute)
	ctx := context.Background()

	e.clock.Add(time.Hour)
	e.reconcile(ctx)
	e.requireOpen(id)
	if recs := e.logs.find("reconcile_unreachable", id); len(recs) != 1 {
		t.Fatalf("reconcile_unreachable records = %d, want 1", len(recs))
	}

	e.clock.Add(24 * time.Hour)
	e.reconcile(ctx)
	r := e.requireFinished(id, "unknown")
	for _, want := range []string{"reconcile deadline", "may have run", "not re-run"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("detail %q does not contain %q", r.Detail, want)
		}
	}
	if recs := e.logs.find("reconcile_deadline_passed", id); len(recs) != 1 {
		t.Fatalf("reconcile_deadline_passed records = %d, want 1", len(recs))
	}
}

// TestReconcileBacksOffBetweenFailures: with a 75 s reconcile interval, a
// second ReconcileOnce right after a failure does not connect; the delay
// doubles after each failure and is capped at maxReconcileBackoff.
func TestReconcileBacksOffBetweenFailures(t *testing.T) {
	e := newReconcileEnv(t)
	srv := startTestSSH(t, e.userPub, sshModeReject)
	e.pin(srv.hostKey)
	id := e.createRun(srv.addr, 10*time.Minute)
	ctx := context.Background()

	// attempt 1 at t0
	e.reconcile(ctx)
	if got := srv.connections(); got != 1 {
		t.Fatalf("connections after attempt 1 = %d, want 1", got)
	}
	// inside the first backoff: no connection
	e.clock.Add(10 * time.Second)
	e.reconcile(ctx)
	// just before the boundary: still no connection
	e.clock.Add(64 * time.Second)
	e.reconcile(ctx)
	if got := srv.connections(); got != 1 {
		t.Fatalf("connections at t0+74s = %d, want 1 (backoff must skip)", got)
	}
	// at the boundary: attempt 2
	e.clock.Add(time.Second)
	e.reconcile(ctx)
	if got := srv.connections(); got != 2 {
		t.Fatalf("connections at t0+75s = %d, want 2", got)
	}
	// delay doubled to 150 s: attempt 3 at t0+225 s
	e.clock.Add(149 * time.Second)
	e.reconcile(ctx)
	if got := srv.connections(); got != 2 {
		t.Fatalf("connections at t0+224s = %d, want 2", got)
	}
	e.clock.Add(time.Second)
	e.reconcile(ctx)
	if got := srv.connections(); got != 3 {
		t.Fatalf("connections at t0+225s = %d, want 3", got)
	}
	// delays 300 s, 600 s, 1200 s, 2400 s: attempts 4..7
	for _, d := range []time.Duration{300 * time.Second, 600 * time.Second, 1200 * time.Second, 2400 * time.Second} {
		e.clock.Add(d - time.Second)
		e.reconcile(ctx)
		e.clock.Add(time.Second)
		e.reconcile(ctx)
	}
	want := int64(7)
	if got := srv.connections(); got != want {
		t.Fatalf("connections = %d, want %d", got, want)
	}
	// from here the delay is capped at 30 min: attempt 8 at +1800 s
	e.clock.Add(1799 * time.Second)
	e.reconcile(ctx)
	if got := srv.connections(); got != want {
		t.Fatalf("connections before cap boundary = %d, want %d", got, want)
	}
	e.clock.Add(time.Second)
	e.reconcile(ctx)
	if got := srv.connections(); got != want+1 {
		t.Fatalf("connections at cap boundary = %d, want %d", got, want+1)
	}
	// the capped delay is reported as 1800 s
	recs := e.logs.find("reconcile_check_failed", id)
	if len(recs) != 8 {
		t.Fatalf("reconcile_check_failed records = %d, want 8", len(recs))
	}
	last := recs[len(recs)-1]
	if last.attrs["attempt"] != 8 {
		t.Errorf("last attempt = %v, want 8", last.attrs["attempt"])
	}
	if last.attrs["next_try_in"] != 1800 {
		t.Errorf("last next_try_in = %v, want 1800 (capped)", last.attrs["next_try_in"])
	}
}

// TestReconcileWaitingForRebootKeepsRebootDeadline: a run that waits for a
// reboot is governed by its reboot deadline, not the reconcile deadline.
func TestReconcileWaitingForRebootKeepsRebootDeadline(t *testing.T) {
	e := newReconcileEnv(t)
	srv := startTestSSH(t, e.userPub, sshModeNormal)
	e.pin(srv.hostKey)
	ctx := context.Background()

	oldBoot := "11111111-2222-4333-8444-555555555555"
	if err := os.WriteFile(e.bootFile, []byte(oldBoot+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	start := e.clock.Now()
	id := e.createRun(srv.addr, 20*time.Minute)
	if err := e.db.MarkRunRunning(id, e.host, srv.addr); err != nil {
		t.Fatal(err)
	}
	if err := e.db.AddRunReboot(executordb.RunReboot{
		ExecutionID: id,
		HostID:      e.host,
		OldBootID:   oldBoot,
		Deadline:    start.Add(20 * time.Minute),
		ExitCode:    0,
		Result:      []byte(`{"await_reboot":true,"boot_id":"` + oldBoot + `"}`),
	}); err != nil {
		t.Fatal(err)
	}

	// Same boot ID before the reboot deadline: still open.
	e.clock.Add(10 * time.Minute)
	e.reconcile(ctx)
	e.requireOpen(id)

	// Past the reboot deadline: host_not_returned, and the reconcile
	// deadline must not have been involved.
	e.clock.Add(11 * time.Minute)
	e.reconcile(ctx)
	e.requireFinished(id, "host_not_returned")
	if recs := e.logs.find("reconcile_deadline_passed", id); len(recs) != 0 {
		t.Fatalf("reconcile_deadline_passed recorded for a reboot-waiting run: %d", len(recs))
	}

	// A new boot ID ends the run as success.
	id2 := e.createRun(srv.addr, 20*time.Minute)
	if err := e.db.MarkRunRunning(id2, e.host, srv.addr); err != nil {
		t.Fatal(err)
	}
	if err := e.db.AddRunReboot(executordb.RunReboot{
		ExecutionID: id2,
		HostID:      e.host,
		OldBootID:   oldBoot,
		Deadline:    e.clock.Now().Add(20 * time.Minute),
		ExitCode:    0,
		Result:      []byte(`{"await_reboot":true,"boot_id":"` + oldBoot + `"}`),
	}); err != nil {
		t.Fatal(err)
	}
	newBoot := "99999999-8888-4777-8666-555555555555"
	if err := os.WriteFile(e.bootFile, []byte(newBoot+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.reconcile(ctx)
	e.requireFinished(id2, "success")
}

// TestReconcileSuccessClearsBackoff: a failed attempt puts the run in
// backoff; once the host is checkable again the run finishes and the
// failure state is cleared.
func TestReconcileSuccessClearsBackoff(t *testing.T) {
	e := newReconcileEnv(t)
	srv := startTestSSH(t, e.userPub, sshModeReject)
	e.pin(srv.hostKey)
	id := e.createRun(srv.addr, 10*time.Minute)
	ctx := context.Background()

	// One failed attempt.
	e.reconcile(ctx)
	if got := e.failAttempts(id); got != 1 {
		t.Fatalf("failure attempts = %d, want 1", got)
	}

	// The host starts working, but the run is still in backoff.
	srv.setMode(sshModeNormal)
	e.clock.Add(10 * time.Second)
	e.reconcile(ctx)
	e.requireOpen(id)
	if got := srv.connections(); got != 1 {
		t.Fatalf("connections during backoff = %d, want 1", got)
	}

	// After the backoff: the check succeeds, the run finishes, and the
	// failure state is gone.
	e.clock.Add(65 * time.Second)
	e.reconcile(ctx)
	e.requireFinished(id, "not_executed")
	if got := e.backoffEntries(); got != 0 {
		t.Fatalf("backoff entries after success = %d, want 0", got)
	}
}

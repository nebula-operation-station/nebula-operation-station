// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// SSH failover to the alternate endpoints of a host (ep02, ADR 0006): the
// next endpoint is tried only after a connection error or a timeout before
// the host key; a host key mismatch, an authentication failure or anything
// after the run started ends the attempt (fail closed).

func newHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// blackhole accepts TCP connections and never speaks SSH: the handshake
// runs into the connect timeout. It counts accepted connections.
type blackhole struct {
	addr  string
	mu    sync.Mutex
	conns []net.Conn
}

func startBlackhole(t *testing.T) *blackhole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{addr: ln.Addr().String()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns = append(b.conns, c)
			b.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		b.mu.Lock()
		for _, c := range b.conns {
			_ = c.Close()
		}
		b.mu.Unlock()
	})
	return b
}

func (b *blackhole) connections() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.conns)
}

func mustEndpoints(t *testing.T, addrs ...string) []sshtransport.Endpoint {
	t.Helper()
	eps, err := parseEndpoints(addrs)
	if err != nil {
		t.Fatal(err)
	}
	return eps
}

func TestConnectFailsOverToAlternateWhenPrimaryDown(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	hk := newHostKey(t)
	e.pin(hk)
	alt := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)
	primary := closedAddr(t)

	c, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, primary, alt.addr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if got := c.Endpoint.String(); got != alt.addr {
		t.Fatalf("endpoint = %s, want the alternate %s", got, alt.addr)
	}
	recs := e.logs.find("ssh_failover", "")
	if len(recs) != 1 {
		t.Fatalf("ssh_failover audit records = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.attrs["host"] != e.host || r.attrs["endpoint"] != alt.addr {
		t.Errorf("audit host/endpoint = %v/%v, want %s/%s", r.attrs["host"], r.attrs["endpoint"], e.host, alt.addr)
	}
	if s, _ := r.attrs["skipped"].(string); !strings.Contains(s, primary+" "+sshtransport.StageTCP) {
		t.Errorf("audit skipped = %q, want it to name %s at stage tcp", s, primary)
	}
	if hk, ok, err := e.db.HostKey(e.host); err != nil || !ok || hk.Blocked != nil {
		t.Fatalf("host pin after failover: ok=%v blocked=%v err=%v", ok, hk.Blocked, err)
	}
}

func TestConnectOnPrimaryWritesNoFailoverAudit(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	hk := newHostKey(t)
	e.pin(hk)
	primary := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)
	alt := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)

	c, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, primary.addr, alt.addr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if c.Endpoint.String() != primary.addr {
		t.Fatalf("endpoint = %s, want the primary %s", c.Endpoint, primary.addr)
	}
	if alt.connections() != 0 {
		t.Fatalf("alternate saw %d connections, want 0", alt.connections())
	}
	if n := len(e.logs.find("ssh_failover", "")); n != 0 {
		t.Fatalf("ssh_failover audit records = %d, want 0", n)
	}
}

// TestHostKeyMismatchStopsFailover: a key other than the pin, on any
// endpoint, ends the connection attempt and blocks the host; later
// endpoints never see the credential.
func TestHostKeyMismatchStopsFailover(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// order builds the endpoint list from the down, impostor and good
		// endpoint addresses.
		order func(down, impostor, good string) []string
	}{
		{"mismatch on alternate after primary down", func(d, i, g string) []string { return []string{d, i, g} }},
		{"mismatch on primary", func(_, i, g string) []string { return []string{i, g} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newReconcileEnv(t)
			hk := newHostKey(t)
			e.pin(hk)
			impostor := startTestSSHWithKey(t, e.userPub, sshModeNormal, newHostKey(t))
			good := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)

			_, err := e.svc.Connect(context.Background(), e.host, e.fp,
				mustEndpoints(t, tc.order(closedAddr(t), impostor.addr, good.addr)...))
			if sshtransport.ClassOf(err) != sshtransport.ClassHostKeyMismatch {
				t.Fatalf("err = %v, want class %s", err, sshtransport.ClassHostKeyMismatch)
			}
			if good.connections() != 0 {
				t.Fatalf("endpoint after the mismatch saw %d connections, want 0", good.connections())
			}
			pin, ok, err := e.db.HostKey(e.host)
			if err != nil || !ok || pin.Blocked == nil {
				t.Fatalf("host not blocked after mismatch: ok=%v err=%v", ok, err)
			}
			if pin.Blocked.Endpoint != impostor.addr {
				t.Errorf("blocked endpoint = %q, want %q", pin.Blocked.Endpoint, impostor.addr)
			}
			recs := e.logs.find("host_key_mismatch", "")
			if len(recs) != 1 || recs[0].attrs["endpoint"] != impostor.addr {
				t.Fatalf("host_key_mismatch audit = %+v, want one naming %s", recs, impostor.addr)
			}
			if n := len(e.logs.find("ssh_failover", "")); n != 0 {
				t.Errorf("ssh_failover audit records = %d, want 0", n)
			}
			// Blocked: the next connect does not even dial.
			if _, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, good.addr)); !errors.Is(err, ErrHostBlocked) {
				t.Fatalf("connect after mismatch: err = %v, want ErrHostBlocked", err)
			}
			if good.connections() != 0 {
				t.Fatalf("blocked host was dialled: %d connections", good.connections())
			}
		})
	}
}

// TestAuthFailureStopsFailover: the pinned key matched and authentication
// failed; no other endpoint is offered the credential.
func TestAuthFailureStopsFailover(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	hk := newHostKey(t)
	e.pin(hk)
	other := newHostKey(t).PublicKey()
	refusing := startTestSSHWithKey(t, other, sshModeNormal, hk) // accepts only another user key
	good := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)

	_, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, closedAddr(t), refusing.addr, good.addr))
	if sshtransport.ClassOf(err) != sshtransport.ClassAuth {
		t.Fatalf("err = %v, want class %s", err, sshtransport.ClassAuth)
	}
	if good.connections() != 0 {
		t.Fatalf("endpoint after the auth failure saw %d connections, want 0", good.connections())
	}
	if class, _ := connectClass(err); class != classAuthenticationFailed {
		t.Errorf("connect class = %q, want %q", class, classAuthenticationFailed)
	}
}

// TestHandshakeTimeoutFailsOverWithinBounds: an endpoint that accepts TCP
// but never answers is left after the connect timeout; a second such
// endpoint ends the attempt (one handshake retry per dial), so the time a
// dead host can hold a run is bounded.
func TestHandshakeTimeoutFailsOverWithinBounds(t *testing.T) {
	t.Parallel()
	const timeout = 300 * time.Millisecond

	t.Run("one silent endpoint then a good one", func(t *testing.T) {
		t.Parallel()
		e := newReconcileEnv(t)
		e.svc.transport.ConnectTimeout = timeout
		hk := newHostKey(t)
		e.pin(hk)
		silent := startBlackhole(t)
		good := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)

		start := time.Now()
		c, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, silent.addr, good.addr))
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer c.Close()
		if el := time.Since(start); el < timeout || el > 10*timeout {
			t.Errorf("connect took %s, want about one connect timeout (%s)", el, timeout)
		}
		if c.Endpoint.String() != good.addr {
			t.Fatalf("endpoint = %s, want %s", c.Endpoint, good.addr)
		}
		recs := e.logs.find("ssh_failover", "")
		if len(recs) != 1 {
			t.Fatalf("ssh_failover audit records = %d, want 1", len(recs))
		}
		if s, _ := recs[0].attrs["skipped"].(string); !strings.Contains(s, silent.addr+" "+sshtransport.StageHandshake) {
			t.Errorf("audit skipped = %q, want %s at stage handshake", s, silent.addr)
		}
	})

	t.Run("two silent endpoints end the dial", func(t *testing.T) {
		t.Parallel()
		e := newReconcileEnv(t)
		e.svc.transport.ConnectTimeout = timeout
		hk := newHostKey(t)
		e.pin(hk)
		s1, s2 := startBlackhole(t), startBlackhole(t)
		good := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)

		start := time.Now()
		_, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, s1.addr, s2.addr, good.addr))
		if sshtransport.ClassOf(err) != sshtransport.ClassUnreachable {
			t.Fatalf("err = %v, want class %s", err, sshtransport.ClassUnreachable)
		}
		if el := time.Since(start); el > 10*timeout {
			t.Errorf("connect took %s, want at most about two connect timeouts", el)
		}
		if good.connections() != 0 {
			t.Fatalf("third endpoint saw %d connections, want 0", good.connections())
		}
		if s1.connections() != 1 || s2.connections() != 1 {
			t.Errorf("silent endpoints dialled %d and %d times, want once each", s1.connections(), s2.connections())
		}
		if class, _ := connectClass(err); class != classNetworkUnreachable {
			t.Errorf("connect class = %q, want %q", class, classNetworkUnreachable)
		}
		rec := requireFailoverFailed(t, e, sshtransport.ClassUnreachable)
		wantSkipped := s1.addr + " " + sshtransport.StageHandshake + ", " + s2.addr + " " + sshtransport.StageHandshake
		if rec.attrs["skipped"] != wantSkipped || rec.attrs["untried"] != good.addr {
			t.Errorf("ssh_failover_failed skipped/untried = %q/%q, want %q/%q",
				rec.attrs["skipped"], rec.attrs["untried"], wantSkipped, good.addr)
		}
	})

	t.Run("caller deadline ends failover", func(t *testing.T) {
		t.Parallel()
		e := newReconcileEnv(t)
		e.svc.transport.ConnectTimeout = 10 * time.Second
		hk := newHostKey(t)
		e.pin(hk)
		silent := startBlackhole(t)
		good := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		start := time.Now()
		_, err := e.svc.Connect(ctx, e.host, e.fp, mustEndpoints(t, silent.addr, good.addr))
		if sshtransport.ClassOf(err) != sshtransport.ClassCanceled {
			t.Fatalf("err = %v, want class %s", err, sshtransport.ClassCanceled)
		}
		if el := time.Since(start); el > 10*timeout {
			t.Errorf("connect took %s, want it bounded by the caller's deadline", el)
		}
		if good.connections() != 0 {
			t.Fatalf("endpoint after the deadline saw %d connections, want 0", good.connections())
		}
		rec := requireFailoverFailed(t, e, sshtransport.ClassCanceled)
		if rec.attrs["skipped"] != silent.addr+" "+sshtransport.StageHandshake || rec.attrs["untried"] != good.addr {
			t.Errorf("ssh_failover_failed skipped/untried = %q/%q, want %s handshake/%s",
				rec.attrs["skipped"], rec.attrs["untried"], silent.addr, good.addr)
		}
	})
}

// TestFailedFailoverIsAudited: when every endpoint fails, the audit names
// each one with the stage it failed at, like a successful failover does.
func TestFailedFailoverIsAudited(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	hk := newHostKey(t)
	e.pin(hk)
	down := closedAddr(t)
	silent := startBlackhole(t)
	e.svc.transport.ConnectTimeout = 300 * time.Millisecond

	_, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, down, silent.addr))
	if sshtransport.ClassOf(err) != sshtransport.ClassUnreachable {
		t.Fatalf("err = %v, want class %s", err, sshtransport.ClassUnreachable)
	}
	rec := requireFailoverFailed(t, e, sshtransport.ClassUnreachable)
	want := down + " " + sshtransport.StageTCP + ", " + silent.addr + " " + sshtransport.StageHandshake
	if rec.attrs["skipped"] != want || rec.attrs["untried"] != "" {
		t.Errorf("ssh_failover_failed skipped/untried = %q/%q, want %q/\"\"", rec.attrs["skipped"], rec.attrs["untried"], want)
	}
	if rec.attrs["host"] != e.host {
		t.Errorf("audit host = %v, want %s", rec.attrs["host"], e.host)
	}
	if n := len(e.logs.find("ssh_failover", "")); n != 0 {
		t.Errorf("ssh_failover (success) audit records = %d, want 0", n)
	}
}

// TestMismatchIsNoFailedFailover: a host key mismatch has its own audit
// (host_key_mismatch); it is not reported as a failed failover.
func TestMismatchIsNoFailedFailover(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	hk := newHostKey(t)
	e.pin(hk)
	impostor := startTestSSHWithKey(t, e.userPub, sshModeNormal, newHostKey(t))
	if _, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, closedAddr(t), impostor.addr)); sshtransport.ClassOf(err) != sshtransport.ClassHostKeyMismatch {
		t.Fatalf("err = %v, want class %s", err, sshtransport.ClassHostKeyMismatch)
	}
	if n := len(e.logs.find("ssh_failover_failed", "")); n != 0 {
		t.Errorf("ssh_failover_failed records after a mismatch = %d, want 0", n)
	}
}

// TestSingleEndpointIsNoFailedFailover: a host with one endpoint (and the
// one-endpoint enroll and pairing connects) has nothing to fail over to;
// an unreachable endpoint is not audited as a failed failover.
func TestSingleEndpointIsNoFailedFailover(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	e.pin(newHostKey(t))
	if _, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, closedAddr(t))); sshtransport.ClassOf(err) != sshtransport.ClassUnreachable {
		t.Fatalf("err = %v, want class %s", err, sshtransport.ClassUnreachable)
	}
	if n := len(e.logs.find("ssh_failover_failed", "")); n != 0 {
		t.Errorf("ssh_failover_failed records for a single endpoint = %d, want 0", n)
	}
}

// TestReconcileAuditsFailedFailoverOnce: the reconciler retries a run whose
// endpoints are all down on every due pass; the failed failover is audited
// once for the run, not once per pass.
func TestReconcileAuditsFailedFailoverOnce(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	e.pin(newHostKey(t))
	id := newTestUUID()
	if err := e.db.CreateRun(executordb.Run{ExecutionID: id, HostID: e.host, Digest: "failover-test-digest",
		Endpoints: []string{closedAddr(t), "127.0.0.2:1"}, Fingerprint: e.fp, Timeout: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		e.reconcile(context.Background())
		e.clock.Add(maxReconcileBackoff + time.Minute)
	}
	if n := e.failAttempts(id); n != 3 {
		t.Fatalf("reconcile attempts = %d, want 3", n)
	}
	recs := e.logs.find("ssh_failover_failed", "")
	if len(recs) != 1 {
		t.Fatalf("ssh_failover_failed records over 3 passes = %d, want 1", len(recs))
	}
	if recs[0].attrs["execution"] != id {
		t.Errorf("ssh_failover_failed execution = %v, want %s", recs[0].attrs["execution"], id)
	}
}

func requireFailoverFailed(t *testing.T, e *reconcileEnv, class sshtransport.Class) logRecord {
	t.Helper()
	recs := e.logs.find("ssh_failover_failed", "")
	if len(recs) != 1 {
		t.Fatalf("ssh_failover_failed audit records = %d, want 1", len(recs))
	}
	if recs[0].attrs["class"] != string(class) {
		t.Errorf("ssh_failover_failed class = %v, want %s", recs[0].attrs["class"], class)
	}
	return recs[0]
}

// TestReconcileOverAlternateNeverRunsTwice: a durable run whose primary
// went down after (or during) dispatch is checked over the alternate
// endpoint; the check only reads the job state and never dispatches it
// again. The run keeps the endpoint its dispatch was attempted on — also a
// run whose dispatch broke while it was still dispatching; the audit names
// it and, separately, the alternate that checked it. The check endpoint is
// never recorded as the dispatch endpoint: a run without a stored one
// keeps none.
func TestReconcileOverAlternateNeverRunsTwice(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		state     string
		stored    bool // the primary is stored as the dispatch endpoint
		wantClass string
	}{
		{"dispatching on primary", executordb.RunDispatching, true, classNotExecuted},
		{"dispatching without endpoint", executordb.RunDispatching, false, classNotExecuted},
		{"running on primary", executordb.RunRunning, true, classUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newReconcileEnv(t)
			hk := newHostKey(t)
			e.pin(hk)
			alt := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)
			primary := closedAddr(t)
			id := newTestUUID()
			if err := e.db.CreateRun(executordb.Run{ExecutionID: id, HostID: e.host, Digest: "failover-test-digest",
				Endpoints: []string{primary, alt.addr}, Fingerprint: e.fp, Timeout: 10 * time.Minute}); err != nil {
				t.Fatal(err)
			}
			if tc.stored {
				if err := e.db.SetRunDispatchEndpoint(id, e.host, primary); err != nil {
					t.Fatal(err)
				}
			}
			if tc.state == executordb.RunRunning {
				if err := e.db.MarkRunRunning(id, e.host, primary); err != nil {
					t.Fatal(err)
				}
			}

			e.reconcile(context.Background())

			want := ""
			if tc.stored {
				want = primary
			}
			r := e.requireFinished(id, tc.wantClass)
			if r.Endpoint != want {
				t.Errorf("run endpoint = %q, want %q", r.Endpoint, want)
			}
			recs := e.logs.find("run_finished", id)
			if len(recs) != 1 || recs[0].attrs["endpoint"] != want || recs[0].attrs["check_endpoint"] != alt.addr {
				t.Fatalf("run_finished audit = %+v, want one with endpoint %s and check_endpoint %s", recs, want, alt.addr)
			}
			for _, cmd := range alt.commands() {
				if strings.Contains(cmd, "systemd-run") || strings.Contains(cmd, "setsid") {
					t.Errorf("reconcile started the job again: %q", cmd)
				}
			}
			// A second pass finds nothing open: nothing is retried.
			conns := alt.connections()
			e.clock.Add(time.Hour)
			e.reconcile(context.Background())
			if alt.connections() != conns {
				t.Fatalf("finished run was contacted again")
			}
		})
	}
}

// TestRunFinishedAuditNamesStoredEndpoint: every close path audits the
// endpoint the run record keeps. A run dispatched on a known endpoint and
// then closed without a connection (deadline passed, unusable stored
// endpoints, a not-dispatched record) still names that endpoint.
func TestRunFinishedAuditNamesStoredEndpoint(t *testing.T) {
	t.Parallel()
	const dispatched = "192.0.2.10:22"
	cases := []struct {
		name      string
		endpoints []string
		wantClass string
		close     func(e *reconcileEnv, id string)
	}{
		{"closeUncheckable", []string{"127.0.0.1:1"}, classUnknown, func(e *reconcileEnv, _ string) {
			e.clock.Add(time.Hour)
			e.reconcile(context.Background())
			e.clock.Add(24 * time.Hour)
			e.reconcile(context.Background())
		}},
		{"stored endpoints unusable", []string{"not an endpoint"}, classUnknown, func(e *reconcileEnv, _ string) {
			e.reconcile(context.Background())
		}},
		{"not dispatched", []string{"127.0.0.1:1"}, classNetworkUnreachable, func(e *reconcileEnv, id string) {
			e.svc.finishRun(executordb.Run{ExecutionID: id, HostID: e.host, Class: classNetworkUnreachable,
				Detail: "not dispatched: unreachable", ExitCode: -1})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newReconcileEnv(t)
			e.pin(newHostKey(t))
			id := newTestUUID()
			if err := e.db.CreateRun(executordb.Run{ExecutionID: id, HostID: e.host, Digest: "endpoint-audit-digest",
				Endpoints: tc.endpoints, Fingerprint: e.fp, Timeout: 10 * time.Minute}); err != nil {
				t.Fatal(err)
			}
			if err := e.db.MarkRunRunning(id, e.host, dispatched); err != nil {
				t.Fatal(err)
			}

			tc.close(e, id)

			r := e.requireFinished(id, tc.wantClass)
			if r.Endpoint != dispatched {
				t.Errorf("run endpoint = %q, want the dispatch endpoint %q", r.Endpoint, dispatched)
			}
			recs := e.logs.find("run_finished", id)
			if len(recs) != 1 || recs[0].attrs["endpoint"] != dispatched || recs[0].attrs["check_endpoint"] != "" {
				t.Fatalf("run_finished audit = %+v, want one with endpoint %s and no check endpoint", recs, dispatched)
			}
		})
	}
}

// TestRunFinishedAuditWithoutDispatchEndpoint: a run that never reached a
// host keeps an empty endpoint, and the audit says so (no invented value).
func TestRunFinishedAuditWithoutDispatchEndpoint(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	e.pin(newHostKey(t))
	id := e.createRun("127.0.0.1:1", 10*time.Minute)
	e.svc.finishRun(executordb.Run{ExecutionID: id, HostID: e.host, Class: classNetworkUnreachable,
		Detail: "not dispatched: unreachable", ExitCode: -1})
	r := e.requireFinished(id, classNetworkUnreachable)
	recs := e.logs.find("run_finished", id)
	if r.Endpoint != "" || len(recs) != 1 || recs[0].attrs["endpoint"] != "" {
		t.Fatalf("endpoint = %q, audit = %+v, want both empty", r.Endpoint, recs)
	}
}

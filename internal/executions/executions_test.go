// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

type fakeExec struct {
	mu        sync.Mutex
	pins      []*pb.HostKeyPin
	risk      pb.RiskClass
	approved  bool
	proposed  *pb.ProposeExecutionRequest
	submitted *pb.SubmitAssertionRequest
	attached  []*pb.RunAttachedRequest
	attachErr error
	durable   []*pb.StartDurableRequest
	polls     int
	released  bool
	result    []byte
	failHost  string
	// unreachable answers that many runs with a retryable network_unreachable.
	unreachable int
}

func (f *fakeExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{Hosts: f.pins}, nil
}

func (f *fakeExec) ProposeExecution(_ context.Context, in *pb.ProposeExecutionRequest, _ ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	f.proposed = in
	r := &pb.ProposeExecutionResponse{ExecutionDigest: strings.Repeat("d", 64), RiskClass: f.risk,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED, State: pb.PermitState_PERMIT_STATE_PENDING,
		RequestOptionsJson: []byte(`{"publicKey":{"challenge":"abc"}}`), ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}
	if f.approved {
		r.State, r.RequestOptionsJson = pb.PermitState_PERMIT_STATE_APPROVED, nil
	}
	return r, nil
}

func (f *fakeExec) SubmitAssertion(_ context.Context, in *pb.SubmitAssertionRequest, _ ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	f.submitted = in
	if string(in.GetAssertionJson()) != "good" {
		return nil, status.Error(codes.PermissionDenied, "assertion_invalid")
	}
	return &pb.SubmitAssertionResponse{State: pb.PermitState_PERMIT_STATE_APPROVED}, nil
}

func (f *fakeExec) RunAttached(_ context.Context, in *pb.RunAttachedRequest, _ ...grpc.CallOption) (*pb.RunAttachedResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attached = append(f.attached, in)
	if f.attachErr != nil {
		return nil, f.attachErr
	}
	if f.unreachable > 0 {
		f.unreachable--
		return &pb.RunAttachedResponse{Class: "network_unreachable", Detail: "all endpoints failed", ExitCode: -1, Retryable: true}, nil
	}
	res := []byte(`{"ok":true}`)
	if f.result != nil {
		res = f.result
	}
	if in.GetRun().GetHostId() == f.failHost {
		return &pb.RunAttachedResponse{Class: "script_failed", ExitCode: 3, Result: res, Log: []byte("secret log line")}, nil
	}
	return &pb.RunAttachedResponse{Class: "success", ExitCode: 0, Result: res, Log: []byte("log")}, nil
}

func (f *fakeExec) StartDurable(_ context.Context, in *pb.StartDurableRequest, _ ...grpc.CallOption) (*pb.StartDurableResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.durable = append(f.durable, in)
	return &pb.StartDurableResponse{Run: &pb.RunStatus{State: "running"}}, nil
}

func (f *fakeExec) GetRun(_ context.Context, in *pb.GetRunRequest, _ ...grpc.CallOption) (*pb.GetRunResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if in.GetRelease() {
		// Like the executor: the release drops the stored result.
		f.released = true
		return &pb.GetRunResponse{Run: &pb.RunStatus{State: "finished", Class: "success"}}, nil
	}
	if f.polls < 2 {
		return &pb.GetRunResponse{Run: &pb.RunStatus{State: "running"}}, nil
	}
	if f.released {
		return &pb.GetRunResponse{Run: &pb.RunStatus{State: "finished", Class: "success"}}, nil
	}
	return &pb.GetRunResponse{Run: &pb.RunStatus{State: "finished", Class: "success", Result: []byte(`{"kept":true}`)}}, nil
}

type fakeHosts map[string]inventory.Host

func (f fakeHosts) Get(_ context.Context, id string) (inventory.Host, error) {
	h, ok := f[id]
	if !ok {
		return inventory.Host{}, inventory.ErrHostNotFound
	}
	return h, nil
}

func setup(t *testing.T, f *fakeExec) (*Service, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	hosts := fakeHosts{
		"web": {ID: "web", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}, {Address: "fd00::5", Port: 2222}}},
		"new": {ID: "new", Endpoints: []inventory.Endpoint{{Address: "10.0.0.6"}}},
		"bad": {ID: "bad", Endpoints: []inventory.Endpoint{{Address: "10.0.0.7", Port: 22}}},
		"db":  {ID: "db", Endpoints: []inventory.Endpoint{{Address: "10.0.0.8", Port: 22}}},
	}
	f.pins = []*pb.HostKeyPin{
		{HostId: "web", Fingerprint: "SHA256:web", CredentialRef: "nebula-default"},
		{HostId: "bad", Fingerprint: "SHA256:bad", CredentialRef: "nebula-default", Blocked: true},
	}
	if f.risk == 0 {
		f.risk = pb.RiskClass_RISK_CLASS_HIGH
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, f, db, hosts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { cancel(); s.Wait() })
	return s, db
}

func TestCreateRefusesUnusableHosts(t *testing.T) {
	s, _ := setup(t, &fakeExec{})
	ctx := context.Background()
	if _, err := s.Create(ctx, "axel", "nope", []string{"web"}, nil); !errors.Is(err, ErrUnknownAction) {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "axel", "core.facts", nil, nil); !errors.Is(err, ErrNoHosts) {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"ghost": "not in the inventory", "new": "not enrolled", "bad": "blocked"} {
		_, err := s.Create(ctx, "axel", "core.facts", []string{host}, nil)
		var he *HostError
		if !errors.As(err, &he) || !strings.Contains(he.Reason, want) {
			t.Errorf("%s: %v", host, err)
		}
	}
}

func TestCreateProposesAndApprovalRuns(t *testing.T) {
	f := &fakeExec{}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web", "web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := actions.Lookup("core.facts")
	r := f.proposed.GetRequest()
	if !f.proposed.GetRaiseToMinimum() || r.GetArtifactSha256() != a.SHA256() || r.GetActionId() != "core.facts" ||
		len(r.GetResolvedTargets()) != 1 || r.GetResolvedTargets()[0].GetHostKeyFingerprint() != "SHA256:web" ||
		strings.Join(r.GetCredentialRefs(), ",") != "nebula-default" || r.GetRiskClass() != pb.RiskClass_RISK_CLASS_LOW {
		t.Fatalf("proposed %v", f.proposed)
	}
	if c.State != "pending" || c.Risk != "HIGH" || string(c.Options) == "" {
		t.Fatalf("created %+v", c)
	}
	if err := s.Approve(ctx, "axel", c.ID, []byte("bad"), 0); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("bad assertion: %v", err)
	}
	if err := s.Approve(ctx, "axel", c.ID, []byte("good"), 0); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	e, _ := s.Get(ctx, c.ID)
	h := e.Hosts[0]
	if h.Class != "success" || string(h.Result) != `{"ok":true}` || string(h.Log) != "log" || len(e.Options) != 0 {
		t.Fatalf("%+v", e)
	}
	run := f.attached[0]
	if strings.Join(run.GetEndpoints(), ",") != "10.0.0.5:22,[fd00::5]:2222" || string(run.GetRun().GetArtifact()) != string(a.Script) ||
		run.GetRun().GetCredentialRef() != "nebula-default" || run.GetRun().GetExecutionDigest() != strings.Repeat("d", 64) {
		t.Fatalf("run %v", run)
	}
	if err := s.Approve(ctx, "axel", c.ID, []byte("good"), 0); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second approval: %v", err)
	}
}

func waitState(t *testing.T, s *Service, id, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		e, err := s.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if e.State == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %s, want %s", e.State, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAutoApprovedRunsAndRefusalsAreRecorded(t *testing.T) {
	f := &fakeExec{approved: true, risk: pb.RiskClass_RISK_CLASS_LOW, attachErr: status.Error(codes.PermissionDenied, "host_already_run")}
	s, _ := setup(t, f)
	c, err := s.Create(context.Background(), "axel", "core.facts", []string{"web"}, nil)
	if err != nil || c.State != "approved" {
		t.Fatalf("%+v %v", c, err)
	}
	waitState(t, s, c.ID, "finished")
	e, _ := s.Get(context.Background(), c.ID)
	if e.Hosts[0].Class != "not_executed" || !strings.Contains(e.Hosts[0].Detail, "host_already_run") {
		t.Fatalf("%+v", e.Hosts[0])
	}
}

func TestDurableRunsArePolledAndReleased(t *testing.T) {
	saved := actions.Builtin
	t.Cleanup(func() { actions.Builtin = saved })
	actions.Builtin = append(append([]actions.Action(nil), saved...), actions.Action{ID: "test.durable", Version: "1.0.0", Risk: pb.RiskClass_RISK_CLASS_HIGH,
		Durable: true, Timeout: time.Minute, Script: []byte("true\n")})
	f := &fakeExec{approved: true}
	s, _ := setup(t, f)
	c, err := s.Create(context.Background(), "axel", "test.durable", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		e, _ := s.Get(context.Background(), c.ID)
		if e.State == "finished" {
			// The result was stored before it was released.
			if e.Hosts[0].Class != "success" || string(e.Hosts[0].Result) != `{"kept":true}` || !f.released || len(f.durable) != 1 {
				t.Fatalf("%+v released=%v", e.Hosts[0], f.released)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %s", e.State)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestResumeMarksInterruptedAttachedRunsUnknown(t *testing.T) {
	f := &fakeExec{}
	s, db := setup(t, f)
	c, err := s.Create(context.Background(), "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET state = 'running' WHERE id = ?`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE execution_hosts SET state = 'running' WHERE execution_id = ?`, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	e, _ := s.Get(context.Background(), c.ID)
	if e.Hosts[0].Class != "unknown" || len(f.attached) != 0 {
		t.Fatalf("%+v attached %d", e.Hosts[0], len(f.attached))
	}
}

func TestDecodeFacts(t *testing.T) {
	b := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	doc := `{"os_release":"` + b("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n") + `","uname":"` + b("Linux 6.1.0 x86_64\n") +
		`","hostname":"` + b("web\u202e01\n") + `","uptime":"` + b("172800.5\n") + `","proxmox":true}`
	got := DecodeFacts([]byte(doc))
	want := map[string]string{"Operating system": "Debian GNU/Linux 12 (bookworm)", "OS ID": "debian 12", "Kernel": "Linux 6.1.0 x86_64",
		"Hostname": "web�01", "Uptime": "2.0 days", "Proxmox VE": "yes"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for _, f := range got {
		if want[f.Name] != f.Value {
			t.Errorf("%s = %q, want %q", f.Name, f.Value, want[f.Name])
		}
	}
	if DecodeFacts([]byte("not json")) != nil {
		t.Error("garbage decoded")
	}
}

func TestSuccessfulUpdateListsAreKept(t *testing.T) {
	f := &fakeExec{approved: true}
	s, _ := setup(t, f)
	sim := base64.StdEncoding.EncodeToString([]byte("Inst openssl [1] (2 Debian-Security:12/stable-security [amd64])\nInst vim [1] (2 Debian:12/stable [amd64])\n"))
	f.result = []byte(`{"format":"apt-simulate-v1","mode":"upgrade","simulate":"` + sim + `","reboot_required":false,"reboot_pkgs":"","lists_mtime":1791960000,"proxmox":false}`)
	c, err := s.Create(context.Background(), "axel", "package.list_updates", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	all, err := s.AllUpdates(context.Background())
	if err != nil || all["web"].Total != 2 || all["web"].Security != 1 {
		t.Fatalf("%+v %v", all, err)
	}
	u, err := s.Updates(context.Background(), "web")
	if err != nil || len(u.Packages) != 2 || u.Packages[0].Name != "openssl" {
		t.Fatalf("%+v %v", u, err)
	}
	if _, err := s.Updates(context.Background(), "new"); !errors.Is(err, ErrNoUpdates) {
		t.Fatal(err)
	}
}

func TestEvaluateOpsState(t *testing.T) {
	at := time.Unix(1791960000, 0)
	for name, tc := range map[string]struct {
		run  lastRun
		upd  *HostUpdates
		want string
	}{
		"never":       {want: StateUnknown},
		"reachable":   {run: lastRun{action: "core.facts", class: "success", at: at, ok: true}, want: StateReady},
		"unreachable": {run: lastRun{action: "core.facts", class: "network_unreachable", at: at, ok: true}, want: StateUnreachable},
		"not back":    {run: lastRun{action: "system.reboot", class: "host_not_returned", at: at, ok: true}, want: StateUnreachable},
		"failed":      {run: lastRun{action: "package.install_all", class: "postcheck_failed", at: at, ok: true}, want: StateWarning},
		"security":    {upd: &HostUpdates{Total: 3, Security: 1, ObservedAt: at}, want: StateWarning},
		"reboot":      {upd: &HostUpdates{RebootRequired: true, ObservedAt: at}, want: StateWarning},
		"clean":       {run: lastRun{action: "package.list_updates", class: "success", at: at, ok: true}, upd: &HostUpdates{Total: 2, ObservedAt: at}, want: StateReady},
	} {
		if got := evaluate(tc.run, tc.upd); got.State != tc.want {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

type sentEvents struct {
	mu     sync.Mutex
	events []notify.Event
}

func (s *sentEvents) Name() string { return "test" }
func (s *sentEvents) Send(_ context.Context, e notify.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// of returns the events of one kind sent so far.
func (s *sentEvents) of(kind string) []notify.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []notify.Event
	for _, e := range s.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// await waits until n events of kind were sent.
func (s *sentEvents) await(t *testing.T, kind string, n int) []notify.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(s.of(kind)) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return s.of(kind)
}

func TestOpsStateTransitionsNotifyOnce(t *testing.T) {
	f := &fakeExec{approved: true}
	s, _ := setup(t, f)
	sent := &sentEvents{}
	s.SetNotifier(notify.NewWithSenders(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, sent))
	run := func() {
		c, err := s.Create(context.Background(), "axel", "core.facts", []string{"web"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		waitState(t, s, c.ID, "finished")
	}
	run() // first state: READY, no transition to notify
	f.mu.Lock()
	f.attachErr = status.Error(codes.Unavailable, "x")
	f.mu.Unlock()
	run() // not_executed -> UNKNOWN
	run() // same state again: no repeat
	f.mu.Lock()
	f.attachErr = nil
	f.mu.Unlock()
	run() // recovered
	states, err := s.AllOpsStates(context.Background())
	if err != nil || states["web"].State != StateReady {
		t.Fatalf("%v %v", states, err)
	}
	ops := sent.of(notify.KindOpsState)
	if len(ops) != 2 || ops[0].State != StateUnknown || !strings.Contains(ops[1].Reason, "recovered") {
		t.Fatalf("%+v", ops)
	}
}

func TestParamsAreValidatedAndCarried(t *testing.T) {
	f := &fakeExec{approved: true}
	s, _ := setup(t, f)
	ctx := context.Background()
	var pe *ParamError
	if _, err := s.Create(ctx, "axel", "service.restart", []string{"web"}, map[string]string{"unit": "-evil"}); !errors.As(err, &pe) {
		t.Fatalf("bad unit: %v", err)
	}
	if _, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, map[string]string{"x": "y"}); !errors.As(err, &pe) {
		t.Fatalf("params for a parameterless action: %v", err)
	}
	c, err := s.Create(ctx, "axel", "service.restart", []string{"web"}, map[string]string{"unit": "nginx.service"})
	if err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	ph, _ := canonical.HashParameters([]byte(`{"unit":"nginx.service"}`))
	if f.proposed.GetRequest().GetParametersHash() != ph || string(f.proposed.GetParametersJson()) != `{"unit":"nginx.service"}` ||
		string(f.attached[0].GetRun().GetParametersJson()) != `{"unit":"nginx.service"}` {
		t.Fatalf("params not carried: %v %v", f.proposed, f.attached[0])
	}
}

func TestFailedExecutionsNotifyOnce(t *testing.T) {
	f := &fakeExec{approved: true}
	s, _ := setup(t, f)
	f.pins = append(f.pins, &pb.HostKeyPin{HostId: "db", Fingerprint: "SHA256:db", CredentialRef: "nebula-default"})
	sent := &sentEvents{}
	s.SetNotifier(notify.NewWithSenders(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, sent))
	run := func(hosts ...string) string {
		c, err := s.Create(context.Background(), "axel", "core.facts", hosts, nil)
		if err != nil {
			t.Fatal(err)
		}
		waitState(t, s, c.ID, "finished")
		return c.ID
	}
	run("web", "db") // all succeeded: nothing to tell
	f.mu.Lock()
	f.failHost = "db"
	f.mu.Unlock()
	partial := run("web", "db")
	got := sent.await(t, notify.KindExecution, 1)
	if len(got) != 1 || got[0].State != "WARNING" || got[0].ExecutionID != partial || got[0].Host != "" ||
		got[0].Reason != "core.facts: 1 of 2 hosts failed: db (script_failed)" {
		t.Fatalf("%+v", got)
	}
	f.mu.Lock()
	f.attachErr = status.Error(codes.Unavailable, "x")
	f.mu.Unlock()
	all := run("web")
	got = sent.await(t, notify.KindExecution, 2)
	if len(got) != 2 || got[1].State != "FAILED" || got[1].Host != "web" || got[1].ExecutionID != all {
		t.Fatalf("%+v", got)
	}
	for _, e := range got {
		if strings.Contains(e.Reason, "log") {
			t.Fatalf("host output in a notification: %+v", e)
		}
	}
	// Finishing again (a resume) does not repeat the notification.
	s.dispatch(all)
	time.Sleep(50 * time.Millisecond)
	if n := len(sent.of(notify.KindExecution)); n != 2 {
		t.Fatalf("repeated: %d", n)
	}
}

func TestSafeActionsRetryARunThatNeverReachedTheHost(t *testing.T) {
	old := retryDelays
	retryDelays = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() { retryDelays = old })
	f := &fakeExec{approved: true, unreachable: 2}
	s, _ := setup(t, f)
	ctx := context.Background()
	attempts := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.attached)
	}
	// Safe: two unreachable runs, then the third reaches the host.
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	e, _ := s.Get(ctx, c.ID)
	if e.Hosts[0].Class != "success" || attempts() != 3 {
		t.Fatalf("%+v after %d attempts", e.Hosts[0], attempts())
	}
	// Safe, but still unreachable after the last retry: reported as such.
	f.mu.Lock()
	f.unreachable, f.attached = 5, nil
	f.mu.Unlock()
	c, _ = s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	waitState(t, s, c.ID, "finished")
	e, _ = s.Get(ctx, c.ID)
	if e.Hosts[0].Class != "network_unreachable" || attempts() != 3 {
		t.Fatalf("%+v after %d attempts", e.Hosts[0], attempts())
	}
	// Not safe (a restart): never retried automatically.
	f.mu.Lock()
	f.unreachable, f.attached = 1, nil
	f.mu.Unlock()
	c, _ = s.Create(ctx, "axel", "service.restart", []string{"web"}, map[string]string{"unit": "nginx.service"})
	waitState(t, s, c.ID, "finished")
	e, _ = s.Get(ctx, c.ID)
	if e.Hosts[0].Class != "network_unreachable" || attempts() != 1 {
		t.Fatalf("%+v after %d attempts", e.Hosts[0], attempts())
	}
}

type lockedSender struct {
	mu sync.Mutex
	n  int
}

func (l *lockedSender) Name() string { return "locked" }
func (l *lockedSender) Send(context.Context, notify.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	return nil
}

// Runs finishing at once on one host must not both report the same
// transition (Hermes review).
func TestConcurrentRunsNotifyATransitionOnce(t *testing.T) {
	s, _ := setup(t, &fakeExec{approved: true})
	sent := &lockedSender{}
	s.SetNotifier(notify.NewWithSenders(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, sent))
	ctx := context.Background()
	s.refreshOpsState(ctx, "web", lastRun{action: "core.facts", class: "success", at: s.now(), ok: true})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.refreshOpsState(ctx, "web", lastRun{action: "core.facts", class: "not_executed", at: s.now(), ok: true})
		}()
	}
	wg.Wait()
	if sent.n != 1 {
		t.Fatalf("%d notifications for one transition", sent.n)
	}
}

// Single-stage executions never ask about rollouts.
func (f *fakeExec) BeginGate(context.Context, *pb.BeginGateRequest, ...grpc.CallOption) (*pb.BeginGateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "no stages")
}

func (f *fakeExec) CommitGate(context.Context, *pb.CommitGateRequest, ...grpc.CallOption) (*pb.CommitGateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "no stages")
}

func (f *fakeExec) AbortRollout(context.Context, *pb.AbortRolloutRequest, ...grpc.CallOption) (*pb.AbortRolloutResponse, error) {
	return nil, status.Error(codes.Unimplemented, "no stages")
}

func (f *fakeExec) GetRollout(context.Context, *pb.GetRolloutRequest, ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	return nil, status.Error(codes.Unimplemented, "no stages")
}

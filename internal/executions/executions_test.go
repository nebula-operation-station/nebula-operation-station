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

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
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
	return &pb.RunAttachedResponse{Class: "success", ExitCode: 0, Result: []byte(`{"ok":true}`), Log: []byte("log")}, nil
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
	f.released = in.GetRelease()
	if f.polls < 2 {
		return &pb.GetRunResponse{Run: &pb.RunStatus{State: "running"}}, nil
	}
	return &pb.GetRunResponse{Run: &pb.RunStatus{State: "finished", Class: "success", Result: []byte(`{}`)}}, nil
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
	if _, err := s.Create(ctx, "axel", "nope", []string{"web"}); !errors.Is(err, ErrUnknownAction) {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "axel", "core.facts", nil); !errors.Is(err, ErrNoHosts) {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"ghost": "not in the inventory", "new": "not enrolled", "bad": "blocked"} {
		_, err := s.Create(ctx, "axel", "core.facts", []string{host})
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
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web", "web"})
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
	c, err := s.Create(context.Background(), "axel", "core.facts", []string{"web"})
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
	c, err := s.Create(context.Background(), "axel", "test.durable", []string{"web"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		e, _ := s.Get(context.Background(), c.ID)
		if e.State == "finished" {
			if e.Hosts[0].Class != "success" || !f.released || len(f.durable) != 1 {
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
	c, err := s.Create(context.Background(), "axel", "core.facts", []string{"web"})
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

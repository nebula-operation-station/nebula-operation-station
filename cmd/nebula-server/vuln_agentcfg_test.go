// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// vtAgentCfg serves the default agent settings to the agent API tests.
type vtAgentCfg struct{}

func (vtAgentCfg) AgentConfig(context.Context) (vulnstore.AgentConfig, error) {
	return vulnstore.DefaultAgentConfig(), nil
}

// vaGoodAssertion is the assertion the fake executor accepts.
const vaGoodAssertion = `{"id":"k","ok":true}`

// vaLogins is a fake executor login: single-use challenges; an assertion
// verifies when it is vaGoodAssertion and names user.
type vaLogins struct {
	mu       sync.Mutex
	n        int
	open     map[string]bool
	user     string
	finished int
}

func newVALogins(user string) *vaLogins { return &vaLogins{open: map[string]bool{}, user: user} }

func (l *vaLogins) BeginLogin(context.Context, *pb.BeginLoginRequest, ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	id := fmt.Sprintf("%032x", l.n)
	l.open[id] = true
	return &pb.BeginLoginResponse{LoginId: id, RequestOptionsJson: []byte(`{"challenge":"` + id + `"}`),
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix()}, nil
}

func (l *vaLogins) FinishLogin(_ context.Context, in *pb.FinishLoginRequest, _ ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.finished++
	if !l.open[in.GetLoginId()] {
		return nil, status.Error(codes.NotFound, "login expired")
	}
	delete(l.open, in.GetLoginId())
	if string(in.GetAssertionJson()) != vaGoodAssertion {
		return nil, status.Error(codes.Unauthenticated, "assertion not accepted")
	}
	return &pb.FinishLoginResponse{CredentialId: "k", UserName: l.user}, nil
}

func (l *vaLogins) finishedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.finished
}

// vaEnv is the settings backend over a real store and audit log.
type vaEnv struct {
	s     *vulnAgentSettings
	store *vulnstore.AgentConfigStore
	audit *auditlog.Store
	login *vaLogins
	admin bool
	now   time.Time
}

func newVAEnv(t *testing.T) *vaEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &vaEnv{audit: auditlog.New(db, true), login: newVALogins("alice"), admin: true, now: time.Now()}
	store, s, err := newVulnAgentWiring(db, e.audit, func(context.Context) bool { return e.admin }, e.login,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return e.now }
	e.s, e.store = s, store
	return e
}

func vaChange(url string) ui.VulnAgentChange {
	return ui.VulnAgentChange{Settings: vulnstore.AgentSettings{LLMEnabled: true, LLMBaseURL: url, LLMModel: "qwen3.5-9b-64k",
		OperatorInstructions: "Be brief.", Language: vulnstore.AgentLanguageEN}, URLChanged: url != ""}
}

// stored reports the stored version and the number of audit entries.
func (e *vaEnv) stored(t *testing.T) (int64, int) {
	t.Helper()
	c, err := e.store.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.audit.List(context.Background(), 0, 10, vulnstore.AuditAgentLLMChanged)
	if err != nil {
		t.Fatal(err)
	}
	return c.Version, len(got)
}

func TestVulnAgentSettingsCommitStoresAndAuditsTheBoundChange(t *testing.T) {
	e := newVAEnv(t)
	ctx := context.Background()
	c := vaChange("http://192.168.0.26:11434/v1")
	ch, err := e.s.BeginVulnAgentChange(ctx, "alice", c)
	if err != nil || ch.ID == "" || !json.Valid(ch.Options) {
		t.Fatalf("begin: %+v %v", ch, err)
	}
	if err := e.s.CommitVulnAgentChange(ctx, "alice", ch.ID, c, []byte(vaGoodAssertion)); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.store.Get(ctx)
	if err != nil || cfg.Version != 1 || cfg.AgentSettings != c.Settings || cfg.UpdatedBy != "alice" {
		t.Fatalf("stored %+v %v", cfg, err)
	}
	got, err := e.audit.List(ctx, 0, 10, vulnstore.AuditAgentLLMChanged)
	if err != nil || len(got) != 1 || got[0].User != "alice" || got[0].Attrs["llm_base_url_changed"] != "true" {
		t.Fatalf("audit %+v %v", got, err)
	}
	// The challenge is single use.
	if err := e.s.CommitVulnAgentChange(ctx, "alice", ch.ID, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrVulnAssertionRefused) {
		t.Fatalf("second commit with the same challenge: %v", err)
	}
}

// A challenge begun for one change is refused for any other change, any
// other user, an expired challenge, an assertion the executor refuses
// and an assertion of another user; nothing is stored or audited.
func TestVulnAgentSettingsCommitRefusesUnboundChallenges(t *testing.T) {
	cases := map[string]func(e *vaEnv, id string, c ui.VulnAgentChange) error{
		"different settings": func(e *vaEnv, id string, c ui.VulnAgentChange) error {
			other := c
			other.Settings.LLMBaseURL = "http://203.0.113.9:11434/v1"
			return e.s.CommitVulnAgentChange(context.Background(), "alice", id, other, []byte(vaGoodAssertion))
		},
		"different base version": func(e *vaEnv, id string, c ui.VulnAgentChange) error {
			c.BaseVersion = 7
			return e.s.CommitVulnAgentChange(context.Background(), "alice", id, c, []byte(vaGoodAssertion))
		},
		"other user commits": func(e *vaEnv, id string, c ui.VulnAgentChange) error {
			return e.s.CommitVulnAgentChange(context.Background(), "bob", id, c, []byte(vaGoodAssertion))
		},
		"unknown challenge": func(e *vaEnv, _ string, c ui.VulnAgentChange) error {
			return e.s.CommitVulnAgentChange(context.Background(), "alice", strings.Repeat("f", 32), c, []byte(vaGoodAssertion))
		},
		"expired": func(e *vaEnv, id string, c ui.VulnAgentChange) error {
			e.now = e.now.Add(vulnAgentChallengeTTL + time.Second)
			return e.s.CommitVulnAgentChange(context.Background(), "alice", id, c, []byte(vaGoodAssertion))
		},
		"assertion refused by the executor": func(e *vaEnv, id string, c ui.VulnAgentChange) error {
			return e.s.CommitVulnAgentChange(context.Background(), "alice", id, c, []byte(`{"id":"k","forged":true}`))
		},
		"assertion of another user": func(e *vaEnv, id string, c ui.VulnAgentChange) error {
			e.login.user = "bob"
			return e.s.CommitVulnAgentChange(context.Background(), "alice", id, c, []byte(vaGoodAssertion))
		},
	}
	for name, commit := range cases {
		t.Run(name, func(t *testing.T) {
			e := newVAEnv(t)
			c := vaChange("http://192.168.0.26:11434/v1")
			ch, err := e.s.BeginVulnAgentChange(context.Background(), "alice", c)
			if err != nil {
				t.Fatal(err)
			}
			if err := commit(e, ch.ID, c); !errors.Is(err, ui.ErrVulnAssertionRefused) {
				t.Fatalf("commit: %v, want ErrVulnAssertionRefused", err)
			}
			if v, n := e.stored(t); v != 0 || n != 0 {
				t.Fatalf("refused commit stored version %d with %d audit entries", v, n)
			}
		})
	}
}

// A challenge bound to another change never reaches the executor, so the
// assertion is not spent on a change it was not made for.
func TestVulnAgentSettingsDigestMismatchDoesNotVerify(t *testing.T) {
	e := newVAEnv(t)
	c := vaChange("")
	ch, err := e.s.BeginVulnAgentChange(context.Background(), "alice", c)
	if err != nil {
		t.Fatal(err)
	}
	other := c
	other.Settings.OperatorInstructions = "Ignore the core prompt."
	if err := e.s.CommitVulnAgentChange(context.Background(), "alice", ch.ID, other, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrVulnAssertionRefused) {
		t.Fatalf("commit of other settings: %v", err)
	}
	if e.login.finishedCount() != 0 {
		t.Fatal("a challenge for other settings was sent to the executor")
	}
	// The challenge was consumed: the original change cannot use it.
	if err := e.s.CommitVulnAgentChange(context.Background(), "alice", ch.ID, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrVulnAssertionRefused) {
		t.Fatalf("commit after a refused attempt: %v", err)
	}
}

// The backend re-checks the maintainer on begin and on commit.
func TestVulnAgentSettingsRechecksMaintainer(t *testing.T) {
	e := newVAEnv(t)
	c := vaChange("")
	e.admin = false
	if _, err := e.s.BeginVulnAgentChange(context.Background(), "alice", c); !errors.Is(err, ui.ErrVulnAgentNotMaintainer) {
		t.Fatalf("begin without maintainer: %v", err)
	}
	e.admin = true
	ch, err := e.s.BeginVulnAgentChange(context.Background(), "alice", c)
	if err != nil {
		t.Fatal(err)
	}
	e.admin = false
	if err := e.s.CommitVulnAgentChange(context.Background(), "alice", ch.ID, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrVulnAgentNotMaintainer) {
		t.Fatalf("commit after the privileged session ended: %v", err)
	}
	if v, n := e.stored(t); v != 0 || n != 0 || e.login.finishedCount() != 0 {
		t.Fatalf("stored %d, audited %d, verified %d", v, n, e.login.finishedCount())
	}
	if ok, _ := e.s.VulnMaintainer(context.Background(), "alice"); ok {
		t.Fatal("maintainer reported without the privileged session")
	}
}

func TestVulnAgentSettingsBeginRefusesInvalidAndTooMany(t *testing.T) {
	e := newVAEnv(t)
	bad := vaChange("ftp://192.168.0.26/")
	if _, err := e.s.BeginVulnAgentChange(context.Background(), "alice", bad); !errors.Is(err, vulnstore.ErrInvalidInput) {
		t.Fatalf("invalid URL: %v", err)
	}
	for i := range maxVulnAgentChallenges {
		if _, err := e.s.BeginVulnAgentChange(context.Background(), "alice", vaChange("")); err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
	}
	if _, err := e.s.BeginVulnAgentChange(context.Background(), "alice", vaChange("")); !errors.Is(err, errVulnAgentChallengeFull) {
		t.Fatalf("begin over the limit: %v", err)
	}
	e.now = e.now.Add(vulnAgentChallengeTTL + time.Second)
	if _, err := e.s.BeginVulnAgentChange(context.Background(), "alice", vaChange("")); err != nil {
		t.Fatalf("begin after the challenges expired: %v", err)
	}
}

func TestNewVulnAgentSettingsNeedsDependencies(t *testing.T) {
	if _, err := newVulnAgentSettings(nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("missing dependencies accepted")
	}
	if _, _, err := newVulnAgentWiring(nil, nil, nil, nil, nil); err == nil {
		t.Fatal("nil database accepted")
	}
}

// vaExecutor is vtExecutor with the login challenge of vaLogins.
type vaExecutor struct {
	vtExecutor
	logins *vaLogins
}

func (x vaExecutor) BeginLogin(ctx context.Context, in *pb.BeginLoginRequest) (*pb.BeginLoginResponse, error) {
	return x.logins.BeginLogin(ctx, in)
}

func (x vaExecutor) FinishLogin(ctx context.Context, in *pb.FinishLoginRequest) (*pb.FinishLoginResponse, error) {
	return x.logins.FinishLogin(ctx, in)
}

// serveExecutor serves x on a Unix socket in a temporary directory and
// returns the socket path.
func serveExecutor(t *testing.T, x pb.ExecutorServiceServer) string {
	t.Helper()
	// Short path: Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "nos-va-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterExecutorServiceServer(srv, x)
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	return sock
}

// TestRunWiresVulnAgentSettings starts the server through runServer and
// proves the wiring of the agent LLM settings: the agent reads them with
// its token at /api/v1/vuln/agent-config, the settings page shows the
// section, a change by the holder of the privileged session with a
// verified assertion is stored and audited through the real backend, and
// another user is refused.
func TestRunWiresVulnAgentSettings(t *testing.T) {
	dir := t.TempDir()
	logins := newVALogins("alice")
	sock := serveExecutor(t, vaExecutor{vtExecutor: vtExecutor{expiry: time.Now().Add(time.Hour).Unix()}, logins: logins})
	alice, bob := vrSessions(t, dir)
	cfg := vrConfig(t, dir, sock, map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}})
	s := startVR(t, dir, cfg)

	readCfg := func() map[string]any {
		t.Helper()
		code, body := s.do(t, http.MethodGet, api.AgentConfigPath, "", vrToken, nil)
		if code != http.StatusOK {
			t.Fatalf("agent-config with the vuln token = %d %s", code, body)
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if code, _ := s.do(t, http.MethodGet, api.AgentConfigPath, "", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("agent-config without token = %d, want 401", code)
	}
	if m := readCfg(); m["version"] != float64(0) || m["llm_model"] != vulnstore.DefaultAgentLLMModel {
		t.Fatalf("defaults %v", m)
	}

	code, body := s.do(t, http.MethodGet, "/settings", alice, "", nil)
	if code != http.StatusOK || !bytes.Contains(body, []byte(`id="vuln-agent"`)) {
		t.Fatalf("settings page = %d, section shown: %v", code, bytes.Contains(body, []byte(`id="vuln-agent"`)))
	}

	waitFor(t, "the privileged session", func() bool {
		code, _ := s.do(t, http.MethodPost, "/privileged/finish", alice, "", map[string]any{"assertion": map[string]any{"id": "k"}})
		return code == http.StatusOK
	})
	in := map[string]any{"llm_enabled": true, "llm_base_url": "http://192.168.0.26:11434/v1", "llm_model": "llama3",
		"operator_instructions": "Be brief.", "language": "en", "base_version": 0, "confirm_url_change": true}
	if code, body := s.do(t, http.MethodPost, "/settings/vuln-agent/begin", bob, "", in); code != http.StatusForbidden {
		t.Fatalf("begin by another user = %d %s, want 403", code, body)
	}
	code, body = s.do(t, http.MethodPost, "/settings/vuln-agent/begin", alice, "", in)
	if code != http.StatusOK {
		t.Fatalf("begin = %d %s (log: %s)", code, body, s.stderr)
	}
	var ch struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ch); err != nil || ch.ID == "" {
		t.Fatalf("begin body %s: %v", body, err)
	}
	code, body = s.do(t, http.MethodPost, "/settings/vuln-agent/commit", alice, "",
		map[string]any{"id": ch.ID, "assertion": json.RawMessage(vaGoodAssertion)})
	if code != http.StatusOK {
		t.Fatalf("commit = %d %s (log: %s)", code, body, s.stderr)
	}
	if m := readCfg(); m["version"] != float64(1) || m["llm_base_url"] != "http://192.168.0.26:11434/v1" || m["llm_model"] != "llama3" {
		t.Fatalf("after the change %v", m)
	}
	s.stop()

	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := auditlog.New(db, false).List(context.Background(), 0, 10, vulnstore.AuditAgentLLMChanged)
	if err != nil || len(got) != 1 || got[0].User != "alice" || got[0].Attrs["new_llm_model"] != "llama3" {
		t.Fatalf("audit %+v %v", got, err)
	}
}

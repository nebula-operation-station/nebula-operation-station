// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// opsSender records the events the real notifier delivers. fail makes the
// delivery fail.
type opsSender struct {
	mu     sync.Mutex
	fail   bool
	events []notify.Event
}

func (o *opsSender) Name() string { return "ops-test" }

func (o *opsSender) Send(_ context.Context, e notify.Event) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail {
		return errors.New("provider down")
	}
	o.events = append(o.events, e)
	return nil
}

func (o *opsSender) delivered() []notify.Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]notify.Event(nil), o.events...)
}

// opsEnv is the ops agent backend over the real settings store, the real
// audit log and the real notifier. The executor login is the fake of the
// vulnerability agent tests; admin is the maintainer check.
type opsEnv struct {
	s     *opsAgentSettings
	store *opsconfig.Store
	audit *auditlog.Store
	login *vaLogins
	sent  *opsSender
	admin bool
}

func newOpsEnv(t *testing.T) *opsEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &opsEnv{audit: auditlog.New(db, true), login: newVALogins("alice"), sent: &opsSender{}, admin: true}
	store, err := opsconfig.NewStore(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.store = store
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := notify.NewWithSenders(quiet, nil, e.sent)
	s, err := newOpsAgentSettings(store, e.audit, func(context.Context) bool { return e.admin }, e.login, n, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	e.s = s
	return e
}

// opsValid is a complete, valid settings value in the lab.
func opsValid() opsconfig.Settings {
	return opsconfig.Settings{Enabled: true, BaseURL: "http://10.0.0.20:11434/v1", Model: "qwen3.5-9b",
		AllowPlainHTTP: true, DataClass: opsconfig.DataClassLab, Language: opsconfig.LanguageDE,
		Instructions: "Prefer Debian trackers."}
}

// opsChange is a change of the valid settings at base version base.
func opsChange(base int64, mod func(s *opsconfig.Settings)) ui.OpsAgentChange {
	s := opsValid()
	if mod != nil {
		mod(&s)
	}
	return ui.OpsAgentChange{Settings: s, BaseVersion: base, URLChanged: true}
}

// stored returns the stored version and model.
func (e *opsEnv) stored(t *testing.T) (int64, string) {
	t.Helper()
	r, err := e.store.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r.Version, r.Model
}

// auditCount returns the number of settings-changed audit entries.
func (e *opsEnv) auditCount(t *testing.T) int {
	t.Helper()
	got, err := e.audit.List(context.Background(), 0, 100, opsconfig.AuditOpsAgentSettingsChanged)
	if err != nil {
		t.Fatal(err)
	}
	return len(got)
}

// beginAs begins a change as user and returns the challenge ID.
func (e *opsEnv) beginAs(t *testing.T, user string, c ui.OpsAgentChange) string {
	t.Helper()
	ch, err := e.s.BeginOpsAgentChange(context.Background(), user, c)
	if err != nil {
		t.Fatalf("begin as %s: %v", user, err)
	}
	if ch.ID == "" || !json.Valid(ch.Options) {
		t.Fatalf("begin returned no usable challenge: %+v", ch)
	}
	return ch.ID
}

// TestOpsAgentChangeThroughHandlerIsStoredAuditedAndNotified drives the real
// HTTP handler over the real backend. Without a session in the request the
// handler names the user "unknown"; the executor fake names the same user.
func TestOpsAgentChangeThroughHandlerIsStoredAuditedAndNotified(t *testing.T) {
	e := newOpsEnv(t)
	e.login.user = "unknown"
	uh, err := ui.New(ui.Options{PublicOrigin: "https://nebula.example.test", OpsAgent: e.s,
		TOTPStatus: func(context.Context) (*pb.GetTOTPStatusResponse, error) {
			return &pb.GetTOTPStatusResponse{Configured: true, Activated: true}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	h := uh.Handler()
	base, _ := e.stored(t)
	body := fmt.Sprintf(`{"enabled":true,"base_url":"http://10.0.0.20:11434/v1","model":"llama3.1-8b",`+
		`"allow_plain_http":true,"data_class":"lab","operator_instructions":"Prefer Debian trackers.",`+
		`"language":"de","base_version":%d,"confirm_url_change":true}`, base)
	id := opsPostOK(t, h, "/settings/ops-agent/begin", body, "id")
	if code := opsPostCode(t, h, "/settings/ops-agent/commit", `{"id":"`+id+`","assertion":`+vaGoodAssertion+`}`); code != http.StatusOK {
		t.Fatalf("commit = %d, want 200", code)
	}
	if v, model := e.stored(t); v != base+1 || model != "llama3.1-8b" {
		t.Fatalf("stored version %d model %q, want %d llama3.1-8b", v, model, base+1)
	}
	if n := e.auditCount(t); n != 1 {
		t.Fatalf("audit entries = %d, want 1", n)
	}
	events := e.sent.delivered()
	if len(events) != 1 || events[0].Kind != notify.KindOpsAgentSettingsChanged {
		t.Fatalf("events = %+v, want one settings_changed", events)
	}
	if want := fmt.Sprintf("Version %d -> %d.", base, base+1); !strings.Contains(events[0].Reason, want) {
		t.Errorf("event reason %q lacks %q", events[0].Reason, want)
	}
	if !strings.Contains(events[0].Reason, "-> llama3.1-8b") {
		t.Errorf("event reason %q lacks the model change", events[0].Reason)
	}
}

// A commit with the assertion of another change is refused; nothing is
// stored, audited or sent, and the challenge is used up.
func TestOpsAgentCommitRefusesAssertionOfAnotherChange(t *testing.T) {
	e := newOpsEnv(t)
	base, _ := e.stored(t)
	id := e.beginAs(t, "alice", opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" }))
	other := opsChange(base, func(s *opsconfig.Settings) { s.Model = "mistral-7b" })
	err := e.s.CommitOpsAgentChange(context.Background(), "alice", id, other, []byte(vaGoodAssertion))
	if !errors.Is(err, ui.ErrOpsAgentAssertionRefused) {
		t.Fatalf("commit with another change's digest = %v, want ErrOpsAgentAssertionRefused", err)
	}
	if v, model := e.stored(t); v != base || model == "mistral-7b" || model == "llama3.1-8b" {
		t.Fatalf("stored version %d model %q after a refused commit", v, model)
	}
	if e.auditCount(t) != 0 {
		t.Fatal("a refused commit was audited")
	}
	if e.auditCount(t) != 0 || len(e.sent.delivered()) != 0 {
		t.Fatal("a refused commit was audited or announced")
	}
}

// The challenge belongs to the user who began it, and the assertion must
// come from that user's credential.
func TestOpsAgentCommitRefusesOtherUsers(t *testing.T) {
	ctx := context.Background()
	t.Run("challenge of another user", func(t *testing.T) {
		e := newOpsEnv(t)
		base, _ := e.stored(t)
		c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
		id := e.beginAs(t, "alice", c)
		if err := e.s.CommitOpsAgentChange(ctx, "mallory", id, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrOpsAgentAssertionRefused) {
			t.Fatalf("commit by another user = %v, want ErrOpsAgentAssertionRefused", err)
		}
		if v, _ := e.stored(t); v != base {
			t.Fatalf("stored version %d after a refused commit", v)
		}
	})
	t.Run("assertion of another credential", func(t *testing.T) {
		e := newOpsEnv(t)
		base, _ := e.stored(t)
		c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
		id := e.beginAs(t, "alice", c)
		e.login.user = "bob"
		if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrOpsAgentAssertionRefused) {
			t.Fatalf("assertion of bob for alice = %v, want ErrOpsAgentAssertionRefused", err)
		}
		if v, _ := e.stored(t); v != base || e.auditCount(t) != 0 {
			t.Fatalf("stored version %d, audit entries %d after a refused commit", v, e.auditCount(t))
		}
	})
}

// The maintainer is needed at begin and again at commit.
func TestOpsAgentChangeNeedsMaintainerAtBeginAndCommit(t *testing.T) {
	ctx := context.Background()
	e := newOpsEnv(t)
	base, _ := e.stored(t)
	c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
	e.admin = false
	if _, err := e.s.BeginOpsAgentChange(ctx, "alice", c); !errors.Is(err, ui.ErrOpsAgentNotMaintainer) {
		t.Fatalf("begin as non-maintainer = %v, want ErrOpsAgentNotMaintainer", err)
	}
	e.admin = true
	id := e.beginAs(t, "alice", c)
	e.admin = false
	if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrOpsAgentNotMaintainer) {
		t.Fatalf("commit as non-maintainer = %v, want ErrOpsAgentNotMaintainer", err)
	}
	if v, _ := e.stored(t); v != base || e.auditCount(t) != 0 {
		t.Fatalf("stored version %d, audit entries %d after refused changes", v, e.auditCount(t))
	}
}

// A challenge is single use: a second commit with it is refused.
func TestOpsAgentChallengeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	e := newOpsEnv(t)
	base, _ := e.stored(t)
	c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
	id := e.beginAs(t, "alice", c)
	if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrOpsAgentAssertionRefused) {
		t.Fatalf("second commit with the same challenge = %v, want ErrOpsAgentAssertionRefused", err)
	}
	if e.auditCount(t) != 1 || len(e.sent.delivered()) != 1 {
		t.Fatalf("audit %d, events %d; want 1 each", e.auditCount(t), len(e.sent.delivered()))
	}
}

// Two changes begun on the same version: the second commit finds the
// stored version moved on. It is refused as stale, audited and announced
// nowhere.
func TestOpsAgentStaleCommitAuditsAndAnnouncesNothing(t *testing.T) {
	ctx := context.Background()
	e := newOpsEnv(t)
	base, _ := e.stored(t)
	a := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
	b := opsChange(base, func(s *opsconfig.Settings) { s.Model = "mistral-7b" })
	idA := e.beginAs(t, "alice", a)
	idB := e.beginAs(t, "alice", b)
	if err := e.s.CommitOpsAgentChange(ctx, "alice", idA, a, []byte(vaGoodAssertion)); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	if err := e.s.CommitOpsAgentChange(ctx, "alice", idB, b, []byte(vaGoodAssertion)); !errors.Is(err, opsconfig.ErrStale) {
		t.Fatalf("commit B on the old version = %v, want ErrStale", err)
	}
	if v, model := e.stored(t); v != base+1 || model != "llama3.1-8b" {
		t.Fatalf("stored version %d model %q; want the first change only", v, model)
	}
	if e.auditCount(t) != 1 || len(e.sent.delivered()) != 1 {
		t.Fatalf("audit %d, events %d; want 1 each", e.auditCount(t), len(e.sent.delivered()))
	}
}

// The change is kept when no provider accepts the event; the commit
// succeeds.
func TestOpsAgentDeliveryFailureDoesNotUndoTheChange(t *testing.T) {
	ctx := context.Background()
	e := newOpsEnv(t)
	e.sent.fail = true
	base, _ := e.stored(t)
	c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
	id := e.beginAs(t, "alice", c)
	if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); err != nil {
		t.Fatalf("commit with a failing notifier = %v, want nil", err)
	}
	if v, model := e.stored(t); v != base+1 || model != "llama3.1-8b" {
		t.Fatalf("stored version %d model %q; the change was undone", v, model)
	}
	if e.auditCount(t) != 1 {
		t.Fatalf("audit entries = %d, want 1", e.auditCount(t))
	}
}

// The pending challenges are bounded; the next begin is refused.
func TestOpsAgentBeginIsBoundedByPendingLimit(t *testing.T) {
	e := newOpsEnv(t)
	base, _ := e.stored(t)
	c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
	for i := 0; i < maxOpsAgentChallenges; i++ {
		e.beginAs(t, "alice", c)
	}
	if _, err := e.s.BeginOpsAgentChange(context.Background(), "alice", c); !errors.Is(err, errOpsAgentChallengeFull) {
		t.Fatalf("begin beyond the limit = %v, want errOpsAgentChallengeFull", err)
	}
}

// opsPostCode posts body to path on h and returns the status.
func opsPostCode(t *testing.T, h http.Handler, path, body string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	return rec.Code
}

// opsPostOK posts body, requires 200 and returns the string field key.
func opsPostOK(t *testing.T, h http.Handler, path, body, key string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d (%s), want 200", path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	v, _ := out[key].(string)
	if v == "" {
		t.Fatalf("POST %s returned no %q: %v", path, key, out)
	}
	return v
}

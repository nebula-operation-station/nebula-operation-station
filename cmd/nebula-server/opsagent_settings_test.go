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
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// opsSender records the events the real notifier delivers. fail makes the
// delivery fail.
type opsSender struct {
	mu     sync.Mutex
	fail   bool
	events []notify.Event
}

func (o *opsSender) Name() string { return "ops-test" }

func (o *opsSender) Send(ctx context.Context, e notify.Event) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("delivery context: %w", err)
	}
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

// opsLogins is the executor login fake of the ops agent tests. It issues a
// fresh login ID per begin and does not expire or single-use the logins: the
// backend's own binding in take must refuse a reused or foreign challenge,
// and the tests would fail if it did not. An assertion verifies when it is
// vaGoodAssertion and names user.
type opsLogins struct {
	mu       sync.Mutex
	n        int
	user     string
	begun    int
	finished int
}

func (l *opsLogins) BeginLogin(context.Context, *pb.BeginLoginRequest, ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n++
	l.begun++
	id := fmt.Sprintf("%032x", l.n)
	return &pb.BeginLoginResponse{LoginId: id, RequestOptionsJson: []byte(`{"challenge":"` + id + `"}`)}, nil
}

func (l *opsLogins) FinishLogin(_ context.Context, in *pb.FinishLoginRequest, _ ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.finished++
	if string(in.GetAssertionJson()) != vaGoodAssertion {
		return nil, status.Error(codes.Unauthenticated, "assertion not accepted")
	}
	return &pb.FinishLoginResponse{CredentialId: "k", UserName: l.user}, nil
}

func (l *opsLogins) counts() (begun, finished int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.begun, l.finished
}

// opsEnv is the ops agent backend over the real settings store, the real
// audit log and the real notifier. The clock is now. admin is the maintainer
// check.
type opsEnv struct {
	s        *opsAgentSettings
	store    *opsconfig.Store
	audit    *auditlog.Store
	login    *opsLogins
	sent     *opsSender
	notifier *notify.Notifier
	admin    bool
	now      time.Time
}

func newOpsEnv(t *testing.T) *opsEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &opsEnv{audit: auditlog.New(db, true), login: &opsLogins{user: "alice"}, sent: &opsSender{}, admin: true,
		now: time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)}
	store, err := opsconfig.NewStore(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.store = store
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	e.notifier = notify.NewWithSenders(quiet, nil, e.sent)
	s, err := newOpsAgentSettings(store, e.audit, func(context.Context) bool { return e.admin }, e.login, e.notifier,
		func() time.Time { return e.now }, quiet)
	if err != nil {
		t.Fatal(err)
	}
	e.s = s
	return e
}

// cancelAfterCommit cancels the request context when the backend hands the
// settings_changed event to the notifier, that is after the commit.
type cancelAfterCommit struct {
	inner  opsAgentNotifier
	cancel context.CancelFunc
}

func (c *cancelAfterCommit) NotifyOpsAgentSettingsChanged(ctx context.Context, change notify.OpsAgentSettingsChange, at time.Time) int {
	c.cancel()
	return c.inner.NotifyOpsAgentSettingsChanged(ctx, change, at)
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
		// The executor names mallory, so only the server's binding of the
		// challenge to alice can refuse this commit.
		e.login.user = "mallory"
		if err := e.s.CommitOpsAgentChange(ctx, "mallory", id, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrOpsAgentAssertionRefused) {
			t.Fatalf("commit by another user = %v, want ErrOpsAgentAssertionRefused", err)
		}
		if _, finished := e.login.counts(); finished != 0 {
			t.Fatalf("the executor verified an assertion for a challenge of another user (%d calls)", finished)
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

// A challenge is single use: a second commit with it is refused by the
// backend, before the executor is asked again. The fake executor accepts a
// reused login, so only take can refuse it.
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
	if _, finished := e.login.counts(); finished != 1 {
		t.Fatalf("executor verified %d assertions, want 1 (the reused challenge must not reach it)", finished)
	}
	if e.auditCount(t) != 1 || len(e.sent.delivered()) != 1 {
		t.Fatalf("audit %d, events %d; want 1 each", e.auditCount(t), len(e.sent.delivered()))
	}
}

// A begun change expires two minutes after the begin, on the backend's own
// clock: a commit at the expiry is refused without asking the executor.
func TestOpsAgentChallengeExpiresAfterTwoMinutes(t *testing.T) {
	ctx := context.Background()
	t.Run("live just before the expiry", func(t *testing.T) {
		e := newOpsEnv(t)
		base, _ := e.stored(t)
		c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
		id := e.beginAs(t, "alice", c)
		e.now = e.now.Add(opsAgentChallengeTTL - time.Second)
		if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); err != nil {
			t.Fatalf("commit one second before the expiry = %v, want nil", err)
		}
	})
	t.Run("refused at the expiry", func(t *testing.T) {
		e := newOpsEnv(t)
		base, _ := e.stored(t)
		c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
		id := e.beginAs(t, "alice", c)
		e.now = e.now.Add(opsAgentChallengeTTL)
		if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrOpsAgentAssertionRefused) {
			t.Fatalf("commit at the expiry = %v, want ErrOpsAgentAssertionRefused", err)
		}
		if _, finished := e.login.counts(); finished != 0 {
			t.Fatalf("executor asked for an expired challenge (%d calls)", finished)
		}
		if v, _ := e.stored(t); v != base || e.auditCount(t) != 0 {
			t.Fatalf("stored version %d, audit entries %d after an expired challenge", v, e.auditCount(t))
		}
	})
}

// The settings_changed event is sent after the commit on a context detached
// from the request: a request cancelled after the commit still delivers it.
func TestOpsAgentEventDeliveredAfterRequestCancelled(t *testing.T) {
	e := newOpsEnv(t)
	base, _ := e.stored(t)
	c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
	id := e.beginAs(t, "alice", c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.s.notifier = &cancelAfterCommit{inner: e.notifier, cancel: cancel}
	if err := e.s.CommitOpsAgentChange(ctx, "alice", id, c, []byte(vaGoodAssertion)); err != nil {
		t.Fatalf("commit with a request cancelled after the commit = %v, want nil", err)
	}
	if ctx.Err() == nil {
		t.Fatal("test setup: the request context was not cancelled")
	}
	if v, model := e.stored(t); v != base+1 || model != "llama3.1-8b" {
		t.Fatalf("stored version %d model %q; want the committed change", v, model)
	}
	events := e.sent.delivered()
	if len(events) != 1 || events[0].Kind != notify.KindOpsAgentSettingsChanged {
		t.Fatalf("events = %+v, want one settings_changed although the request was cancelled", events)
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

// The pending challenges are bounded; the next begin is refused before the
// executor is asked, so no challenge is left orphaned there. An expired
// challenge frees its slot.
func TestOpsAgentBeginIsBoundedByPendingLimit(t *testing.T) {
	ctx := context.Background()
	e := newOpsEnv(t)
	base, _ := e.stored(t)
	c := opsChange(base, func(s *opsconfig.Settings) { s.Model = "llama3.1-8b" })
	for i := 0; i < maxOpsAgentChallenges; i++ {
		e.beginAs(t, "alice", c)
	}
	if begun, _ := e.login.counts(); begun != maxOpsAgentChallenges {
		t.Fatalf("executor challenges = %d, want %d", begun, maxOpsAgentChallenges)
	}
	if _, err := e.s.BeginOpsAgentChange(ctx, "alice", c); !errors.Is(err, errOpsAgentChallengeFull) {
		t.Fatalf("begin beyond the limit = %v, want errOpsAgentChallengeFull", err)
	}
	if begun, _ := e.login.counts(); begun != maxOpsAgentChallenges {
		t.Fatalf("a begin refused as full asked the executor (%d challenges, want %d)", begun, maxOpsAgentChallenges)
	}
	e.now = e.now.Add(opsAgentChallengeTTL)
	e.beginAs(t, "alice", c)
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

// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the notifications inbox (ADR 0016 D10, AG-06). They cover: the
// list is read-only and newest first, hostile text is escaped, the cursor is
// parsed strictly (400 on anything else), the page is admin-only and fails
// closed, the empty and store-error states show fixed text, the outcome
// badges, the NOS-only link, and that the page has no inline script.
package ui_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// notifFakeLog is a notification log whose List always fails with err.
type notifFakeLog struct{ err error }

func (f notifFakeLog) List(context.Context, int64, int) ([]notifylog.Entry, error) {
	return nil, f.err
}

type notifEnv struct {
	t        *testing.T
	srv      *httptest.Server
	sessions *auth.Store
	store    *notifylog.Store
	admins   map[string]bool
	cookie   *http.Cookie
}

// newNotifEnv serves the UI with the notification log. A nil log uses a
// real store on a fresh server database. alice is the only admin unless
// adminErr is set, in which case the admin check fails for every user.
func newNotifEnv(t *testing.T, log ui.NotificationLog, adminErr error) *notifEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	clk := func() time.Time { return time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC) }
	e := &notifEnv{t: t, admins: map[string]bool{"alice": true}}
	if log == nil {
		s, err := notifylog.New(db, clk)
		if err != nil {
			t.Fatalf("notifylog.New: %v", err)
		}
		e.store = s
		log = s
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, err := ui.New(ui.Options{
		PublicOrigin:  pveOrigin,
		Log:           logger,
		Now:           clk,
		Notifications: log,
		NotificationsAdmin: func(_ context.Context, user string) (bool, error) {
			if adminErr != nil {
				return false, adminErr
			}
			return e.admins[user], nil
		},
	})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", u.Handler())
	e.sessions = auth.NewStore(db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: e.sessions, Log: logger})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	e.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: pveOrigin}, a.Wrap(mux)))
	t.Cleanup(e.srv.Close)
	e.cookie = e.session("cred-alice", "alice")
	return e
}

func (e *notifEnv) session(cred, user string) *http.Cookie {
	e.t.Helper()
	token, _, err := e.sessions.Create(context.Background(), cred, user)
	if err != nil {
		e.t.Fatalf("create session: %v", err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: token}
}

// get fetches path with cookie (nil: logged out) without following redirects.
func (e *notifEnv) get(cookie *http.Cookie, path string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	return res, string(body)
}

func notifRecord(host, outcome string) notifylog.Record {
	return notifylog.Record{
		Kind:      notifylog.KindLeaseRunFailed,
		Host:      host,
		State:     notifylog.StateFailed,
		Reason:    notifylog.ReasonTimeout,
		Outcome:   notifylog.Outcome(outcome),
		Providers: 1,
	}
}

func TestNotificationsListIsNewestFirst(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	for _, h := range []string{"web-1", "db-2", "nas-3"} {
		if _, err := e.store.Append(context.Background(), notifRecord(h, "sent")); err != nil {
			t.Fatal(err)
		}
	}
	res, body := e.get(e.cookie, "/notifications")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /notifications = %d, want 200", res.StatusCode)
	}
	i3, i2, i1 := strings.Index(body, "nas-3"), strings.Index(body, "db-2"), strings.Index(body, "web-1")
	if i3 < 0 || i2 < 0 || i1 < 0 || !(i3 < i2 && i2 < i1) {
		t.Errorf("rows not newest first: nas-3@%d db-2@%d web-1@%d", i3, i2, i1)
	}
}

func TestNotificationsHostileTextIsEscaped(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	// A host label with markup is refused by the store (shape check), so the
	// log can only hold plain labels. A NOS link may carry quotes and angle
	// brackets (printable ASCII, no spaces); the page must escape them.
	if _, err := e.store.Append(context.Background(), notifRecord("<script>x</script>", "sent")); err == nil {
		t.Fatal("append with markup host label accepted, want refusal")
	}
	r := notifRecord("web-1", "failed")
	r.ExecutionID = "ex-1"
	r.Link = `/"><svg/onload=alert(1)>`
	if _, err := e.store.Append(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	res, body := e.get(e.cookie, "/notifications")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d", res.StatusCode)
	}
	if strings.Contains(body, "<svg/onload") || strings.Contains(body, `"><svg`) {
		t.Errorf("hostile link reached the page unescaped")
	}
	if strings.Contains(body, "<script>x") {
		t.Errorf("markup host label reached the page")
	}
}

func TestNotificationsCursorIsStrict(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	if _, err := e.store.Append(context.Background(), notifRecord("web-1", "sent")); err != nil {
		t.Fatal(err)
	}
	bad := []string{"0", "-1", "+1", "abc", "1.5", "%201", "1e3", "9223372036854775808", "00000000000000000001", "1%2C2"}
	for _, c := range bad {
		res, _ := e.get(e.cookie, "/notifications?after="+c)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("after=%q = %d, want 400", c, res.StatusCode)
		}
	}
	res, _ := e.get(e.cookie, "/notifications?after=1&after=2")
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("repeated after = %d, want 400", res.StatusCode)
	}
	res, _ = e.get(e.cookie, "/notifications?after=1")
	if res.StatusCode != http.StatusOK {
		t.Errorf("after=1 = %d, want 200", res.StatusCode)
	}
}

func TestNotificationsPagesWithCursor(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	const n = 52 // one more than a page
	for i := 1; i <= n; i++ {
		if _, err := e.store.Append(context.Background(), notifRecord(fmt.Sprintf("h%03d", i), "sent")); err != nil {
			t.Fatal(err)
		}
	}
	_, page1 := e.get(e.cookie, "/notifications")
	if !strings.Contains(page1, "h052") || strings.Contains(page1, "h001") {
		t.Fatalf("first page does not hold the newest rows only")
	}
	m := regexp.MustCompile(`href="/notifications\?after=(\d+)"`).FindStringSubmatch(page1)
	if m == nil {
		t.Fatal("first page has no link to older entries")
	}
	_, page2 := e.get(e.cookie, "/notifications?after="+m[1])
	if !strings.Contains(page2, "h001") || strings.Contains(page2, "h052") {
		t.Errorf("second page does not continue after the cursor")
	}
}

func TestNotificationsNeedAdmin(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	if _, err := e.store.Append(context.Background(), notifRecord("secret-host", "sent")); err != nil {
		t.Fatal(err)
	}
	bob := e.session("cred-bob", "bob")
	res, body := e.get(bob, "/notifications")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("GET /notifications as non-admin = %d, want 403", res.StatusCode)
	}
	if strings.Contains(body, "secret-host") {
		t.Errorf("non-admin sees notification rows")
	}
	res, _ = e.get(nil, "/notifications")
	if res.StatusCode != http.StatusSeeOther && res.StatusCode != http.StatusFound {
		t.Errorf("GET /notifications logged out = %d, want redirect", res.StatusCode)
	}
}

func TestNotificationsAdminCheckErrorFailsClosed(t *testing.T) {
	e := newNotifEnv(t, nil, errors.New("executor down"))
	res, body := e.get(e.cookie, "/notifications")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("admin check error = %d, want 403", res.StatusCode)
	}
	if strings.Contains(body, "executor down") {
		t.Errorf("admin check error detail leaked")
	}
}

func TestNotificationsEmptyState(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	res, body := e.get(e.cookie, "/notifications")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d", res.StatusCode)
	}
	if !strings.Contains(body, "No notifications yet.") {
		t.Errorf("empty state text missing")
	}
}

func TestNotificationsStoreErrorShowsFixedText(t *testing.T) {
	e := newNotifEnv(t, notifFakeLog{err: errors.New("sql: secret detail 42")}, nil)
	res, body := e.get(e.cookie, "/notifications")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET with store error = %d", res.StatusCode)
	}
	if !strings.Contains(body, "Notifications unavailable") {
		t.Errorf("fixed unavailable text missing")
	}
	if strings.Contains(body, "secret detail") {
		t.Errorf("store error detail reached the page")
	}
}

func TestNotificationsOutcomeBadges(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	for _, c := range []struct{ host, outcome string }{
		{"a-sent", "sent"},
		{"a-held", "held_rate_limit"},
		{"a-mute", "held_muted"},
		{"a-fail", "failed"},
	} {
		if _, err := e.store.Append(context.Background(), notifRecord(c.host, c.outcome)); err != nil {
			t.Fatal(err)
		}
	}
	_, body := e.get(e.cookie, "/notifications")
	for _, want := range []string{"Sent", "Throttled", "Muted", "Failed"} {
		if !strings.Contains(body, `>`+want+`</span>`) {
			t.Errorf("badge %q missing", want)
		}
	}
}

func TestNotificationsLinkOnlyToNOSPath(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	r := notifRecord("web-1", "sent")
	r.ExecutionID = "ex-1"
	r.Link = "/operations/ex-1"
	if _, err := e.store.Append(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// A link the store would drop (scheme-relative) is never stored, so the
	// page cannot show it either.
	r2 := notifRecord("web-2", "sent")
	r2.Link = "//evil.example/x"
	if _, err := e.store.Append(context.Background(), r2); err != nil {
		t.Fatal(err)
	}
	_, body := e.get(e.cookie, "/notifications")
	if !strings.Contains(body, `href="/operations/ex-1"`) {
		t.Errorf("NOS execution link missing")
	}
	if strings.Contains(body, "evil.example") {
		t.Errorf("external link reached the page")
	}
}

func TestNotificationsPageHasNoInlineScript(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	res, body := e.get(e.cookie, "/notifications")
	for _, tag := range regexp.MustCompile(`<script[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(tag, " src=") {
			t.Errorf("inline script on the notifications page: %s", tag)
		}
	}
	if csp := res.Header.Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP allows inline scripts: %q", csp)
	}
	if !strings.Contains(body, `href="/notifications"`) {
		t.Errorf("navigation entry for Notifications missing")
	}
}

func TestNotificationsOnlyGET(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/notifications", strings.NewReader(""))
	req.Header.Set("Origin", pveOrigin)
	req.AddCookie(e.cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	// The mux answers 404 here (the "/" catch-all takes the POST); what
	// matters is that the inbox does not serve a write.
	if res.StatusCode != http.StatusNotFound && res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /notifications = %d, want 404 or 405", res.StatusCode)
	}
}

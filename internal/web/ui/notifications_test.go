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
	"sync/atomic"
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
	// adminCalls counts the admin checks the server ran.
	adminCalls atomic.Int32
}

// newNotifEnv serves the UI with the notification log. A nil log uses a
// real store on a fresh server database. alice is the only admin unless
// adminErr is set, in which case the admin check fails for every user.
func newNotifEnv(t *testing.T, log ui.NotificationLog, adminErr error) *notifEnv {
	t.Helper()
	return newNotifEnvWired(t, log, adminErr, true)
}

// newNotifEnvWired is newNotifEnv; with wired false the options carry no
// notification log and no admin check, so the inbox is off.
func newNotifEnvWired(t *testing.T, log ui.NotificationLog, adminErr error, wired bool) *notifEnv {
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
	opts := ui.Options{PublicOrigin: pveOrigin, Log: logger, Now: clk}
	if wired {
		opts.Notifications = log
		opts.NotificationsAdmin = func(_ context.Context, user string) (bool, error) {
			e.adminCalls.Add(1)
			if adminErr != nil {
				return false, adminErr
			}
			return e.admins[user], nil
		}
	}
	u, err := ui.New(opts)
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

// notifExecID is a lowercase UUIDv4, the only execution ID form the log accepts.
const notifExecID = "3f1c2b4e-5d6a-4b7c-8d9e-0f1a2b3c4d5e"

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
	r.ExecutionID = notifExecID
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

// notifMarkupLog returns one entry whose every displayed field holds markup.
// It stands in for a log that a broken write path or a future column could
// fill with markup; the page must still escape every field.
type notifMarkupLog struct{}

func (notifMarkupLog) List(context.Context, int64, int) ([]notifylog.Entry, error) {
	return []notifylog.Entry{{
		Seq: 1,
		At:  time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC),
		Record: notifylog.Record{
			Kind:        notifylog.KindCode("<kind-x>"),
			Host:        "<host-x>",
			State:       notifylog.StateCode("<state-x>"),
			Reason:      notifylog.ReasonCode("<reason-x>"),
			Outcome:     notifylog.Outcome("sent"),
			ExecutionID: "<exec-x>",
			Link:        `/"><svg/onload=alert(1)>`,
		},
	}}, nil
}

func TestNotificationsEveryFieldIsEscaped(t *testing.T) {
	e := newNotifEnv(t, notifMarkupLog{}, nil)
	res, body := e.get(e.cookie, "/notifications")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", res.StatusCode)
	}
	for _, raw := range []string{"<kind-x>", "<host-x>", "<state-x>", "<reason-x>", "<exec-x>", "<svg/onload", `"><svg`} {
		if strings.Contains(body, raw) {
			t.Errorf("unescaped %q reached the page", raw)
		}
	}
	for _, esc := range []string{"&lt;kind-x&gt;", "&lt;host-x&gt;", "&lt;state-x&gt;", "&lt;reason-x&gt;", "&lt;exec-x&gt;"} {
		if !strings.Contains(body, esc) {
			t.Errorf("escaped field %q missing: the row was not rendered", esc)
		}
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
	r.ExecutionID = notifExecID
	r.Link = "/operations/" + notifExecID
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
	if !strings.Contains(body, `href="/operations/`+notifExecID+`"`) {
		t.Errorf("NOS execution link missing")
	}
	if strings.Contains(body, "evil.example") {
		t.Errorf("external link reached the page")
	}
}

// notifRawLinkLog returns one entry whose link bypasses the store's write
// check, as a log filled by a broken write path could. The page must drop the
// link at render time and still show the row.
type notifRawLinkLog struct{ link string }

func (f notifRawLinkLog) List(context.Context, int64, int) ([]notifylog.Entry, error) {
	return []notifylog.Entry{{
		Seq: 1,
		At:  time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC),
		Record: notifylog.Record{
			Kind:        notifylog.KindLeaseRunFailed,
			Host:        "web-1",
			State:       notifylog.StateFailed,
			Reason:      notifylog.ReasonTimeout,
			Outcome:     notifylog.Outcome("sent"),
			ExecutionID: notifExecID,
			Link:        f.link,
		},
	}}, nil
}

// TestNotificationsDropsBadLinkAtRenderTime checks the render-time link rule
// through the handler: each bad link is absent from the markup, and the row
// stays. The good link case shows the same row keeps a valid link.
func TestNotificationsDropsBadLinkAtRenderTime(t *testing.T) {
	bad := []string{"//evil.example/x", "https://evil.example/x", `/a"b`, "/x?token=1", `/x\evil`}
	for _, link := range bad {
		e := newNotifEnv(t, notifRawLinkLog{link: link}, nil)
		res, body := e.get(e.cookie, "/notifications")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("link %q: GET = %d, want 200", link, res.StatusCode)
		}
		if strings.Contains(body, "evil.example") || strings.Contains(body, `href="`+link) {
			t.Errorf("link %q reached the page", link)
		}
		if !strings.Contains(body, "web-1") {
			t.Errorf("link %q: row missing from the page", link)
		}
	}
	e := newNotifEnv(t, notifRawLinkLog{link: "/operations/" + notifExecID}, nil)
	if _, body := e.get(e.cookie, "/notifications"); !strings.Contains(body, `href="/operations/`+notifExecID+`"`) {
		t.Errorf("valid NOS link missing: the render check drops too much")
	}
}

// TestNotificationsShowsExecutionIDAsText: the execution ID is shown as text
// in every row that has one, whether the row has a link or not. A missing or
// dropped link never hides the ID.
func TestNotificationsShowsExecutionIDAsText(t *testing.T) {
	for _, link := range []string{"", "//evil.example/x", "/x?token=1"} {
		e := newNotifEnv(t, notifRawLinkLog{link: link}, nil)
		res, body := e.get(e.cookie, "/notifications")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("link %q: GET = %d, want 200", link, res.StatusCode)
		}
		if !strings.Contains(body, ">"+notifExecID+"<") {
			t.Errorf("link %q: execution ID not shown as text", link)
		}
		if strings.Contains(body, "evil.example") || strings.Contains(body, "token=1") {
			t.Errorf("link %q reached the page", link)
		}
	}
	e := newNotifEnv(t, notifRawLinkLog{link: "/operations/" + notifExecID}, nil)
	if _, body := e.get(e.cookie, "/notifications"); !strings.Contains(body, `href="/operations/`+notifExecID+`">`+notifExecID+`</a>`) {
		t.Errorf("valid link: want the execution ID as the link text")
	}
}

// TestNotificationsAdminCheckRunsOncePerRequest: the page needs the admin
// check for the 403 decision and for the navigation entry; it runs once.
func TestNotificationsAdminCheckRunsOncePerRequest(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	if res, _ := e.get(e.cookie, "/notifications"); res.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", res.StatusCode)
	}
	if n := e.adminCalls.Load(); n != 1 {
		t.Errorf("admin checks for one page view = %d, want 1", n)
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
	csp := res.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	script := ""
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "script-src ") || d == "script-src" {
			script = d
		}
	}
	if script == "" {
		t.Fatalf("CSP has no script-src directive: %q", csp)
	}
	if !strings.Contains(script, "'self'") || strings.Contains(script, "unsafe-inline") {
		t.Errorf("script-src must be 'self' without unsafe-inline, got %q", script)
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

// notifNavPages are pages that render the shared layout and must keep
// rendering with or without the notifications navigation entry.
var notifNavPages = []string{"/dashboard", "/inventory", "/help", "/settings", "/network", "/history", "/operations", "/runbooks"}

const notifNavHref = `href="/notifications"`

func TestNotificationsNavHiddenWithoutInbox(t *testing.T) {
	e := newNotifEnvWired(t, nil, nil, false)
	for _, p := range notifNavPages {
		res, body := e.get(e.cookie, p)
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s without inbox = %d, want 200", p, res.StatusCode)
		}
		if strings.Contains(body, notifNavHref) {
			t.Errorf("GET %s without inbox: navigation entry for Notifications shown", p)
		}
	}
	res, _ := e.get(e.cookie, "/notifications")
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("GET /notifications without inbox = %d, want 404", res.StatusCode)
	}
}

func TestNotificationsNavHiddenForNonAdmin(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	bob := e.session("cred-bob", "bob")
	for _, p := range notifNavPages {
		res, body := e.get(bob, p)
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s as non-admin = %d, want 200", p, res.StatusCode)
		}
		if strings.Contains(body, notifNavHref) {
			t.Errorf("GET %s as non-admin: navigation entry for Notifications shown", p)
		}
	}
}

func TestNotificationsNavHiddenWhenAdminCheckFails(t *testing.T) {
	e := newNotifEnv(t, nil, errors.New("executor down"))
	for _, p := range notifNavPages {
		res, body := e.get(e.cookie, p)
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s with admin check error = %d, want 200", p, res.StatusCode)
		}
		if strings.Contains(body, notifNavHref) {
			t.Errorf("GET %s with admin check error: navigation entry shown", p)
		}
	}
}

func TestNotificationsNavShownForAdmin(t *testing.T) {
	e := newNotifEnv(t, nil, nil)
	for _, p := range notifNavPages {
		res, body := e.get(e.cookie, p)
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s as admin = %d, want 200", p, res.StatusCode)
		}
		if !strings.Contains(body, notifNavHref) {
			t.Errorf("GET %s as admin: navigation entry for Notifications missing", p)
		}
	}
}

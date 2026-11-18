// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// rejectEnv is the full web stack (real web sessions and the privileged
// holder check) over fakeOps. alice opened the executor's privileged session
// when open is true; bob is logged in but holds nothing.
type rejectEnv struct {
	srv   *httptest.Server
	alice *http.Cookie
	bob   *http.Cookie
}

func newRejectEnv(t *testing.T, ops ui.Operations, open bool) *rejectEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &linkClock{t: time.Now()}
	sessions := auth.NewStore(db, clk.now)
	st := &linkStatus{active: false, expiry: clk.now().Add(15 * time.Minute).Unix()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, err := ui.New(ui.Options{PublicOrigin: pveOrigin, Log: log, Status: st, Operations: ops})
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Options{Executor: linkExec{status: st}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	e := &rejectEnv{srv: httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: pveOrigin}, a.Wrap(u.Handler())))}
	t.Cleanup(e.srv.Close)
	e.alice = cookieFor(t, sessions, "cred-alice", "alice")
	e.bob = cookieFor(t, sessions, "cred-bob", "bob")
	if open {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/privileged/finish", strings.NewReader(`{"assertion":{"id":"k"}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", pveOrigin)
		req.AddCookie(e.alice)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("privileged finish = %d", res.StatusCode)
		}
		st.active = true
	}
	return e
}

// cookieFor opens a web session for cred of user.
func cookieFor(t *testing.T, sessions *auth.Store, cred, user string) *http.Cookie {
	t.Helper()
	token, _, err := sessions.Create(context.Background(), cred, user)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: token}
}

// do sends one request with the given Origin and cookie and returns the status
// and the body.
func (e *rejectEnv) do(t *testing.T, method, path string, form url.Values, origin string, c *http.Cookie) (int, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if c != nil {
		req.AddCookie(c)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// pendingList is a list with one pending and one rejected operation.
func pendingList() []executions.Summary {
	return []executions.Summary{
		{ID: opID, ActionID: "core.facts", Risk: "HIGH", State: "pending", CreatedBy: "alice", CreatedAt: time.Unix(1791960000, 0), Hosts: 1},
		// Another action and time, so the two are not grouped as one batch.
		{ID: idB, ActionID: "core.other", Risk: "HIGH", State: "rejected", CreatedBy: "bob", CreatedAt: time.Unix(1791950000, 0), Hosts: 1},
	}
}

// TestRejectNeedsThePrivilegedSessionOfThisLogin: without an open privileged
// session, and with one held by another login, the reject pages and the form
// answer 403 and the service is never called.
func TestRejectNeedsThePrivilegedSessionOfThisLogin(t *testing.T) {
	f := &fakeOps{}
	closed := newRejectEnv(t, f, false)
	held := newRejectEnv(t, f, true)
	form := url.Values{"id": {opID}}
	for name, tc := range map[string]struct {
		e *rejectEnv
		c *http.Cookie
	}{
		"no session open":         {closed, closed.alice},
		"open, but another login": {held, held.bob},
	} {
		t.Run(name, func(t *testing.T) {
			if code, body := tc.e.do(t, http.MethodGet, "/operations/reject/confirm?id="+opID, nil, "", tc.c); code != http.StatusForbidden || !strings.Contains(body, "privileged session") {
				t.Errorf("confirm: %d %s", code, body)
			}
			if code, body := tc.e.do(t, http.MethodPost, "/operations/reject/form", form, pveOrigin, tc.c); code != http.StatusForbidden || !strings.Contains(body, "privileged session") {
				t.Errorf("form: %d %s", code, body)
			}
		})
	}
	if len(f.rejects) != 0 {
		t.Fatalf("refused requests reached the service: %v", f.rejects)
	}
}

// TestRejectFormRefusesForeignOrMissingOrigin: the reject is a state change,
// so the security middleware refuses a POST without this server's Origin
// before the handler runs (the same CSRF guard as the other operations POSTs).
func TestRejectFormRefusesForeignOrMissingOrigin(t *testing.T) {
	f := &fakeOps{}
	e := newRejectEnv(t, f, true)
	form := url.Values{"id": {opID}}
	for _, origin := range []string{"", "https://evil.example.net", "null"} {
		if code, _ := e.do(t, http.MethodPost, "/operations/reject/form", form, origin, e.alice); code != http.StatusForbidden {
			t.Errorf("origin %q: status %d, want 403", origin, code)
		}
	}
	if len(f.rejects) != 0 {
		t.Fatalf("refused posts reached the service: %v", f.rejects)
	}
	if code, body := e.do(t, http.MethodPost, "/operations/reject/form", form, pveOrigin, e.alice); code != http.StatusOK || !strings.Contains(body, "rejected") {
		t.Fatalf("own origin: %d %s", code, body)
	}
}

// TestRejectFormAnswersEachRowWithItsOwnError: a mixed selection rejects what
// it can and reports every other row with its reason. Executor internals are
// not shown; malformed IDs never reach the service.
func TestRejectFormAnswersEachRowWithItsOwnError(t *testing.T) {
	f := &fakeOps{rejectErrs: map[string]error{
		idB: executions.ErrNotPending,
		idC: status.Error(codes.FailedPrecondition, "privileged session required"),
		idD: errors.New("socket /run/secret.sock: refused"),
	}}
	e := newRejectEnv(t, f, true)
	form := url.Values{"id": {opID, idB, idC, idD, "not an id"}, "reason": {"wrong host"}}
	code, body := e.do(t, http.MethodPost, "/operations/reject/form", form, pveOrigin, e.alice)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	want := []string{"alice " + opID + " wrong host", "alice " + idB + " wrong host", "alice " + idC + " wrong host", "alice " + idD + " wrong host"}
	if !reflect.DeepEqual(f.rejects, want) {
		t.Fatalf("rejects %v, want %v", f.rejects, want)
	}
	for _, msg := range []string{"rejected", "not waiting for approval any more", "the executor refused: privileged session required", "executor unavailable", "invalid operation id"} {
		if !strings.Contains(body, msg) {
			t.Errorf("result misses %q: %s", msg, body)
		}
	}
	if strings.Contains(body, "secret") {
		t.Errorf("executor internals shown: %s", body)
	}
}

// TestRejectFormRefusesALongReasonBeforeTheExecutor: a reason over 200
// characters, over 800 bytes or with a control character is refused for the
// whole request, and the service is not called.
func TestRejectFormRefusesALongReasonBeforeTheExecutor(t *testing.T) {
	f := &fakeOps{}
	e := newRejectEnv(t, f, true)
	for name, reason := range map[string]string{
		"201 characters": strings.Repeat("a", 201),
		"801 bytes":      strings.Repeat("ö", 401),
		"newline":        "a\nb",
	} {
		form := url.Values{"id": {opID}, "reason": {reason}}
		if code, _ := e.do(t, http.MethodPost, "/operations/reject/form", form, pveOrigin, e.alice); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
	if len(f.rejects) != 0 {
		t.Fatalf("refused reasons reached the service: %v", f.rejects)
	}
}

// TestRejectConfirmOffersOnlyPendingRows: the confirmation page carries the
// reason field and a hidden ID only for pending operations; it is a GET and
// changes nothing.
func TestRejectConfirmOffersOnlyPendingRows(t *testing.T) {
	f := &fakeOps{exec: executions.Execution{ID: opID, State: "pending", Digest: strings.Repeat("d", 64)}}
	e := newRejectEnv(t, f, true)
	code, body := e.do(t, http.MethodGet, "/operations/reject/confirm?id="+opID+"&id="+idB, nil, "", e.alice)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if !strings.Contains(body, `<input type="hidden" name="id" value="`+opID+`">`) {
		t.Fatalf("pending row not offered: %s", body)
	}
	if !strings.Contains(body, `name="reason" maxlength="200"`) || !strings.Contains(body, `action="/operations/reject/form"`) {
		t.Fatalf("confirm page misses the reason field or the form: %s", body)
	}
	if strings.Contains(body, `name="id" value="`+idB+`"`) {
		t.Fatalf("row that is not pending is submitted: %s", body)
	}
	if len(f.rejects) != 0 {
		t.Fatalf("GET rejected something: %v", f.rejects)
	}
}

// TestOperationsListOffersRejectOnlyToThePrivilegedSession: the pending row
// gets the reject control and the rejected state is shown with its own badge,
// distinct from expired; without the privileged session no reject control.
func TestOperationsListOffersRejectOnlyToThePrivilegedSession(t *testing.T) {
	f := &fakeOps{list: pendingList()}
	open := newRejectEnv(t, f, true)
	closed := newRejectEnv(t, f, false)

	code, body := open.do(t, http.MethodGet, "/operations", nil, "", open.alice)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{`form="reject-select"`, `href="/operations/reject/confirm?id=` + opID + `"`, `badge badge--rejected">rejected`} {
		if !strings.Contains(body, want) {
			t.Errorf("privileged list misses %q", want)
		}
	}
	if strings.Contains(body, `badge--expired`) {
		t.Errorf("rejected row shown with the expired badge")
	}

	_, body = closed.do(t, http.MethodGet, "/operations", nil, "", closed.alice)
	if strings.Contains(body, "reject-select") || strings.Contains(body, "/operations/reject/confirm") {
		t.Errorf("list offers rejection without a privileged session: %s", body)
	}
	if !strings.Contains(body, `badge badge--rejected">rejected`) {
		t.Errorf("rejected state not shown without a privileged session")
	}
}

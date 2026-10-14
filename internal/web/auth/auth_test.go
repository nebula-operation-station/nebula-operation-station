// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const origin = "https://nebula.example.org"

type fakeExec struct {
	mu          sync.Mutex
	beginErr    error
	finishErr   error
	regErr      error
	gotCode     string
	gotFinish   *pb.FinishLoginRequest
	gotRegister *pb.FinishRegistrationRequest

	gotPrivileged *pb.CompletePrivilegedSessionRequest
	privErr       error
	locked        int

	removed  map[string]bool
	checks   int
	checkErr error
}

func (f *fakeExec) BeginLogin(context.Context, *pb.BeginLoginRequest, ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return &pb.BeginLoginResponse{LoginId: "L1", RequestOptionsJson: []byte(`{"publicKey":{"challenge":"AAAA"}}`)}, nil
}

func (f *fakeExec) FinishLogin(_ context.Context, in *pb.FinishLoginRequest, _ ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	f.mu.Lock()
	f.gotFinish = in
	f.mu.Unlock()
	if f.finishErr != nil {
		return nil, f.finishErr
	}
	return &pb.FinishLoginResponse{CredentialId: "Y3JlZA", UserName: "axel"}, nil
}

func (f *fakeExec) BeginRegistration(_ context.Context, in *pb.BeginRegistrationRequest, _ ...grpc.CallOption) (*pb.BeginRegistrationResponse, error) {
	f.gotCode = in.GetCode()
	if f.regErr != nil {
		return nil, f.regErr
	}
	return &pb.BeginRegistrationResponse{RegistrationId: "R1", CreationOptionsJson: []byte(`{"publicKey":{}}`),
		AuthorizationOptionsJson: []byte(`{"publicKey":{}}`)}, nil
}

func (f *fakeExec) FinishRegistration(_ context.Context, in *pb.FinishRegistrationRequest, _ ...grpc.CallOption) (*pb.FinishRegistrationResponse, error) {
	f.gotRegister = in
	return &pb.FinishRegistrationResponse{}, nil
}

func (f *fakeExec) BeginPrivilegedSession(context.Context, *pb.BeginPrivilegedSessionRequest, ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error) {
	return &pb.BeginPrivilegedSessionResponse{RequestOptionsJson: []byte(`{"publicKey":{"challenge":"BBBB"}}`)}, nil
}

func (f *fakeExec) CompletePrivilegedSession(_ context.Context, in *pb.CompletePrivilegedSessionRequest, _ ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	f.mu.Lock()
	f.gotPrivileged = in
	f.mu.Unlock()
	if f.privErr != nil {
		return nil, f.privErr
	}
	return &pb.CompletePrivilegedSessionResponse{SessionExpiryUnix: 1234}, nil
}

func (f *fakeExec) Lock(context.Context, *pb.LockRequest, ...grpc.CallOption) (*pb.LockResponse, error) {
	f.mu.Lock()
	f.locked++
	f.mu.Unlock()
	return &pb.LockResponse{}, nil
}

func (f *fakeExec) CheckCredential(_ context.Context, in *pb.CheckCredentialRequest, _ ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	return &pb.CheckCredentialResponse{Registered: !f.removed[in.GetCredentialId()]}, nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type env struct {
	t     *testing.T
	exec  *fakeExec
	srv   *httptest.Server
	db    *sql.DB
	clk   *clock
	store *auth.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{t: t, exec: &fakeExec{}, db: db, clk: &clock{t: time.Now()}}
	e.store = auth.NewStore(db, e.clk.now)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := auth.New(auth.Options{Executor: e.exec, Sessions: e.store, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	u, err := ui.New(ui.Options{PublicOrigin: origin, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: origin}, a.Wrap(u.Handler())))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(method, path, body string, cookie *http.Cookie) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { res.Body.Close() })
	return res
}

func jsonBody(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func sessionCookie(res *http.Response) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == auth.CookieName {
			return c
		}
	}
	return nil
}

func (e *env) login() *http.Cookie {
	e.t.Helper()
	res := e.do("POST", "/login/finish", `{"login_id":"L1","assertion":{"id":"x"}}`, nil)
	if res.StatusCode != 200 {
		e.t.Fatalf("login status %d", res.StatusCode)
	}
	c := sessionCookie(res)
	if c == nil {
		e.t.Fatal("no session cookie")
	}
	return c
}

func TestPagesNeedASession(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/dashboard", "/inventory", "/settings", "/", "/anything"} {
		res := e.do("GET", p, "", nil)
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
			t.Errorf("GET %s: %d %q", p, res.StatusCode, res.Header.Get("Location"))
		}
	}
	res := e.do("POST", "/dashboard", `{}`, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST without session: %d", res.StatusCode)
	}
	// A made-up cookie does not help.
	res = e.do("GET", "/dashboard", "", &http.Cookie{Name: auth.CookieName, Value: strings.Repeat("A", 43)})
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("forged cookie: %d", res.StatusCode)
	}
}

func TestLoginAndSetupPagesArePublic(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/login", "/setup", "/static/login.js", "/static/setup.js", "/static/webauthn.js", "/static/nav.js", "/static/app.css"} {
		if res := e.do("GET", p, "", nil); res.StatusCode != 200 {
			t.Errorf("GET %s: %d", p, res.StatusCode)
		}
	}
	res := e.do("GET", "/login", "", nil)
	b, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(b), `src="/static/login.js"`) || strings.Contains(string(b), `href="/inventory"`) {
		t.Fatalf("login page: %s", b)
	}
}

func TestLoginCreatesASecureSession(t *testing.T) {
	e := newEnv(t)
	res := e.do("POST", "/login/begin", `{}`, nil)
	m := jsonBody(t, res)
	if res.StatusCode != 200 || m["login_id"] != "L1" || m["options"] == nil {
		t.Fatalf("begin: %d %v", res.StatusCode, m)
	}
	c := e.login()
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie attributes %+v", c)
	}
	if e.exec.gotFinish.GetLoginId() != "L1" || string(e.exec.gotFinish.GetAssertionJson()) != `{"id":"x"}` {
		t.Fatalf("relayed %v", e.exec.gotFinish)
	}
	if res := e.do("GET", "/dashboard", "", c); res.StatusCode != 200 {
		t.Fatalf("dashboard with session: %d", res.StatusCode)
	}
	// Only the hash of the token is stored.
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM web_sessions WHERE token_hash = ? OR CAST(token_hash AS TEXT) = ?`, c.Value, c.Value).Scan(&n); err != nil || n != 0 {
		t.Fatalf("token stored in clear: %d %v", n, err)
	}
}

func TestFailedLoginGivesNoSession(t *testing.T) {
	e := newEnv(t)
	e.exec.finishErr = status.Error(codes.Unauthenticated, "login_rejected: webauthn: assertion invalid (detail)")
	res := e.do("POST", "/login/finish", `{"login_id":"L1","assertion":{}}`, nil)
	m := jsonBody(t, res)
	if res.StatusCode != 400 || m["error"] != "security key not accepted" || sessionCookie(res) != nil {
		t.Fatalf("failed login: %d %v", res.StatusCode, m)
	}
	e.exec.beginErr = status.Error(codes.FailedPrecondition, "no_credentials")
	res = e.do("POST", "/login/begin", `{}`, nil)
	if m := jsonBody(t, res); res.StatusCode != http.StatusConflict || m["setup"] != true {
		t.Fatalf("no credentials: %d %v", res.StatusCode, m)
	}
	e.exec.beginErr = status.Error(codes.Unavailable, "socket /run/nebula/executor.sock: connection refused")
	res = e.do("POST", "/login/begin", `{}`, nil)
	if m := jsonBody(t, res); res.StatusCode != 503 || strings.Contains(m["error"].(string), "sock") {
		t.Fatalf("executor down: %d %v", res.StatusCode, m)
	}
}

func TestRequestsAreStrict(t *testing.T) {
	e := newEnv(t)
	if res := e.do("POST", "/login/finish", `{"login_id":"L1","assertion":{},"extra":1}`, nil); res.StatusCode != 400 {
		t.Errorf("unknown field: %d", res.StatusCode)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/login/finish", strings.NewReader(`{"login_id":"L1"}`))
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "text/plain")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", res.StatusCode)
	}
	// Cross-origin: rejected by the security middleware before auth.
	req, _ = http.NewRequest("POST", e.srv.URL+"/login/finish", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || e.exec.gotFinish != nil {
		t.Errorf("cross-origin: %d", res.StatusCode)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t)
	c := e.login()
	res := e.do("POST", "/logout", ``, c)
	if res.StatusCode != http.StatusOK || sessionCookie(res) == nil || sessionCookie(res).MaxAge >= 0 {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	if res := e.do("GET", "/dashboard", "", c); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("old cookie still valid: %d", res.StatusCode)
	}
}

func TestSessionsExpire(t *testing.T) {
	e := newEnv(t)
	c := e.login()
	e.clk.add(auth.IdleTimeout + time.Minute)
	if res := e.do("GET", "/dashboard", "", c); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("idle session still valid: %d", res.StatusCode)
	}

	// Activity keeps a session alive, but not past the absolute limit.
	c = e.login()
	for elapsed := time.Duration(0); elapsed < auth.AbsoluteTimeout-auth.IdleTimeout; elapsed += auth.IdleTimeout / 2 {
		e.clk.add(auth.IdleTimeout / 2)
		if res := e.do("GET", "/dashboard", "", c); res.StatusCode != 200 {
			t.Fatalf("active session dropped after %v: %d", elapsed, res.StatusCode)
		}
	}
	e.clk.add(auth.IdleTimeout)
	if res := e.do("GET", "/dashboard", "", c); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("session past absolute timeout: %d", res.StatusCode)
	}
}

func TestSetupRelaysToTheExecutor(t *testing.T) {
	e := newEnv(t)
	res := e.do("POST", "/setup/begin", `{"code":"ABCD-EFGH"}`, nil)
	m := jsonBody(t, res)
	if res.StatusCode != 200 || e.exec.gotCode != "ABCD-EFGH" || m["registration_id"] != "R1" || m["authorization_options"] == nil {
		t.Fatalf("setup begin: %d %v", res.StatusCode, m)
	}
	res = e.do("POST", "/setup/finish", `{"registration_id":"R1","attestation":{"a":1},"assertion":{"b":2}}`, nil)
	if res.StatusCode != 200 || string(e.exec.gotRegister.GetAttestationJson()) != `{"a":1}` || string(e.exec.gotRegister.GetAssertionJson()) != `{"b":2}` {
		t.Fatalf("setup finish: %d %v", res.StatusCode, e.exec.gotRegister)
	}
	if sessionCookie(res) != nil {
		t.Fatal("registration opened a session")
	}
	e.exec.regErr = status.Error(codes.Unauthenticated, "registration_code_invalid")
	res = e.do("POST", "/setup/begin", `{"code":"wrong"}`, nil)
	if m := jsonBody(t, res); res.StatusCode != 400 || m["error"] != "registration code invalid or expired" {
		t.Fatalf("wrong code: %d %v", res.StatusCode, m)
	}
}

func TestStorePruneAndDeleteAll(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, _, err := e.store.Create(ctx, "Y3JlZA", "axel"); err != nil {
			t.Fatal(err)
		}
	}
	e.clk.add(auth.IdleTimeout + time.Second)
	if n, err := e.store.Prune(ctx); err != nil || n != 3 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, _, err := e.store.Create(ctx, "Y3JlZA", "axel"); err != nil {
		t.Fatal(err)
	}
	if n, err := e.store.DeleteAll(ctx); err != nil || n != 1 {
		t.Fatalf("delete all: %d %v", n, err)
	}
	if _, err := e.store.Lookup(ctx, "not-a-token"); err != auth.ErrNoSession {
		t.Fatalf("malformed token: %v", err)
	}
}

func TestPrivilegedSessionAndLockNeedAWebSession(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/privileged/begin", "/privileged/finish", "/executor/lock"} {
		if res := e.do("POST", p, `{}`, nil); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST %s without session: %d", p, res.StatusCode)
		}
	}
	if e.exec.locked != 0 || e.exec.gotPrivileged != nil {
		t.Fatal("executor called without a web session")
	}
	c := e.login()
	res := e.do("POST", "/privileged/begin", `{}`, c)
	if m := jsonBody(t, res); res.StatusCode != 200 || m["options"] == nil {
		t.Fatalf("begin: %d %v", res.StatusCode, m)
	}
	res = e.do("POST", "/privileged/finish", `{"assertion":{"id":"k"}}`, c)
	if m := jsonBody(t, res); res.StatusCode != 200 || m["expiry_unix"] != float64(1234) || string(e.exec.gotPrivileged.GetAssertionJson()) != `{"id":"k"}` {
		t.Fatalf("finish: %d %v", res.StatusCode, m)
	}
	e.exec.privErr = status.Error(codes.PermissionDenied, "assertion_rejected: detail")
	res = e.do("POST", "/privileged/finish", `{"assertion":{}}`, c)
	if m := jsonBody(t, res); res.StatusCode != 400 || m["error"] != "security key not accepted" {
		t.Fatalf("rejected: %d %v", res.StatusCode, m)
	}
	if res := e.do("POST", "/executor/lock", `{}`, c); res.StatusCode != 200 || e.exec.locked != 1 {
		t.Fatalf("lock: %d %d", res.StatusCode, e.exec.locked)
	}
	// GET is not allowed on these endpoints.
	if res := e.do("GET", "/executor/lock", "", c); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET lock: %d", res.StatusCode)
	}
}

func TestRemovedCredentialEndsTheWebSession(t *testing.T) {
	e := newEnv(t)
	c := e.login()
	if res := e.do("GET", "/dashboard", "", c); res.StatusCode != 200 {
		t.Fatalf("dashboard: %d", res.StatusCode)
	}
	// Checked once, then cached for the interval.
	e.do("GET", "/dashboard", "", c)
	if e.exec.checks != 1 {
		t.Fatalf("%d credential checks, want 1", e.exec.checks)
	}

	// Executor unreachable: the session stays.
	e.exec.mu.Lock()
	e.exec.checkErr = status.Error(codes.Unavailable, "down")
	e.exec.mu.Unlock()
	c2 := e.login()
	if res := e.do("GET", "/dashboard", "", c2); res.StatusCode != 200 {
		t.Fatalf("session dropped while the executor is down: %d", res.StatusCode)
	}

	// The credential is removed on the executor: the next check ends both sessions.
	e.exec.mu.Lock()
	e.exec.checkErr = nil
	e.exec.removed = map[string]bool{"Y3JlZA": true}
	e.exec.mu.Unlock()
	if res := e.do("GET", "/dashboard", "", c2); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("session of a removed credential still valid: %d", res.StatusCode)
	}
	if res := e.do("GET", "/dashboard", "", c2); res.StatusCode != http.StatusSeeOther {
		t.Fatal("revoked session came back")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the privileged-session holder: the web session whose
// credential opened the executor's privileged session through POST
// /privileged/finish. Only that web session holds it, only for that
// executor session (its expiry), and only until it expires, the executor
// is locked from the web, the web session logs out or its credential is
// removed. Who may open a privileged session is unchanged.

package auth_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
)

// newHolderEnv serves the login chain around a probe at GET /probe?exp=N
// that answers what the auth package says about the request: whether it
// holds the privileged session with executor expiry N, and the recorded
// holder.
func newHolderEnv(t *testing.T) *env {
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
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exp, _ := strconv.ParseInt(r.URL.Query().Get("exp"), 10, 64)
		cred, user, ok := auth.PrivilegedHolder(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"holds":`+strconv.FormatBool(auth.HoldsPrivilegedSession(r.Context(), exp))+
			`,"ok":`+strconv.FormatBool(ok)+`,"cred":`+strconv.Quote(cred)+`,"user":`+strconv.Quote(user)+`}`)
	})
	e.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: origin}, a.Wrap(probe)))
	t.Cleanup(e.srv.Close)
	return e
}

// loginAs opens a web session for credential cred of user.
func (e *env) loginAs(cred, user string) *http.Cookie {
	e.t.Helper()
	e.exec.mu.Lock()
	e.exec.loginCred, e.exec.loginUser = cred, user
	e.exec.mu.Unlock()
	return e.login()
}

// openPrivileged completes a privileged session from the web session c;
// the executor reports expiry exp.
func (e *env) openPrivileged(c *http.Cookie, exp int64) {
	e.t.Helper()
	e.exec.mu.Lock()
	e.exec.privExpiry, e.exec.privErr = exp, nil
	e.exec.mu.Unlock()
	if res := e.do("POST", "/privileged/finish", `{"assertion":{"id":"k"}}`, c); res.StatusCode != 200 {
		e.t.Fatalf("privileged finish: %d", res.StatusCode)
	}
}

type probeResult struct {
	holds, ok  bool
	cred, user string
}

func (e *env) probe(c *http.Cookie, exp int64) probeResult {
	e.t.Helper()
	res := e.do("GET", "/probe?exp="+strconv.FormatInt(exp, 10), "", c)
	if res.StatusCode != 200 {
		e.t.Fatalf("probe: %d", res.StatusCode)
	}
	m := jsonBody(e.t, res)
	return probeResult{holds: m["holds"] == true, ok: m["ok"] == true, cred: m["cred"].(string), user: m["user"].(string)}
}

func TestPrivilegedHolderIsTheOpeningWebSession(t *testing.T) {
	e := newHolderEnv(t)
	exp := e.clk.now().Add(15 * time.Minute).Unix()
	alice := e.loginAs("cred-alice", "alice")
	bob := e.loginAs("cred-bob", "bob")

	if p := e.probe(alice, exp); p.holds || p.ok {
		t.Fatalf("before any privileged session: %+v", p)
	}
	e.openPrivileged(alice, exp)

	if p := e.probe(alice, exp); !p.holds || !p.ok || p.cred != "cred-alice" || p.user != "alice" {
		t.Fatalf("holder: %+v, want alice holding", p)
	}
	// Another logged-in user sees who holds it but does not hold it.
	if p := e.probe(bob, exp); p.holds || !p.ok || p.cred != "cred-alice" {
		t.Fatalf("other user: %+v, want not holding, holder alice", p)
	}
	// A second web session of the same credential is a different session.
	alice2 := e.loginAs("cred-alice", "alice")
	if p := e.probe(alice2, exp); p.holds {
		t.Fatalf("second web session of the holder's credential holds the session: %+v", p)
	}
	// An executor session with another expiry was opened elsewhere (CLI,
	// or reopened after a lock that bypassed the web): not this holder's.
	for _, other := range []int64{exp + 1, exp - 1, 0, -1} {
		if p := e.probe(alice, other); p.holds {
			t.Errorf("executor expiry %d: holder still holds", other)
		}
	}
}

func TestPrivilegedHolderReplacedOnlyBySuccessfulOpen(t *testing.T) {
	e := newHolderEnv(t)
	exp := e.clk.now().Add(15 * time.Minute).Unix()
	alice := e.loginAs("cred-alice", "alice")
	bob := e.loginAs("cred-bob", "bob")
	e.openPrivileged(alice, exp)

	// Bob's rejected assertion changes nothing.
	e.exec.mu.Lock()
	e.exec.privErr = status.Error(codes.PermissionDenied, "assertion_rejected")
	e.exec.mu.Unlock()
	if res := e.do("POST", "/privileged/finish", `{"assertion":{}}`, bob); res.StatusCode != 400 {
		t.Fatalf("rejected finish: %d", res.StatusCode)
	}
	if p := e.probe(alice, exp); !p.holds {
		t.Fatalf("a rejected open by another user dropped the holder: %+v", p)
	}
	if p := e.probe(bob, exp); p.holds {
		t.Fatalf("a rejected open made bob the holder: %+v", p)
	}

	// Bob's accepted assertion makes him the holder of the new session.
	exp2 := exp + 60
	e.openPrivileged(bob, exp2)
	if p := e.probe(bob, exp2); !p.holds || p.cred != "cred-bob" || p.user != "bob" {
		t.Fatalf("bob after open: %+v", p)
	}
	if p := e.probe(alice, exp2); p.holds {
		t.Fatalf("alice still holds after bob opened: %+v", p)
	}
}

func TestPrivilegedHolderEndsWithExpiry(t *testing.T) {
	e := newHolderEnv(t)
	exp := e.clk.now().Add(15 * time.Minute).Unix()
	alice := e.loginAs("cred-alice", "alice")
	e.openPrivileged(alice, exp)
	e.clk.add(15*time.Minute + time.Second)
	if p := e.probe(alice, exp); p.holds || p.ok {
		t.Fatalf("after expiry: %+v", p)
	}
	// An executor that answers an expiry already in the past records nothing.
	e.openPrivileged(alice, e.clk.now().Add(-time.Second).Unix())
	if p := e.probe(alice, e.clk.now().Add(-time.Second).Unix()); p.holds || p.ok {
		t.Fatalf("expired at open: %+v", p)
	}
}

func TestPrivilegedHolderEndsWithWebLock(t *testing.T) {
	e := newHolderEnv(t)
	exp := e.clk.now().Add(15 * time.Minute).Unix()
	alice := e.loginAs("cred-alice", "alice")
	bob := e.loginAs("cred-bob", "bob")
	e.openPrivileged(alice, exp)
	// Any web user may lock the executor; the lock ends the holder too.
	if res := e.do("POST", "/executor/lock", `{}`, bob); res.StatusCode != 200 {
		t.Fatalf("lock: %d", res.StatusCode)
	}
	if p := e.probe(alice, exp); p.holds || p.ok {
		t.Fatalf("after lock: %+v", p)
	}
}

func TestPrivilegedHolderEndsWithItsLogoutOnly(t *testing.T) {
	e := newHolderEnv(t)
	exp := e.clk.now().Add(15 * time.Minute).Unix()
	alice := e.loginAs("cred-alice", "alice")
	bob := e.loginAs("cred-bob", "bob")
	e.openPrivileged(alice, exp)

	if res := e.do("POST", "/logout", `{}`, bob); res.StatusCode != 200 {
		t.Fatalf("bob logout: %d", res.StatusCode)
	}
	if p := e.probe(alice, exp); !p.holds {
		t.Fatalf("another user's logout dropped the holder: %+v", p)
	}
	if res := e.do("POST", "/logout", `{}`, alice); res.StatusCode != 200 {
		t.Fatalf("alice logout: %d", res.StatusCode)
	}
	// A fresh login of the same credential does not inherit the holder.
	again := e.loginAs("cred-alice", "alice")
	if p := e.probe(again, exp); p.holds || p.ok {
		t.Fatalf("after the holder logged out: %+v", p)
	}
}

func TestPrivilegedHolderEndsWhenItsCredentialIsRemoved(t *testing.T) {
	e := newHolderEnv(t)
	exp := e.clk.now().Add(15 * time.Minute).Unix()
	alice := e.loginAs("cred-alice", "alice")
	bob := e.loginAs("cred-bob", "bob")
	e.openPrivileged(alice, exp)

	e.exec.mu.Lock()
	e.exec.removed = map[string]bool{"cred-alice": true}
	e.exec.mu.Unlock()
	e.clk.add(auth.CredentialCheckInterval)
	if res := e.do("GET", "/probe?exp=1", "", alice); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoked session: %d, want redirect to login", res.StatusCode)
	}
	if p := e.probe(bob, exp); p.ok || p.holds {
		t.Fatalf("holder survived the removal of its credential: %+v", p)
	}
}

func TestPrivilegedHolderOutsideTheLoginChain(t *testing.T) {
	ctx := context.Background()
	if cred, user, ok := auth.PrivilegedHolder(ctx); ok || cred != "" || user != "" {
		t.Fatalf("PrivilegedHolder without a request: %q %q %v", cred, user, ok)
	}
	if auth.HoldsPrivilegedSession(ctx, time.Now().Add(time.Minute).Unix()) {
		t.Fatal("HoldsPrivilegedSession without a request reported true")
	}
}

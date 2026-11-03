// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// The live chart renews its visible boxes every 10 s from an open tab.
// That background POST must not count as activity: an unattended chart
// tab still runs into the idle timeout.
func TestLiveTargetRenewalDoesNotKeepSessionAlive(t *testing.T) {
	const step = 5 * time.Minute // the touch interval: a normal request moves last_seen every time
	renew := func(e *env, c *http.Cookie) int {
		t.Helper()
		return e.do(http.MethodPost, auth.LiveTargetsPath, `{"viewer":"x","boxes":[]}`, c).StatusCode
	}
	authenticated := func(code int) bool { return code != http.StatusUnauthorized && code != http.StatusSeeOther }

	e := newEnv(t)
	c := e.login()
	for elapsed := step; elapsed < auth.IdleTimeout; elapsed += step {
		e.clk.add(step)
		if code := renew(e, c); !authenticated(code) {
			t.Fatalf("renewal after %v: %d, session should still be valid", elapsed, code)
		}
	}
	e.clk.add(step)
	if code := renew(e, c); authenticated(code) {
		t.Fatalf("renewal past idle timeout: %d, want unauthenticated", code)
	}
	if res := e.do("GET", "/dashboard", "", c); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("live renewals kept the session alive: %d", res.StatusCode)
	}
}

// Only the renewal POST is exempt: other POSTs and other methods on the
// same path are activity as before.
func TestOnlyLiveRenewalPostIsPassive(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/inventory/refresh"},
		{http.MethodPost, auth.LiveTargetsPath + "/x"},
		{http.MethodPut, auth.LiveTargetsPath},
		{http.MethodGet, auth.LiveTargetsPath},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			e := newEnv(t)
			c := e.login()
			e.clk.add(auth.IdleTimeout - time.Minute)
			e.do(tc.method, tc.path, `{}`, c)
			e.clk.add(2 * time.Minute)
			if res := e.do("GET", "/dashboard", "", c); res.StatusCode != http.StatusOK {
				t.Fatalf("%s %s was not recorded as activity: %d", tc.method, tc.path, res.StatusCode)
			}
		})
	}
}

// revEnv is a session store and login handler without the HTTP stack.
type revEnv struct {
	exec  *fakeExec
	clk   *clock
	store *auth.Store
	login *auth.Handler
}

func newRevEnv(t *testing.T) *revEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &revEnv{exec: &fakeExec{}, clk: &clock{t: time.Now()}}
	e.store = auth.NewStore(db, e.clk.now)
	e.login, err = auth.New(auth.Options{Executor: e.exec, Sessions: e.store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// PeekRegistered is the open live stream's re-check: it ends the session
// of a removed credential, keeps it while the executor is unreachable,
// and never records activity.
func TestPeekRegisteredEndsSessionOfRemovedCredential(t *testing.T) {
	ctx := context.Background()
	e := newRevEnv(t)
	tok, created, err := e.store.Create(ctx, "Y3JlZA", "axel")
	if err != nil {
		t.Fatal(err)
	}
	e.clk.add(10 * time.Minute)
	sess, err := e.login.PeekRegistered(ctx, tok)
	if err != nil {
		t.Fatalf("valid session: %v", err)
	}
	if !sess.LastSeenAt.Equal(created.LastSeenAt) {
		t.Fatalf("PeekRegistered recorded activity: last_seen %v, want %v", sess.LastSeenAt, created.LastSeenAt)
	}
	if e.exec.checks != 1 {
		t.Fatalf("%d credential checks, want 1", e.exec.checks)
	}

	// Executor down: the session stays.
	e.exec.mu.Lock()
	e.exec.checkErr = status.Error(codes.Unavailable, "down")
	e.exec.mu.Unlock()
	e.clk.add(auth.CredentialCheckInterval)
	if _, err := e.login.PeekRegistered(ctx, tok); err != nil {
		t.Fatalf("session dropped while the executor is down: %v", err)
	}

	// Credential removed: the next check ends the session.
	e.exec.mu.Lock()
	e.exec.checkErr = nil
	e.exec.removed = map[string]bool{"Y3JlZA": true}
	e.exec.mu.Unlock()
	if _, err := e.login.PeekRegistered(ctx, tok); !errors.Is(err, auth.ErrNoSession) {
		t.Fatalf("session of a removed credential: err %v, want ErrNoSession", err)
	}
	if _, err := e.store.Peek(ctx, tok); !errors.Is(err, auth.ErrNoSession) {
		t.Fatalf("revoked session still stored: %v", err)
	}
}

func TestPeekRegisteredRejectsUnknownSession(t *testing.T) {
	e := newRevEnv(t)
	for _, tok := range []string{"", "not-base64!", "AAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := e.login.PeekRegistered(context.Background(), tok); !errors.Is(err, auth.ErrNoSession) {
			t.Fatalf("token %q: err %v, want ErrNoSession", tok, err)
		}
	}
	if e.exec.checks != 0 {
		t.Fatalf("executor asked %d times for an unknown session", e.exec.checks)
	}
}

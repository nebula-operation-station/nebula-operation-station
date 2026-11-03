// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// credExec is the executor surface login.Wrap uses on every request:
// every credential is still registered. Other methods are not called.
type credExec struct{ auth.Executor }

func (credExec) CheckCredential(context.Context, *pb.CheckCredentialRequest, ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	return &pb.CheckCredentialResponse{Registered: true}, nil
}

// newLogin returns a real session store and login wrapper on a fresh
// server DB, and two sessions of different credentials.
func newLogin(t *testing.T) (*auth.Store, *auth.Handler, [2]string, [2]auth.Session) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: credExec{}, Sessions: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	var toks [2]string
	var sess [2]auth.Session
	for i, cred := range []string{"cred-a", "cred-b"} {
		if toks[i], sess[i], err = store.Create(context.Background(), cred, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	return store, login, toks, sess
}

func withCookie(r *http.Request, token string) *http.Request {
	r = r.Clone(r.Context())
	r.Header.Del("Cookie")
	r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	return r
}

// The re-check binds a stream to the session login.Wrap authenticated
// it with: the same cookie passes; another valid session's cookie on
// the same request (credential and CreatedAt differ) does not.
func TestPeekSessionRequiresTheWrappedSession(t *testing.T) {
	store, login, toks, sess := newLogin(t)
	recheck := PeekSession(store.Peek)
	type result struct {
		exp           time.Time
		same, other   bool
		hasWrapperCtx bool
	}
	got := make(chan result, 1)
	h := login.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var res result
		_, res.hasWrapperCtx = auth.SessionFrom(r.Context())
		res.exp, res.same = recheck(r.Context(), r)
		_, res.other = recheck(r.Context(), withCookie(r, toks[1]))
		got <- res
	}))
	r := withCookie(httptest.NewRequest(http.MethodGet, EventsPath, nil), toks[0])
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	var res result
	select {
	case res = <-got:
	default:
		t.Fatalf("login.Wrap did not reach the handler: %d", rec.Code)
	}
	if !res.hasWrapperCtx {
		t.Fatal("no login.Wrap session in the request context")
	}
	if !res.same || !res.exp.Equal(sess[0].ExpiresAt) {
		t.Fatalf("own session: ok %v, expiry %v (want %v)", res.same, res.exp, sess[0].ExpiresAt)
	}
	if res.other {
		t.Fatal("another session's cookie passed the re-check of this stream")
	}
}

// End to end through login.Wrap and the session store: logging out
// (deleting the session) ends the open stream and frees its slot.
func TestLogoutThroughLoginWrapEndsStream(t *testing.T) {
	store, login, toks, _ := newLogin(t)
	h, _, _ := newRecHub(t)
	hd, err := New(Options{Hub: h, Recheck: PeekSession(store.Peek)})
	if err != nil {
		t.Fatal(err)
	}
	hd.recheckEvery = 50 * time.Millisecond
	mux := http.NewServeMux()
	hd.Register(mux)
	srv := httptest.NewServer(login.Wrap(mux))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+EventsPath, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: toks[0]})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events = %d", resp.StatusCode)
	}
	time.Sleep(200 * time.Millisecond)
	if n := viewerCount(h); n != 1 {
		t.Fatalf("viewers = %d while logged in, want 1", n)
	}
	if err := store.Delete(context.Background(), toks[0]); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream still open 5 s after logout")
	}
	deadline := time.Now().Add(5 * time.Second)
	for viewerCount(h) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("slot not freed after logout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

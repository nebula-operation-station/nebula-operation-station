// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// withServerFeatures replaces the feature registry for one test.
func withServerFeatures(t *testing.T, fs ...serverFeature) {
	t.Helper()
	saved := serverFeatures
	serverFeatures = fs
	t.Cleanup(func() { serverFeatures = saved })
}

// TestFeatureNamesRunInOrder: hooks run in name order, not registration order.
func TestFeatureNamesRunInOrder(t *testing.T) {
	var seen []string
	hook := func(name string) serverFeature {
		return serverFeature{name: name, options: func(serverDeps, *ui.Options) error {
			seen = append(seen, name)
			return nil
		}}
	}
	withServerFeatures(t, hook("charlie"), hook("alpha"), hook("bravo"))
	if err := applyServerFeatureOptions(serverDeps{}, &ui.Options{}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"alpha", "bravo", "charlie"}; !slices.Equal(seen, want) {
		t.Fatalf("hook order = %v, want %v", seen, want)
	}
}

// TestDuplicateFeatureNameStopsStart: two features with one name are a
// startup error for every phase, and the error names the feature.
func TestDuplicateFeatureNameStopsStart(t *testing.T) {
	noop := func(serverDeps, *ui.Options) error { return nil }
	withServerFeatures(t, serverFeature{name: "dup", options: noop}, serverFeature{name: "dup", options: noop})
	err := applyServerFeatureOptions(serverDeps{}, &ui.Options{})
	if !errors.Is(err, errDuplicateFeature) || !strings.Contains(err.Error(), `"dup"`) {
		t.Fatalf("duplicate name: err = %v, want errDuplicateFeature naming \"dup\"", err)
	}
	if err := mountServerFeaturePages(serverDeps{}, http.NewServeMux()); !errors.Is(err, errDuplicateFeature) {
		t.Fatalf("duplicate name, pages: err = %v, want errDuplicateFeature", err)
	}
}

// TestEmptyFeatureNameStopsStart: a feature without a name is refused.
func TestEmptyFeatureNameStopsStart(t *testing.T) {
	withServerFeatures(t, serverFeature{name: "", options: func(serverDeps, *ui.Options) error { return nil }})
	if err := applyServerFeatureOptions(serverDeps{}, &ui.Options{}); !errors.Is(err, errBadFeature) {
		t.Fatalf("empty name: err = %v, want errBadFeature", err)
	}
}

// TestFeatureHookErrorNamesFeature: a failing hook stops the start with the
// feature name and keeps the cause for errors.Is.
func TestFeatureHookErrorNamesFeature(t *testing.T) {
	cause := errors.New("boom")
	withServerFeatures(t,
		serverFeature{name: "widget", options: func(serverDeps, *ui.Options) error { return cause }},
	)
	err := applyServerFeatureOptions(serverDeps{}, &ui.Options{})
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "widget") {
		t.Fatalf("options hook error: err = %v, want the cause and the name widget", err)
	}
	withServerFeatures(t,
		serverFeature{name: "widget", pages: func(serverDeps, *http.ServeMux) error { return cause }},
	)
	if err := mountServerFeaturePages(serverDeps{}, http.NewServeMux()); !errors.Is(err, cause) || !strings.Contains(err.Error(), "widget") {
		t.Fatalf("pages hook error: err = %v, want the cause and the name widget", err)
	}
}

// TestFeatureRouteConflictIsStartError: a page hook that registers a route
// the mux already has fails the start with the feature name; it does not
// panic and does not replace the existing route.
func TestFeatureRouteConflictIsStartError(t *testing.T) {
	pages := http.NewServeMux()
	pages.Handle("GET /taken", http.NotFoundHandler())
	withServerFeatures(t, serverFeature{name: "clash", pages: func(_ serverDeps, mux *http.ServeMux) error {
		mux.Handle("GET /taken", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		return nil
	}})
	err := mountServerFeaturePages(serverDeps{}, pages)
	if err == nil || !strings.Contains(err.Error(), "clash") {
		t.Fatalf("route conflict: err = %v, want an error naming clash", err)
	}
}

// TestFeatureHookSeesUIOptionsByPointer: the options hook edits the value
// the caller then passes to ui.New; no copy is made behind its back.
func TestFeatureHookSeesUIOptionsByPointer(t *testing.T) {
	var got *ui.Options
	withServerFeatures(t, serverFeature{name: "opts", options: func(_ serverDeps, o *ui.Options) error {
		got = o
		o.PublicOrigin = "https://changed.example.org"
		return nil
	}})
	o := ui.Options{PublicOrigin: swOrigin}
	if err := applyServerFeatureOptions(serverDeps{}, &o); err != nil {
		t.Fatal(err)
	}
	if got != &o || o.PublicOrigin != "https://changed.example.org" {
		t.Fatalf("options hook: pointer same = %v, origin = %q", got == &o, o.PublicOrigin)
	}
}

// TestFeatureHooksThroughWebServer is the real path: one test feature with
// its options and pages hooks, served by webServer. The page route answers
// like every other page: 303 to /login without a session, 200 with one.
func TestFeatureHooksThroughWebServer(t *testing.T) {
	const pagePath = "/feature-test/page"
	var optsSeen *ui.Options
	withServerFeatures(t, serverFeature{
		name: "feature-test",
		options: func(_ serverDeps, o *ui.Options) error {
			optsSeen = o
			return nil
		},
		pages: func(_ serverDeps, mux *http.ServeMux) error {
			mux.Handle("GET "+pagePath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			return nil
		},
	})

	o := ui.Options{PublicOrigin: swOrigin}
	if err := applyServerFeatureOptions(serverDeps{}, &o); err != nil {
		t.Fatal(err)
	}
	if optsSeen != &o {
		t.Fatal("options hook did not get the ui.Options passed to ui.New")
	}

	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(context.Background(), "cred-feature", "admin")
	if err != nil {
		t.Fatal(err)
	}

	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	if err := mountServerFeaturePages(serverDeps{}, pages); err != nil {
		t.Fatal(err)
	}
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	do := func(path, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, swOrigin+path, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		return rec
	}

	// Without a session the new page behaves like the login-gated pages.
	if rec := do(pagePath, ""); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("page without session: status %d location %q, want 303 to /login", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(pagePath, token); rec.Code != http.StatusOK {
		t.Fatalf("page with session: status %d, want 200", rec.Code)
	}
}

// calleeName returns "pkg.Func" for a selector on an identifier, "Func" for
// a plain identifier, and "" for anything else.
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
	}
	return ""
}

// TestRunServerWiresFeaturesInOrder reads runServer in main.go. The hooks
// must see the ui.Options before ui.New, and the feature pages must be
// mounted on the pages mux after its own routes and before webServer. A
// test that calls the two phases itself cannot see main.go drop or move
// them; this one fails when that happens.
func TestRunServerWiresFeaturesInOrder(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "runServer" {
			body = fd.Body
		}
	}
	if body == nil {
		t.Fatal("runServer not found in main.go")
	}
	type site struct {
		pos  token.Pos
		args []ast.Expr
	}
	calls := map[string][]site{}
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if name := calleeName(c.Fun); name != "" {
				calls[name] = append(calls[name], site{c.Pos(), c.Args})
			}
		}
		return true
	})
	one := func(name string) site {
		t.Helper()
		s := calls[name]
		if len(s) != 1 {
			t.Fatalf("runServer calls %s %d times, want exactly 1", name, len(s))
		}
		return s[0]
	}
	ident := func(e ast.Expr, want string) {
		t.Helper()
		if id, ok := e.(*ast.Ident); !ok || id.Name != want {
			t.Fatalf("argument = %T, want identifier %s", e, want)
		}
	}

	opts := one("applyServerFeatureOptions")
	uiNew := one("ui.New")
	ident(opts.args[0], "deps")
	if u, ok := opts.args[1].(*ast.UnaryExpr); !ok || u.Op != token.AND {
		t.Fatalf("applyServerFeatureOptions second argument is not &uiOpts")
	} else {
		ident(u.X, "uiOpts")
	}
	ident(uiNew.args[0], "uiOpts")
	if opts.pos >= uiNew.pos {
		t.Fatal("applyServerFeatureOptions must run before ui.New")
	}

	mount := one("mountServerFeaturePages")
	ident(mount.args[0], "deps")
	ident(mount.args[1], "pages")
	webSrv := one("webServer")
	if mount.pos >= webSrv.pos {
		t.Fatal("mountServerFeaturePages must run before webServer")
	}
	// The mount comes after every route main.go registers on pages, so the
	// feature pages are added last, as reviewed.
	for _, s := range calls["pages.Handle"] {
		if s.pos > mount.pos {
			t.Fatal("mountServerFeaturePages must come after every pages.Handle route")
		}
	}
}

// TestBackgroundRunRefusedAfterClose: a feature that starts a loop after
// shutdown has begun gets an error and no goroutine; the loops started before
// it are still waited for.
func TestBackgroundRunRefusedAfterClose(t *testing.T) {
	var wg sync.WaitGroup
	runs := newBackgroundRuns(&wg)
	started := make(chan struct{})
	if err := runs.Go(func() { close(started) }); err != nil {
		t.Fatalf("run before close: %v", err)
	}
	<-started
	runs.Close()
	err := runs.Go(func() { t.Error("loop started after shutdown began") })
	if !errors.Is(err, errServerStopping) {
		t.Fatalf("run after close: err = %v, want errServerStopping", err)
	}
	wg.Wait()
}

// TestFeatureRunRefusedAfterCloseIsSeenByFeature: the feature gets the error
// from serverDeps.run, so it can stop its own setup.
func TestFeatureRunRefusedAfterCloseIsSeenByFeature(t *testing.T) {
	var wg sync.WaitGroup
	runs := newBackgroundRuns(&wg)
	runs.Close()
	deps := serverDeps{run: func(f func(context.Context)) error { return runs.Go(func() { f(context.Background()) }) }}
	if err := deps.run(func(context.Context) { t.Error("loop ran after close") }); !errors.Is(err, errServerStopping) {
		t.Fatalf("serverDeps.run after close: err = %v, want errServerStopping", err)
	}
	wg.Wait()
}

// expectedServerFeatures are the features the real registry must hold. A
// feature file whose init() is removed or renamed fails here, not silently.
var expectedServerFeatures = []string{"attackpaths"}

// TestRealRegistryHoldsExpectedFeatures reads the registry the server runs
// with (no withServerFeatures swap): every expected feature is registered
// exactly once with a pages hook, and the names are valid.
func TestRealRegistryHoldsExpectedFeatures(t *testing.T) {
	if _, err := orderServerFeatures(serverFeatures); err != nil {
		t.Fatalf("real registry: %v", err)
	}
	for _, want := range expectedServerFeatures {
		n := 0
		for _, f := range serverFeatures {
			if f.name != want {
				continue
			}
			n++
			if f.pages == nil {
				t.Errorf("feature %s has no pages hook", want)
			}
		}
		if n != 1 {
			t.Errorf("feature %s registered %d times, want 1", want, n)
		}
	}
}

// TestRealRegistryMountsPagesThroughRegistry: mountServerFeaturePages on the
// real registry serves the attack-path page behind the session check, the
// same as run does; a request without a session is sent to /login.
func TestRealRegistryMountsPagesThroughRegistry(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.DiscardHandler)
	isAdmin := func(ctx context.Context) bool {
		s, ok := auth.SessionFrom(ctx)
		return ok && s.UserName == "admin"
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	deps := serverDeps{cfg: serverconfig.Config{PublicOrigin: swOrigin}, isAdmin: isAdmin, log: log}
	if err := mountServerFeaturePages(deps, pages); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(context.Background(), "cred-reg", "admin")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	do := func(cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, swOrigin+"/vuln/paths", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := do(""); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("attack-path page without session: status %d location %q, want 303 to /login", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(token); rec.Code != http.StatusOK {
		t.Fatalf("attack-path page as admin: status %d, want 200", rec.Code)
	}
}

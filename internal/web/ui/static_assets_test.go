// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
)

// repoRoot is the repository root relative to this package.
var repoRoot = filepath.Join("..", "..", "..")

// staticRefRE matches /static/<file>.js|css references in templates.
var staticRefRE = regexp.MustCompile(`/static/([A-Za-z0-9_.-]+\.(?:js|css))`)

// assetLiteralRE matches Go string literals naming a page script or
// stylesheet ("software.js"), as passed to the layout's Scripts list.
var assetLiteralRE = regexp.MustCompile(`"([A-Za-z0-9_-]+\.(?:js|css))"`)

// referencedStaticAssets collects every top-level .js/.css file that the
// UI can ask a browser to load: files shipped in web/static, /static/
// references in templates, and script names in the UI's Go sources.
func referencedStaticAssets(t *testing.T) []string {
	t.Helper()
	set := map[string]bool{}

	entries, err := os.ReadDir(filepath.Join(repoRoot, "web", "static"))
	if err != nil {
		t.Fatalf("read web/static: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext == ".js" || ext == ".css" {
			set[e.Name()] = true
		}
	}

	tmpls, err := filepath.Glob(filepath.Join(repoRoot, "web", "templates", "*.html"))
	if err != nil || len(tmpls) == 0 {
		t.Fatalf("templates: %v %v", tmpls, err)
	}
	for _, p := range tmpls {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range staticRefRE.FindAllSubmatch(b, -1) {
			set[string(m[1])] = true
		}
	}

	err = filepath.WalkDir(filepath.Join(repoRoot, "internal", "web", "ui"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range assetLiteralRE.FindAllSubmatch(b, -1) {
			set[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/web/ui: %v", err)
	}

	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// strictCSP is the Content-Security-Policy of docs/spec/09 and 14 that
// internal/web/middleware sets on every response.
const strictCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// TestReferencedStaticAssetsAreEmbedded fails when a script or stylesheet
// the UI loads is missing from the //go:embed list in web/static, which
// would make it 404 in a real server. Every asset is fetched through the
// full security chain (middleware.NewServer) and must carry the strict
// CSP, nosniff and its real content type.
func TestReferencedStaticAssetsAreEmbedded(t *testing.T) {
	const origin = "https://nebula.example.org"
	srv, err := middleware.NewServer(middleware.Options{PublicOrigin: origin},
		newTestHandler(t, ui.Options{PublicOrigin: origin}).Handler())
	if err != nil {
		t.Fatalf("middleware.NewServer: %v", err)
	}
	h := srv.Handler
	names := referencedStaticAssets(t)
	for _, want := range []string{"software.js", "formpost.js", "app.css"} {
		if i := sort.SearchStrings(names, want); i >= len(names) || names[i] != want {
			t.Fatalf("asset scan did not find %s; scan is broken: %v", want, names)
		}
	}
	for _, name := range names {
		if _, err := static.FS.ReadFile(name); err != nil {
			t.Errorf("%s is referenced but not embedded (add it to //go:embed in web/static/static.go): %v", name, err)
			continue
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/"+name, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET /static/%s: status %d, want 200", name, rec.Code)
			continue
		}
		if csp := rec.Header().Get("Content-Security-Policy"); csp != strictCSP {
			t.Errorf("GET /static/%s: CSP %q, want %q", name, csp, strictCSP)
		}
		if v := rec.Header().Get("X-Content-Type-Options"); v != "nosniff" {
			t.Errorf("GET /static/%s: X-Content-Type-Options %q, want nosniff", name, v)
		}
		want := "text/css"
		if strings.HasSuffix(name, ".js") {
			want = "javascript"
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, want) {
			t.Errorf("GET /static/%s: Content-Type %q, want %s", name, ct, want)
		}
	}
}

// TestStaticSoftwareJSIsServed fetches the software admin script through
// the real UI handler and embedded static FS.
func TestStaticSoftwareJSIsServed(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	srv, err := h.Server()
	if err != nil {
		t.Fatalf("h.Server: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/software.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/software.js: status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type %q, want javascript", ct)
	}
	if nosniff := rec.Header().Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Errorf("X-Content-Type-Options %q, want nosniff", nosniff)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP %q is not strict", csp)
	}
	want, err := static.FS.ReadFile("software.js")
	if err != nil {
		t.Fatalf("embedded software.js missing: %v", err)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Error("served bytes differ from embedded software.js")
	}
	for _, bad := range []string{"eval(", "new Function", "innerHTML", "document.write"} {
		if bytes.Contains(want, []byte(bad)) {
			t.Errorf("software.js contains %q, which strict CSP or safe DOM use forbids", bad)
		}
	}
}

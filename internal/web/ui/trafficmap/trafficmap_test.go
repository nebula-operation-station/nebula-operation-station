// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
)

const testOrigin = "https://nebula.example.org"

// allWindows is what Builder.Windows() returns with a 21-day retention.
func allWindows() []string { return []string{"1h", "24h", "7d", "21d"} }

func newTestHandler(t *testing.T, windows func() []string) http.Handler {
	t.Helper()
	h, err := New(Options{PublicOrigin: testOrigin, Windows: windows})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	// The full security chain, as in the server: the middleware sets the
	// strict CSP first and the handlers may only replace it.
	srv, err := middleware.NewServer(middleware.Options{PublicOrigin: testOrigin}, mux)
	if err != nil {
		t.Fatalf("middleware.NewServer: %v", err)
	}
	return srv.Handler
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

var iframeRE = regexp.MustCompile(`(?s)<iframe\b[^>]*>`)

func TestPageEmbedsRendererInSandboxWithoutSameOrigin(t *testing.T) {
	rec := get(t, newTestHandler(t, allWindows), "/traffic")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	frames := iframeRE.FindAllString(body, -1)
	if len(frames) != 1 {
		t.Fatalf("want exactly one iframe, got %d", len(frames))
	}
	f := frames[0]
	for _, want := range []string{`sandbox="allow-scripts"`, `src="/traffic/frame"`, `id="trafficmap-frame"`, `referrerpolicy="no-referrer"`} {
		if !strings.Contains(f, want) {
			t.Errorf("iframe %s lacks %s", f, want)
		}
	}
	if strings.Contains(body, "allow-same-origin") || strings.Contains(body, "allow-top-navigation") ||
		strings.Contains(body, "allow-popups") || strings.Contains(body, "allow-forms") {
		t.Error("page grants a sandbox permission beyond allow-scripts")
	}
	if strings.Count(f, "sandbox=") != 1 {
		t.Error("iframe must carry exactly one sandbox attribute")
	}
	if !strings.Contains(body, `<script src="/static/trafficmap-bridge.js"></script>`) {
		t.Error("page does not load the parent bridge")
	}
	if strings.Contains(body, "<script>") || regexp.MustCompile(`\son[a-z]+=`).MatchString(body) {
		t.Error("page has inline script or inline event handlers")
	}
	// The parent page keeps the strict CSP of the middleware.
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "sandbox") {
		t.Errorf("parent page CSP changed: %q", csp)
	}
}

func TestPageHasNavEntryMarkedActive(t *testing.T) {
	body := get(t, newTestHandler(t, allWindows), "/traffic").Body.String()
	if !regexp.MustCompile(`<a class="sidebar__item sidebar__item--active" href="/traffic"[^>]*aria-current="page"`).MatchString(body) {
		t.Error("navigation has no active Traffic map entry")
	}
}

func TestPageOffersOnlyWindowsTheAPIAllows(t *testing.T) {
	cases := []struct {
		name        string
		windows     []string
		query       string
		wantActive  string
		wantMissing []string
	}{
		{"default 24h", allWindows(), "", "24h", nil},
		{"explicit 7d", allWindows(), "?window=7d", "7d", nil},
		{"retention 3d clamps to 24h", []string{"1h", "24h"}, "", "24h", []string{"7d", "21d"}},
		{"retention 2h falls back to longest", []string{"1h"}, "", "1h", []string{"24h", "7d", "21d"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.windows
			rec := get(t, newTestHandler(t, func() []string { return w }), "/traffic"+tc.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `data-window="`+tc.wantActive+`"`) {
				t.Errorf("data-window is not %s", tc.wantActive)
			}
			if !strings.Contains(body, `href="/traffic?window=`+tc.wantActive+`" aria-current="page"`) {
				t.Errorf("window %s is not the active link", tc.wantActive)
			}
			for _, name := range w {
				if !strings.Contains(body, `href="/traffic?window=`+name+`"`) {
					t.Errorf("window %s not offered", name)
				}
			}
			for _, name := range tc.wantMissing {
				if strings.Contains(body, `?window=`+name+`"`) {
					t.Errorf("window %s offered beyond retention", name)
				}
			}
		})
	}
}

func TestPageRejectsWindowBeyondRetention(t *testing.T) {
	h := newTestHandler(t, func() []string { return []string{"1h", "24h"} })
	if rec := get(t, h, "/traffic?window=7d"); rec.Code != http.StatusBadRequest {
		t.Errorf("window=7d with 3d retention: status %d, want 400", rec.Code)
	}
}

func TestPageRejectsMalformedQuery(t *testing.T) {
	h := newTestHandler(t, allWindows)
	for _, q := range []string{
		"?window=30d",
		"?window=",
		"?window=1h&window=24h",
		"?focus=",
		"?focus=..%2Fsecret",
		"?focus=%3Cscript%3E",
		"?focus=-leading-dash",
		"?focus=a%20b",
		"?focus=" + strings.Repeat("a", 129),
		"?focus=x&focus=y",
		"?foo=bar",
		"?%zz",
		"?window=1h&pad=" + strings.Repeat("x", 600),
	} {
		if rec := get(t, h, "/traffic"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("GET /traffic%s: status %d, want 400", q, rec.Code)
		}
	}
}

func TestPagePassesValidFocusToBridgeEscaped(t *testing.T) {
	h := newTestHandler(t, allWindows)
	rec := get(t, h, "/traffic?window=1h&focus=pve1:vm.101_a-b")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-focus="pve1:vm.101_a-b"`) {
		t.Error("focus not passed to the bridge")
	}
	// Window links drop the focus (the overview of that window).
	if !strings.Contains(body, `href="/traffic?window=24h"`) {
		t.Error("window link missing")
	}
	if !strings.Contains(body, `href="/traffic?window=1h"`) {
		t.Error("overview link missing")
	}
}

func TestPageHasStatusAndSummaryRegions(t *testing.T) {
	body := get(t, newTestHandler(t, allWindows), "/traffic").Body.String()
	for _, id := range []string{"trafficmap-page", "trafficmap-status", "trafficmap-summary", "trafficmap-unmapped", "trafficmap-truncated", "trafficmap-selection"} {
		if !strings.Contains(body, `id="`+id+`"`) {
			t.Errorf("page lacks #%s", id)
		}
	}
}

func TestPageRejectsOtherMethods(t *testing.T) {
	h := newTestHandler(t, allWindows)
	for _, path := range []string{"/traffic", "/traffic/frame", "/static/trafficmap/main.js"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Origin", testOrigin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: status %d, want 405", path, rec.Code)
		}
	}
}

// cspDirectives splits a CSP header into directive name → value.
func cspDirectives(t *testing.T, csp string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, " ")
		if _, dup := out[name]; dup {
			t.Errorf("duplicate CSP directive %s", name)
		}
		out[name] = value
	}
	return out
}

func TestFrameDocumentIsSandboxedAndOffline(t *testing.T) {
	rec := get(t, newTestHandler(t, allWindows), "/traffic/frame")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	if v := rec.Header().Get("Cache-Control"); v != "no-store" {
		t.Errorf("Cache-Control %q", v)
	}
	if v := rec.Header().Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("nosniff missing: %q", v)
	}
	if v := rec.Header().Get("Referrer-Policy"); v != "no-referrer" {
		t.Errorf("Referrer-Policy %q", v)
	}
	d := cspDirectives(t, rec.Header().Get("Content-Security-Policy"))
	want := map[string]string{
		"default-src":     "'none'",
		"script-src":      testOrigin + "/static/trafficmap/",
		"connect-src":     "'none'",
		"img-src":         "'none'",
		"font-src":        "'none'",
		"media-src":       "'none'",
		"object-src":      "'none'",
		"worker-src":      "'none'",
		"frame-src":       "'none'",
		"child-src":       "'none'",
		"manifest-src":    "'none'",
		"base-uri":        "'none'",
		"form-action":     "'none'",
		"frame-ancestors": testOrigin,
		// The sandbox also applies when the document is opened top-level.
		"sandbox": "allow-scripts",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("CSP %s = %q, want %q", k, d[k], v)
		}
	}
	body := rec.Body.String()
	m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(body, -1)
	if len(m) != 1 {
		t.Fatalf("want exactly one <style>, got %d", len(m))
	}
	sum := sha256.Sum256([]byte(m[0][1]))
	if want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; d["style-src"] != want {
		t.Errorf("style-src = %q, want the hash of the inline style %q", d["style-src"], want)
	}
	if strings.Contains(d["style-src"], "unsafe") || strings.Contains(d["script-src"], "unsafe") || strings.Contains(d["script-src"], "'self'") {
		t.Error("frame CSP allows unsafe or broader script/style sources")
	}
	scripts := regexp.MustCompile(`<script\b[^>]*>`).FindAllString(body, -1)
	if len(scripts) != 1 || scripts[0] != `<script type="module" src="/static/trafficmap/boot.js">` {
		t.Errorf("frame must load only the renderer boot module, got %q", scripts)
	}
	if !strings.Contains(body, `id="trafficmap"`) {
		t.Error("frame lacks the renderer root")
	}
	for _, bad := range []string{"<iframe", "<img", "<link", "<form", "href=", "/api/", "/icons/"} {
		if strings.Contains(body, bad) {
			t.Errorf("frame document contains %q", bad)
		}
	}
}

func TestRendererModulesServedForOpaqueOrigin(t *testing.T) {
	h := newTestHandler(t, allWindows)
	for _, name := range []string{"boot.js", "main.js", "bridge.js", "model.js"} {
		req := httptest.NewRequest(http.MethodGet, "/static/trafficmap/"+name, nil)
		// A sandboxed document without allow-same-origin sends Origin: null
		// and no cookies.
		req.Header.Set("Origin", "null")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", name, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
			t.Errorf("%s: Content-Type %q", name, ct)
		}
		if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "*" {
			t.Errorf("%s: Access-Control-Allow-Origin %q, want *", name, v)
		}
		if v := rec.Header().Get("Access-Control-Allow-Credentials"); v != "" {
			t.Errorf("%s: must not allow credentials, got %q", name, v)
		}
		if v := rec.Header().Get("X-Content-Type-Options"); v != "nosniff" {
			t.Errorf("%s: nosniff missing", name)
		}
		want, err := static.FS.ReadFile("trafficmap/" + name)
		if err != nil {
			t.Fatalf("embedded %s: %v", name, err)
		}
		got, _ := io.ReadAll(rec.Body)
		if string(got) != string(want) {
			t.Errorf("%s: served bytes differ from the embedded module", name)
		}
	}
}

func TestRendererRouteServesOnlyEmbeddedModules(t *testing.T) {
	h := newTestHandler(t, allWindows)
	for _, p := range []string{
		"/static/trafficmap/",
		"/static/trafficmap/nope.js",
		"/static/trafficmap/main.test.mjs",
		"/static/trafficmap/package.json",
		"/static/trafficmap/contract_test.go",
		"/static/trafficmap/testdata/model-valid.json",
		"/static/trafficmap/Main.js",
		"/static/trafficmap/..%2Fapp.css",
		"/static/trafficmap/%2e%2e/app.css",
	} {
		rec := get(t, h, p)
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s: status 200, want an error", p)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("GET %s: CORS header on an error", p)
		}
	}
}

func TestParentBridgeIsEmbedded(t *testing.T) {
	if _, err := static.FS.ReadFile("trafficmap-bridge.js"); err != nil {
		t.Fatalf("trafficmap-bridge.js not embedded: %v", err)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	cases := []Options{
		{Windows: allWindows},
		{PublicOrigin: "https://nebula.example.org/path", Windows: allWindows},
		{PublicOrigin: "https://nebula.example.org; script-src *", Windows: allWindows},
		{PublicOrigin: "javascript:alert(1)", Windows: allWindows},
		{PublicOrigin: "https://user@nebula.example.org", Windows: allWindows},
		{PublicOrigin: "https://nebula.example.org?x", Windows: allWindows},
		{PublicOrigin: "nebula.example.org", Windows: allWindows},
		{PublicOrigin: testOrigin},
	}
	for i, o := range cases {
		if _, err := New(o); err == nil {
			t.Errorf("case %d (%q): New accepted invalid options", i, o.PublicOrigin)
		}
	}
	for _, ok := range []string{"https://nebula.example.org", "http://127.0.0.1:8443", "https://[::1]:9000"} {
		if _, err := New(Options{PublicOrigin: ok, Windows: allWindows}); err != nil {
			t.Errorf("New(%q): %v", ok, err)
		}
	}
}

func TestPageFailsClosedWithoutWindows(t *testing.T) {
	h := newTestHandler(t, func() []string { return nil })
	if rec := get(t, h, "/traffic"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", rec.Code)
	}
	h = newTestHandler(t, func() []string { return []string{"1h", "2h<script>"} })
	if rec := get(t, h, "/traffic"); strings.Contains(rec.Body.String(), "2h<script>") || strings.Contains(rec.Body.String(), "window=2h") {
		t.Error("unknown window names from the provider are rendered")
	}
}

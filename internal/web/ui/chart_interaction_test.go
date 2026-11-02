// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// P1-35: the org chart gets its interaction layer (pan, Ctrl+wheel zoom,
// fit, automatic list mode, details sheet) from the existing
// web/static/inventory.js — one small script under the strict CSP. These
// tests pin the page contract: only embedded scripts, JS-only controls
// hidden without JS, native no-JS links and collapse intact, no
// orientation toggle, no second chart runtime.

var (
	scriptTagRe = regexp.MustCompile(`<script[^>]*>`)
	scriptSrcRe = regexp.MustCompile(`<script src="(/static/[^"]+)"`)
	// buttonTagRe extracts every button opening tag from a chart section.
	buttonTagRe = regexp.MustCompile(`<button[^>]*>`)
)

// The chart page loads the shared inventory.js, every script it references
// is embedded, and there is no inline script (strict CSP).
func TestChartPageLoadsOnlyEmbeddedScripts(t *testing.T) {
	h := chartHandler(t).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inventory/chart", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /inventory/chart: %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<script src="/static/inventory.js">`) {
		t.Errorf("chart page does not load the shared inventory.js")
	}
	for _, tag := range scriptTagRe.FindAllString(body, -1) {
		if !strings.Contains(tag, `src="/static/`) {
			t.Errorf("inline script on chart page (strict CSP): %s", tag)
		}
	}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, m[1], nil))
		if r.Code != http.StatusOK {
			t.Errorf("%s answers %d", m[1], r.Code)
		}
	}
}

// The page-specific scripts are exactly the shared pair: no second chart
// runtime is loaded.
func TestChartPageScriptSet(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	srcs := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		srcs[m[1]] = true
	}
	delete(srcs, "/static/htmx.min.js")
	delete(srcs, "/static/time.js")
	delete(srcs, "/static/nav.js")
	if len(srcs) != 2 || !srcs["/static/webauthn.js"] || !srcs["/static/inventory.js"] {
		t.Errorf("chart page scripts = %v, want webauthn.js + inventory.js only", srcs)
	}
}

// Without JS the chart is the plain page: native details/summary collapse,
// plain host links, and every JS-only control hidden.
func TestChartNoJSPageStillWorks(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	for _, want := range []string{
		`href="/hosts/web"`,
		`href="/hosts/nas"`,
		`>open host</a>`, // details panel link (no-JS navigation)
		`<details class="chart__details"`,
		`<summary class="chart__box chart__box--host">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("no-JS chart page lost %q", want)
		}
	}
	if !strings.Contains(body, `id="chart-fit" class="button button--secondary" hidden`) {
		t.Errorf("Fit control must be hidden without JS")
	}
	if !strings.Contains(body, `id="chart-sheet" hidden`) {
		t.Errorf("details sheet must be hidden without JS")
	}
	btns := regexp.MustCompile(`class="chart__dpanel-btn"[^>]*>`).FindAllString(body, -1)
	if len(btns) != 4 {
		t.Fatalf("want 4 details buttons (one per managed host), got %d", len(btns))
	}
	for _, b := range btns {
		if !strings.Contains(b, "hidden") {
			t.Errorf("details button must be hidden without JS: %s", b)
		}
	}
}

// The chart page answers with the strict CSP header (middleware chain).
func TestChartPageStrictCSP(t *testing.T) {
	srv, err := chartHandler(t).Server()
	if err != nil {
		t.Fatalf("Server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/inventory/chart")
	if err != nil {
		t.Fatalf("GET /inventory/chart: %v", err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'", "script-src 'self'", "style-src 'self'",
		"object-src 'none'", "frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
}

// The CSS carries the pan-mode and details-sheet rules; the sheet (not the
// chart layout) owns its scroll area.
func TestChartCSSHasPanModeAndSheet(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "app.css"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{".chart--pan", ".dpanel-sheet", ".chart__dpanel-btn"} {
		if !strings.Contains(string(css), want) {
			t.Errorf("app.css missing %s", want)
		}
	}
}

// No orientation toggle: neither the page nor the script references the
// orientation API or a toggle control.
func TestChartHasNoOrientationToggle(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	if strings.Contains(body, "orientation") {
		t.Errorf("chart page must not offer an orientation toggle")
	}
	js, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "inventory.js"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "orientation") {
		t.Errorf("inventory.js must not use the orientation API")
	}
}

// One small script: inventory.js stays under the size budget and no
// chart-specific JS file appears in the static tree.
func TestChartScriptIsOneSmallScript(t *testing.T) {
	root := filepath.Join("..", "..", "..", "web", "static")
	fi, err := os.Stat(filepath.Join(root, "inventory.js"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 30*1024 {
		t.Errorf("inventory.js is %d bytes; the chart interaction must stay in one small script", fi.Size())
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if len(name) > 3 && strings.HasSuffix(name, ".js") && strings.HasPrefix(name, "chart") {
			t.Errorf("second chart runtime %s", name)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// P1-35: the org chart gets its interaction layer (pan, zoom, fit,
// automatic list mode, details sheet) from the existing
// web/static/inventory.js — one small script under the strict CSP. These
// tests pin the page contract: only embedded scripts, JS-only controls
// hidden without JS, native no-JS links and collapse intact, no
// orientation toggle, no second chart runtime.

var (
	scriptTagRe = regexp.MustCompile(`<script[^>]*>`)
	scriptSrcRe = regexp.MustCompile(`<script src="(/static/[^"]+)"`)
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

// The page-specific script is exactly the shared inventory.js: no second
// chart runtime, and no webauthn.js (the chart page has no add-host
// dialog; inventory.js guards its nebulaWebAuthn reference instead).
func TestChartPageScriptSet(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	srcs := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		srcs[m[1]] = true
	}
	delete(srcs, "/static/htmx.min.js")
	delete(srcs, "/static/time.js")
	delete(srcs, "/static/nav.js")
	if len(srcs) != 1 || !srcs["/static/inventory.js"] {
		t.Errorf("chart page scripts = %v, want inventory.js only", srcs)
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
	for _, id := range []string{"chart-zoom-out", "chart-zoom-in", "chart-zoom-100"} {
		if !strings.Contains(body, `id="`+id+`" class="button button--secondary" hidden`) {
			t.Errorf("%s must be hidden without JS", id)
		}
	}
	if !strings.Contains(body, `id="chart-hint" class="hint chart__hint" hidden`) {
		t.Errorf("zoom hint must be hidden without JS")
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

// The toolbar offers Zoom out, Zoom in, Fit and 100% with accessible names,
// and the one-line hint sits under the toolbar, above the canvas.
func TestChartToolbarHasZoomControlsAndHint(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	for _, want := range []string{
		`aria-label="Zoom out"`, `>−</button>`,
		`aria-label="Zoom in"`, `>+</button>`,
		`>Fit</button>`,
		`aria-label="Zoom to 100%"`, `>100%</button>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart toolbar lacks %q", want)
		}
	}
	toolbar := strings.Index(body, `<div class="toolbar">`)
	hint := strings.Index(body, "Drag or scroll to move · pinch or Ctrl+scroll to zoom")
	canvas := strings.Index(body, `<section class="panel chart"`)
	if toolbar < 0 || hint < toolbar || canvas < hint {
		t.Errorf("hint must sit between toolbar and canvas: toolbar %d, hint %d, canvas %d", toolbar, hint, canvas)
	}
}

// Strict CSP: the new controls carry no inline style or inline handler;
// they are wired from inventory.js only.
func TestChartToolbarHasNoInlineStyleOrHandler(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	start := strings.Index(body, `<div class="toolbar">`)
	end := strings.Index(body, `<section class="panel chart"`)
	if start < 0 || end < start {
		t.Fatalf("toolbar not found: %d, %d", start, end)
	}
	if bad := regexp.MustCompile(`(?i)\s(style|on[a-z]+)=`).FindString(body[start:end]); bad != "" {
		t.Errorf("inline attribute in the chart toolbar: %q", bad)
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
	for _, want := range []string{".chart--pan", ".dpanel-sheet", ".chart__dpanel-btn", ".chart__hint"} {
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

// Review of PR #165 (HIGH): the chart interaction must start on the chart
// page. inventory.js stops early on pages without the add-host dialog and
// throws without webauthn.js, so the chart code has to be its own block
// that runs before the inventory page code.
func TestChartInteractionRunsBeforeInventoryCode(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "inventory.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)
	chart := strings.Index(src, "document.querySelector('.chart')")
	inv := strings.Index(src, guardedWebAuthn)
	early := strings.Index(src, "if (!dialog || !form || !w) return;")
	if chart < 0 || inv < 0 || early < 0 {
		t.Fatalf("markers missing: chart %d, inventory %d, early return %d", chart, inv, early)
	}
	if chart > inv || chart > early {
		t.Errorf("chart interaction starts at %d, after the inventory code (%d) or its early return (%d): it never runs on the chart page", chart, inv, early)
	}
}

// Review of PR #165 (HIGH): the Details lookup reads the dataset key that
// matches the rendered attribute (data-nos-dpanel-btn -> nosDpanelBtn).
func TestChartDetailsDatasetKeyMatchesTemplate(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	if !strings.Contains(body, "data-nos-dpanel-btn=") || !strings.Contains(body, "data-nos-dpanel=") {
		t.Fatal("chart page lost the details button/panel attributes")
	}
	js, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "inventory.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "dataset.nosDpanelBtn") {
		t.Error("inventory.js does not read dataset.nosDpanelBtn")
	}
	if strings.Contains(string(js), "dataset.dpanelBtn") {
		t.Error("inventory.js reads dataset.dpanelBtn, which no element carries")
	}
}

// guardedWebAuthn is the only way inventory.js may reach nebulaWebAuthn:
// the global exists only where webauthn.js is loaded, which the chart
// page no longer does.
const guardedWebAuthn = "const w = typeof nebulaWebAuthn === 'undefined' ? null : nebulaWebAuthn;"

// inventoryJS reads web/static/inventory.js.
func inventoryJS(t *testing.T) string {
	t.Helper()
	js, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "inventory.js"))
	if err != nil {
		t.Fatal(err)
	}
	return string(js)
}

// chartJS returns the chart interaction block of inventory.js (the first
// IIFE), so checks on it cannot be satisfied by the inventory page code.
func chartJS(t *testing.T) string {
	t.Helper()
	src := inventoryJS(t)
	start := strings.Index(src, "document.querySelector('.chart')")
	if start < 0 {
		t.Fatal("chart block not found")
	}
	end := strings.Index(src[start:], "\n})();")
	if end < 0 {
		t.Fatal("chart block is not closed")
	}
	return src[start : start+end]
}

// jsFunc returns the body of an arrow function declared at block level as
// "  const <name> = (...) => {" up to its closing "\n  };".
func jsFunc(t *testing.T, block, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)\n  const ` + regexp.QuoteMeta(name) + ` = \([^)]*\) => \{(.*?)\n  \};`)
	m := re.FindStringSubmatch(block)
	if m == nil {
		t.Fatalf("function %s not found in the chart block", name)
	}
	return m[1]
}

// Review of PR #165 (item 7): the inventory page code reaches
// nebulaWebAuthn only through the typeof guard and stops before using it
// when the global or the add-host dialog is absent.
func TestInventoryJSGuardsWebAuthn(t *testing.T) {
	src := inventoryJS(t)
	if !strings.Contains(src, guardedWebAuthn) {
		t.Fatalf("inventory.js lost the guarded nebulaWebAuthn reference")
	}
	if n := strings.Count(src, "nebulaWebAuthn"); n != 2 {
		t.Errorf("inventory.js mentions nebulaWebAuthn %d times, want only the guard (2)", n)
	}
	early := strings.Index(src, "if (!dialog || !form || !w) return;")
	if early < 0 {
		t.Fatal("inventory page code does not stop without the dialog or webauthn.js")
	}
	for _, use := range regexp.MustCompile(`\bw\.(show|post)\(`).FindAllStringIndex(src, -1) {
		if use[0] < early {
			t.Errorf("w used at %d before the early return at %d", use[0], early)
		}
	}
}

// Review of PR #165 (item 3): the chart is a tab stop only in pan mode.
// setMode adds it for pan and removes it for list mode; nothing else
// touches the chart's tab order.
func TestChartTabbableOnlyInPanMode(t *testing.T) {
	block := chartJS(t)
	setMode := jsFunc(t, block, "setMode")
	re := regexp.MustCompile(`if \(pan\) chartSection\.tabIndex = 0;\s*else chartSection\.removeAttribute\('tabindex'\);`)
	if !re.MatchString(setMode) {
		t.Errorf("setMode does not add the tab stop in pan mode and remove it in list mode:\n%s", setMode)
	}
	if n := strings.Count(block, "tabIndex"); n != 1 {
		t.Errorf("chart block sets tabIndex %d times, want only in setMode (1)", n)
	}
}

// Review of PR #165 (item 5): the pan canvas clips (overflow hidden), so
// native scrolling of it is undone: fit() resets scrollTop/scrollLeft,
// every focus call passes preventScroll, nothing calls scrollIntoView, and
// revealFocus folds a browser focus scroll into the transform.
func TestChartFocusAndFitNeverScrollCanvas(t *testing.T) {
	block := chartJS(t)
	fit := jsFunc(t, block, "fit")
	for _, want := range []string{"chartSection.scrollTop = 0", "chartSection.scrollLeft = 0", "applyTransform()"} {
		if !strings.Contains(fit, want) {
			t.Errorf("fit() lacks %q:\n%s", want, fit)
		}
	}
	if strings.Contains(block, "scrollIntoView") {
		t.Error("chart block calls scrollIntoView (scrolls the clipped canvas)")
	}
	calls := regexp.MustCompile(`\.focus\(([^)]*)\)`).FindAllStringSubmatch(block, -1)
	if len(calls) == 0 {
		t.Fatal("no focus calls found in the chart block")
	}
	for _, c := range calls {
		if c[1] != "{ preventScroll: true }" {
			t.Errorf("focus call without preventScroll: %s", c[0])
		}
	}
	unscroll := jsFunc(t, block, "unscroll")
	for _, want := range []string{"tx -= chartSection.scrollLeft", "ty -= chartSection.scrollTop"} {
		if !strings.Contains(unscroll, want) {
			t.Errorf("unscroll lacks %q:\n%s", want, unscroll)
		}
	}
	if !strings.Contains(jsFunc(t, block, "revealFocus"), "unscroll()") {
		t.Error("revealFocus does not fold the native scroll offset into the transform")
	}
}

// Review of PR #165 (item 6): while the modal sheet is open the rest of
// the page is inert, and a backdrop click closes it.
func TestChartSheetInertAndBackdropClose(t *testing.T) {
	block := chartJS(t)
	for _, want := range []string{
		"document.getElementById('chart-sheet-backdrop')",
		"backdrop.addEventListener('click', closeSheet)",
		"closeBtn.addEventListener('click', closeSheet)",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("chart block lacks %q", want)
		}
	}
	openFn := jsFunc(t, block, "openSheet")
	closeFn := jsFunc(t, block, "closeSheet")
	if !strings.Contains(openFn, "setInert(true)") || !strings.Contains(openFn, "backdrop.hidden = false") {
		t.Errorf("openSheet does not make the page inert and show the backdrop:\n%s", openFn)
	}
	if !strings.Contains(closeFn, "setInert(false)") || !strings.Contains(closeFn, "backdrop.hidden = true") {
		t.Errorf("closeSheet does not restore the page and hide the backdrop:\n%s", closeFn)
	}
	setInert := jsFunc(t, block, "setInert")
	for _, want := range []string{"document.body.children", "el === sheet", "el === backdrop", "el.inert = on"} {
		if !strings.Contains(setInert, want) {
			t.Errorf("setInert lacks %q:\n%s", want, setInert)
		}
	}
}

// Every zoom control is wired by its template id, and in list mode the
// controls and the hint are hidden again.
func TestChartZoomControlsWired(t *testing.T) {
	block := chartJS(t)
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	for _, id := range []string{"chart-zoom-out", "chart-zoom-in", "chart-fit", "chart-zoom-100", "chart-hint"} {
		if !strings.Contains(body, `id="`+id+`"`) {
			t.Errorf("template lacks #%s", id)
		}
		if !strings.Contains(block, "'"+id+"'") {
			t.Errorf("chart block does not reference #%s", id)
		}
	}
	if !strings.Contains(jsFunc(t, block, "setMode"), ".hidden = !pan") {
		t.Error("setMode does not hide the pan controls in list mode")
	}
	for _, want := range []string{"zoomBy(1 / zoomStep)", "zoomBy(zoomStep)", "actualSize"} {
		if !strings.Contains(block, want) {
			t.Errorf("chart block lacks %q", want)
		}
	}
}

// The minimum scale lets Fit show 100 hosts: they stack vertically, a host
// with its Details button, padding and gap is about 200px high, and the
// smallest canvas (420px) has 388px left inside its 16px padding. The harness
// checks the same through Fit (scenario hundredhosts).
func TestChartMinScaleFitsHundredHosts(t *testing.T) {
	const (
		hostHeight = 200.0
		canvas     = 420.0 - 2*16
	)
	m := regexp.MustCompile(`const minScale = ([0-9.]+);`).FindStringSubmatch(inventoryJS(t))
	if m == nil {
		t.Fatal("inventory.js has no minScale constant")
	}
	minScale, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatal(err)
	}
	if minScale <= 0 || minScale*100*hostHeight > canvas {
		t.Errorf("minScale %v cannot fit 100 hosts into the canvas", minScale)
	}
}

// Safari's gesture events zoom and leave the browser defaults alone in list
// mode. The wheel handler cancels only what the chart uses, see the harness
// scenarios wheelpan, wheelrelease, wheelzoom and listmode.
func TestChartGestureHandlers(t *testing.T) {
	block := chartJS(t)
	for _, name := range []string{"gesturestart", "gesturechange", "gestureend"} {
		re := regexp.MustCompile(`(?s)chartSection\.addEventListener\('` + name + `', \(e\) => \{\n    if \(!panning\(\)\) return;\n    e\.preventDefault\(\);.*?\}, \{ passive: false \}\);`)
		if !re.MatchString(block) {
			t.Errorf("%s handler must stop in list mode, call preventDefault and be non-passive", name)
		}
	}
}

// The staged update form and its confirmation are not part of the chart:
// inside the clipped canvas they could not be reached or scrolled to.
func TestChartStagedSectionSitsOutsideTheCanvas(t *testing.T) {
	h, _ := stagedChartHandler(t, false)
	body := getBody(t, h.Handler(), "/inventory/chart")
	start := strings.Index(body, `<section class="panel chart"`)
	end := strings.Index(body, `<section class="panel staged-update"`)
	if start < 0 || end < start {
		t.Fatalf("chart or staged section missing: %d, %d", start, end)
	}
	between := body[start:end]
	if opened, closed := strings.Count(between, "<section"), strings.Count(between, "</section>"); opened != closed {
		t.Errorf("staged section is nested in the canvas: %d sections opened, %d closed", opened, closed)
	}
}

// A sideways trackpad scroll at the canvas edge must not swipe back in
// history, but the vertical scroll must chain: the wheel handler hands it on
// at the edge, and a contained axis would swallow it (a page scroll trap).
// List mode gets every default back.
func TestChartCSSContainsOverscrollSidewaysOnly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "app.css"))
	if err != nil {
		t.Fatal(err)
	}
	var pan, list bool
	for line := range strings.Lines(string(raw)) {
		if !strings.Contains(line, ".chart--pan {") {
			continue
		}
		pan = pan || strings.Contains(line, "overscroll-behavior-x: contain")
		list = list || strings.Contains(line, "overscroll-behavior: auto")
		if strings.Contains(line, "overscroll-behavior: contain") || strings.Contains(line, "overscroll-behavior-y: contain") {
			t.Errorf("vertical overscroll is contained, the page cannot take over: %s", line)
		}
	}
	if !pan || !list {
		t.Errorf("overscroll-behavior-x: contain in pan mode %v, auto in list mode %v", pan, list)
	}
}

// The canvas must leave the vertical pan to the browser: with touch-action:
// none no swipe could reach the page, and a landscape phone is all canvas.
// Pinch stays off so that two fingers reach the chart's own handler; list
// mode gets every default back. Harness scenarios: touchswipe, touchlandscape.
func TestChartCSSLeavesVerticalSwipeToThePage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "static", "app.css"))
	if err != nil {
		t.Fatal(err)
	}
	var pan, list int
	for line := range strings.Lines(string(raw)) {
		if !strings.Contains(line, ".chart--pan {") {
			continue
		}
		if strings.Contains(line, "touch-action: pan-y;") {
			pan++
		}
		if strings.Contains(line, "touch-action: auto;") {
			list++
		}
		if strings.Contains(line, "touch-action: none") {
			t.Errorf("touch-action: none traps touch users on the canvas: %s", line)
		}
	}
	if pan != 1 || list != 1 {
		t.Errorf("touch-action: pan-y in pan mode %d times, auto in list mode %d times, want once each", pan, list)
	}
}

// Strict CSP and untrusted text: inventory.js builds no markup from
// strings, evaluates no code and sets styles through CSSOM only.
func TestInventoryJSUsesNoMarkupStrings(t *testing.T) {
	src := inventoryJS(t)
	for _, bad := range []string{".innerHTML", ".outerHTML", ".insertAdjacentHTML", "document.write", "setAttribute('style'", "eval(", "new Function"} {
		if strings.Contains(src, bad) {
			t.Errorf("inventory.js uses %s", bad)
		}
	}
}

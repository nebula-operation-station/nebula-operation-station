// SPDX-License-Identifier: AGPL-3.0-or-later

// Package static_test pins the screen-size contract of the inventory
// bulk action bar: the bar is fixed at every width, so the script
// measures the distance from the bar's top to the bottom of the
// viewport into --bulkbar-h and the stylesheet consumes it as extra
// bottom padding of the content area and scroll-padding-bottom of the
// scroll container. Without this, the last list rows and focused
// controls sit hidden behind the bar.
package static_test

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/web/static"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

func mustRead(t *testing.T, fs embed.FS, name string) string {
	t.Helper()
	b, err := fs.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// mediaBlocks returns the text of every @media (max-width: <w>px) block
// in the stylesheet, up to the next at-rule.
func mediaBlocks(css string, w int) []string {
	re := regexp.MustCompile(`@media\s*\(\s*max-width:\s*` + fmt.Sprintf("%d", w) + `px\s*\)\s*\{`)
	var out []string
	for _, loc := range re.FindAllStringIndex(css, -1) {
		rest := css[loc[1]:]
		end := strings.Index(rest, "@media")
		if end < 0 {
			end = len(rest)
		}
		out = append(out, rest[:end])
	}
	return out
}

// ruleBody returns the declaration text of the first rule in css whose
// selector is exactly sel, so a rule for a different selector cannot
// satisfy a check.
func ruleBody(css, sel string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(sel) + `\s*\{`)
	loc := re.FindStringIndex(css)
	if loc == nil {
		return ""
	}
	rest := css[loc[1]:]
	end := strings.IndexByte(rest, '}')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// decl returns the value of the first declaration named name in the
// rule body body (e.g. "padding-bottom" -> "calc(...)"), or "". The
// property name must not be part of a longer name (so
// "scroll-padding-bottom" does not match "padding-bottom").
func decl(body, name string) string {
	re := regexp.MustCompile(`[^a-zA-Z-]` + regexp.QuoteMeta(name) + `:\s*([^;]+);`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// TestBulkBarClearancePadsContentAtEveryWidth: the bar is fixed at
// every width, so the content area must gain bottom padding equal to
// the bar's clearance at every width, not only below a single
// breakpoint.
func TestBulkBarClearancePadsContentAtEveryWidth(t *testing.T) {
	css := mustRead(t, static.FS, "app.css")
	base := decl(ruleBody(css, ".main"), "padding-bottom")
	if !strings.Contains(base, "var(--space-3)") || !strings.Contains(base, "--bulkbar-h") {
		t.Error("app.css: the base .main rule's padding-bottom must be the desktop space-3 plus the --bulkbar-h clearance; the fixed bulk bar covers the last rows at every width, not only below 640px")
	}
	// The phone rule overrides .main's padding, so it must keep the
	// clearance on top of the phone's own space-2 base; otherwise
	// phones either lose the clearance or gain the desktop space-3 as
	// uneven bottom padding even with no bar present.
	found := false
	for _, block := range mediaBlocks(css, 600) {
		body := ruleBody(block, ".main")
		if body == "" {
			continue
		}
		found = true
		pb := decl(body, "padding-bottom")
		if !strings.Contains(pb, "var(--space-2)") || !strings.Contains(pb, "--bulkbar-h") {
			t.Error("app.css: the @media (max-width: 600px) .main rule must keep the phone's space-2 base plus the --bulkbar-h clearance")
		}
	}
	if !found {
		t.Error("app.css: no @media (max-width: 600px) rule for .main; the phone padding override is missing")
	}
}

// TestBulkBarClearanceKeepsFocusClear: a keyboard or switch user tabbing
// through row checkboxes and host links must not land on focused
// elements underneath the fixed bar (WCAG 2.2 2.4.11 Focus Not
// Obscured), so the scroll container needs scroll-padding-bottom from
// the same clearance.
func TestBulkBarClearanceKeepsFocusClear(t *testing.T) {
	css := mustRead(t, static.FS, "app.css")
	re := regexp.MustCompile(`[^{}@]+\{[^}]*scroll-padding-bottom:[^}]*--bulkbar-h[^}]*\}`)
	if !re.MatchString(css) {
		t.Error("app.css: no rule sets scroll-padding-bottom from the --bulkbar-h clearance; focused row checkboxes and host links land under the fixed bulk bar")
	}
}

// TestBulkBarJSKeepsClearanceInSync: the script must measure the bar's
// clearance into --bulkbar-h and react to every height change (toggle,
// inline confirms, text wrap, viewport resize). The checks look for the
// code itself, not bare tokens, so a comment mentioning the tokens
// cannot satisfy them.
func TestBulkBarJSKeepsClearanceInSync(t *testing.T) {
	js := mustRead(t, static.FS, "inventory.js")
	for _, want := range []string{
		`setProperty('--bulkbar-h'`, // the variable the stylesheet consumes
		"getBoundingClientRect",     // the bar's position, not just its size
		"new ResizeObserver(",       // height changes without a script event
		`addEventListener('resize'`, // viewport changes
	} {
		if !strings.Contains(js, want) {
			t.Errorf("inventory.js: missing %q; the bulk bar clearance is not kept in sync with the bar", want)
		}
	}
}

// TestInventoryTemplateBulkBarToggleA11y: the sheet toggle must be a
// real button with the ARIA state and control wiring, so keyboard and
// screen-reader users can expand the sheet without a pointer, and the
// script must keep aria-expanded in sync with the sheet.
func TestInventoryTemplateBulkBarToggleA11y(t *testing.T) {
	html := mustRead(t, templates.FS, "inventory.html")
	re := regexp.MustCompile(`<button[^>]*id="bulkbar-toggle"[^>]*aria-expanded="false"[^>]*aria-controls="bulkbar-body"`)
	if !re.MatchString(html) {
		t.Error(`inventory.html: the bulk bar toggle must be a real <button> with aria-expanded and aria-controls="bulkbar-body" to stay keyboard and screen-reader friendly`)
	}
	if !strings.Contains(html, `id="bulkbar-body"`) {
		t.Error("inventory.html: missing the #bulkbar-body group the toggle controls")
	}
	js := mustRead(t, static.FS, "inventory.js")
	if !strings.Contains(js, `setAttribute('aria-expanded'`) {
		t.Error("inventory.js: the script must keep the toggle's aria-expanded in sync with the sheet")
	}
}

// TestBulkBarSheetFitsViewport: a sheet taller than the viewport (high
// browser zoom) must stay scrollable so its toggle and confirms at the
// top remain reachable, and the script must clear the area the bar
// covers when its top edge sits above the viewport.
func TestBulkBarSheetFitsViewport(t *testing.T) {
	css := mustRead(t, static.FS, "app.css")
	body := ruleBody(css, ".bulkbar")
	if !strings.Contains(body, "max-height") || !strings.Contains(body, "overflow-y") {
		t.Error("app.css: the fixed .bulkbar needs max-height and overflow-y so a sheet taller than the viewport keeps its toggle and confirms reachable")
	}
	js := mustRead(t, static.FS, "inventory.js")
	if !strings.Contains(js, "r.bottom") {
		t.Error("inventory.js: when the bar's top is above the viewport (r.top <= 0) the clearance must cover the visible part of the bar (r.bottom), not 0")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package static_test pins the narrow-screen contract of the inventory
// bulk action bar: the bar is fixed, so the script measures the distance
// from the bar's top to the bottom of the viewport into --bulkbar-h and
// the stylesheet consumes it as extra bottom padding of the content area.
// Without this, the last list rows sit hidden behind the bar on phones.
package static_test

import (
	"embed"
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

// mediaBlocks returns the text of every @media (max-width: 640px) block
// in the stylesheet, up to the next at-rule.
func mediaBlocks(css string) []string {
	re := regexp.MustCompile(`@media\s*\(\s*max-width:\s*640px\s*\)\s*\{`)
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

// TestBulkBarClearancePadsContentOnNarrowScreens: on narrow screens the
// content area must gain bottom padding equal to the bar's clearance, so
// no list row is hidden behind the fixed bar.
func TestBulkBarClearancePadsContentOnNarrowScreens(t *testing.T) {
	css := mustRead(t, static.FS, "app.css")
	for _, block := range mediaBlocks(css) {
		if strings.Contains(block, ".main") &&
			strings.Contains(block, "padding-bottom") &&
			strings.Contains(block, "--bulkbar-h") {
			return
		}
	}
	t.Error("app.css: no @media (max-width: 640px) rule pads .main's bottom padding with the --bulkbar-h clearance; the fixed bulk bar covers the last list rows")
}

// TestBulkBarJSKeepsClearanceInSync: the script must measure the bar's
// clearance into --bulkbar-h and react to every height change (toggle,
// inline confirms, text wrap, viewport resize).
func TestBulkBarJSKeepsClearanceInSync(t *testing.T) {
	js := mustRead(t, static.FS, "inventory.js")
	for _, want := range []string{
		"--bulkbar-h",           // the variable the stylesheet consumes
		"getBoundingClientRect", // the bar's position, not just its size
		"ResizeObserver",        // height changes without a script event
	} {
		if !strings.Contains(js, want) {
			t.Errorf("inventory.js: missing %q; the bulk bar clearance is not kept in sync with the bar", want)
		}
	}
}

// TestInventoryTemplateBulkBarToggleA11y: the sheet toggle must be a real
// button with the ARIA state and control wiring, so keyboard and
// screen-reader users can expand the sheet without a pointer.
func TestInventoryTemplateBulkBarToggleA11y(t *testing.T) {
	html := mustRead(t, templates.FS, "inventory.html")
	re := regexp.MustCompile(`id="bulkbar-toggle"[^>]*aria-expanded="false"[^>]*aria-controls="bulkbar-body"`)
	if !re.MatchString(html) {
		t.Error(`inventory.html: the bulk bar toggle needs aria-expanded and aria-controls="bulkbar-body" to stay keyboard and screen-reader friendly`)
	}
	if !strings.Contains(html, `id="bulkbar-body"`) {
		t.Error("inventory.html: missing the #bulkbar-body group the toggle controls")
	}
}

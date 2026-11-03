// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// liveClientBlock returns the live-values block of inventory.js.
func liveClientBlock(t *testing.T) string {
	t.Helper()
	js, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "web", "static", "inventory.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)
	start := strings.Index(src, "// Live chart values (ADR 0006 P1-37)")
	if start < 0 {
		t.Fatal("inventory.js has no live chart block")
	}
	end := strings.Index(src[start:], "\n})();")
	if end < 0 {
		t.Fatal("live chart block is not closed")
	}
	return src[start : start+end]
}

// The client speaks the server's contract: the same routes, events and
// renewal, and it releases its boxes when the page is hidden.
func TestInventoryJSConsumesLiveStream(t *testing.T) {
	block := liveClientBlock(t)
	for _, want := range []string{
		"new EventSource('" + EventsPath + "')",
		"fetch('" + TargetsPath + "'",
		"on('hello'", "on('value'", "on('age'",
		"res.status === 410",   // expired viewer: reopen the stream
		"document.hidden ? []", // hidden page: release every box
		"'visibilitychange'",   // ... as soon as it is hidden
		"IntersectionObserver", // only visible boxes are requested
		".slice(0, 32)",        // maxViewerBoxes
		"textContent",          // values rendered as text
		"renew * 1000",         // server-provided renewal cadence
		// One POST at a time: a send while one runs is queued and the
		// newest list goes out after it, so a stale list never lands
		// after the empty list of a hidden page.
		"if (busy || !v) { again = busy; return; }",
		"if (again || v !== viewer) return send();",
		// A box the server did not grant (denied, revoked or expired
		// grant, over budget) loses its live line, and a box without a
		// value for staleAfter shows its age: never a fresh-looking
		// old value (P1-37).
		"new Set((await res.json()).granted)",
		"if (!g.has(id)) drop(els.get(id));",
		"b.t.parentNode.remove()",
		"b.at = Date.now();",
		"Date.now() - b.at > 15e3) show(b, ",
		"kind: 'node'", "kind: 'guest'", "kind: 'host'",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("live block lacks %q", want)
		}
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "document.write"} {
		if strings.Contains(block, bad) {
			t.Errorf("live block uses %s", bad)
		}
	}
	if maxViewerBoxes != 32 {
		t.Errorf("maxViewerBoxes = %d; update the client slice", maxViewerBoxes)
	}
	if staleAfter != 15*time.Second {
		t.Errorf("staleAfter = %s; update the client's 15e3 stale threshold", staleAfter)
	}
	if clientRenewal >= viewerLease {
		t.Errorf("client renewal %s must be shorter than the viewer lease %s", clientRenewal, viewerLease)
	}
}

// inventoryJSBudget is the size budget of inventory.js; it equals the
// limit of TestChartScriptIsOneSmallScript in internal/web/ui, checked
// here too because the live block is the part of the script that grows.
const inventoryJSBudget = 30 * 1024

func TestInventoryJSStaysWithinBudget(t *testing.T) {
	fi, err := os.Stat(filepath.Join("..", "..", "..", "..", "web", "static", "inventory.js"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > inventoryJSBudget {
		t.Errorf("inventory.js is %d bytes, over its %d-byte budget", fi.Size(), inventoryJSBudget)
	}
}

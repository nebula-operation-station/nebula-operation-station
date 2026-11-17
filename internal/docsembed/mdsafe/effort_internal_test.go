// SPDX-License-Identifier: AGPL-3.0-or-later

package mdsafe

import (
	"strings"
	"testing"
)

// stepBound is the largest step count renderCounted may report. A scan
// starts only while steps < maxScanSteps and then adds at most one scan
// window (findRun) or one window plus one destination (parseLink).
const stepBound = maxScanSteps + maxInlineScan + maxLinkDestBytes

// TestScanStepsAreLinear renders the delimiter units that drive the
// scanners at MaxSourceBytes and counts the bytes they scan. The count
// must stay under stepBound. A quadratic scanner, or one that ignores
// its window, exceeds it at this size: the check is an operation count,
// not a timing.
func TestScanStepsAreLinear(t *testing.T) {
	for _, unit := range []string{"*", "**", "[", "[a](b", "`", "](", "|", "| a |\n|-|\n", "- ", "&"} {
		src := strings.Repeat(unit, MaxSourceBytes/len(unit))
		_, steps, err := renderCounted([]byte(src), Options{})
		if err != nil {
			t.Fatalf("unit %q: %v", unit, err)
		}
		if steps > stepBound {
			t.Errorf("unit %q: %d scan steps for %d bytes, bound %d", unit, steps, len(src), stepBound)
		}
	}
}

// TestScanBudgetDoesNotTouchNormalDocuments checks that ordinary Markdown
// stays far below the budget: its scan steps are at most its length, so
// the budget never degrades a real document into text.
func TestScanBudgetDoesNotTouchNormalDocuments(t *testing.T) {
	line := "Some *em* and **strong** and `code` and [x](hosts.md#frag) text & more.\n"
	src := strings.Repeat(line, MaxSourceBytes/len(line))
	res, steps, err := renderCounted([]byte(src), Options{Relative: func(string, string) (string, bool) { return "/help/hosts", true }})
	if err != nil {
		t.Fatal(err)
	}
	if steps > len(src) {
		t.Errorf("normal document: %d scan steps for %d bytes", steps, len(src))
	}
	if !strings.Contains(string(res.HTML), `<a href="/help/hosts">x</a>`) {
		t.Errorf("normal document lost its links after the scan")
	}
}

// TestSpentBudgetRendersDelimitersAsText checks the fail-safe: once the
// budget is spent, delimiters are plain text and the output stays
// escaped.
func TestSpentBudgetRendersDelimitersAsText(t *testing.T) {
	r := &renderer{taken: map[string]bool{}, next: map[string]int{}, steps: maxScanSteps}
	var b strings.Builder
	r.inline(&b, "*a* [x](/help) `c` <b>", 0, false)
	want := "*a* [x](/help) `c` &lt;b&gt;"
	if got := b.String(); got != want {
		t.Errorf("spent budget: got %q, want %q", got, want)
	}
}

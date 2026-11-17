// SPDX-License-Identifier: AGPL-3.0-or-later

package mdsafe

import (
	"strings"
	"testing"
)

// stepBound is the largest step count renderCounted may report. A scan
// starts only while steps < maxScanSteps, so it enters with at most
// maxScanSteps-1 steps. The largest single charge is one parseLink with a
// closed label and a destination that runs to its window: the label adds
// at most maxInlineScan-1 bytes (up to the "]"), and the destination scan
// adds "](" plus at most maxLinkDestBytes bytes, so 1023 + 2050 = 3073.
// A label that runs out of window charges at most maxInlineScan+1 and
// returns early, and findRun adds at most maxInlineScan, so both are
// smaller.
const (
	maxParseLinkCharge = (maxInlineScan - 1) + (maxLinkDestBytes + 2)
	stepBound          = maxScanSteps - 1 + maxParseLinkCharge
)

// linearSmall and linearLarge are the two source sizes the linearity test
// compares; the large one is exactly twice the small one, and both are
// multiples of every scanUnits length. Both keep the work below
// maxScanSteps (about 1024 steps per byte is the worst), so the budget
// does not set the count.
//
// linearSlack bounds the difference between steps(2N) and 2*steps(N) for
// an input that repeats a unit. Scan starts before the last
// maxParseLinkCharge bytes of a document parse the same way in N and 2N,
// so only starts in the last maxParseLinkCharge bytes of the N-byte
// document or of the 2N-byte document can differ. There are at most
// maxParseLinkCharge such starts in each, and each is charged at most
// maxParseLinkCharge steps, so the difference is at most
// 2*maxParseLinkCharge². The slack does not grow with the size.
const (
	linearSmall = 5 << 10
	linearLarge = 10 << 10
	linearSlack = 2 * maxParseLinkCharge * maxParseLinkCharge
)

// scanUnits are the delimiter patterns that drive the scanners.
var scanUnits = []string{"*", "**", "[", "[a](b", "`", "](", "|", "| a |\n|-|\n", "- ", "&"}

// TestScanStepsAreLinear measures the scan steps at two sizes, the second
// exactly twice the first, both below the budget. Linear work doubles the
// steps when the input doubles (up to linearSlack); a scanner that is
// quadratic in the input more than doubles them. A scanner whose work
// reaches the budget at these sizes fails too, because then the count
// measures the cap, not the scanner. The MaxSourceBytes test below keeps
// the absolute bound.
func TestScanStepsAreLinear(t *testing.T) {
	for _, unit := range scanUnits {
		small := scanStepsFor(t, unit, linearSmall/len(unit))
		large := scanStepsFor(t, unit, linearLarge/len(unit))
		if large.size != 2*small.size {
			t.Fatalf("unit %q: sizes %d and %d are not in ratio 2", unit, small.size, large.size)
		}
		if large.steps >= maxScanSteps {
			t.Errorf("unit %q: %d steps for %d bytes reaches the budget %d; the scanner is not measured", unit, large.steps, large.size, maxScanSteps)
			continue
		}
		if notLinear(small, large) {
			t.Errorf("unit %q: %d steps for %d bytes, %d for %d bytes: not linear (bound %d)",
				unit, small.steps, small.size, large.steps, large.size, 2*small.steps+linearSlack)
		}
	}
}

// notLinear reports whether doubling the input (large is twice small)
// more than doubles the steps beyond linearSlack.
func notLinear(small, large scanResult) bool {
	return large.steps > 2*small.steps+linearSlack
}

// unboundedLimits is a scanner with no window and no budget: every scan
// runs to the end of the source, so its work is quadratic in the input.
// Its budget is far above maxScanSteps, so the budget never stops it at
// the sizes the test uses; only the linearity comparison can fail.
var unboundedLimits = scanLimits{window: 1 << 40, linkDest: 1 << 40, budget: 1 << 40}

// The self-test sizes are larger than the linearity sizes. A quadratic
// scanner exceeds the slack only once its excess over 2*steps(N) passes
// linearSlack, which is about 2*maxParseLinkCharge² of steps; at 5 KiB
// the "*" unit gives about 6.5M steps, not enough to pass the slack.
const (
	quadraticSmall = 8 << 10
	quadraticLarge = 16 << 10
)

// TestQuadraticScannerFailsLinearity checks that the linearity comparison
// itself catches a superlinear scanner. The test hook is unboundedLimits,
// so the budget cannot stop the scanner; the comparison must reject it.
func TestQuadraticScannerFailsLinearity(t *testing.T) {
	for _, unit := range []string{"*", "["} {
		small := scanStepsWith(t, unboundedLimits, unit, quadraticSmall/len(unit))
		large := scanStepsWith(t, unboundedLimits, unit, quadraticLarge/len(unit))
		if !notLinear(small, large) {
			t.Errorf("unit %q: quadratic scanner passed: %d steps for %d bytes, %d for %d bytes (bound %d)",
				unit, small.steps, small.size, large.steps, large.size, 2*small.steps+linearSlack)
		}
	}
}

// TestScanStepsBoundedAtMaxSize checks the absolute bound at the largest
// accepted source for each unit.
func TestScanStepsBoundedAtMaxSize(t *testing.T) {
	for _, unit := range scanUnits {
		m := scanStepsFor(t, unit, MaxSourceBytes/len(unit))
		if m.steps > stepBound {
			t.Errorf("unit %q: %d scan steps for %d bytes, bound %d", unit, m.steps, m.size, stepBound)
		}
	}
}

// scanResult is the step count for one rendered source and its length.
type scanResult struct{ steps, size int }

// scanStepsFor renders unit repeated reps times and returns the scan steps
// spent and the source length.
func scanStepsFor(t *testing.T, unit string, reps int) scanResult {
	t.Helper()
	return scanStepsWith(t, defaultLimits, unit, reps)
}

// scanStepsWith is scanStepsFor under the given scan limits.
func scanStepsWith(t *testing.T, lim scanLimits, unit string, reps int) scanResult {
	t.Helper()
	src := strings.Repeat(unit, reps)
	_, steps, err := renderLimited([]byte(src), Options{}, lim)
	if err != nil {
		t.Fatalf("unit %q, %d repeats: %v", unit, reps, err)
	}
	return scanResult{steps: steps, size: len(src)}
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
	r := &renderer{lim: defaultLimits, taken: map[string]bool{}, next: map[string]int{}, steps: maxScanSteps}
	var b strings.Builder
	r.inline(&b, "*a* [x](/help) `c` <b>", 0, false)
	want := "*a* [x](/help) `c` &lt;b&gt;"
	if got := b.String(); got != want {
		t.Errorf("spent budget: got %q, want %q", got, want)
	}
}

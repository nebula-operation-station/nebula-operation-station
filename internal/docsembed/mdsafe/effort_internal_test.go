// SPDX-License-Identifier: AGPL-3.0-or-later

package mdsafe

import (
	"errors"
	"fmt"
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

// Linearity check. It measures the scan steps at three sizes, each a
// whole number of repeats of one unit, and compares steps per byte.
//
// Why not a doubling check, steps(2N) <= 2*steps(N) + slack? Let
// B = maxScanSteps = 16*2^20 = 16,777,216 and M = maxParseLinkCharge =
// 3073. A quadratic scanner with steps(N) = c*N^2 has
// steps(2N) - 2*steps(N) = 2cN^2 = steps(2N)/2. The check can only reach
// a verdict below the budget, so steps(2N) < B and the excess is below
// B/2 = 8,388,608. A sound slack for the real scanner is M^2 = 9,443,329
// (the earlier 2*M^2 = 18,886,658 is larger still), so an excess above the slack needs
// steps(2N) > 2*M^2 > B, which is past the budget. No choice of sizes
// makes such a check fire, so it is replaced by the ratio below.
//
// Ratio: a linear scanner's steps per byte settle to a constant, and the
// finite-size offset shrinks as N grows. A quadratic scanner's steps per
// byte grow in proportion to N, so from 4 KiB to 16 KiB they grow 4x.
// The measured steps per byte for the real scanner, 4 KiB -> 16 KiB, are
// at most 1.26x ("[a](b": 308 -> 385; "*": 448 -> 496; "[": 896 ->
// 992). linearFactor = 2 sits between 1.26 and 4.
//
// The largest size is 16 KiB because the "[" unit uses 16,253,440 steps
// there, within 3% of the budget; a larger size would make the real
// scanner hit its budget and the verdict would measure the cap.
const linearFactor = 2

// linearSizes are the source sizes the linearity check measures. Each is
// rounded down to a whole number of unit repeats.
var linearSizes = [3]int{4 << 10, 8 << 10, 16 << 10}

// scanUnits are the delimiter patterns that drive the scanners.
var scanUnits = []string{"*", "**", "[", "[a](b", "`", "](", "|", "| a |\n|-|\n", "- ", "&"}

// errNotLinear reports that scan steps per byte grow beyond linearFactor
// between the smallest and a larger size.
var errNotLinear = errors.New("scan steps grow faster than the source")

// errOverBudget reports that a measurement reached the scanner's own
// budget, so the count measures the cap, not the scanner.
var errOverBudget = errors.New("scan steps reach the budget; the scanner is not measured")

// checkLinearity measures the scan steps for unit at linearSizes under lim
// and returns nil if they grow linearly. It returns an error wrapping
// errOverBudget if a measurement reaches lim.budget, and one wrapping
// errNotLinear if steps per byte at a size exceed linearFactor times
// steps per byte at the smallest size. TestScanStepsAreLinear and its
// self-test both call this function; only lim differs.
func checkLinearity(lim scanLimits, unit string) error {
	var sizes, steps [len(linearSizes)]int
	for i, n := range linearSizes {
		src := strings.Repeat(unit, n/len(unit))
		_, s, err := renderLimited([]byte(src), Options{}, lim)
		if err != nil {
			return fmt.Errorf("unit %q, %d bytes: %w", unit, len(src), err)
		}
		if s >= lim.budget {
			return fmt.Errorf("unit %q: %d steps for %d bytes: %w", unit, s, len(src), errOverBudget)
		}
		sizes[i], steps[i] = len(src), s
	}
	// steps[i]/sizes[i] <= linearFactor * steps[0]/sizes[0], cross-multiplied
	// in int64 so the products cannot overflow on 32-bit platforms.
	for i := 1; i < len(linearSizes); i++ {
		if int64(steps[i])*int64(sizes[0]) > linearFactor*int64(steps[0])*int64(sizes[i]) {
			return fmt.Errorf("unit %q: %d steps for %d bytes, %d for %d bytes (per-byte ratio over x%d): %w",
				unit, steps[0], sizes[0], steps[i], sizes[i], linearFactor, errNotLinear)
		}
	}
	return nil
}

// TestScanStepsAreLinear checks that every unit's scan steps grow linearly
// with the source under the production limits.
func TestScanStepsAreLinear(t *testing.T) {
	for _, unit := range scanUnits {
		if err := checkLinearity(defaultLimits, unit); err != nil {
			t.Error(err)
		}
	}
}

// unboundedLimits is a scanner with no window and no budget: every scan
// runs to the end of the source, so its work is quadratic in the input.
// Its budget is far above maxScanSteps, so the budget never stops it at
// the sizes the check uses; only the ratio comparison can fail.
var unboundedLimits = scanLimits{window: 1 << 40, linkDest: 1 << 40, budget: 1 << 40}

// TestQuadraticScannerFailsLinearity runs the same checkLinearity as
// TestScanStepsAreLinear with an injected quadratic scanner. It must
// return errNotLinear, not pass and not hit the budget, which proves the
// linearity check can fail.
func TestQuadraticScannerFailsLinearity(t *testing.T) {
	for _, unit := range []string{"*", "["} {
		if err := checkLinearity(unboundedLimits, unit); !errors.Is(err, errNotLinear) {
			t.Errorf("unit %q: quadratic scanner: got %v, want errNotLinear", unit, err)
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
	src := strings.Repeat(unit, reps)
	_, steps, err := renderLimited([]byte(src), Options{}, defaultLimits)
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

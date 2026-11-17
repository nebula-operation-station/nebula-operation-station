// SPDX-License-Identifier: AGPL-3.0-or-later

package helpdocs

import (
	"runtime"
	"strings"
	"testing"
)

// TestFenceCloseNeedsRunOfMarkers pins the closing-fence rule: a line
// closes an opening fence only if it starts with at least run copies of
// the opening marker and holds nothing but marker characters and spaces.
func TestFenceCloseNeedsRunOfMarkers(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		marker byte
		run    int
		want   bool
	}{
		{"exact run", "```", '`', 3, true},
		{"longer run closes", "````", '`', 3, true},
		{"shorter run does not close", "``", '`', 3, false},
		{"run four needs four", "```", '`', 4, false},
		{"trailing spaces allowed", "```   ", '`', 3, true},
		{"indent up to three allowed", "   ```", '`', 3, true},
		{"indent four is not a fence", "    ```", '`', 3, false},
		{"info string blocks close", "```go", '`', 3, false},
		{"other marker does not close", "~~~", '`', 3, false},
		{"mixed marker does not close", "```~", '`', 3, false},
		{"marker and spaces mixed close", "```  `", '`', 3, true},
		{"empty line does not close", "", '`', 3, false},
		{"tilde run closes tilde fence", "~~~~", '~', 3, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fenceClose(tc.line, tc.marker, tc.run); got != tc.want {
				t.Fatalf("fenceClose(%q, %q, %d) = %v, want %v",
					tc.line, tc.marker, tc.run, got, tc.want)
			}
		})
	}
}

// TestLongFenceRunScansInLinearAllocation guards against quadratic work
// on a long fence run. Before the fix, every line after the opening
// fence allocated a copy of the whole run, so this input allocated
// about run*lines bytes (4 GiB here). A linear scan allocates only the
// lines slice, far below the limit.
func TestLongFenceRunScansInLinearAllocation(t *testing.T) {
	const (
		run   = 64 << 10
		lines = 64 << 10
		limit = 32 << 20
	)
	src := make([]string, 0, lines+1)
	src = append(src, strings.Repeat("`", run))
	for i := 0; i < lines; i++ {
		src = append(src, "a")
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fences := scanFences(src)
	runtime.ReadMemStats(&after)

	if len(fences) != 1 || fences[0].closed {
		t.Fatalf("scanFences = %+v, want one unclosed fence", fences)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > limit {
		t.Fatalf("scanFences allocated %d bytes, want at most %d", alloc, limit)
	}
}

// TestLongFenceRunBuildWithinSourceLimit runs Build on a source near the
// 1 MiB limit whose fence run is about half of it, followed by many
// short lines. It must finish and index the document.
func TestLongFenceRunBuildWithinSourceLimit(t *testing.T) {
	const run = 256 << 10
	var b strings.Builder
	b.WriteString("# T\n\n## A\n\n")
	b.WriteString(strings.Repeat("`", run))
	b.WriteString("\n")
	for b.Len() < 1<<20-16 {
		b.WriteString("a\n")
	}
	ix := build(t, "longfence", b.String())
	checkInvariants(t, ix)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package paths_test

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/paths"
)

// TestOverlayLimitsMatchRenderer keeps the Go overlay limits equal to
// PATHS_LIMITS in the renderer's paths.js, so an overlay the server builds
// is never rejected by the renderer for its size or ranks.
func TestOverlayLimitsMatchRenderer(t *testing.T) {
	src, err := os.ReadFile("../../../../web/static/trafficmap/paths.js")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)PATHS_LIMITS = Object\.freeze\(\{(.*?)\}\)`).FindSubmatch(src)
	if block == nil {
		t.Fatal("PATHS_LIMITS not found")
	}
	want := map[string]int{"beams": paths.MaxBeams, "marks": paths.MaxMarks, "rank": attackpath.PathsPerTarget, "idLength": 128}
	for k, v := range want {
		m := regexp.MustCompile(`\b` + k + `: (\d+),`).FindSubmatch(block[1])
		if m == nil {
			t.Errorf("PATHS_LIMITS.%s not found", k)
			continue
		}
		if got, _ := strconv.Atoi(string(m[1])); got != v {
			t.Errorf("PATHS_LIMITS.%s = %d, Go says %d", k, got, v)
		}
	}
}

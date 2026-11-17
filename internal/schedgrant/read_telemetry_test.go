// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import "testing"

// TestIsTelemetryActionAcceptsExactlyTheReviewedReads pins the telemetry
// authority to the five reviewed actions. Any other name, including a
// near miss in prefix, case or whitespace, gets no telemetry profile.
func TestIsTelemetryActionAcceptsExactlyTheReviewedReads(t *testing.T) {
	cases := []struct {
		name  string
		id    string
		telem bool
	}{
		{"host metrics", "host.metrics", true},
		{"filesystem list", "filesystem.list", true},
		{"pci inventory", "pci.inventory", true},
		{"gpu status", "gpu.status", true},
		{"docker stats", "docker.stats", true},
		{"empty", "", false},
		{"other prefix", "x.host.metrics", false},
		{"other prefix on docker", "exec.docker.stats", false},
		{"mixed case", "Host.metrics", false},
		{"upper case", "GPU.STATUS", false},
		{"trailing space", "gpu.status ", false},
		{"leading space", " docker.stats", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTelemetryAction(tc.id); got != tc.telem {
				t.Fatalf("IsTelemetryAction(%q) = %v, want %v", tc.id, got, tc.telem)
			}
		})
	}
}

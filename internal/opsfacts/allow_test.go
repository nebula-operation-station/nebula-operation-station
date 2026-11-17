// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import "testing"

// TestFamiliesOnlyAllowlistedActions checks the suggestion allowlist: the
// five families of ADR 0016 D4 and no read-only action.
func TestFamiliesOnlyAllowlistedActions(t *testing.T) {
	tests := []struct {
		action string
		family string
		ok     bool
	}{
		{"package.install_security", FamilyOSUpdate, true},
		{"package.install_all", FamilyOSUpdate, true},
		{"system.reboot", FamilyReboot, true},
		{"service.restart", FamilyServiceRestart, true},
		{"docker.compose_update", FamilyContainerUpdate, true},
		{"docker.update", FamilyContainerUpdate, true},
		{"docker.restart", FamilyContainerRestart, true},
		{"package.list_updates", "", false},
		{"host.list_updates", "", false},
		{"service.status", "", false},
		{"docker.logs", "", false},
		{"", "", false},
		{"package.install_security ", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			family, ok := Families(tt.action)
			if ok != tt.ok || family != tt.family {
				t.Fatalf("Families(%q) = (%q, %v), want (%q, %v)", tt.action, family, ok, tt.family, tt.ok)
			}
		})
	}
}

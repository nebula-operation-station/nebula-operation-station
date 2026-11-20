// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

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

// TestEveryAllowlistedActionHasOneFixedLabel checks the fixed NOS labels of
// ADR 0016 D4: each allowlisted action has exactly one label, short, plain
// text with no control character and no URL.
func TestEveryAllowlistedActionHasOneFixedLabel(t *testing.T) {
	if len(suggestionLabels) != len(suggestionAllowlist) {
		t.Fatalf("%d labels for %d allowlisted actions", len(suggestionLabels), len(suggestionAllowlist))
	}
	for action := range suggestionAllowlist {
		label, ok := Label(action)
		if !ok {
			t.Errorf("%s: no label", action)
			continue
		}
		if label == "" || len(label) > MaxCandidateLabelBytes {
			t.Errorf("%s: label %q has %d bytes, want 1..%d", action, label, len(label), MaxCandidateLabelBytes)
		}
		if !utf8.ValidString(label) {
			t.Errorf("%s: label is not UTF-8", action)
		}
		for _, r := range label {
			if unicode.IsControl(r) {
				t.Errorf("%s: label %q has a control character", action, label)
				break
			}
		}
		if lower := strings.ToLower(label); strings.Contains(lower, "://") || strings.Contains(lower, "www.") {
			t.Errorf("%s: label %q looks like a URL", action, label)
		}
	}
}

// TestLabelOnlyForAllowlistedActions checks that Label answers for an
// allowlisted action only: a read-only action, an empty ID or a near miss
// has no label and so never becomes a candidate.
func TestLabelOnlyForAllowlistedActions(t *testing.T) {
	for _, action := range []string{"package.list_updates", "docker.logs", "", "system.reboot "} {
		if label, ok := Label(action); ok || label != "" {
			t.Errorf("Label(%q) = (%q, %v), want no label", action, label, ok)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
)

// TestContainerUpdateNamesEveryReason: every reason the preview can report,
// and every preview status other than ok, has an explanation, so no
// unavailable unit, service or image is shown with a bare code.
func TestContainerUpdateNamesEveryReason(t *testing.T) {
	reasons := append(dockerhost.PreviewReasons(), dockerhost.PreviewPrepareRequired, "salt_unsafe", "tooling_missing", "not_root",
		"params_invalid", "host_unreadable", "result_too_large", "internal_error", "snapshot_too_large")
	for _, r := range reasons {
		if _, ok := ctrReasonText[r]; !ok {
			t.Errorf("reason %q has no explanation", r)
		}
	}
}

func TestSplitKeyFromTheRight(t *testing.T) {
	cases := []struct {
		key   string
		n     int
		host  string
		parts []string
		ok    bool
	}{
		{"web-01/site/web", 2, "web-01", []string{"site", "web"}, true},
		{"a/b/site/web", 2, "a/b", []string{"site", "web"}, true},
		{"web-01/x", 1, "web-01", []string{"x"}, true},
		{"web-01", 1, "", nil, false},
		{"/site/web", 2, "", nil, false},
		{"web-01/site/", 2, "", nil, false},
		{"web-01//web", 2, "", nil, false},
	}
	for _, c := range cases {
		host, parts, ok := splitKey(c.key, c.n)
		if ok != c.ok || host != c.host || len(parts) != len(c.parts) {
			t.Errorf("splitKey(%q) = %q %v %v", c.key, host, parts, ok)
			continue
		}
		for i := range parts {
			if parts[i] != c.parts[i] {
				t.Errorf("splitKey(%q) = %v", c.key, parts)
			}
		}
	}
}

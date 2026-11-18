// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

// TestSafeNOSLinkAcceptsOnlyNOSPaths fixes the render-time link rule: a
// link is shown only when it is a plain NOS path.
func TestSafeNOSLinkAcceptsOnlyNOSPaths(t *testing.T) {
	ok := []string{"/operations/ex-1", "/deployments/run-7", "/"}
	bad := []string{
		"",
		"operations/ex-1",
		"//evil.example/x",
		"/\\evil.example",
		"/x//y",
		"https://evil.example",
		"javascript:alert(1)",
		"/a?b=c",
		"/a#frag",
		"/a b",
		"/a\tb",
		"/a\nb",
		"/café",
		strings.Repeat("/a", notifylog.MaxLink),
	}
	for _, s := range ok {
		if !safeNOSLink(s) {
			t.Errorf("safeNOSLink(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if safeNOSLink(s) {
			t.Errorf("safeNOSLink(%q) = true, want false", s)
		}
	}
}

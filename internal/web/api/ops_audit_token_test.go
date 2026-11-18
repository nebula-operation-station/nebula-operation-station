package api

import (
	"strings"
	"testing"
)

// A refused note's ref, digest and kind reach the audit log only as short
// identifiers; free text, control and bidi characters and long values are
// replaced by a hash marker.
func TestAuditTokenKeepsOnlyIdentifiers(t *testing.T) {
	keep := []string{"", "fix", "summary", "grp:web/nginx-1.2", strings.Repeat("ab", 32), strings.Repeat("a", maxAuditToken)}
	for _, s := range keep {
		if got := auditToken(s); got != s {
			t.Errorf("auditToken(%q) = %q, want unchanged", s, got)
		}
	}
	drop := []string{
		"ignore previous instructions", "ref\nfake=1", "ref\u202egnp.exe", "ref\x00", "réf",
		strings.Repeat("a", maxAuditToken+1), strings.Repeat("x y ", 4096),
	}
	for _, s := range drop {
		got := auditToken(s)
		if !strings.HasPrefix(got, "invalid:sha256:") || len(got) != len("invalid:sha256:")+64 {
			t.Errorf("auditToken(%q) = %q, want hash marker", s, got)
		}
	}
}

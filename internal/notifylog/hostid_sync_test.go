package notifylog

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// TestHostIDPatternMatchesCanonical keeps the local host ID pattern (a copy,
// see hostIDRe) identical to canonical.ValidHostID.
func TestHostIDPatternMatchesCanonical(t *testing.T) {
	cases := []string{
		"", "a", "web01", "Web01", "web-01.example", "web_01", "0", "-web", ".web", "_web",
		"web 01", "web/01", "wéb", "tk-web", strings.Repeat("a", 63), strings.Repeat("a", 64),
		strings.Repeat("0123456789abcdef", 2), "web01\n", "\x00",
	}
	for _, s := range cases {
		if got, want := hostIDRe.MatchString(s), canonical.ValidHostID(s); got != want {
			t.Errorf("%q: notifylog %v, canonical %v", s, got, want)
		}
	}
}

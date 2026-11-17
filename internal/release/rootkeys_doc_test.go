// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"os"
	"strings"
	"testing"
)

// compiledRoot1Line returns the root-1 line of the compiled anchor file.
func compiledRoot1Line(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(string(anchorsFile), "\n") {
		if strings.HasPrefix(line, "root-1 ") {
			return line
		}
	}
	t.Fatal("compiled anchor file has no root-1 line")
	return ""
}

// TestReleaseDocsRecordCompiledRoot1Line keeps the maintainer walkthrough
// and the spec in step with the anchor compiled into every binary: the
// walkthrough records the compiled line byte for byte and the spec records
// the same public key line without the slot ID.
func TestReleaseDocsRecordCompiledRoot1Line(t *testing.T) {
	line := compiledRoot1Line(t)
	pub := strings.TrimPrefix(line, "root-1 ")
	for _, c := range []struct{ path, want string }{
		{"../../docs/admin/release-signing.md", line},
		{"../../docs/spec/10-modules.md", pub},
	} {
		raw, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatalf("read %s: %v", c.path, err)
		}
		found := false
		for _, l := range strings.Split(string(raw), "\n") {
			if l == c.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s has no line equal to %q", c.path, c.want)
		}
	}
}

// TestCompiledRoot1CommentNamesNoHardware checks that the compiled root-1
// comment carries only the key name and owner, no device details.
func TestCompiledRoot1CommentNamesNoHardware(t *testing.T) {
	f := strings.Fields(compiledRoot1Line(t))
	if got := strings.Join(f[3:], " "); got != "nebula-release-root-1 (Axel)" {
		t.Fatalf("root-1 comment = %q", got)
	}
}

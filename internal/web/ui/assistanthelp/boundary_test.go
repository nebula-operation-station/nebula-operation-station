// SPDX-License-Identifier: AGPL-3.0-or-later

package assistanthelp

import (
	"os/exec"
	"strings"
	"testing"
)

// The Help backend (ADR 0016 D11) never reads notes, findings or the Ops
// configuration. This test checks the transitive import graph of this
// package with the go tool, so a file added here or in a dependency that
// reaches those packages fails the test.
func TestHelpPackageDoesNotReachNotesOrOpsPackages(t *testing.T) {
	forbidden := []string{
		"/internal/opsnotes",
		"/internal/vulnstore",
		"/internal/web/ui",
	}
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	if len(deps) == 0 {
		t.Fatal("go list -deps returned no packages")
	}
	for _, dep := range deps {
		for _, bad := range forbidden {
			if strings.HasSuffix(dep, bad) {
				t.Errorf("assistanthelp depends on %s; the Help backend must not reach notes, findings or the Ops handler", dep)
			}
		}
	}
}

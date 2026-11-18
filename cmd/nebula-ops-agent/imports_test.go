// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os/exec"
	"strings"
	"testing"
)

const modulePath = "github.com/nebula-operation-station/nebula-operation-station"

// allowedImports is the import boundary of the ops agent (ADR 0016 D2): the
// standard library, its own packages, the shared LLM client and the two
// documentation packages. The documentation packages import the embedded
// handbook (docsembed and its mdsafe helper); those are named here, not
// matched by prefix, so nothing else is reachable through them.
var allowedImports = []string{
	modulePath + "/cmd/nebula-ops-agent",
	modulePath + "/internal/opsagent/",
	modulePath + "/internal/llmclient",
	modulePath + "/internal/helpdocs",
	modulePath + "/internal/helpsearch",
	modulePath + "/internal/docsembed",
	modulePath + "/internal/docsembed/mdsafe",
}

// TestOpsAgentImportsOnlyAllowlist walks the full dependency closure of the
// agent binary. Every package must be in the standard library or in the
// allowlist above; the test fails closed on anything else.
func TestOpsAgentImportsOnlyAllowlist(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{.Standard}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		path, std, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("unexpected go list line %q", line)
		}
		if std == "true" {
			continue
		}
		if !allowed(path) {
			t.Errorf("import %s is outside the ops agent allowlist", path)
		}
		seen[path] = true
	}
	// The test must not pass vacuously: the packages the agent is built on
	// have to show up in the closure.
	for _, want := range []string{modulePath + "/internal/llmclient", modulePath + "/internal/helpsearch",
		modulePath + "/internal/opsagent/run"} {
		if !seen[want] {
			t.Errorf("expected %s in the dependency closure", want)
		}
	}
}

func allowed(path string) bool {
	for _, a := range allowedImports {
		if path == a || (strings.HasSuffix(a, "/") && strings.HasPrefix(path, a)) {
			return true
		}
	}
	return false
}

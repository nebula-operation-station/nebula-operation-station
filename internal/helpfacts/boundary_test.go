// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports are the stores and services the fact projector must
// never reach (ADR 0014 D3, AS-06): hosts' secrets, audit, execution,
// findings, traffic and the web layer.
var forbiddenImports = []string{
	"internal/vault",
	"internal/keyring",
	"internal/auditlog",
	"internal/executor",
	"internal/executordb",
	"internal/executions",
	"internal/vulnstore",
	"internal/vulnfinding",
	"internal/trafficstore",
	"internal/serverdb",
	"internal/permit",
	"internal/hostrun",
	"internal/web",
	"internal/sshtransport",
}

// TestProjectorImportsNoStoreOrService parses every non-test file of the
// package and fails on an import of a forbidden package.
func TestProjectorImportsNoStoreOrService(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenImports {
				if strings.Contains(path, bad) {
					t.Errorf("%s imports %s, which the fact projector must not reach", name, path)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfix_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// modulePath is the import path prefix of this module.
const modulePath = "github.com/nebula-operation-station/nebula-operation-station/"

// forbiddenImports are packages the decision package must never reach,
// directly or through other module packages: the web layer, the vault,
// the keyring and the executor client (ADR 0011 D8: decisions are pure).
var forbiddenImports = []string{
	"internal/web",
	"internal/vault",
	"internal/keyring",
	"internal/executor",
	"internal/executorclient",
}

// moduleImports returns the import paths of the non-test Go files of the
// module package at rel (a path relative to the module root).
func moduleImports(t *testing.T, rel string) []string {
	t.Helper()
	dir := filepath.Join("..", "..", rel)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s/%s: %v", rel, name, err)
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("import path %s: %v", imp.Path.Value, err)
			}
			out = append(out, p)
		}
	}
	return out
}

// TestVulnfixImportBoundary walks every module package vulnfix depends on
// (transitively) and fails when one of them is forbidden.
func TestVulnfixImportBoundary(t *testing.T) {
	seen := map[string]bool{}
	queue := []string{"internal/vulnfix"}
	for len(queue) > 0 {
		rel := queue[0]
		queue = queue[1:]
		if seen[rel] {
			continue
		}
		seen[rel] = true
		for _, imp := range moduleImports(t, rel) {
			if !strings.HasPrefix(imp, modulePath) {
				continue
			}
			next := strings.TrimPrefix(imp, modulePath)
			for _, bad := range forbiddenImports {
				if next == bad || strings.HasPrefix(next, bad+"/") {
					t.Errorf("%s imports %s (forbidden: %s)", rel, next, bad)
				}
			}
			queue = append(queue, next)
		}
	}
	if !seen["internal/vulnstore"] || !seen["internal/vulnver"] {
		t.Fatalf("walk did not reach the expected dependencies: %v", seen)
	}
}

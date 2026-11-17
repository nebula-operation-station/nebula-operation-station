// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/nebula-operation-station/nebula-operation-station/"

// allowedImports is the complete list of direct imports of this package:
// the standard library and three module packages whose enum types or
// decision are used. Any other import fails TestImportsAreAllowlisted until
// it is reviewed and added here.
var allowedImports = map[string]bool{
	"context":                         true,
	"errors":                          true,
	"regexp":                          true,
	"strings":                         true,
	"unicode":                         true,
	"unicode/utf8":                    true,
	"sort":                            true,
	"encoding/json":                   true,
	"crypto/sha256":                   true,
	"fmt":                             true,
	"strconv":                         true,
	modulePath + "internal/inventory": true,
	modulePath + "internal/vulnfix":   true,
	modulePath + "internal/vulnprio":  true,
}

// forbiddenReach lists packages that must never be reachable from this
// package, directly or through other module packages: the vault, the
// keyring, execution logs and their store, the audit log, the traffic store
// and the vulnerability agent (ADR 0016 D4: never in any item).
var forbiddenReach = []string{
	"internal/web",
	"internal/vault",
	"internal/keyring",
	"internal/executor",
	"internal/executorclient",
	"internal/executordb",
	"internal/executions",
	"internal/auditlog",
	"internal/trafficstore",
	"internal/trafficingest",
	"internal/vulnagent",
}

// productionFiles returns the parsed import lists of the non-test files of
// the package, keyed by file name.
func productionFiles(t *testing.T, dir string) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string][]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("import path %s: %v", imp.Path.Value, err)
			}
			out[filepath.Base(name)] = append(out[filepath.Base(name)], p)
		}
	}
	return out
}

// TestImportsAreAllowlisted fails on any direct import outside the
// allowlist. A new import is a boundary change and needs review.
func TestImportsAreAllowlisted(t *testing.T) {
	files := productionFiles(t, ".")
	if len(files) == 0 {
		t.Fatal("no source files checked")
	}
	for name, imports := range files {
		for _, p := range imports {
			if !allowedImports[p] {
				t.Errorf("%s imports %q, which is not on the opsfacts allowlist", name, p)
			}
		}
	}
}

// TestNoForbiddenPackageReachable walks the module packages this package
// depends on, transitively, and fails when one of them is forbidden.
func TestNoForbiddenPackageReachable(t *testing.T) {
	seen := map[string]bool{}
	queue := []string{"internal/opsfacts"}
	for len(queue) > 0 {
		rel := queue[0]
		queue = queue[1:]
		if seen[rel] {
			continue
		}
		seen[rel] = true
		dir := filepath.Join("..", "..", rel)
		if rel == "internal/opsfacts" {
			dir = "."
		}
		for _, imports := range productionFiles(t, dir) {
			for _, imp := range imports {
				if !strings.HasPrefix(imp, modulePath) {
					continue
				}
				next := strings.TrimPrefix(imp, modulePath)
				for _, bad := range forbiddenReach {
					if next == bad || strings.HasPrefix(next, bad+"/") {
						t.Errorf("%s reaches %s (forbidden: %s)", rel, next, bad)
					}
				}
				queue = append(queue, next)
			}
		}
	}
	if !seen["internal/vulnfix"] {
		t.Fatalf("walk did not reach vulnfix: %v", seen)
	}
}

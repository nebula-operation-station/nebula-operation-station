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

// allowedStd is the complete list of standard-library packages that the
// package and its tests may import. The standard library cannot reach a
// module store, so a closed list of it is enough to keep stores out. A new
// import fails TestImportsAreAllowlisted until it is reviewed and added here.
var allowedStd = map[string]bool{
	"context":       true,
	"crypto/sha256": true,
	"encoding/hex":  true,
	"encoding/json": true,
	"errors":        true,
	"fmt":           true,
	"go/parser":     true,
	"go/token":      true,
	"path/filepath": true,
	"reflect":       true,
	"regexp":        true,
	"sort":          true,
	"strconv":       true,
	"strings":       true,
	"testing":       true,
	"unicode":       true,
	"unicode/utf8":  true,
}

// allowedModule is the list of module packages that may be imported. It is
// empty on purpose: the projection reads its inputs as plain values that the
// caller converts (see the package doc). A module package is added here only
// after review, and then its own imports are checked by the walk below.
// Stores, sessions, the audit log, the vault, the keyring and the executor
// are therefore unreachable by construction, not by a list of their names.
var allowedModule = map[string]bool{}

// parseImports returns the import paths of every .go file of dir, tests
// included, keyed by file name.
func parseImports(t *testing.T, dir string) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string][]string{}
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		base := filepath.Base(name)
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("import path %s: %v", imp.Path.Value, err)
			}
			out[base] = append(out[base], p)
		}
	}
	return out
}

// isModule reports whether an import path belongs to this module.
func isModule(p string) bool { return strings.HasPrefix(p, modulePath) }

// TestImportsAreAllowlisted fails on any import outside the allowlists, in
// production files and in tests alike.
func TestImportsAreAllowlisted(t *testing.T) {
	files := parseImports(t, ".")
	if len(files) == 0 {
		t.Fatal("no source files checked")
	}
	for name, imports := range files {
		for _, p := range imports {
			if isModule(p) {
				if !allowedModule[strings.TrimPrefix(p, modulePath)] {
					t.Errorf("%s imports module package %q, which is not on the opsfacts allowlist", name, p)
				}
				continue
			}
			if !allowedStd[p] {
				t.Errorf("%s imports %q, which is not on the opsfacts allowlist", name, p)
			}
		}
	}
}

// TestTransitiveImportsAreAllowlisted walks every allowed module package
// transitively and fails on any import outside the allowlists. With the
// present allowlist the walk has nothing to follow, so it checks that no
// module package is reachable at all.
func TestTransitiveImportsAreAllowlisted(t *testing.T) {
	seen := map[string]bool{}
	queue := []string{""} // "" is this package
	for len(queue) > 0 {
		rel := queue[0]
		queue = queue[1:]
		if seen[rel] {
			continue
		}
		seen[rel] = true
		dir := filepath.Join("..", "..", rel)
		if rel == "" {
			dir = "."
		}
		for name, imports := range parseImports(t, dir) {
			for _, p := range imports {
				if !isModule(p) {
					if !allowedStd[p] {
						t.Errorf("%s (in %q) imports %q, which is not on the allowlist", name, rel, p)
					}
					continue
				}
				next := strings.TrimPrefix(p, modulePath)
				if !allowedModule[next] {
					t.Errorf("%s (in %q) reaches module package %q, which is not on the allowlist", name, rel, next)
					continue
				}
				queue = append(queue, next)
			}
		}
	}
}

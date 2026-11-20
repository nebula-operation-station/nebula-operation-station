// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// importAllowlist lists the module packages this package may import
// (ADR 0014 D3: the prompt sees only the types of the docs and facts
// packages). Standard library packages are always allowed. Everything
// else is refused: the executor client, internal/permit, the vault, the
// keyring and the stores.
var importAllowlist = map[string]bool{
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs":  true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpfacts": true,
}

// TestPromptImportsOnlyAllowlist parses every Go file of the package,
// tests included, and fails on any import that is neither standard
// library nor on the allowlist.
func TestPromptImportsOnlyAllowlist(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		checked++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquote import %s: %v", e.Name(), imp.Path.Value, err)
			}
			if isStdlib(path) || importAllowlist[path] {
				continue
			}
			t.Errorf("%s imports %q: not on the allowlist of ADR 0014 D3", e.Name(), path)
		}
	}
	if checked == 0 {
		t.Fatal("no Go files found in the package directory")
	}
}

// isStdlib reports whether an import path has no dot in its first element,
// the rule the Go toolchain uses for standard library packages.
func isStdlib(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

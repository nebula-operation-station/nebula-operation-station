// SPDX-License-Identifier: AGPL-3.0-or-later

package turns

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTurnsImportsOnlyStdlib enforces the rule of ticket AS-09: the turns
// package uses the standard library only. A standard-library import path has
// no dot in its first element; a module path such as github.com/... does.
func TestTurnsImportsOnlyStdlib(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no Go files found")
	}
	fset := token.NewFileSet()
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: import path %s: %v", name, imp.Path.Value, err)
			}
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") {
				t.Errorf("%s imports %q: only the standard library is allowed", name, path)
			}
		}
	}
}

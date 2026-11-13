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

// allowedImports is the complete list of packages the fact projector may
// import (ADR 0014 D3, AS-06). Every one is from the standard library. The
// projector reaches no other store or service: a new import, including a
// new internal package such as a future secrets or inventory store, fails
// TestProjectorImportsOnlyStandardLibrary until it is reviewed and added
// here.
var allowedImports = map[string]bool{
	"context":      true,
	"errors":       true,
	"fmt":          true,
	"net":          true,
	"net/url":      true,
	"regexp":       true,
	"sort":         true,
	"strconv":      true,
	"strings":      true,
	"time":         true,
	"unicode":      true,
	"unicode/utf8": true,
}

// TestProjectorImportsOnlyStandardLibrary parses every non-test file of the
// package and fails on any import that is not in allowedImports.
func TestProjectorImportsOnlyStandardLibrary(t *testing.T) {
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
			if !allowedImports[path] {
				t.Errorf("%s imports %q, which is not on the fact projector's allowlist", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
	for path := range allowedImports {
		if strings.Contains(path, ".") {
			t.Errorf("allowlist entry %q is not a standard library path", path)
		}
	}
}

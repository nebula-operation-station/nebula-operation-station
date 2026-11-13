// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// libraryAllowedImports is the complete import set of the non-test files of
// this package. The package is a pure parser library: it has no network
// access, no dialer, no configuration and no clock. Adding an import here is
// a review decision, not a routine change.
var libraryAllowedImports = map[string]bool{
	"bytes":        true,
	"cmp":          true,
	"errors":       true,
	"fmt":          true,
	"io":           true,
	"net/netip":    true,
	"slices":       true,
	"strings":      true,
	"time":         true,
	"unicode/utf8": true,
}

// libraryFiles returns the parsed non-test Go files of this package.
func libraryFiles(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no library files found")
	}
	return files
}

// TestLibraryImportsOnlyAllowedPackages checks the import set of the
// package: no net/http, no net dialer, no os (no configuration read), no
// os/exec and no crypto/tls. A new import needs a change to the list above.
func TestLibraryImportsOnlyAllowedPackages(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range libraryFiles(t) {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("import path %s: %v", imp.Path.Value, err)
			}
			seen[path] = true
			if !libraryAllowedImports[path] {
				t.Errorf("import %q is not allowed in the reputation parser library", path)
			}
		}
	}
	for path := range libraryAllowedImports {
		if !seen[path] {
			t.Errorf("allowlist entry %q is unused; remove it", path)
		}
	}
}

// forbiddenCallNames are functions that open a connection, resolve a host or
// read a clock. None may appear in the library.
var forbiddenCallNames = map[string]bool{
	"Dial":         true,
	"DialContext":  true,
	"DialTCP":      true,
	"DialUDP":      true,
	"Listen":       true,
	"LookupHost":   true,
	"LookupIP":     true,
	"LookupAddr":   true,
	"LookupIPAddr": true,
	"Get":          true,
	"Post":         true,
	"NewRequest":   true,
	"Now":          true,
	"Since":        true,
	"Until":        true,
}

// TestLibraryHasNoLookupOrClockCalls checks that no selector in the library
// calls a dialer, a resolver, an HTTP client or time.Now. The contract (NS-14)
// is that no per-address lookup code path exists at any provider, so the
// library must not be able to ask one.
func TestLibraryHasNoLookupOrClockCalls(t *testing.T) {
	for _, f := range libraryFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && forbiddenCallNames[sel.Sel.Name] {
				t.Errorf("forbidden call %s", sel.Sel.Name)
			}
			return true
		})
	}
}

// lookupNameRe matches exported or unexported identifiers that describe a
// single-address query. The library exports entries and snapshots only; a
// matcher of observed addresses belongs to NOS (ADR 0012 D6).
var lookupNameRe = regexp.MustCompile(`(?i)(lookup|query|check|resolve|match|reputation|fetch|dial)`)

// TestLibraryHasNoSingleAddressQueryFunction fails when a declared function
// or method name suggests a per-address query path.
func TestLibraryHasNoSingleAddressQueryFunction(t *testing.T) {
	for _, f := range libraryFiles(t) {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if ok && lookupNameRe.MatchString(fd.Name.Name) {
				t.Errorf("function %s suggests a per-address query path", fd.Name.Name)
			}
		}
	}
}

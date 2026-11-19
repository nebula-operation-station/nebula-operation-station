// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// The Help routes live in assistant.go, in the same package as the Handler
// that holds the notes store. Imports alone cannot keep them apart, so this
// test walks the bodies of the Help route functions and fails on any use of
// the Ops configuration, the store or the Ops body builders. The Help view
// itself is built in assistanthelp, which has its own boundary test.
func TestAssistantHelpRouteFunctionsNeverTouchOpsStore(t *testing.T) {
	helpFuncs := map[string]bool{
		"handleAssistantPanel": true,
		"handleAssistantHelp":  true,
		"serveAssistantHelp":   true,
		"writeAssistantPanel":  true,
	}
	forbiddenSelectors := map[string]bool{
		"Store":                  true,
		"assistantOps":           true,
		"assistantOpsBody":       true,
		"assistantCardFor":       true,
		"assistantCitations":     true,
		"assistantStepLink":      true,
		"handleAssistantOps":     true,
		"handleAssistantOpsNote": true,
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "assistant.go", nil, 0)
	if err != nil {
		t.Fatalf("parse assistant.go: %v", err)
	}
	found := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || !helpFuncs[fd.Name.Name] {
			continue
		}
		found[fd.Name.Name] = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if forbiddenSelectors[x.Sel.Name] {
					t.Errorf("%s uses %s; the Help route must not reach the Ops store or its builders (%s)", fd.Name.Name, x.Sel.Name, fset.Position(x.Pos()))
				}
			case *ast.Ident:
				if x.Name == "opsnotes" {
					t.Errorf("%s names opsnotes (%s)", fd.Name.Name, fset.Position(x.Pos()))
				}
			}
			return true
		})
	}
	for name := range helpFuncs {
		if !found[name] {
			t.Errorf("assistant.go has no function %s; update this test with the Help routes", name)
		}
	}
}

// assistant.go must not import the notes store: the only Ops-facing name it
// may use is the Handler's admin check.
func TestAssistantPanelFileDoesNotImportNotesStore(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "assistant.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse assistant.go: %v", err)
	}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatalf("import %s: %v", imp.Path.Value, err)
		}
		if path == "github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes" {
			t.Errorf("assistant.go imports %s; the panel shell must not read notes", path)
		}
	}
}

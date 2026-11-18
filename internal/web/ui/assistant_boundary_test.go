// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The Help backend holds no notes store: its struct has only the fields
// below, and none of them can reach the Ops configuration or the notes
// store. A new field fails this test until it is reviewed and listed here.
func TestAssistantHelpTypeHoldsNoNotesStore(t *testing.T) {
	allowed := map[string]bool{"log": true, "page": true, "showOps": true}
	typ := reflect.TypeOf(assistantHelp{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !allowed[f.Name] {
			t.Errorf("assistantHelp has field %s; the Help backend may only hold %v", f.Name, []string{"log", "page", "showOps"})
		}
		// The types the field may use must not name the notes or Ops store.
		if s := f.Type.String(); strings.Contains(s, "opsnotes") || strings.Contains(s, "AssistantOps") || strings.Contains(s, "Handler") {
			t.Errorf("assistantHelp field %s has type %s, which reaches the notes store", f.Name, s)
		}
	}
}

// The Help backend (ADR 0016 D11) never reads notes, findings or questions.
// The files that serve the Help tab and the panel shell must not import the
// notes store or the vulnerability store. This test reads the import lists
// of those files and fails if one of the forbidden packages appears.
func TestAssistantHelpFilesDoNotImportNotesOrFindings(t *testing.T) {
	forbidden := []string{
		"internal/opsnotes",
		"internal/vulnstore",
	}
	// help.go is the handbook backend; assistant.go is the panel shell and
	// the Help tab routes. assistant_ops.go is deliberately not listed.
	helpFiles := []string{"assistant.go", "help.go"}
	fset := token.NewFileSet()
	for _, file := range helpFiles {
		f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: import %s: %v", file, imp.Path.Value, err)
			}
			for _, bad := range forbidden {
				if strings.HasSuffix(path, bad) {
					t.Errorf("%s imports %s; the Help backend must not read notes or findings", file, path)
				}
			}
		}
	}
}

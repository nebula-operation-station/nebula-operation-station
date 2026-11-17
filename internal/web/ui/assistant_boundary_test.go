// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

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

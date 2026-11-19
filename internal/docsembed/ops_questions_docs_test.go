// SPDX-License-Identifier: AGPL-3.0-or-later

package docsembed_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpsQuestionDocsMatchTheBuild keeps the statements that the agent
// refuses or does not read admin questions out of the docs: since the work
// item contract was fixed, the agent answers an open question when the ops
// agent is enabled.
func TestOpsQuestionDocsMatchTheBuild(t *testing.T) {
	stale := []string{
		"refuses a question item",
		"refuses question items",
		"does not read questions yet",
		"stored but not answered",
		"liest Fragen noch",
		"gespeichert, aber nicht beantwortet",
		"Antworten auf Fragen im Tab Ops werden noch nicht erzeugt",
		"are not produced yet",
	}
	files := []string{"../../docs/admin/guide.md"}
	for _, pattern := range []string{"../../docs/handbook/*.md", "../../docs/handbook/de/*.md"} {
		more, err := filepath.Glob(pattern)
		if err != nil || len(more) == 0 {
			t.Fatalf("list %s: %v (%d files)", pattern, err, len(more))
		}
		files = append(files, more...)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// Line breaks in the Markdown source must not hide a phrase.
		text := strings.Join(strings.Fields(string(src)), " ")
		for _, s := range stale {
			if strings.Contains(text, s) {
				t.Errorf("%s still says %q; describe the question answers as built", f, s)
			}
		}
	}
}

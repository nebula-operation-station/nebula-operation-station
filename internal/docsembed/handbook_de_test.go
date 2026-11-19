// SPDX-License-Identifier: AGPL-3.0-or-later

package docsembed_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// duForms matches the informal address ("du" and its forms) and the du
// imperatives that slipped into the German handbook before. The handbook
// addresses its reader with "Sie" throughout.
// Go's \b knows ASCII letters only, so the word boundaries are spelled out
// with Unicode letter classes (an "Ö" starts a word, too).
var duForms = regexp.MustCompile(`(?i)(^|[^\pL\pN_])(du|dich|dir|dein|deine|deinen|deinem|deiner|deines)([^\pL\pN_]|$)|` +
	`(^|[^\pL\pN_])(Öffne|Klicke|Wähle|Prüfe|Starte|Lies|Gib|Nimm|Trage|Führe)[ \t]+` +
	`(den|die|das|dem|einen|eine|ein|im|in|auf|mit|zuerst)([^\pL\pN_]|$)`)

// codeSpans blanks fenced code blocks and inline code (also inline code that
// runs over a line break), so that commands and paths such as `<dir>` do not
// count as German text. Line numbers stay the same.
func codeSpans(src string) string {
	var b strings.Builder
	fenced := false
	for line := range strings.Lines(src) {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			b.WriteString("\n")
			continue
		}
		if fenced {
			b.WriteString("\n")
			continue
		}
		b.WriteString(line)
	}
	return inlineCode.ReplaceAllStringFunc(b.String(), func(code string) string {
		return "``" + strings.Repeat("\n", strings.Count(code, "\n"))
	})
}

var inlineCode = regexp.MustCompile("`[^`]*`")

// TestGermanHandbookUsesSie keeps the German handbook in the formal address:
// no "du", "dich", "dein…" and no du imperative such as "Öffne den Tab".
func TestGermanHandbookUsesSie(t *testing.T) {
	files, err := filepath.Glob("../../docs/handbook/de/*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("list docs/handbook/de: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(codeSpans(string(src)), "\n") {
			if m := duForms.FindString(line); m != "" {
				t.Errorf("%s:%d uses the informal address %q; write it with \"Sie\"", filepath.Base(f), i+1, strings.TrimSpace(m))
			}
		}
	}
}

func TestDuFormsDetector(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"Du kannst dem Bot nicht antworten.", true},
		{"Wenn du willst, geht das.", true},
		{"1. Öffne den Tab **Ops**.", true},
		{"Prüfe die Ausgabe.", true},
		{"1. Öffnen Sie den Tab **Ops**.", false},
		{"Sie bekommen eine Nachricht.", false},
		{"Prüfen Sie die Ausgabe.", false},
		{"Durch das Dunkel, dummerweise.", false},
		{"Für dich.", true},
		{codeSpans("Pfad `/var/lib/nebula/<dir>` bleibt.\n"), false},
		{codeSpans("Pfad `/var/lib/\nnebula/<dir>` bleibt.\n"), false},
	} {
		if got := duForms.MatchString(tc.line); got != tc.want {
			t.Errorf("duForms(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

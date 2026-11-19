// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// checkAnswer fails the fuzz run when an accepted answer breaks a bound of
// ADR 0014 D4 or carries text that is not valid UTF-8.
func checkAnswer(t *testing.T, a Answer) {
	t.Helper()
	if a.Language != "de" && a.Language != "en" {
		t.Fatalf("accepted language %q", a.Language)
	}
	if len(a.Summary) > MaxSummaryBytes || !utf8.ValidString(a.Summary) {
		t.Fatalf("accepted a summary of %d bytes", len(a.Summary))
	}
	if len(a.Steps) > MaxSteps {
		t.Fatalf("accepted %d steps", len(a.Steps))
	}
	for _, s := range a.Steps {
		if len(s.Text) > MaxStepTextBytes || !utf8.ValidString(s.Text) {
			t.Fatalf("accepted a step text of %d bytes", len(s.Text))
		}
		if len(s.Command) > MaxCommandBytes || strings.ContainsFunc(s.Command, oneLineBreak) {
			t.Fatalf("accepted command %q", s.Command)
		}
		if s.Where != "" && s.Where != WhereNebulaHost && s.Where != WhereManagedHost && s.Where != WhereBrowser {
			t.Fatalf("accepted where %q", s.Where)
		}
	}
	for _, c := range a.Citations {
		if !utf8.ValidString(c) {
			t.Fatalf("accepted a citation that is not UTF-8")
		}
	}
}

// FuzzDecode feeds arbitrary bytes to Decode. It must not panic. Every error
// is exactly ErrInvalidAnswer. An accepted answer is at most MaxAnswerBytes
// long, comes from valid UTF-8 and respects every bound.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(validEN))
	f.Add([]byte(`{"in_scope":false,"language":"de","summary":"","steps":[],"citations":[]}`))
	f.Add([]byte(`{"in_scope":true,"language":"de","summary":"s","steps":[{"text":"t","command":"nebula status","where":"browser"}],"citations":["c1","c1"]}`))
	f.Add([]byte(`{"in_scope":true,"language":"en","summary":"\ud800","steps":[],"citations":[]}`))
	f.Add([]byte(`{"in_scope":true,"language":"en","summary":"s","steps":[{"text":"t","command":"a\nb"}],"citations":[]}`))
	f.Add([]byte(`{"in_scope":true,"language":"en","summary":"s","steps":[{"text":"","command":"a b"}],"citations":[]}`))
	f.Add([]byte("```json\n" + validEN + "\n```"))
	f.Add([]byte(`{"in_scope":true,"in_scope":true}`))
	f.Add([]byte(`{"in_scope":true,"language":"en","summary":"s","steps":[{"text":"t","x":1}],"citations":[]}`))
	f.Add([]byte(`{"a":{"b":[1,2,{"c":null}]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := Decode(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidAnswer) || err.Error() != ErrInvalidAnswer.Error() {
				t.Fatalf("error %q is not the fixed ErrInvalidAnswer", err)
			}
			return
		}
		if len(raw) > MaxAnswerBytes || !utf8.Valid(raw) {
			t.Fatalf("accepted %d bytes (valid UTF-8: %t)", len(raw), utf8.Valid(raw))
		}
		checkAnswer(t, a)
	})
}

// FuzzCleanText checks CleanText: the output is valid UTF-8, holds none of
// the forbidden characters, keeps every other rune, and is idempotent.
func FuzzCleanText(f *testing.F) {
	f.Add("Pin the host.")
	f.Add("a\x1b[31mb\x1b[0m")
	f.Add("a\xe2\x80\xaeb\xe2\x80\x8bc\xef\xbb\xbfd")
	f.Add("line\nbreak\r\ttab")
	f.Add("\xff\xfe bytes")
	f.Add("\xe2\x80\xa8\xe2\x80\xa9 \xc2\xad \xc2\x85")
	f.Fuzz(func(t *testing.T, s string) {
		out := CleanText(s)
		if !utf8.ValidString(out) {
			t.Fatalf("output is not valid UTF-8: %q", out)
		}
		for _, c := range out {
			if forbiddenRune(c) {
				t.Fatalf("output keeps forbidden rune U+%04X", c)
			}
		}
		if again := CleanText(out); again != out {
			t.Fatalf("not idempotent: %q then %q", out, again)
		}
		if utf8.ValidString(s) && utf8.RuneCountInString(out) != utf8.RuneCountInString(s) {
			t.Fatalf("rune count changed from %d to %d", utf8.RuneCountInString(s), utf8.RuneCountInString(out))
		}
	})
}

// oneLineBreak is the test's own list of line breaks for a command: CR, LF,
// VT, FF, U+0085, U+2028 and U+2029. It mirrors the one-line rule of D4 and
// is kept apart from isLineBreak so the oracle does not reuse the code under
// test.
func oneLineBreak(c rune) bool {
	switch c {
	case '\r', '\n', '\v', '\f', '\u0085', ' ', ' ':
		return true
	}
	return false
}

// forbiddenRune is the test's own reading of ADR 0014 D4: control, format
// (bidi overrides, zero-width characters) and line or paragraph separators.
func forbiddenRune(c rune) bool {
	return unicode.In(c, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
}

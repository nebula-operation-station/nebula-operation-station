// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"testing"
)

// FuzzMatchShape checks two properties of the V3 matching on arbitrary input:
// it never panics, and a command without a placeholder matches itself as a
// doc shape exactly when the tokenizer accepts it.
func FuzzMatchShape(f *testing.F) {
	seeds := []string{
		"",
		"nebula status",
		`nebula pve add "10.0.0.1"`,
		"ssh <host>",
		"https://<digest>/x",
		`echo "unbalanced`,
		`a\ b c`,
		"<host>:<date>",
		"copy <host> <id>",
		"x=<version>",
		"2001:db8::1",
	}
	for _, s := range seeds {
		f.Add(s, s)
		f.Add(s, "nebula x 10.0.0.1")
	}
	f.Fuzz(func(t *testing.T, doc, cmd string) {
		// Property 1: no input panics; the error, if any, is one of the
		// documented kinds or a tokenizer error.
		if _, err := MatchShape(doc, cmd); err != nil {
			if !errors.Is(err, ErrNoMatch) && !errors.Is(err, ErrUnbalancedQuote) && !errors.Is(err, ErrTooLong) {
				t.Fatalf("MatchShape(%q, %q) error %v is none of the documented kinds", doc, cmd, err)
			}
		}

		// Property 2: without a placeholder, the command matches itself exactly
		// when the tokenizer accepts it.
		if HasPlaceholder(cmd) {
			return
		}
		_, tokErr := Tokenize(cmd)
		m, err := MatchShape(cmd, cmd)
		if (err == nil) != (tokErr == nil) {
			t.Fatalf("self match of %q: MatchShape error = %v, Tokenize error = %v; want the same verdict", cmd, err, tokErr)
		}
		if err == nil && (m.Unchanged() || len(m.Bindings) != 0) {
			t.Fatalf("self match of %q without placeholder has bindings %+v", cmd, m.Bindings)
		}
	})
}

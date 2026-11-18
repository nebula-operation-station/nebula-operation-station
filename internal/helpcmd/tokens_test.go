// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestTokenizeSplitsOnUnquotedSpaces checks the separation rules of ADR 0014
// D4: runs of spaces separate tokens, quoted or escaped spaces do not, and
// quotes and backslashes stay in the token text.
func TestTokenizeSplitsOnUnquotedSpaces(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty input has no tokens", "", nil},
		{"only spaces has no tokens", "   ", nil},
		{"single word", "nebula", []string{"nebula"}},
		{"run of spaces is one separator", "a    b", []string{"a", "b"}},
		{"leading and trailing spaces add no empty token", "  a b  ", []string{"a", "b"}},
		{"space inside double quotes stays in the token", `a "b c" d`, []string{"a", `"b c"`, "d"}},
		{"space inside single quotes stays in the token", `a 'b c' d`, []string{"a", `'b c'`, "d"}},
		{"quote characters stay in the token text", `x="a b"`, []string{`x="a b"`}},
		{"escaped space does not separate", `a\ b c`, []string{`a\ b`, "c"}},
		{"escaped space at the end of a token", `a\  b`, []string{`a\ `, "b"}},
		{"backslash in single quotes is literal", `'a\' b`, []string{`'a\'`, "b"}},
		{"escaped double quote does not close the quote", `"a\" b"`, []string{`"a\" b"`}},
		{"empty quotes are token text", `""`, []string{`""`}},
		{"trailing backslash is ordinary text", `a\`, []string{`a\`}},
		{"adjacent quoted and plain text form one token", `--x="a b"c d`, []string{`--x="a b"c`, "d"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Tokenize(tt.input)
			if err != nil {
				t.Fatalf("Tokenize(%q) error = %v; want nil", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Tokenize(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestTokenizeKeepsTokensLiteral checks that no token is expanded, unescaped
// or shortened: joining the tokens with single spaces gives back the input
// when the input has single spaces only.
func TestTokenizeKeepsTokensLiteral(t *testing.T) {
	inputs := []string{
		`a \$HOME "x y" 'z' \\ b`,
		`nebula pve remote add r --endpoint "10.0.0.1:8006"`,
		`echo 'it''s' \"`,
	}
	for _, in := range inputs {
		tokens, err := Tokenize(in)
		if err != nil {
			t.Fatalf("Tokenize(%q) error = %v", in, err)
		}
		if got := strings.Join(tokens, " "); got != in {
			t.Errorf("join of Tokenize(%q) = %q; want the input unchanged", in, got)
		}
		for _, tok := range tokens {
			if !strings.Contains(in, tok) {
				t.Errorf("token %q of %q is not a literal substring", tok, in)
			}
		}
	}
}

// TestTokenizeRejectsUnbalancedQuote checks that an opened and unclosed quote
// is an error (red), with the sentinel error.
func TestTokenizeRejectsUnbalancedQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"double quote never closed", `a "b c`},
		{"single quote never closed", `a 'b`},
		{"quote closed by the other kind does not count", `a "b'`},
		{"quote opened after escape is open", `a \\"b`},
		{"lone quote", `"`},
		{"escaped quote alone is open", `"a\"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Tokenize(tt.input)
			if !errors.Is(err, ErrUnbalancedQuote) {
				t.Errorf("Tokenize(%q) error = %v; want ErrUnbalancedQuote", tt.input, err)
			}
		})
	}
}

// TestTokenizeRejectsTooLongInput checks the named size limit.
func TestTokenizeRejectsTooLongInput(t *testing.T) {
	if _, err := Tokenize(strings.Repeat("a", MaxCommandBytes)); err != nil {
		t.Errorf("input of exactly the limit: error = %v; want nil", err)
	}
	_, err := Tokenize(strings.Repeat("a", MaxCommandBytes+1))
	if !errors.Is(err, ErrTooLong) {
		t.Errorf("input over the limit: error = %v; want ErrTooLong", err)
	}
}

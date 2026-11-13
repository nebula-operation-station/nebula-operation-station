// SPDX-License-Identifier: AGPL-3.0-or-later

package prelude

import (
	"strconv"
	"strings"
	"testing"
)

// names returns n distinct names prefix0, prefix1, … (valid as parameter
// names, secret slots and choice values for the prefixes used here).
func names(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strconv.Itoa(i)
	}
	return out
}

// okParam is a valid name parameter; tests change one field at a time.
func okParam() Param {
	return Param{Name: "unit", Label: "Unit", Type: TypeName}
}

func TestCheckRefuses(t *testing.T) {
	ps := func(n int) []Param {
		out := make([]Param, n)
		for i, nm := range names("p", n) {
			out[i] = Param{Name: nm, Label: "L", Type: TypeInt}
		}
		return out
	}
	tests := []struct {
		name    string
		params  []Param
		secrets []string
	}{
		{"too many params", ps(MaxParams + 1), nil},
		{"too many secret slots", nil, names("s", MaxSecrets+1)},
		{"name with nebula prefix", []Param{{Name: "nebula_x", Label: "L", Type: TypeName}}, nil},
		{"slot with nebula prefix", nil, []string{"nebula"}},
		{"name too long", []Param{{Name: "a" + strings.Repeat("b", 32), Label: "L", Type: TypeName}}, nil},
		{"name uppercase", []Param{{Name: "Unit", Label: "L", Type: TypeName}}, nil},
		{"name with quote", []Param{{Name: "u'x", Label: "L", Type: TypeName}}, nil},
		{"name starts with digit", []Param{{Name: "1unit", Label: "L", Type: TypeName}}, nil},
		{"empty name", []Param{{Name: "", Label: "L", Type: TypeName}}, nil},
		{"duplicate param name", []Param{
			{Name: "unit", Label: "A", Type: TypeName},
			{Name: "unit", Label: "B", Type: TypeInt},
		}, nil},
		{"param name equals secret slot", []Param{okParam()}, []string{"unit"}},
		{"duplicate secret slot", nil, []string{"token", "token"}},
		{"empty label", []Param{{Name: "unit", Label: "", Type: TypeName}}, nil},
		{"label over MaxLabel", []Param{{Name: "unit", Label: strings.Repeat("a", MaxLabel+1), Type: TypeName}}, nil},
		{"label with control character", []Param{{Name: "unit", Label: "a\x07b", Type: TypeName}}, nil},
		{"label with newline", []Param{{Name: "unit", Label: "a\nb", Type: TypeName}}, nil},
		{"label with bidi override", []Param{{Name: "unit", Label: "a‮b", Type: TypeName}}, nil},
		{"label with invalid UTF-8", []Param{{Name: "unit", Label: "a\xffb", Type: TypeName}}, nil},
		{"unknown type", []Param{{Name: "unit", Label: "L", Type: "string"}}, nil},
		{"empty type", []Param{{Name: "unit", Label: "L", Type: ""}}, nil},
		{"choices on name", []Param{{Name: "unit", Label: "L", Type: TypeName, Choices: []string{"a"}}}, nil},
		{"choices on int", []Param{{Name: "unit", Label: "L", Type: TypeInt, Choices: []string{"a"}}}, nil},
		{"choices on path", []Param{{Name: "unit", Label: "L", Type: TypePath, Choices: []string{"a"}}}, nil},
		{"choice without values", []Param{{Name: "unit", Label: "L", Type: TypeChoice}}, nil},
		{"choice with more than MaxChoices values", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: names("c", MaxChoices+1)}}, nil},
		{"choice with duplicate value", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a", "a"}}}, nil},
		{"choice value with quote", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a'b"}}}, nil},
		{"choice value with pipe", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a|b"}}}, nil},
		{"choice value with parenthesis", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a)"}}}, nil},
		{"choice value with space", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a b"}}}, nil},
		{"choice value with uppercase", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"Soft"}}}, nil},
		{"choice value with dot", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a.b"}}}, nil},
		{"choice value with newline", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a\nb"}}}, nil},
		{"choice value empty", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{""}}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := Check(tc.params, tc.secrets)
			if ok {
				t.Fatalf("accepted, want refused")
			}
			if reason == "" {
				t.Fatalf("refused without a reason")
			}
		})
	}
}

func TestCheckAccepts(t *testing.T) {
	maxChoices := names("c", MaxChoices)
	tests := []struct {
		name    string
		params  []Param
		secrets []string
	}{
		{"empty", nil, nil},
		{"name at limits", []Param{{Name: "a" + strings.Repeat("b", 31), Label: "L", Type: TypeName}}, nil},
		{"int", []Param{{Name: "count", Label: "Count", Type: TypeInt}}, nil},
		{"path", []Param{{Name: "dir", Label: "Dir", Type: TypePath}}, nil},
		{"choice with one value", []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: []string{"soft"}}}, nil},
		{"choice with MaxChoices values", []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: maxChoices}}, nil},
		{"choice values with digits, _ and -", []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: []string{"0", "hard-reset", "a_b"}}}, nil},
		{"label of exactly MaxLabel bytes", []Param{{Name: "unit", Label: strings.Repeat("a", MaxLabel), Type: TypeName}}, nil},
		{"label with umlauts", []Param{{Name: "unit", Label: "Größe der Einheit", Type: TypeName}}, nil},
		{"MaxParams parameters, one of each type", func() []Param {
			out := make([]Param, 0, MaxParams)
			types := []string{TypeName, TypeInt, TypePath, TypeChoice}
			for i, nm := range names("p", MaxParams) {
				p := Param{Name: nm, Label: "L", Type: types[i%len(types)]}
				if p.Type == TypeChoice {
					p.Choices = []string{"x"}
				}
				out = append(out, p)
			}
			return out
		}(), nil},
		{"MaxSecrets slots", nil, names("s", MaxSecrets)},
		{"params and slots together", []Param{okParam()}, []string{"token"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if reason, ok := Check(tc.params, tc.secrets); !ok {
				t.Fatalf("refused: %s", reason)
			}
		})
	}
}

func TestClean(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		multiline bool
		want      bool
	}{
		{"plain text", "Hallo Welt", false, true},
		{"umlauts", "Größe, Äpfel und Öl – ß", false, true},
		{"invalid UTF-8", "a\xffb", false, false},
		{"invalid UTF-8 multiline", "a\xffb\n", true, false},
		{"carriage return", "a\rb", false, false},
		{"carriage return multiline", "a\r\nb", true, false},
		{"NUL", "a\x00b", false, false},
		{"escape", "a\x1b[2Jb", false, false},
		{"DEL", "a\x7fb", true, false},
		{"BEL", "a\x07b", false, false},
		{"bidi override U+202E (Cf)", "a‮b", false, false},
		{"zero width space U+200B (Cf)", "a​b", false, false},
		{"line separator U+2028", "a b", false, false},
		{"paragraph separator U+2029", "a b", false, false},
		{"line separator U+2028 multiline", "a b", true, false},
		{"newline without multiline", "a\nb", false, false},
		{"newline with multiline", "a\nb", true, true},
		{"tab without multiline", "a\tb", false, false},
		{"tab with multiline", "a\tb", true, true},
		{"empty", "", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Clean(tc.s, tc.multiline); got != tc.want {
				t.Fatalf("Clean(%q, %v) = %v, want %v", tc.s, tc.multiline, got, tc.want)
			}
		})
	}
}

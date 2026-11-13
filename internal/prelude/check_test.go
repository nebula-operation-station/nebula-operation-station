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

// around returns "a" + the rune r + "b", so that the format and separator
// characters in the tests are written as code points, not as literal text.
func around(r rune) string {
	return "a" + string(r) + "b"
}

// okParam is a valid name parameter; tests change one field at a time.
func okParam() Param {
	return Param{Name: "unit", Label: "Unit", Type: TypeName}
}

// refusal is one row of TestCheckRefuses: the input and the substring the
// reason must contain, so that a row fails if Check refuses it for some
// other reason.
type refusal struct {
	name    string
	params  []Param
	secrets []string
	want    string
}

// Reason substrings, one per refusal kind in Check.
const (
	reasonParams     = "at most 10 parameters"
	reasonSlots      = "at most 8 secret slots"
	reasonSlotName   = "secret slots are distinct names"
	reasonParamName  = "parameter names are"
	reasonTwice      = "appears twice or is also a secret slot"
	reasonLabel      = "needs a label of 1 to 100 characters"
	reasonChoiceOnly = "only a choice has choices"
	reasonChoiceSize = "a choice has 1 to 20 values"
	reasonChoiceVal  = "choices are distinct lowercase words"
	reasonType       = "the type must be name, int, path or choice"
)

// shellMeta are the characters that matter to the shell and to ERE in an
// unquoted name, slot or choice value. Each must be refused in all three.
var shellMeta = []string{"$", "`", ";", "&", "\\", "*", "[", "]", ",", "|", "(", ")", "'", "\"", " ", "\t", "\n", "<", ">", "{", "}", "?", "!", "#", "~", "%", "^", "+", ".", "/", "@", ":", "="}

// metaRows refuses shell and ERE metacharacters in each position.
func metaRows(c string) []refusal {
	return []refusal{
		{"parameter name with " + c, []Param{{Name: "u" + c + "x", Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"choice value with " + c, []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a" + c + "b"}}}, nil, reasonChoiceVal},
		{"secret slot with " + c, nil, []string{"s" + c + "x"}, reasonSlotName},
	}
}

func TestCheckRefuses(t *testing.T) {
	ps := func(n int) []Param {
		out := make([]Param, n)
		for i, nm := range names("p", n) {
			out[i] = Param{Name: nm, Label: "L", Type: TypeInt}
		}
		return out
	}
	tests := []refusal{
		{"too many params", ps(MaxParams + 1), nil, reasonParams},
		{"too many secret slots", nil, names("s", MaxSecrets+1), reasonSlots},
		{"name with nebula prefix", []Param{{Name: "nebula_x", Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"slot with nebula prefix", nil, []string{"nebula"}, reasonSlotName},
		{"name too long", []Param{{Name: "a" + strings.Repeat("b", 32), Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"name uppercase", []Param{{Name: "Unit", Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"name with quote", []Param{{Name: "u'x", Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"name starts with digit", []Param{{Name: "1unit", Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"empty name", []Param{{Name: "", Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"name with newline", []Param{{Name: "unit\n", Label: "L", Type: TypeName}}, nil, reasonParamName},
		{"duplicate param name", []Param{
			{Name: "unit", Label: "A", Type: TypeName},
			{Name: "unit", Label: "B", Type: TypeInt},
		}, nil, reasonTwice},
		{"param name equals secret slot", []Param{okParam()}, []string{"unit"}, reasonTwice},
		{"duplicate secret slot", nil, []string{"token", "token"}, reasonSlotName},
		{"empty secret slot", nil, []string{""}, reasonSlotName},
		{"empty label", []Param{{Name: "unit", Label: "", Type: TypeName}}, nil, reasonLabel},
		{"label over MaxLabel", []Param{{Name: "unit", Label: strings.Repeat("a", MaxLabel+1), Type: TypeName}}, nil, reasonLabel},
		{"label with control character", []Param{{Name: "unit", Label: "a\x07b", Type: TypeName}}, nil, reasonLabel},
		{"label with newline", []Param{{Name: "unit", Label: "a\nb", Type: TypeName}}, nil, reasonLabel},
		{"label with bidi override", []Param{{Name: "unit", Label: around(0x202e), Type: TypeName}}, nil, reasonLabel},
		{"label with invalid UTF-8", []Param{{Name: "unit", Label: "a\xffb", Type: TypeName}}, nil, reasonLabel},
		{"unknown type", []Param{{Name: "unit", Label: "L", Type: "string"}}, nil, reasonType},
		{"empty type", []Param{{Name: "unit", Label: "L", Type: ""}}, nil, reasonType},
		{"choices on name", []Param{{Name: "unit", Label: "L", Type: TypeName, Choices: []string{"a"}}}, nil, reasonChoiceOnly},
		{"choices on int", []Param{{Name: "unit", Label: "L", Type: TypeInt, Choices: []string{"a"}}}, nil, reasonChoiceOnly},
		{"choices on path", []Param{{Name: "unit", Label: "L", Type: TypePath, Choices: []string{"a"}}}, nil, reasonChoiceOnly},
		{"choice without values", []Param{{Name: "unit", Label: "L", Type: TypeChoice}}, nil, reasonChoiceSize},
		{"choice with more than MaxChoices values", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: names("c", MaxChoices+1)}}, nil, reasonChoiceSize},
		{"choice with duplicate value", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a", "a"}}}, nil, reasonChoiceVal},
		{"choice value with quote", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a'b"}}}, nil, reasonChoiceVal},
		{"choice value with pipe", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a|b"}}}, nil, reasonChoiceVal},
		{"choice value with parenthesis", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a)"}}}, nil, reasonChoiceVal},
		{"choice value with ERE group and alternation", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"x)|(.*"}}}, nil, reasonChoiceVal},
		{"choice value with command substitution", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"$(id)"}}}, nil, reasonChoiceVal},
		{"choice value with backticks", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"`id`"}}}, nil, reasonChoiceVal},
		{"choice value with space", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a b"}}}, nil, reasonChoiceVal},
		{"choice value with uppercase", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"Soft"}}}, nil, reasonChoiceVal},
		{"choice value with dot", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a.b"}}}, nil, reasonChoiceVal},
		{"choice value with newline", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{"a\nb"}}}, nil, reasonChoiceVal},
		{"choice value empty", []Param{{Name: "unit", Label: "L", Type: TypeChoice, Choices: []string{""}}}, nil, reasonChoiceVal},
	}
	for _, c := range shellMeta {
		tests = append(tests, metaRows(c)...)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := Check(tc.params, tc.secrets)
			if ok {
				t.Fatalf("accepted, want refused")
			}
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("refused for the wrong reason %q, want it to contain %q", reason, tc.want)
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
		{"bidi override U+202E (Cf)", around(0x202e), false, false},
		{"zero width space U+200B (Cf)", around(0x200b), false, false},
		{"line separator U+2028", around(0x2028), false, false},
		{"paragraph separator U+2029", around(0x2029), false, false},
		{"line separator U+2028 multiline", around(0x2028), true, false},
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

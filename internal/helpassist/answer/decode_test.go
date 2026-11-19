// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

import (
	"errors"
	"strings"
	"testing"
)

// validEN is a complete, valid answer in English that cites one prompted ID.
const validEN = `{"in_scope":true,"language":"en","summary":"Pin the host.","steps":[{"text":"Run the command on the NOS host.","command":"nebula host pin host-01","where":"nos-host"}],"citations":["c1"]}`

// with replaces the first occurrence of old in validEN. The test fails when
// old is not part of validEN, so a stale fixture cannot pass silently.
func with(t *testing.T, old, repl string) string {
	t.Helper()
	if !strings.Contains(validEN, old) {
		t.Fatalf("fixture has no %q", old)
	}
	return strings.Replace(validEN, old, repl, 1)
}

// padded returns s followed by spaces until it is exactly n bytes long.
func padded(s string, n int) string {
	return s + strings.Repeat(" ", n-len(s))
}

// makeSteps returns n steps with the text "Check the log.".
func makeSteps(n int) []Step {
	out := make([]Step, n)
	for i := range out {
		out[i] = Step{Text: "Check the log."}
	}
	return out
}

// sameAnswer compares two answers field by field. A nil and an empty slice
// are equal, because the schema does not distinguish them.
func sameAnswer(a, b Answer) bool {
	if a.InScope != b.InScope || a.Language != b.Language || a.Summary != b.Summary {
		return false
	}
	if len(a.Steps) != len(b.Steps) || len(a.Citations) != len(b.Citations) {
		return false
	}
	for i := range a.Steps {
		if a.Steps[i] != b.Steps[i] {
			return false
		}
	}
	for i := range a.Citations {
		if a.Citations[i] != b.Citations[i] {
			return false
		}
	}
	return true
}

// TestDecodeAcceptsValidAnswer checks the fields of valid answers.
func TestDecodeAcceptsValidAnswer(t *testing.T) {
	steps12 := strings.TrimSuffix(strings.Repeat(`{"text":"Check the log."},`, MaxSteps), ",")
	pinStep := Step{Text: "Run the command on the NOS host.", Command: "nebula host pin host-01", Where: WhereNebulaHost}
	tests := []struct {
		name string
		raw  string
		want Answer
	}{
		{
			name: "english answer with command and where",
			raw:  validEN,
			want: Answer{InScope: true, Language: "en", Summary: "Pin the host.",
				Steps: []Step{pinStep}, Citations: []string{"c1"}},
		},
		{
			name: "german answer",
			raw:  with(t, `"language":"en"`, `"language":"de"`),
			want: Answer{InScope: true, Language: "de", Summary: "Pin the host.",
				Steps: []Step{pinStep}, Citations: []string{"c1"}},
		},
		{
			name: "out of scope without citations and steps",
			raw:  `{"in_scope":false,"language":"en","summary":"","steps":[],"citations":[]}`,
			want: Answer{InScope: false, Language: "en", Steps: []Step{}, Citations: []string{}},
		},
		{
			name: "empty step text is valid (ADR 0014 D4 gives only a maximum)",
			raw:  with(t, `"Run the command on the NOS host."`, `""`),
			want: Answer{InScope: true, Language: "en", Summary: "Pin the host.",
				Steps: []Step{{Command: "nebula host pin host-01", Where: WhereNebulaHost}}, Citations: []string{"c1"}},
		},
		{
			name: "step without command and where",
			raw:  `{"in_scope":true,"language":"en","summary":"s","steps":[{"text":"Check the log."}],"citations":["c2"]}`,
			want: Answer{InScope: true, Language: "en", Summary: "s",
				Steps: []Step{{Text: "Check the log."}}, Citations: []string{"c2"}},
		},
		{
			name: "duplicate citations are decoded, mapping removes them",
			raw:  with(t, `"citations":["c1"]`, `"citations":["c1","c1"]`),
			want: Answer{InScope: true, Language: "en", Summary: "Pin the host.",
				Steps: []Step{pinStep}, Citations: []string{"c1", "c1"}},
		},
		{
			name: "surrogate pair and unicode escape",
			raw:  with(t, `"Pin the host."`, "\"P\x5cu00e4 \x5cud83d\x5cude00\""),
			want: Answer{InScope: true, Language: "en", Summary: "P\xc3\xa4 \U0001F600",
				Steps: []Step{pinStep}, Citations: []string{"c1"}},
		},
		{
			name: "whitespace around the object",
			raw:  " \r\n\t" + validEN + " \n",
			want: Answer{InScope: true, Language: "en", Summary: "Pin the host.",
				Steps: []Step{pinStep}, Citations: []string{"c1"}},
		},
		{
			name: "twelve steps is the maximum",
			raw:  `{"in_scope":true,"language":"en","summary":"s","steps":[` + steps12 + `],"citations":["c1"]}`,
			want: Answer{InScope: true, Language: "en", Summary: "s", Steps: makeSteps(MaxSteps), Citations: []string{"c1"}},
		},
		{
			name: "summary of exactly MaxSummaryBytes",
			raw:  with(t, `"Pin the host."`, `"`+strings.Repeat("s", MaxSummaryBytes)+`"`),
			want: Answer{InScope: true, Language: "en", Summary: strings.Repeat("s", MaxSummaryBytes),
				Steps: []Step{pinStep}, Citations: []string{"c1"}},
		},
		{
			name: "exactly MaxAnswerBytes",
			raw:  padded(validEN, MaxAnswerBytes),
			want: Answer{InScope: true, Language: "en", Summary: "Pin the host.",
				Steps: []Step{pinStep}, Citations: []string{"c1"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode([]byte(tc.raw))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !sameAnswer(got, tc.want) {
				t.Fatalf("Decode = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestDecodeRejectsInvalidAnswer covers one table row per rejection reason.
// Every rejection returns exactly ErrInvalidAnswer and its fixed text.
func TestDecodeRejectsInvalidAnswer(t *testing.T) {
	tooManySteps := `{"in_scope":true,"language":"en","summary":"s","steps":[` +
		strings.TrimSuffix(strings.Repeat(`{"text":"x"},`, MaxSteps+1), ",") +
		`],"citations":["c1"]}`
	tests := []struct {
		name string
		raw  string
	}{
		// Text around or instead of the object.
		{"empty input", ``},
		{"plain text", `Sure, here is the answer.`},
		{"html page", `<html><body><script>alert(1)</script></body></html>`},
		{"ansi escape before object", "\x1b[31m" + validEN + "\x1b[0m"},
		{"markdown fence around object", "```json\n" + validEN + "\n```"},
		{"text before object", "Answer: " + validEN},
		{"text after object", validEN + " Hope that helps."},
		{"two objects in a row", validEN + validEN},
		{"byte order mark", "\xef\xbb\xbf" + validEN},
		{"nul byte after object", validEN + "\x00"},
		{"truncated object", `{"in_scope":true`},
		{"array instead of object", `[` + validEN + `]`},
		{"null", `null`},
		{"string", `"text"`},

		// Unknown, duplicate and misspelt fields.
		{"unknown top-level field", with(t, `"citations"`, `"extra":1,"citations"`)},
		{"unknown step field", with(t, `"where":"nos-host"`, `"where":"nos-host","x":1`)},
		{"duplicate top-level field", with(t, `"language":"en"`, `"language":"en","language":"en"`)},
		{"duplicate step field", with(t, `"command":"nebula host pin host-01"`, `"command":"nebula host pin host-01","command":"nebula status"`)},
		{"field name with other case", with(t, `"in_scope"`, `"In_Scope"`)},

		// Wrong types.
		{"in_scope as string", with(t, `"in_scope":true`, `"in_scope":"true"`)},
		{"in_scope as number", with(t, `"in_scope":true`, `"in_scope":1`)},
		{"language as number", with(t, `"language":"en"`, `"language":1`)},
		{"steps as object", `{"in_scope":true,"language":"en","summary":"s","steps":{},"citations":[]}`},
		{"citations as string", with(t, `"citations":["c1"]`, `"citations":"c1"`)},
		{"citation as number", with(t, `"citations":["c1"]`, `"citations":[1]`)},
		{"step as null", with(t, `{"text":"Run the command on the NOS host.","command":"nebula host pin host-01","where":"nos-host"}`, `null`)},
		{"command as null", with(t, `"command":"nebula host pin host-01"`, `"command":null`)},
		{"summary as null", with(t, `"summary":"Pin the host."`, `"summary":null`)},
		{"where as null", with(t, `"where":"nos-host"`, `"where":null`)},

		// Missing required fields.
		{"missing in_scope", `{"language":"en","summary":"s","steps":[],"citations":[]}`},
		{"missing language", `{"in_scope":false,"summary":"s","steps":[],"citations":[]}`},
		{"missing summary", `{"in_scope":false,"language":"en","steps":[],"citations":[]}`},
		{"missing steps", `{"in_scope":false,"language":"en","summary":"s","citations":[]}`},
		{"missing citations", `{"in_scope":false,"language":"en","summary":"s","steps":[]}`},
		{"step without text", with(t, `{"text":"Run the command on the NOS host.","command":"nebula host pin host-01","where":"nos-host"}`, `{"command":"nebula host pin host-01"}`)},

		// Enumerations.
		{"language fr", with(t, `"language":"en"`, `"language":"fr"`)},
		{"language in upper case", with(t, `"language":"en"`, `"language":"EN"`)},
		{"language empty", with(t, `"language":"en"`, `"language":""`)},
		{"where host", with(t, `"where":"nos-host"`, `"where":"host"`)},
		{"where empty", with(t, `"where":"nos-host"`, `"where":""`)},

		// Limits.
		{"thirteen steps", tooManySteps},
		{"summary one byte too long", with(t, `"Pin the host."`, `"`+strings.Repeat("s", MaxSummaryBytes+1)+`"`)},
		{"step text one byte too long", with(t, `"Run the command on the NOS host."`, `"`+strings.Repeat("t", MaxStepTextBytes+1)+`"`)},
		{"command one byte too long", with(t, `"nebula host pin host-01"`, `"`+strings.Repeat("c", MaxCommandBytes+1)+`"`)},
		{"empty command", with(t, `"nebula host pin host-01"`, `""`)},
		{"MaxAnswerBytes plus one", padded(validEN, MaxAnswerBytes+1)},

		// One line for commands.
		{"command with line feed escape", with(t, `"nebula host pin host-01"`, `"nebula host pin host-01\nrm -rf /"`)},
		{"command with carriage return escape", with(t, `"nebula host pin host-01"`, `"nebula host pin host-01\rrm"`)},
		{"command with raw line feed", with(t, `"nebula host pin host-01"`, "\"nebula host pin host-01\nrm\"")},

		// Encoding.
		{"invalid utf-8 in summary", with(t, `"Pin the host."`, "\"Pin \xff host.\"")},
		{"raw control character in string", with(t, `"Pin the host."`, "\"Pin\x01 host.\"")},
		{"lone high surrogate escape", with(t, `"Pin the host."`, `"Pin \ud800 host."`)},
		{"lone low surrogate escape", with(t, `"Pin the host."`, `"Pin \udc00 host."`)},
		{"high surrogate followed by plain character", with(t, `"Pin the host."`, `"Pin \ud800A."`)},
		{"high surrogate followed by non-low escape", with(t, `"Pin the host."`, "\"Pin \\ud800\x5cu0041.\"")},
		{"high surrogate followed by high surrogate escape", with(t, `"Pin the host."`, `"Pin \ud800\ud800."`)},
		{"malformed unicode escape", with(t, `"Pin the host."`, `"Pin \u12G4."`)},

		// Syntax.
		{"trailing comma in citations", with(t, `"citations":["c1"]`, `"citations":["c1",]`)},
		{"trailing comma in object", with(t, `"citations":["c1"]`, `"citations":["c1"],`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode([]byte(tc.raw))
			if err == nil {
				t.Fatalf("Decode accepted the input: %+v", got)
			}
			if !errors.Is(err, ErrInvalidAnswer) {
				t.Fatalf("Decode error = %v, want ErrInvalidAnswer", err)
			}
			if err.Error() != ErrInvalidAnswer.Error() {
				t.Fatalf("Decode error text = %q, want the fixed text only", err.Error())
			}
		})
	}
}

// TestLimitsMatchADR pins the named limits to the values of ADR 0014 D4.
func TestLimitsMatchADR(t *testing.T) {
	if MaxAnswerBytes != 8<<10 || MaxSteps != 12 || MaxSummaryBytes != 1<<10 ||
		MaxStepTextBytes != 1<<10 || MaxCommandBytes != 512 {
		t.Fatalf("limits differ from ADR 0014 D4: answer=%d steps=%d summary=%d text=%d command=%d",
			MaxAnswerBytes, MaxSteps, MaxSummaryBytes, MaxStepTextBytes, MaxCommandBytes)
	}
}

// TestErrInvalidAnswerText pins the fixed message of ADR 0014 D4.
func TestErrInvalidAnswerText(t *testing.T) {
	const want = "the assistant returned an invalid answer"
	if ErrInvalidAnswer.Error() != want {
		t.Fatalf("ErrInvalidAnswer = %q, want %q", ErrInvalidAnswer.Error(), want)
	}
}

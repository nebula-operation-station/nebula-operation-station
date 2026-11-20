// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"errors"
	"strings"
	"testing"
)

// TestEstimateConstantsMatchSpec pins the token estimate to the values
// of spec 01 (D5 "How NOS counts tokens").
func TestEstimateConstantsMatchSpec(t *testing.T) {
	if PromptBytesPerToken != 3 {
		t.Errorf("PromptBytesPerToken = %d, want 3", PromptBytesPerToken)
	}
	if PromptMessageOverheadTokens != 8 {
		t.Errorf("PromptMessageOverheadTokens = %d, want 8", PromptMessageOverheadTokens)
	}
}

// TestEstimateMessageTokensAddsOverheadPerMessage checks that every
// message counts its own rounded-up bytes plus the per-message overhead.
func TestEstimateMessageTokensAddsOverheadPerMessage(t *testing.T) {
	tests := map[string]struct {
		messages []string
		want     int
	}{
		"no message":          {nil, 0},
		"one empty message":   {[]string{""}, 8},
		"one byte":            {[]string{"a"}, 1 + 8},
		"two messages":        {[]string{"abc", "abcd"}, 1 + 8 + 2 + 8},
		"rounded per message": {[]string{"a", "a"}, 1 + 8 + 1 + 8},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := EstimateMessageTokens(tt.messages...); got != tt.want {
				t.Fatalf("EstimateMessageTokens = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestBuildTotalCountsMessageOverhead checks that Build's total check
// refuses a prompt whose content alone fits the limit but whose content
// plus the overhead of its two messages does not.
func TestBuildTotalCountsMessageOverhead(t *testing.T) {
	p, err := Build(testInput(testChunk(1, "text")))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	content := EstimateTokens(len(p.System)) + EstimateTokens(len(p.User))
	full := content + 2*PromptMessageOverheadTokens
	if err := checkTotal(p, full); err != nil {
		t.Fatalf("checkTotal at %d tokens: %v", full, err)
	}
	for _, limit := range []int{full - 1, content} {
		if err := checkTotal(p, limit); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("checkTotal at %d tokens: error = %v, want ErrTooLarge", limit, err)
		}
	}
}

// TestSystemPromptRule8NamesFactsEncoding checks that rule 8 does not
// claim the entity escaping for the <facts> block, which is JSON, and
// states the JSON escapes instead.
func TestSystemPromptRule8NamesFactsEncoding(t *testing.T) {
	for _, want := range []string{
		"Inside the <docs> and <question> blocks the characters & < > [ ] are written as &amp; &lt; &gt; &#91; &#93;.",
		"The <facts> block is JSON: in it, & < > are written as \x5cu0026 \x5cu003c \x5cu003e,",
	} {
		if !strings.Contains(SystemPrompt, want) {
			t.Errorf("SystemPrompt lacks %q", want)
		}
	}
	if strings.Contains(SystemPrompt, "Inside the blocks the characters") {
		t.Error("rule 8 still claims entity escaping for every block")
	}
}

// TestFactsBlockHasNoRawMarkupCharacters checks the claim of rule 8 for
// the facts block: encoding/json writes & < > only as escapes, even when
// every text value is full of them.
func TestFactsBlockHasNoRawMarkupCharacters(t *testing.T) {
	enc, err := encodeFacts(fullFacts(t, "&<>"))
	if err != nil {
		t.Fatalf("encodeFacts: %v", err)
	}
	if strings.ContainsAny(enc, "&<>") {
		t.Fatal("facts block contains a raw & < or >")
	}
	if !strings.Contains(enc, "\x5cu0026\x5cu003c\x5cu003e") { // \x5c is the backslash
		t.Fatal("facts block lacks the JSON escapes rule 8 names")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"errors"
	"testing"
)

// TestConstantsMatchADR pins the limits to the values of ADR 0014 D2 and D5.
func TestConstantsMatchADR(t *testing.T) {
	if MaxPromptTokens != 16000 {
		t.Errorf("MaxPromptTokens = %d, want 16000", MaxPromptTokens)
	}
	if MaxFactsBlockBytes != 12<<10 {
		t.Errorf("MaxFactsBlockBytes = %d, want 12 KiB", MaxFactsBlockBytes)
	}
	if MaxOutputTokens != 1500 {
		t.Errorf("MaxOutputTokens = %d, want 1500", MaxOutputTokens)
	}
	if MaxContextDocBytes != 24<<10 {
		t.Errorf("MaxContextDocBytes = %d, want 24 KiB", MaxContextDocBytes)
	}
	if MaxChunks != 6 {
		t.Errorf("MaxChunks = %d, want 6", MaxChunks)
	}
}

func TestEstimateTokensRoundsUpFromBytes(t *testing.T) {
	tests := []struct{ bytes, want int }{
		{-5, 0}, {0, 0}, {1, 1}, {3, 1}, {4, 2}, {6, 2}, {7, 3},
	}
	for _, tt := range tests {
		if got := EstimateTokens(tt.bytes); got != tt.want {
			t.Errorf("EstimateTokens(%d) = %d, want %d", tt.bytes, got, tt.want)
		}
	}
}

// TestCheckFitPassesForConstants checks the worst case of the shipped limits.
func TestCheckFitPassesForConstants(t *testing.T) {
	if err := CheckFit(); err != nil {
		t.Fatalf("CheckFit: %v", err)
	}
}

// TestCheckFitFailsForSmallBudget checks that a budget too small for the
// worst case is refused, with the constants otherwise unchanged.
func TestCheckFitFailsForSmallBudget(t *testing.T) {
	tests := map[string]struct {
		maxTokens, docBytes, factsBytes int
	}{
		"token limit below the worst case": {maxTokens: 100, docBytes: MaxContextDocBytes, factsBytes: MaxFactsBlockBytes},
		"docs doubled":                     {maxTokens: MaxPromptTokens, docBytes: 2 * MaxContextDocBytes, factsBytes: MaxFactsBlockBytes},
		"facts cap doubled":                {maxTokens: MaxPromptTokens, docBytes: MaxContextDocBytes, factsBytes: 2 * MaxFactsBlockBytes},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkFit(SystemPrompt, tt.maxTokens, tt.docBytes, MaxQuestionBytes, tt.factsBytes)
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("checkFit error = %v, want ErrTooLarge", err)
			}
		})
	}
}

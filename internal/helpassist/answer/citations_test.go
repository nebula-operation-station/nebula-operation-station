// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

import (
	"slices"
	"testing"
)

// TestMapCitations covers ADR 0014 D2: only IDs from the prompt count, in
// the order of the answer, without duplicates. An unknown ID, or no valid ID
// for an in-scope answer, makes the answer unsupported.
func TestMapCitations(t *testing.T) {
	prompted := []string{"c1", "c2", "c3"}
	tests := []struct {
		name          string
		answer        Answer
		prompted      []string
		wantValid     []string
		wantSupported bool
	}{
		{
			name:          "valid IDs keep the order of the answer",
			answer:        Answer{InScope: true, Citations: []string{"c2", "c1"}},
			prompted:      prompted,
			wantValid:     []string{"c2", "c1"},
			wantSupported: true,
		},
		{
			name:          "duplicates are removed",
			answer:        Answer{InScope: true, Citations: []string{"c2", "c2", "c1", "c2"}},
			prompted:      prompted,
			wantValid:     []string{"c2", "c1"},
			wantSupported: true,
		},
		{
			name:          "unknown ID makes the answer unsupported even with a valid one",
			answer:        Answer{InScope: true, Citations: []string{"c1", "c9"}},
			prompted:      prompted,
			wantValid:     []string{"c1"},
			wantSupported: false,
		},
		{
			name:          "empty list for an in-scope answer",
			answer:        Answer{InScope: true, Citations: []string{}},
			prompted:      prompted,
			wantValid:     nil,
			wantSupported: false,
		},
		{
			name:          "only unknown IDs for an in-scope answer",
			answer:        Answer{InScope: true, Citations: []string{"c7"}},
			prompted:      prompted,
			wantValid:     nil,
			wantSupported: false,
		},
		{
			name:          "out of scope without citations is supported",
			answer:        Answer{InScope: false, Citations: []string{}},
			prompted:      prompted,
			wantValid:     nil,
			wantSupported: true,
		},
		{
			name:          "out of scope with an unknown ID is unsupported",
			answer:        Answer{InScope: false, Citations: []string{"c9"}},
			prompted:      prompted,
			wantValid:     nil,
			wantSupported: false,
		},
		{
			name:          "ID that was not prompted is never valid",
			answer:        Answer{InScope: true, Citations: []string{"c1"}},
			prompted:      nil,
			wantValid:     nil,
			wantSupported: false,
		},
		{
			name:          "IDs are compared exactly, not case-folded",
			answer:        Answer{InScope: true, Citations: []string{"C1"}},
			prompted:      prompted,
			wantValid:     nil,
			wantSupported: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid, supported := MapCitations(tc.answer, tc.prompted)
			if !slices.Equal(valid, tc.wantValid) {
				t.Fatalf("valid = %q, want %q", valid, tc.wantValid)
			}
			if supported != tc.wantSupported {
				t.Fatalf("supported = %t, want %t", supported, tc.wantSupported)
			}
		})
	}
}

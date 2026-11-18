// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import "testing"

// TestParseSuggestionRefAcceptsOnlyStoredShapes pins the reference shape
// that the notes store can return: a positive note ID, and a step counted
// from 1 (opsnotes.Step.Index). The server's parser shares this function.
func TestParseSuggestionRefAcceptsOnlyStoredShapes(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		ok   bool
		id   int64
		idx  int
	}{
		{"first step", "3.1", true, 3, 1},
		{"later step", "120.6", true, 120, 6},
		{"step zero is never stored", "3.0", false, 0, 0},
		{"step leading zero", "3.01", false, 0, 0},
		{"note zero", "0.1", false, 0, 0},
		{"note leading zero", "03.1", false, 0, 0},
		{"negative step", "3.-1", false, 0, 0},
		{"plus sign", "+3.1", false, 0, 0},
		{"missing step", "3.", false, 0, 0},
		{"missing note", ".1", false, 0, 0},
		{"letters", "x.1", false, 0, 0},
		{"no dot", "31", false, 0, 0},
		{"two dots", "3.1.2", false, 0, 0},
		{"empty", "", false, 0, 0},
		{"over the length limit", "1234567890123456789.12345678901234567", false, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, idx, ok := ParseSuggestionRef(tc.ref)
			if ok != tc.ok || id != tc.id || idx != tc.idx {
				t.Fatalf("ParseSuggestionRef(%q) = %d, %d, %v; want %d, %d, %v", tc.ref, id, idx, ok, tc.id, tc.idx, tc.ok)
			}
		})
	}
}

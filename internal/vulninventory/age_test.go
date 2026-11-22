// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import "testing"

// TestReadTooOldOnlyWhenAThirdReadExists pins the count rule of E2: a read is
// too old once two newer reads of its host exist (a third read), and not
// before. There is no time limit, so no age value is an input.
//
// The case with one newer read is reading (i) of open question Q2 (Claude's
// reading, not yet confirmed by the maintainer): the read before the newest
// stays not too old, because E1 keeps it. Under reading (ii) it would be too
// old, so flip that row if Q2 is answered with (ii).
func TestReadTooOldOnlyWhenAThirdReadExists(t *testing.T) {
	tests := []struct {
		name  string
		newer int
		want  bool
	}{
		{"newest read of the host is not too old", 0, false},
		{"Q2 reading (i): the read before the newest is not too old (E1 keeps it)", 1, false},
		{"the oldest of three reads is too old", 2, true},
		{"older reads stay too old", 5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tooOld(tt.newer); got != tt.want {
				t.Fatalf("tooOld(%d) = %v, want %v", tt.newer, got, tt.want)
			}
		})
	}
}

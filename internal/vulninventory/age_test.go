// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import "testing"

// TestReadTooOldOnlyWhenAThirdReadExists pins the count rule of E2: a read is
// too old once two newer reads of its host exist (a third read), and not
// before. There is no time limit, so no age value is an input.
func TestReadTooOldOnlyWhenAThirdReadExists(t *testing.T) {
	tests := []struct {
		name  string
		newer int
		want  bool
	}{
		{"newest read of the host is not too old", 0, false},
		{"the read before the newest is not too old (E1 keeps it)", 1, false},
		{"the oldest of three reads is too old", 2, true},
		{"older reads stay too old", 5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TooOld(tt.newer); got != tt.want {
				t.Fatalf("TooOld(%d) = %v, want %v", tt.newer, got, tt.want)
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package edl

import "testing"

// TestMaxEntriesMatchesADR0012 pins the size cap to ADR 0012 D7 (default 10,000).
func TestMaxEntriesMatchesADR0012(t *testing.T) {
	if MaxEntries != 10000 {
		t.Fatalf("MaxEntries = %d, want 10000 (ADR 0012 D7)", MaxEntries)
	}
}

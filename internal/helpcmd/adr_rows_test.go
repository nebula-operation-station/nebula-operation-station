// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"os"
	"strings"
	"testing"
)

// adrV6Path is the ADR that defines the V6 list, relative to this package.
const adrV6Path = "../../docs/adr/0014-help-assistant.md"

// TestPatternListMatchesADRV6Text ties destructivePatterns to the V6 row of
// ADR 0014. The list is read from the ADR text, so a row removed from the code
// (with its rowCases entry) or added without the ADR fails this test too.
func TestPatternListMatchesADRV6Text(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(adrV6Path)
	if err != nil {
		t.Fatalf("read ADR: %v", err)
	}
	text := string(raw)
	const lead = "destructive-pattern list** in `internal/helpcmd/`: "
	const tail = " (previously only `nebula restore`"
	start := strings.Index(text, lead)
	if start < 0 {
		t.Fatalf("ADR 0014 V6 list not found (lead %q)", lead)
	}
	rest := text[start+len(lead):]
	end := strings.Index(rest, tail)
	if end < 0 {
		t.Fatalf("ADR 0014 V6 list not found (tail %q)", tail)
	}
	seg := rest[:end]

	var items []string
	for _, it := range strings.Split(seg, ", ") {
		it = strings.TrimPrefix(it, "and the catalog paths ")
		it = strings.TrimPrefix(it, "and ")
		items = append(items, it)
	}

	adr := map[string]bool{}
	for _, it := range items {
		if adr[it] {
			t.Errorf("ADR V6 lists %q twice", it)
		}
		adr[it] = true
	}
	rows := map[string]bool{}
	for _, p := range destructivePatterns {
		if rows[p.adr] {
			t.Errorf("destructivePatterns has row %q twice", p.adr)
		}
		rows[p.adr] = true
		if !strings.Contains(text, p.adr) {
			t.Errorf("row %q is not the wording of the ADR", p.adr)
		}
		if !adr[p.adr] {
			t.Errorf("row %q is not in the ADR V6 list", p.adr)
		}
	}
	for it := range adr {
		if !rows[it] {
			t.Errorf("ADR V6 lists %q, but destructivePatterns has no row for it", it)
		}
	}
	if len(items) != len(destructivePatterns) {
		t.Errorf("ADR V6 has %d items, destructivePatterns has %d rows", len(items), len(destructivePatterns))
	}
}

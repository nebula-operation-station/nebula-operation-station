// SPDX-License-Identifier: AGPL-3.0-or-later

package exportconform

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// tables lists the three shared tables under the names used in failure
// messages. Both the server and the client mirror run exactly these slices, so
// a table that contradicts itself would make the two sides disagree.
var tables = []struct {
	name  string
	cases []Case
}{
	{"Vendor", Vendor},
	{"Model", Model},
	{"Firmware", Firmware},
}

// invalidEncodingMarker is the text a case name must contain when its value is
// deliberately not valid UTF-8. No such case exists today; the rule is kept so
// that one cannot be added silently.
const invalidEncodingMarker = "invalid UTF-8"

// TestConformanceTableNamesAreUniqueAndNonEmpty checks that every case in a
// table has a name, and that no two cases in the same table share a name, so a
// failure in a consumer test names exactly one row.
func TestConformanceTableNamesAreUniqueAndNonEmpty(t *testing.T) {
	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			seen := make(map[string]int, len(tbl.cases))
			for i, c := range tbl.cases {
				if strings.TrimSpace(c.Name) == "" {
					t.Errorf("case %d has an empty name (value %q)", i, c.Value)
					continue
				}
				if j, dup := seen[c.Name]; dup {
					t.Errorf("name %q is used by case %d and case %d", c.Name, j, i)
					continue
				}
				seen[c.Name] = i
			}
		})
	}
}

// TestConformanceTableValuesAppearOnce checks that each value occurs at most
// once per table. A value listed twice with different verdicts would make the
// table contradict itself; the same verdict twice would hide a copy error.
func TestConformanceTableValuesAppearOnce(t *testing.T) {
	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			seen := make(map[string]string, len(tbl.cases))
			for _, c := range tbl.cases {
				if prev, dup := seen[c.Value]; dup {
					t.Errorf("value %q appears twice: cases %q and %q", c.Value, prev, c.Name)
					continue
				}
				seen[c.Value] = c.Name
			}
		})
	}
}

// TestConformanceTableHasAcceptedAndRefusedCases checks that each table is not
// empty and contains at least one value that must be accepted and one that
// must be refused. A table with only one verdict would pass a consumer that
// accepts everything, or one that refuses everything.
func TestConformanceTableHasAcceptedAndRefusedCases(t *testing.T) {
	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			if len(tbl.cases) == 0 {
				t.Fatal("table is empty")
			}
			var accepted, refused int
			for _, c := range tbl.cases {
				if c.OK {
					accepted++
				} else {
					refused++
				}
			}
			if accepted == 0 {
				t.Error("table has no accepted case")
			}
			if refused == 0 {
				t.Error("table has no refused case")
			}
		})
	}
}

// TestConformanceTableValuesAreUTF8 checks that every value is valid UTF-8.
// A value that is not must say so in its name (invalidEncodingMarker), so the
// reader knows the byte sequence is intentional. Values are printed with %q so
// raw bytes never reach the test output.
func TestConformanceTableValuesAreUTF8(t *testing.T) {
	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			for _, c := range tbl.cases {
				if utf8.ValidString(c.Value) {
					continue
				}
				if !strings.Contains(c.Name, invalidEncodingMarker) {
					t.Errorf("case %q has value %q, which is not valid UTF-8, and its name does not say %q",
						c.Name, c.Value, invalidEncodingMarker)
				}
			}
		})
	}
}

// TestConformanceTableInvalidEncodingIsNamed checks the reverse direction: a
// case whose name claims invalid UTF-8 must really carry such a value, so the
// marker cannot be used as a label for ordinary text.
func TestConformanceTableInvalidEncodingIsNamed(t *testing.T) {
	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			for _, c := range tbl.cases {
				if strings.Contains(c.Name, invalidEncodingMarker) && utf8.ValidString(c.Value) {
					t.Errorf("case %q is named as invalid UTF-8 but its value %q is valid", c.Name, c.Value)
				}
			}
		})
	}
}

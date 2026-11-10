// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// fixedRow formats cells into columns of the given widths separated by
// one space, like the CBS CLI; the last cell is not padded.
func fixedRow(widths []int, cells ...string) string {
	var b strings.Builder
	for i, c := range cells {
		if i > 0 {
			b.WriteByte(' ')
		}
		if i < len(cells)-1 {
			fmt.Fprintf(&b, "%-*s", widths[i], c)
		} else {
			b.WriteString(c)
		}
	}
	return strings.TrimRight(b.String(), " ") + "\n"
}

func dashRule(widths []int) string {
	parts := make([]string, len(widths))
	for i, w := range widths {
		parts[i] = strings.Repeat("-", w)
	}
	return strings.Join(parts, " ") + "\n"
}

// vlanWidths has a wider ID column than the fixtures so that five-digit
// out-of-range IDs fit their column and are refused for their value.
var vlanWidths = []int{6, 17, 18, 18, 16}

// vlanTable builds a synthetic "show vlan" output from rows of five cells.
func vlanTable(rows ...[]string) []byte {
	var b strings.Builder
	b.WriteString(fixedRow(vlanWidths, "Vlan", "Name", "Tagged Ports", "UnTagged Ports", "Created by"))
	b.WriteString(dashRule(vlanWidths))
	for _, r := range rows {
		b.WriteString(fixedRow(vlanWidths, r...))
	}
	return []byte(b.String())
}

func portRange(prefix string, lo, hi int) []string {
	var out []string
	for i := lo; i <= hi; i++ {
		out = append(out, fmt.Sprintf("%s%d", prefix, i))
	}
	return out
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

func TestParseVLANsFixtures(t *testing.T) {
	uplinks350 := []string{"te1/0/1", "te1/0/2", "Po1"}
	tests := []struct {
		fixture string
		want    []VLAN
	}{
		{
			fixture: "vlan_cbs350.txt",
			want: []VLAN{
				{ID: 1, Name: "1", Untagged: concat(portRange("gi1/0/", 9, 24), portRange("te1/0/", 3, 4), portRange("Po", 2, 8)), Type: "DV"},
				{ID: 10, Name: "servers-a", Tagged: uplinks350, Untagged: portRange("gi1/0/", 1, 4), Type: "S"},
				{ID: 20, Name: "storage-b", Tagged: uplinks350, Untagged: portRange("gi1/0/", 5, 8), Type: "S"},
				{ID: 30, Name: "mgmt lab", Tagged: uplinks350, Type: "S"},
				{ID: 99, Name: "guest", Tagged: []string{"Po1"}, Type: "S"},
			},
		},
		{
			fixture: "vlan_cbs250.txt",
			want: []VLAN{
				{ID: 1, Name: "1", Untagged: portRange("gi", 5, 8), Type: "DV"},
				{ID: 10, Name: "office", Tagged: []string{"gi9", "gi10"}, Untagged: portRange("gi", 1, 4), Type: "S"},
				{ID: 20, Name: "lab", Tagged: []string{"gi9", "gi10"}, Type: "S"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			got, incomplete, err := ParseVLANs(syntheticFixture(t, tt.fixture))
			if err != nil {
				t.Fatalf("ParseVLANs: %v", err)
			}
			if incomplete {
				t.Fatal("fixture parsed as incomplete")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseVLANsCRLF(t *testing.T) {
	in := strings.ReplaceAll(string(syntheticFixture(t, "vlan_cbs250.txt")), "\n", "\r\n")
	got, incomplete, err := ParseVLANs([]byte(in))
	if err != nil || incomplete || len(got) != 3 {
		t.Fatalf("got %d VLANs, incomplete %v, err %v", len(got), incomplete, err)
	}
}

func TestParseVLANsRefusesWholeOutput(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		wantErr error
	}{
		{"empty output", nil, ErrNoTable},
		{"blank lines only", []byte("\n\n  \n"), ErrNoTable},
		{"text without table", []byte("% Unrecognized command\n"), ErrNoTable},
		{"duplicate VLAN", vlanTable([]string{" 10", "a", "", "gi1", "S"}, []string{" 10", "b", "", "gi2", "S"}), ErrDuplicate},
		{"missing tagged column", []byte("Vlan Name\n---- -----\n 1   one\n"), ErrUnrecognizedTable},
		{"table without titles", []byte("\n---- ----\n 1   one\n"), ErrUnrecognizedTable},
		{"title column named twice", []byte("Vlan Name  Tagged Ports UnTagged Ports Type Created by\n---- ----- ------------ -------------- ---- ----------\n"), ErrUnrecognizedTable},
		{"title crossing a column gap", []byte("Vlan Name  TaggedXPorts UnTagged Ports\n---- ------ ----- ------- --------------\n"), ErrUnrecognizedTable},
		{"over the line limit", []byte(strings.Repeat("\n", tableMaxLines+1)), netdevcontract.ErrOverLimit},
		{"line over MaxLineBytes", append(vlanTable(), []byte(" 2   "+strings.Repeat("a", netdevcontract.MaxLineBytes))...), netdevcontract.ErrOverLimit},
		{"output over the byte cap", make([]byte, netdevcontract.MaxCBSCommandOutputBytes+1), netdevcontract.ErrOverLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseVLANs(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != nil || incomplete {
				t.Fatalf("error with result %+v, incomplete %v", got, incomplete)
			}
		})
	}
}

func TestParseVLANsRefusesHostileText(t *testing.T) {
	base := string(vlanTable([]string{" 1", "default", "", "gi1", "DV"}))
	for name, bad := range map[string]string{
		"ANSI escape":   "\x1b[2J\x1b[31m",
		"NUL":           "\x00",
		"invalid UTF-8": "\xff\xfe",
		"bell":          "\a",
		"bidi override": string(rune(0x202e)),
	} {
		t.Run(name, func(t *testing.T) {
			in := base + fixedRow(vlanWidths, " 2", "x"+bad+"y", "", "gi2", "S")
			got, incomplete, err := ParseVLANs([]byte(in))
			if err == nil {
				t.Fatalf("hostile name accepted: %+v incomplete %v", got, incomplete)
			}
			if strings.Contains(err.Error(), bad) {
				t.Fatalf("error echoes the hostile bytes: %q", err)
			}
		})
	}
}

func TestParseVLANsDropsMalformedRows(t *testing.T) {
	good := []string{" 1", "default", "", "gi1", "DV"}
	tests := []struct {
		name string
		rows [][]string
		// extra is appended verbatim after the rows.
		extra string
	}{
		{name: "VLAN 0", rows: [][]string{{" 0", "zero", "", "gi2", "S"}}},
		{name: "VLAN 4095", rows: [][]string{{" 4095", "over", "", "gi2", "S"}}},
		{name: "VLAN 65537", rows: [][]string{{" 65537", "over", "", "gi2", "S"}}},
		{name: "leading zero ID", rows: [][]string{{" 010", "ten", "", "gi2", "S"}}},
		{name: "signed ID", rows: [][]string{{" +10", "ten", "", "gi2", "S"}}},
		{name: "non-numeric ID", rows: [][]string{{" ten", "ten", "", "gi2", "S"}}},
		{name: "unknown port syntax", rows: [][]string{{" 10", "ten", "", "eth0", "S"}}},
		{name: "upper-case prefix", rows: [][]string{{" 10", "ten", "", "GI2", "S"}}},
		{name: "two-component port", rows: [][]string{{" 10", "ten", "", "gi1/2", "S"}}},
		{name: "port zero", rows: [][]string{{" 10", "ten", "", "gi0", "S"}}},
		{name: "reversed range", rows: [][]string{{" 10", "ten", "", "gi4-2", "S"}}},
		{name: "empty list entry", rows: [][]string{{" 10", "ten", "", "gi2,,gi3", "S"}}},
		{name: "trailing comma", rows: [][]string{{" 10", "ten", "", "gi2,", "S"}}},
		{name: "port listed twice", rows: [][]string{{" 10", "ten", "", "gi2-4,gi3", "S"}}},
		{name: "tagged and untagged", rows: [][]string{{" 10", "ten", "gi2", "gi2", "S"}}},
		{name: "range over the port limit", rows: [][]string{{" 10", "ten", "", "gi1/0/1-999,gi1/1/1-999", "S"}}},
		{name: "name with U+FFFD", rows: [][]string{{" 10", "a�b", "", "gi2", "S"}}},
		{name: "name over MaxLabelBytes", extra: " 10" + strings.Repeat(" ", 2) + strings.Repeat("n", netdevcontract.MaxLabelBytes+1) + "\n"},
		{name: "type over its limit", rows: [][]string{{" 10", "ten", "", "gi2", strings.Repeat("S", vlanTypeMaxBytes+1)}}},
		{name: "name crossing a column gap", extra: " 10  name-that-is-much-too-long  gi2\n"},
		{name: "tab in row", extra: " 10\tten\n"},
		{name: "continuation fills name", rows: [][]string{{" 10", "ten", "", "gi2,", "S"}, {"", "more", "", "gi3", ""}}},
		{name: "continuation without comma", rows: [][]string{{" 10", "ten", "", "gi2", "S"}, {"", "", "", "gi3", ""}}},
		{name: "continuation splits a range", rows: [][]string{{" 10", "ten", "", "gi2-", "S"}, {"", "", "", "4", ""}}},
		{name: "malformed continuation", rows: [][]string{{" 10", "ten", "", "gi2,", "S"}}, extra: "\tgi3\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := string(vlanTable(append([][]string{good}, tt.rows...)...)) + tt.extra
			got, incomplete, err := ParseVLANs([]byte(in))
			if err != nil {
				t.Fatalf("ParseVLANs: %v", err)
			}
			if !incomplete {
				t.Fatal("malformed row did not mark the result incomplete")
			}
			want := []VLAN{{ID: 1, Name: "default", Untagged: []string{"gi1"}, Type: "DV"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want only the valid row", got)
			}
		})
	}
}

func TestParseVLANsOrphanContinuationIsIncomplete(t *testing.T) {
	got, incomplete, err := ParseVLANs(vlanTable([]string{"", "", "", "gi3", ""}, []string{" 5", "five", "", "", ""}))
	if err != nil || !incomplete || len(got) != 1 || got[0].ID != 5 {
		t.Fatalf("got %+v, incomplete %v, err %v", got, incomplete, err)
	}
}

func TestParseVLANsMalformedRowAfterContinuationDropsRow(t *testing.T) {
	// A misaligned line after a row may continue it, so the row is dropped.
	in := string(vlanTable([]string{" 5", "five", "", "gi3,", ""})) + "     x  y  z  w  v  u  t  s  r  q  p\n"
	got, incomplete, err := ParseVLANs([]byte(in))
	if err != nil || !incomplete || len(got) != 0 {
		t.Fatalf("got %+v, incomplete %v, err %v", got, incomplete, err)
	}
}

func TestParseVLANsAcceptsBoundaryValues(t *testing.T) {
	// Name is the last column here, so a name of MaxLabelBytes fits.
	name := strings.Repeat("n", netdevcontract.MaxLabelBytes)
	w := []int{4, 18, 18, 4, 17}
	in := fixedRow(w, "Vlan", "Tagged Ports", "UnTagged Ports", "Type", "Name") + dashRule(w) +
		fixedRow(w, " 1", "", "", "", "") +
		fixedRow(w, "4094", "Po1-8", "gi1/0/1-48", "S", name)
	got, incomplete, err := ParseVLANs([]byte(in))
	if err != nil || incomplete {
		t.Fatalf("incomplete %v, err %v", incomplete, err)
	}
	if len(got) != 2 || got[1].ID != 4094 || got[1].Name != name || len(got[1].Untagged) != 48 || len(got[1].Tagged) != 8 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseVLANsDropsNameOverLabelLimit(t *testing.T) {
	w := []int{4, 18, 18, 4, 17}
	in := fixedRow(w, "Vlan", "Tagged Ports", "UnTagged Ports", "Type", "Name") + dashRule(w) +
		fixedRow(w, " 1", "", "", "", "one") +
		fixedRow(w, " 2", "", "", "", strings.Repeat("n", netdevcontract.MaxLabelBytes+1))
	got, incomplete, err := ParseVLANs([]byte(in))
	if err != nil || !incomplete || len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("got %+v, incomplete %v, err %v", got, incomplete, err)
	}
}

func TestParseVLANsTruncatesAtLimit(t *testing.T) {
	rows := make([][]string, 0, netdevcontract.MaxVLANsPerDevice+1)
	for id := 1; id <= netdevcontract.MaxVLANsPerDevice; id++ {
		rows = append(rows, []string{fmt.Sprint(id), "", "", "", ""})
	}
	t.Run("at the limit", func(t *testing.T) {
		got, incomplete, err := ParseVLANs(vlanTable(rows...))
		if err != nil || incomplete || len(got) != netdevcontract.MaxVLANsPerDevice {
			t.Fatalf("got %d, incomplete %v, err %v", len(got), incomplete, err)
		}
	})
	t.Run("one row over the limit", func(t *testing.T) {
		over := append(rows, []string{"1", "dup-after-limit", "", "", ""})
		got, incomplete, err := ParseVLANs(vlanTable(over...))
		if err != nil || !incomplete || len(got) != netdevcontract.MaxVLANsPerDevice {
			t.Fatalf("got %d, incomplete %v, err %v", len(got), incomplete, err)
		}
	})
}

func TestParseVLANsTooManyContinuationLines(t *testing.T) {
	rows := [][]string{{" 5", "five", "", "gi1/0/1,", ""}}
	for i := 0; i <= vlanMaxContinuationLines; i++ {
		rows = append(rows, []string{"", "", "", fmt.Sprintf("gi1/%d/1,", i), ""})
	}
	got, incomplete, err := ParseVLANs(vlanTable(rows...))
	if err != nil || !incomplete || len(got) != 0 {
		t.Fatalf("got %+v, incomplete %v, err %v", got, incomplete, err)
	}
}

// FuzzParseVLANs: no panic on arbitrary bytes; an error returns nil and
// not incomplete; every returned VLAN satisfies the contract rules.
func FuzzParseVLANs(f *testing.F) {
	f.Add([]byte{})
	f.Add(syntheticFixture(f, "vlan_cbs350.txt"))
	f.Add(syntheticFixture(f, "vlan_cbs250.txt"))
	f.Add(vlanTable([]string{" 10", "a", "", "gi1", "S"}, []string{" 10", "b", "", "gi2", "S"}))
	f.Add(vlanTable([]string{" 0", "a", "gi1-999", "Po1", "S"}, []string{"", "", "", "gi2,", ""}))
	f.Add([]byte("Vlan Name\n---- ----\n\n---- ----\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, incomplete, err := ParseVLANs(in)
		if err != nil {
			if got != nil || incomplete {
				t.Fatalf("error %v with result %+v incomplete %v", err, got, incomplete)
			}
			return
		}
		checkVLANInvariants(t, got)
	})
}

func checkVLANInvariants(t *testing.T, got []VLAN) {
	t.Helper()
	if len(got) > netdevcontract.MaxVLANsPerDevice {
		t.Fatalf("%d VLANs over the limit", len(got))
	}
	ids := map[uint16]bool{}
	for _, v := range got {
		if v.ID < 1 || v.ID > netdevcontract.MaxVLANID || ids[v.ID] {
			t.Fatalf("bad or duplicate ID %d", v.ID)
		}
		ids[v.ID] = true
		if !validLabel(v.Name) || !validValueText(v.Type) || len(v.Type) > vlanTypeMaxBytes {
			t.Fatalf("VLAN %d: name %q or type %q violates the text rule", v.ID, v.Name, v.Type)
		}
		ports := map[string]bool{}
		for _, p := range concat(v.Tagged, v.Untagged) {
			if !validPortName(p) || !netdevcontract.ValidInterfaceName(p) || ports[p] {
				t.Fatalf("VLAN %d: bad or repeated port %q", v.ID, p)
			}
			ports[p] = true
		}
		if len(ports) > 2*netdevcontract.MaxInterfacesPerDevice {
			t.Fatalf("VLAN %d: %d ports", v.ID, len(ports))
		}
	}
}

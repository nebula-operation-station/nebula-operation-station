// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// statusWidths has a port column wide enough for gi10/0/10.
var statusWidths = []int{10, 12, 6, 6, 6, 11}

// statusTable builds a synthetic "show interfaces status" table with the
// columns Port, Type, Duplex, Speed, Vlan, Link State.
func statusTable(rows ...[]string) []byte {
	var b strings.Builder
	b.WriteString(fixedRow(statusWidths, "", "", "", "", "", "Link"))
	b.WriteString(fixedRow(statusWidths, "Port", "Type", "Duplex", "Speed", "Vlan", "State"))
	b.WriteString(dashRule(statusWidths))
	for _, r := range rows {
		b.WriteString(fixedRow(statusWidths, r...))
	}
	return []byte(b.String())
}

var descWidths = []int{9, 30}

func descTable(rows ...[]string) []byte {
	var b strings.Builder
	b.WriteString(fixedRow(descWidths, "Port", "Description"))
	b.WriteString(dashRule(descWidths))
	for _, r := range rows {
		b.WriteString(fixedRow(descWidths, r...))
	}
	return []byte(b.String())
}

func up(name, typ string, mbps uint64) Interface {
	return Interface{Name: name, Type: typ, Status: netdevcontract.LinkUp, Duplex: DuplexFull, SpeedMbps: mbps}
}

func down(name, typ string) Interface {
	return Interface{Name: name, Type: typ, Status: netdevcontract.LinkDown}
}

func TestParseInterfacesFixtures(t *testing.T) {
	var want350 []Interface
	for i := 1; i <= 24; i++ {
		n := fmt.Sprintf("gi1/0/%d", i)
		if i%3 == 0 {
			want350 = append(want350, down(n, "1G-Copper"))
		} else {
			want350 = append(want350, up(n, "1G-Copper", 1000))
		}
	}
	want350 = append(want350,
		up("te1/0/1", "10G-Fiber", 10000), up("te1/0/2", "10G-Fiber", 10000),
		down("te1/0/3", "10G-Fiber"), down("te1/0/4", "10G-Fiber"),
		up("Po1", "10G", 20000))
	for i := 2; i <= 8; i++ {
		want350 = append(want350, Interface{Name: fmt.Sprintf("Po%d", i), Status: netdevcontract.LinkUnknown})
	}

	var want250 []Interface
	for i := 1; i <= 5; i++ {
		want250 = append(want250, up(fmt.Sprintf("gi%d", i), "1G-Copper", 1000))
	}
	want250 = append(want250,
		Interface{Name: "gi6", Type: "1G-Copper", Status: netdevcontract.LinkUp, Duplex: DuplexHalf, SpeedMbps: 100},
		down("gi7", "1G-Copper"), down("gi8", "1G-Copper"),
		up("gi9", "1G-Fiber", 1000), down("gi10", "1G-Fiber"))

	tests := []struct {
		fixture string
		want    []Interface
		ports   int
	}{
		{"interfaces_status_cbs350.txt", want350, 28 + 8},
		{"interfaces_status_cbs250.txt", want250, 10},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			got, incomplete, err := ParseInterfaces(syntheticFixture(t, tt.fixture))
			if err != nil {
				t.Fatalf("ParseInterfaces: %v", err)
			}
			if incomplete {
				t.Fatal("fixture parsed as incomplete")
			}
			if len(got) != tt.ports {
				t.Fatalf("got %d ports, want %d", len(got), tt.ports)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseInterfaceDescriptionsFixturesAndMerge(t *testing.T) {
	tests := []struct {
		status, desc string
		want         map[string]string
	}{
		{
			status: "interfaces_status_cbs350.txt",
			desc:   "interfaces_description_cbs350.txt",
			want: map[string]string{
				"gi1/0/1": "synthetic access port 1", "gi1/0/8": "synthetic access port 8",
				"gi1/0/9": "", "te1/0/2": "synthetic uplink member 2", "te1/0/3": "",
				"Po1": "synthetic uplink lag", "Po8": "",
			},
		},
		{
			status: "interfaces_status_cbs250.txt",
			desc:   "interfaces_description_cbs250.txt",
			want:   map[string]string{"gi1": "synthetic office port 1", "gi4": "synthetic office port 4", "gi5": "", "gi10": ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ifaces, incomplete, err := ParseInterfaces(syntheticFixture(t, tt.status))
			if err != nil || incomplete {
				t.Fatalf("ParseInterfaces: incomplete %v, err %v", incomplete, err)
			}
			descs, incomplete, err := ParseInterfaceDescriptions(syntheticFixture(t, tt.desc))
			if err != nil || incomplete {
				t.Fatalf("ParseInterfaceDescriptions: incomplete %v, err %v", incomplete, err)
			}
			if len(descs) != len(ifaces) {
				t.Fatalf("%d descriptions for %d ports", len(descs), len(ifaces))
			}
			before := append([]Interface(nil), ifaces...)
			merged, incomplete := MergeDescriptions(ifaces, descs)
			if incomplete {
				t.Fatal("merge of matching outputs is incomplete")
			}
			if !reflect.DeepEqual(ifaces, before) {
				t.Fatal("MergeDescriptions modified its input")
			}
			byName := map[string]string{}
			for _, itf := range merged {
				byName[itf.Name] = itf.Description
			}
			for port, d := range tt.want {
				if got, ok := byName[port]; !ok || got != d {
					t.Fatalf("port %s: description %q (present %v), want %q", port, got, ok, d)
				}
			}
		})
	}
}

func TestMergeDescriptionsMismatchIsIncomplete(t *testing.T) {
	ifaces := []Interface{{Name: "gi1"}, {Name: "gi2"}}
	t.Run("port without description", func(t *testing.T) {
		merged, incomplete := MergeDescriptions(ifaces, map[string]string{"gi1": "a"})
		if !incomplete || merged[0].Description != "a" || merged[1].Description != "" {
			t.Fatalf("merged %+v incomplete %v", merged, incomplete)
		}
	})
	t.Run("description without port", func(t *testing.T) {
		merged, incomplete := MergeDescriptions(ifaces, map[string]string{"gi1": "a", "gi2": "b", "gi3": "c"})
		if !incomplete || len(merged) != 2 {
			t.Fatalf("merged %+v incomplete %v", merged, incomplete)
		}
	})
}

func TestParseInterfacesVLANColumn(t *testing.T) {
	got, incomplete, err := ParseInterfaces(statusTable(
		[]string{"gi1", "1G-Copper", "Full", "1000", "10", "Up"},
		[]string{"gi2", "1G-Copper", "--", "--", "4094", "Down"},
		[]string{"gi3", "1G-Copper", "Full", "1000", "trunk", "Up"},
		[]string{"Po1", "--", "--", "--", "--", "Not Present"},
	))
	if err != nil || incomplete {
		t.Fatalf("incomplete %v, err %v", incomplete, err)
	}
	want := []Interface{
		{Name: "gi1", Type: "1G-Copper", Status: netdevcontract.LinkUp, VLAN: 10, Duplex: DuplexFull, SpeedMbps: 1000},
		{Name: "gi2", Type: "1G-Copper", Status: netdevcontract.LinkDown, VLAN: 4094},
		{Name: "gi3", Type: "1G-Copper", Status: netdevcontract.LinkUp, Duplex: DuplexFull, SpeedMbps: 1000},
		{Name: "Po1", Status: netdevcontract.LinkUnknown},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseInterfacesDropsUnknownPorts(t *testing.T) {
	good := []string{"gi1", "1G-Copper", "Full", "1000", "1", "Up"}
	for _, name := range []string{
		"eth0", "Gi1", "GE1", "gi01", "gi0", "gi1/0", "gi1/0/0", "gi1/0/1/1", "gi1000",
		"po1", "Po1/0/1", "fa1", "te", "gi1-2", "vlan1", "oob", "gi1/00/1",
	} {
		t.Run(name, func(t *testing.T) {
			got, incomplete, err := ParseInterfaces(statusTable(good, []string{name, "1G-Copper", "Full", "1000", "1", "Up"}))
			if err != nil {
				t.Fatalf("ParseInterfaces: %v", err)
			}
			if !incomplete || len(got) != 1 || got[0].Name != "gi1" {
				t.Fatalf("unknown port %q not dropped: %+v incomplete %v", name, got, incomplete)
			}
		})
	}
}

func TestParseInterfacesDropsMisalignedRows(t *testing.T) {
	good := string(statusTable([]string{"gi1", "1G-Copper", "Full", "1000", "1", "Up"}))
	typeWidth := statusWidths[1]
	tests := []struct {
		name string
		line string
		// rowOK and port are what the lexer must make of line, so that the
		// case reaches the path its name describes.
		rowOK bool
		port  string
	}{
		{
			// The port fits its column; the type runs one rune past the
			// Type column into the Type/Duplex gap.
			name: "type crossing a gap",
			line: fixedRow(statusWidths, "gi2", strings.Repeat("T", typeWidth+1), "Full", "1000", "1", "Up"),
		},
		{name: "tab in row", line: "gi2\t1G-Copper Full 1000 1 Up\n"},
		{
			// An aligned row whose Port cell is empty.
			name:  "no port name",
			line:  fixedRow(statusWidths, "", "1G-Copper", "Full", "1000", "1", "Up"),
			rowOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := good + tt.line
			blocks, err := splitTables([]byte(in), "test", nil)
			if err != nil || len(blocks) != 1 || len(blocks[0].rows) != 2 {
				t.Fatalf("lexer: %+v, err %v", blocks, err)
			}
			if r := blocks[0].rows[1]; r.ok != tt.rowOK || (r.ok && r.cells[0] != tt.port) {
				t.Fatalf("lexer row %+v, want ok %v port %q", r, tt.rowOK, tt.port)
			}
			got, incomplete, err := ParseInterfaces([]byte(in))
			if err != nil || !incomplete || len(got) != 1 || got[0].Name != "gi1" {
				t.Fatalf("got %+v, incomplete %v, err %v", got, incomplete, err)
			}
		})
	}
}

func TestParseInterfacesTypeFillingItsColumnIsKept(t *testing.T) {
	// Control for "type crossing a gap": one rune shorter is a valid row.
	typ := strings.Repeat("T", statusWidths[1])
	got, incomplete, err := ParseInterfaces(statusTable([]string{"gi2", typ, "Full", "1000", "1", "Up"}))
	if err != nil || incomplete || len(got) != 1 || got[0].Type != typ {
		t.Fatalf("got %+v, incomplete %v, err %v", got, incomplete, err)
	}
}

func TestParseInterfacesRowAboveNextHeaderIsIncomplete(t *testing.T) {
	// A port-channel table with an ignored Neg column follows the port
	// table without a blank line. A stray line just above its two title
	// lines is taken as a third title line; its text falls into the
	// ignored column, so it only vanishes from the port table.
	chWidths := []int{10, 8, 11}
	second := fixedRow(chWidths, "", "", "Link") +
		fixedRow(chWidths, "Ch", "Neg", "State") +
		dashRule(chWidths) +
		fixedRow(chWidths, "Po1", "Enabled", "Up")
	first := string(statusTable([]string{"gi1", "1G-Copper", "Full", "1000", "1", "Up"}))
	want := []Interface{
		{Name: "gi1", Type: "1G-Copper", Status: netdevcontract.LinkUp, VLAN: 1, Duplex: DuplexFull, SpeedMbps: 1000},
		{Name: "Po1", Status: netdevcontract.LinkUp},
	}
	tests := []struct {
		name           string
		between        string
		wantIncomplete bool
	}{
		{"blank line between the tables", "\n", false},
		{"orphan row above the header", fixedRow(chWidths, "", "gi1/0/9", ""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseInterfaces([]byte(first + tt.between + second))
			if err != nil || incomplete != tt.wantIncomplete || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, incomplete %v (want %v), err %v", got, incomplete, tt.wantIncomplete, err)
			}
		})
	}
}

func TestParseInterfaceDescriptionsRowAboveNextHeaderIsIncomplete(t *testing.T) {
	// As in ParseInterfaces: a stray line directly above the two title
	// lines of the port-channel table is taken as a third title line; its
	// text falls into the ignored LACP Neg column and only vanishes from
	// the port table.
	chWidths := []int{9, 8, 30}
	second := fixedRow(chWidths, "", "LACP", "") +
		fixedRow(chWidths, "Ch", "Neg", "Description") +
		dashRule(chWidths) +
		fixedRow(chWidths, "Po1", "Enabled", "lag to core")
	first := string(descTable([]string{"gi1", "uplink"}))
	want := map[string]string{"gi1": "uplink", "Po1": "lag to core"}
	tests := []struct {
		name           string
		between        string
		wantIncomplete bool
	}{
		{"blank line between the tables", "\n", false},
		{"orphan row above the header", fixedRow(chWidths, "", "gi1/0/9", ""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseInterfaceDescriptions([]byte(first + tt.between + second))
			if err != nil || incomplete != tt.wantIncomplete || !maps.Equal(got, want) {
				t.Fatalf("got %q, incomplete %v (want %v), err %v", got, incomplete, tt.wantIncomplete, err)
			}
		})
	}
}

func TestParseInterfacesUnrecognizedValuesAreIncomplete(t *testing.T) {
	tests := []struct {
		name string
		row  []string
		want Interface
	}{
		{"status", []string{"gi2", "x", "Full", "1000", "1", "err-dis"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUnknown, Duplex: DuplexFull, SpeedMbps: 1000, VLAN: 1}},
		{"duplex", []string{"gi2", "x", "Auto", "1000", "1", "Up"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUp, SpeedMbps: 1000, VLAN: 1}},
		{"speed text", []string{"gi2", "x", "Full", "2.5G", "1", "Up"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUp, Duplex: DuplexFull, VLAN: 1}},
		{"speed zero", []string{"gi2", "x", "Full", "0", "1", "Up"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUp, Duplex: DuplexFull, VLAN: 1}},
		{"speed over limit", []string{"gi2", "x", "Full", "2000G", "1", "Up"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUp, Duplex: DuplexFull, VLAN: 1}},
		{"VLAN 0", []string{"gi2", "x", "Full", "1000", "0", "Up"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUp, Duplex: DuplexFull, SpeedMbps: 1000}},
		{"VLAN 4095", []string{"gi2", "x", "Full", "1000", "4095", "Up"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUp, Duplex: DuplexFull, SpeedMbps: 1000}},
		{"VLAN leading zero", []string{"gi2", "x", "Full", "1000", "01", "Up"}, Interface{Name: "gi2", Type: "x", Status: netdevcontract.LinkUp, Duplex: DuplexFull, SpeedMbps: 1000}},
		{"type with U+FFFD", []string{"gi2", "a�", "Full", "1000", "1", "Up"}, Interface{Name: "gi2", Status: netdevcontract.LinkUp, Duplex: DuplexFull, SpeedMbps: 1000, VLAN: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseInterfaces(statusTable(tt.row))
			if err != nil {
				t.Fatalf("ParseInterfaces: %v", err)
			}
			if !incomplete {
				t.Fatal("unrecognised value did not mark the result incomplete")
			}
			if len(got) != 1 || !reflect.DeepEqual(got[0], tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseInterfacesRefusesWholeOutput(t *testing.T) {
	row := []string{"gi1", "1G-Copper", "Full", "1000", "1", "Up"}
	tests := []struct {
		name    string
		in      []byte
		wantErr error
	}{
		{"empty output", []byte{}, ErrNoTable},
		{"duplicate port", statusTable(row, row), ErrDuplicate},
		{"no status column", []byte("Port     Type\n-------- ----\ngi1      x\n"), ErrUnrecognizedTable},
		{"no port column", []byte("Name     Status\n-------- ------\ngi1      Up\n"), ErrUnrecognizedTable},
		{"over the line limit", []byte(strings.Repeat("x\n", tableMaxLines+1)), netdevcontract.ErrOverLimit},
		{"output over the byte cap", make([]byte, netdevcontract.MaxCBSCommandOutputBytes+1), netdevcontract.ErrOverLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseInterfaces(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != nil || incomplete {
				t.Fatalf("error with result %+v incomplete %v", got, incomplete)
			}
		})
	}
}

func TestParseInterfacesTruncatesAtLimit(t *testing.T) {
	var rows [][]string
	for u := 1; len(rows) < netdevcontract.MaxInterfacesPerDevice+1; u++ {
		for p := 1; p <= 64 && len(rows) < netdevcontract.MaxInterfacesPerDevice+1; p++ {
			rows = append(rows, []string{fmt.Sprintf("gi%d/0/%d", u, p), "", "", "", "", "Up"})
		}
	}
	got, incomplete, err := ParseInterfaces(statusTable(rows[:netdevcontract.MaxInterfacesPerDevice]...))
	if err != nil || incomplete || len(got) != netdevcontract.MaxInterfacesPerDevice {
		t.Fatalf("at the limit: got %d, incomplete %v, err %v", len(got), incomplete, err)
	}
	got, incomplete, err = ParseInterfaces(statusTable(rows...))
	if err != nil || !incomplete || len(got) != netdevcontract.MaxInterfacesPerDevice {
		t.Fatalf("over the limit: got %d, incomplete %v, err %v", len(got), incomplete, err)
	}

	var drows [][]string
	for _, r := range rows {
		drows = append(drows, []string{r[0], "d"})
	}
	descs, incomplete, err := ParseInterfaceDescriptions(descTable(drows...))
	if err != nil || !incomplete || len(descs) != netdevcontract.MaxInterfacesPerDevice {
		t.Fatalf("descriptions over the limit: got %d, incomplete %v, err %v", len(descs), incomplete, err)
	}
}

func TestParseInterfaceDescriptionsHostile(t *testing.T) {
	good := []string{"gi1", "uplink to core"}
	t.Run("refused", func(t *testing.T) {
		for name, desc := range map[string]string{
			"ANSI escape":   "\x1b[31mred\x1b[0m",
			"NUL":           "a\x00b",
			"invalid UTF-8": "a\xc3\x28b",
			"DEL":           "a\x7fb",
			"bidi isolate":  "a" + string(rune(0x2066)) + "b",
			"4 KiB":         strings.Repeat("d", 4<<10),
		} {
			t.Run(name, func(t *testing.T) {
				in := descTable(good, []string{"gi2", desc})
				got, incomplete, err := ParseInterfaceDescriptions(in)
				if err == nil || got != nil || incomplete {
					t.Fatalf("hostile description accepted: %q incomplete %v err %v", got, incomplete, err)
				}
				if strings.Contains(err.Error(), desc) {
					t.Fatal("error echoes the description")
				}
			})
		}
	})
	t.Run("dropped", func(t *testing.T) {
		for name, desc := range map[string]string{
			"over MaxLabelBytes": strings.Repeat("d", netdevcontract.MaxLabelBytes+1),
			"near 4 KiB":         strings.Repeat("d", 4000),
			"U+FFFD":             "a�b",
		} {
			t.Run(name, func(t *testing.T) {
				got, incomplete, err := ParseInterfaceDescriptions(descTable(good, []string{"gi2", desc}))
				if err != nil {
					t.Fatalf("ParseInterfaceDescriptions: %v", err)
				}
				want := map[string]string{"gi1": "uplink to core", "gi2": ""}
				if !incomplete || !maps.Equal(got, want) {
					t.Fatalf("got %q incomplete %v, want %q incomplete", got, incomplete, want)
				}
			})
		}
	})
	t.Run("at MaxLabelBytes", func(t *testing.T) {
		d := strings.Repeat("d", netdevcontract.MaxLabelBytes)
		got, incomplete, err := ParseInterfaceDescriptions(descTable([]string{"gi1", d}))
		if err != nil || incomplete || got["gi1"] != d {
			t.Fatalf("incomplete %v err %v", incomplete, err)
		}
	})
	t.Run("description with spaces and dashes", func(t *testing.T) {
		d := "a  --  b ---- c"
		got, incomplete, err := ParseInterfaceDescriptions(descTable([]string{"gi1", d}))
		if err != nil || incomplete || got["gi1"] != d {
			t.Fatalf("got %q incomplete %v err %v", got, incomplete, err)
		}
	})
	t.Run("unknown port and duplicate", func(t *testing.T) {
		got, incomplete, err := ParseInterfaceDescriptions(descTable(good, []string{"eth0", "x"}))
		if err != nil || !incomplete || len(got) != 1 {
			t.Fatalf("got %q incomplete %v err %v", got, incomplete, err)
		}
		_, _, err = ParseInterfaceDescriptions(descTable(good, good))
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("duplicate port: err %v", err)
		}
	})
	t.Run("empty output", func(t *testing.T) {
		if _, _, err := ParseInterfaceDescriptions(nil); !errors.Is(err, ErrNoTable) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestParsePortList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
		ok   bool
	}{
		{"", nil, true},
		{"gi1", []string{"gi1"}, true},
		{"gi1/0/1-3,Po2", []string{"gi1/0/1", "gi1/0/2", "gi1/0/3", "Po2"}, true},
		{"te1/0/4-4", []string{"te1/0/4"}, true},
		{"gi3-1", nil, false},
		{"gi1-", nil, false},
		{"gi1-x", nil, false},
		{"gi1--2", nil, false},
		{"gi1,", nil, false},
		{",gi1", nil, false},
		{"gi1 ,gi2", nil, false},
		{"gi1,gi1", nil, false},
		{"gi1/0/1-999,gi1/1/1-26", nil, false},
		{"gi1/0/1-999", nil, true},
		{"Po0", nil, false},
		{strings.Repeat("gi1,", portListMaxTokens) + "gi2", nil, false},
	}
	for _, tt := range tests {
		budget := vlanMaxMemberships
		got, err := parsePortList(tt.in, &budget)
		if ok := err == nil; ok != tt.ok {
			t.Fatalf("parsePortList(%.40q) ok = %v, want %v", tt.in, ok, tt.ok)
		}
		if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("parsePortList(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParsePortListMembershipBudget(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		budget     int
		wantErr    error
		wantBudget int
	}{
		{"exactly the budget", "gi1-4", 4, nil, 0},
		{"under the budget", "gi1-2,Po1", 10, nil, 7},
		{"empty list with no budget left", "", 0, nil, 0},
		{"range over the budget", "gi1-4", 3, errMembershipCap, 3},
		{"second entry over the budget", "gi1-3,gi4", 3, errMembershipCap, 0},
		{"malformed list is not a cap", "gi4-2", 0, errPortList, 0},
		{"per-list limit before the budget", "gi1/0/1-999,gi1/1/1-26", 1000, errPortList, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			budget := tt.budget
			got, err := parsePortList(tt.in, &budget)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil && got != nil {
				t.Fatalf("error with ports %v", got)
			}
			if budget != tt.wantBudget {
				t.Fatalf("budget left %d, want %d", budget, tt.wantBudget)
			}
		})
	}
}

// FuzzParseInterfaces: no panic on arbitrary bytes; an error returns nil
// and not incomplete; every returned interface satisfies the contract
// rules; the description parser and the merge keep the same rules.
func FuzzParseInterfaces(f *testing.F) {
	f.Add([]byte{})
	f.Add(syntheticFixture(f, "interfaces_status_cbs350.txt"))
	f.Add(syntheticFixture(f, "interfaces_status_cbs250.txt"))
	f.Add(syntheticFixture(f, "interfaces_description_cbs350.txt"))
	f.Add(syntheticFixture(f, "interfaces_description_cbs250.txt"))
	f.Add(statusTable([]string{"gi1", "x", "Full", "10G", "4095", "Up"}, []string{"gi1", "x", "", "", "", "Down"}))
	f.Add(descTable([]string{"gi1", "a�"}, []string{"Po1", "b"}))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, incomplete, err := ParseInterfaces(in)
		if err != nil {
			if got != nil || incomplete {
				t.Fatalf("error %v with result %+v incomplete %v", err, got, incomplete)
			}
		} else {
			checkInterfaceInvariants(t, got)
		}
		descs, dIncomplete, err := ParseInterfaceDescriptions(in)
		if err != nil {
			if descs != nil || dIncomplete {
				t.Fatalf("error %v with result %q incomplete %v", err, descs, dIncomplete)
			}
			return
		}
		if len(descs) > netdevcontract.MaxInterfacesPerDevice {
			t.Fatalf("%d descriptions", len(descs))
		}
		for port, d := range descs {
			if !validPortName(port) || !validLabel(d) {
				t.Fatalf("bad description entry %q: %q", port, d)
			}
		}
		merged, _ := MergeDescriptions(got, descs)
		checkInterfaceInvariants(t, merged)
	})
}

func checkInterfaceInvariants(t *testing.T, got []Interface) {
	t.Helper()
	if len(got) > netdevcontract.MaxInterfacesPerDevice {
		t.Fatalf("%d interfaces over the limit", len(got))
	}
	names := map[string]bool{}
	for _, itf := range got {
		if !validPortName(itf.Name) || !netdevcontract.ValidInterfaceName(itf.Name) || names[itf.Name] {
			t.Fatalf("bad or duplicate port %q", itf.Name)
		}
		names[itf.Name] = true
		switch itf.Status {
		case netdevcontract.LinkUp, netdevcontract.LinkDown, netdevcontract.LinkUnknown:
		default:
			t.Fatalf("%s: status %q", itf.Name, itf.Status)
		}
		switch itf.Duplex {
		case DuplexFull, DuplexHalf, DuplexUnknown:
		default:
			t.Fatalf("%s: duplex %q", itf.Name, itf.Duplex)
		}
		if itf.SpeedMbps > netdevcontract.MaxSpeedMbps || itf.VLAN > netdevcontract.MaxVLANID {
			t.Fatalf("%s: speed %d or VLAN %d out of range", itf.Name, itf.SpeedMbps, itf.VLAN)
		}
		if !validLabel(itf.Type) || !validLabel(itf.Description) {
			t.Fatalf("%s: type %q or description %q violates the text rule", itf.Name, itf.Type, itf.Description)
		}
	}
}

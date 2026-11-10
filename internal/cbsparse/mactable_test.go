// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

var macWidths = []int{8, 21, 10, 10}

// macTable builds a synthetic "show mac address-table" output from rows
// of four cells.
func macTable(rows ...[]string) []byte {
	var b strings.Builder
	b.WriteString(fixedRow(macWidths, "Vlan", "Mac Address", "Port", "Type"))
	b.WriteString(dashRule(macWidths))
	for _, r := range rows {
		b.WriteString(fixedRow(macWidths, r...))
	}
	return []byte(b.String())
}

// docMAC returns a documentation MAC (RFC 7042, 00:00:5e:00:53:00/24).
func docMAC(n int) string { return fmt.Sprintf("00:00:5e:00:53:%02x", n&0xff) }

// bulkMACRows returns n rows with distinct (VLAN, MAC) pairs from the
// documentation range.
func bulkMACRows(n int) [][]string {
	rows := make([][]string, n)
	for i := range rows {
		rows[i] = []string{fmt.Sprint(1 + i/256), docMAC(i), "gi1/0/1", "dynamic"}
	}
	return rows
}

type macE = netdevcontract.MACEntry

func TestParseMACTableFixtures(t *testing.T) {
	dyn, st, other := netdevcontract.MACDynamic, netdevcontract.MACStatic, netdevcontract.MACOther
	tests := []struct {
		fixture string
		want    []macE
	}{
		{"mac_table_cbs350.txt", []macE{
			{VLAN: 1, MAC: "00:00:5e:00:53:01", Type: other},
			{VLAN: 1, MAC: "00:00:5e:00:53:0a", Port: "gi1/0/1", Type: dyn},
			{VLAN: 1, MAC: "00:00:5e:00:53:0b", Port: "gi1/0/2", Type: dyn},
			{VLAN: 10, MAC: "00:00:5e:00:53:10", Port: "te1/0/1", Type: dyn},
			{VLAN: 10, MAC: "00:00:5e:00:53:11", Port: "te1/0/1", Type: dyn},
			{VLAN: 20, MAC: "00:00:5e:00:53:20", Port: "Po1", Type: st},
			{VLAN: 99, MAC: "00:00:5e:00:53:0a", Port: "gi1/0/24", Type: dyn},
		}},
		{"mac_table_cbs250.txt", []macE{
			{VLAN: 1, MAC: "00:00:5e:00:53:01", Type: other},
			{VLAN: 1, MAC: "00:00:5e:00:53:21", Port: "gi1", Type: dyn},
			{VLAN: 1, MAC: "00:00:5e:00:53:22", Port: "gi8", Type: dyn},
			{VLAN: 30, MAC: "00:00:5e:00:53:23", Port: "gi8", Type: st},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			got, incomplete, err := ParseMACTable(syntheticFixture(t, tt.fixture))
			if err != nil || incomplete {
				t.Fatalf("err %v incomplete %v", err, incomplete)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v\nwant %+v", got, tt.want)
			}
			checkMACInvariants(t, got)
		})
	}
}

func TestParseMACTableStrictMACSyntax(t *testing.T) {
	good := []string{"gi1/0/1", "dynamic"}
	tests := []struct {
		mac  string
		want string // "" means dropped
	}{
		{"00:00:5e:00:53:01", "00:00:5e:00:53:01"},
		{"00:00:5E:00:53:AB", "00:00:5e:00:53:ab"},
		{"00-00-5e-00-53-01", ""},
		{"0000.5e00.5301", ""},
		{"00005e005301", ""},
		{"0:0:5e:0:53:1", ""},
		{"00:00:5e:00:53", ""},
		{"00:00:5e:00:53:01:02", ""},
		{"00:00:5e:00:53:0g", ""},
		{"00:00:5e:00:53;01", ""},
		{"00:00:5e:00:53:０1", ""}, // fullwidth digit
		{"x0:00:5e:00:53:01", ""},
		{"00:00:5e:00:53:", ""},
	}
	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			got, incomplete, err := ParseMACTable(macTable(
				[]string{"1", tt.mac, good[0], good[1]},
				[]string{"2", docMAC(0x99), "gi1/0/2", "static"},
			))
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if !incomplete || len(got) != 1 || got[0].VLAN != 2 {
					t.Fatalf("invalid MAC kept: %+v incomplete %v", got, incomplete)
				}
				return
			}
			if incomplete || len(got) != 2 || got[0].MAC != tt.want {
				t.Fatalf("got %+v incomplete %v, want MAC %s", got, incomplete, tt.want)
			}
		})
	}
}

func TestParseMACTableDropsMalformedRows(t *testing.T) {
	tests := []struct {
		name string
		row  string
	}{
		{"vlan zero", fixedRow(macWidths, "0", docMAC(1), "gi1/0/1", "dynamic")},
		{"vlan 4095", fixedRow(macWidths, "4095", docMAC(1), "gi1/0/1", "dynamic")},
		{"vlan leading zero", fixedRow(macWidths, "01", docMAC(1), "gi1/0/1", "dynamic")},
		{"vlan signed", fixedRow(macWidths, "+1", docMAC(1), "gi1/0/1", "dynamic")},
		{"unknown port", fixedRow(macWidths, "1", docMAC(1), "eth0", "dynamic")},
		{"empty port", fixedRow(macWidths, "1", docMAC(1), "", "dynamic")},
		{"unknown type", fixedRow(macWidths, "1", docMAC(1), "gi1/0/1", "secure")},
		{"missing type", fixedRow(macWidths, "1", docMAC(1), "gi1/0/1", "")},
		{"tab", "1\t" + docMAC(1) + "\tgi1/0/1\tdynamic\n"},
		{"text in gap", strings.Replace(fixedRow(macWidths, "1", docMAC(1), "gi1/0/1", "dynamic"), "gi1/0/1    dynamic", "gi1/0/1   xdynamic", 1)},
		{"mac crosses gap", fixedRow([]int{8, 22, 9, 10}, "1", docMAC(1)+"0000", "gi1/0/1", "dynamic")},
		{"replacement rune", fixedRow(macWidths, "1", docMAC(1), "gi1/0/1", "dyn�mic")},
		// A row wrapped onto two lines: the first half lacks port and type,
		// the second half has no VLAN.
		{"wrapped row", fixedRow(macWidths, "1", docMAC(1)) + fixedRow(macWidths, "", "", "gi1/0/1", "dynamic")},
		{"continuation line", fixedRow(macWidths, "", docMAC(1), "gi1/0/1", "dynamic")},
		{"footer", "Total number of entries: 2\n"},
	}
	keep := fixedRow(macWidths, "7", docMAC(0x77), "gi1/0/7", "dynamic")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "text in gap" && !strings.Contains(tt.row, "x") {
				t.Fatal("test row lost its gap text")
			}
			in := append(macTable(), []byte(keep+tt.row)...)
			got, incomplete, err := ParseMACTable(in)
			if err != nil {
				t.Fatal(err)
			}
			want := []macE{{VLAN: 7, MAC: docMAC(0x77), Port: "gi1/0/7", Type: netdevcontract.MACDynamic}}
			if !incomplete || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v incomplete %v", got, incomplete)
			}
		})
	}
}

func TestParseMACTableDuplicatesDropEveryCopy(t *testing.T) {
	tests := []struct {
		name string
		rows [][]string
	}{
		{"identical", [][]string{
			{"1", docMAC(1), "gi1/0/1", "dynamic"},
			{"1", docMAC(1), "gi1/0/1", "dynamic"},
		}},
		{"moved port", [][]string{
			{"1", docMAC(1), "gi1/0/1", "dynamic"},
			{"1", docMAC(1), "gi1/0/9", "dynamic"},
		}},
		{"case differs", [][]string{
			{"1", "00:00:5E:00:53:01", "gi1/0/1", "static"},
			{"1", docMAC(1), "gi1/0/1", "dynamic"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := append(tt.rows, []string{"2", docMAC(1), "gi1/0/2", "dynamic"})
			got, incomplete, err := ParseMACTable(macTable(rows...))
			if err != nil {
				t.Fatal(err)
			}
			want := []macE{{VLAN: 2, MAC: docMAC(1), Port: "gi1/0/2", Type: netdevcontract.MACDynamic}}
			if !incomplete || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v incomplete %v", got, incomplete)
			}
		})
	}
}

func TestParseMACTablePerDeviceLimit(t *testing.T) {
	limit := netdevcontract.MaxMACEntriesPerDevice
	for _, n := range []int{limit, limit + 1, 16000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			got, incomplete, err := ParseMACTable(macTable(bulkMACRows(n)...))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != min(n, limit) || incomplete != (n > limit) {
				t.Fatalf("%d rows: got %d entries incomplete %v", n, len(got), incomplete)
			}
			checkMACInvariants(t, got)
		})
	}
}

// TestParseMACTableRefuses70000Lines: 70,000 MAC lines exceed both the
// 1 MiB transport cap and macMaxLines; the output is refused, never
// silently truncated.
func TestParseMACTableRefuses70000Lines(t *testing.T) {
	got, incomplete, err := ParseMACTable(macTable(bulkMACRows(70000)...))
	if !errors.Is(err, netdevcontract.ErrOverLimit) || got != nil || incomplete {
		t.Fatalf("got %d entries incomplete %v err %v", len(got), incomplete, err)
	}
	// The line limit alone, below the byte cap.
	flood := append(macTable(), strings.Repeat(" \n", macMaxLines)...)
	if _, _, err := ParseMACTable(flood); !errors.Is(err, netdevcontract.ErrOverLimit) {
		t.Fatalf("line flood: err %v", err)
	}
}

func TestParseMACTableRefusesOutput(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrNoTable},
		{"no table", []byte("% Unrecognized command\n"), ErrNoTable},
		{"missing type column", []byte("Vlan Mac Address       Port\n---- ----------------- -------\n1    " + docMAC(1) + " gi1\n"), ErrUnrecognizedTable},
		{"escape sequence", append(macTable([]string{"1", docMAC(1), "gi1", "dynamic"}), "\x1b[2J\n"...), nil},
		{"invalid utf-8", append(macTable(), 0xff, '\n'), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseMACTable(tt.in)
			if err == nil || got != nil || incomplete {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseMACTableEmptyTableIsAvailable(t *testing.T) {
	got, incomplete, err := ParseMACTable(macTable())
	if err != nil || incomplete || got == nil || len(got) != 0 {
		t.Fatalf("got %#v incomplete %v err %v", got, incomplete, err)
	}
}

// checkMACInvariants checks what ParseMACTable promises for a result and
// that it passes the netdevcontract observation validation.
func checkMACInvariants(t *testing.T, got []netdevcontract.MACEntry) {
	t.Helper()
	if len(got) > netdevcontract.MaxMACEntriesPerDevice {
		t.Fatalf("%d entries over the device limit", len(got))
	}
	seen := map[macKey]struct{}{}
	for _, e := range got {
		if e.VLAN < 1 || e.VLAN > netdevcontract.MaxVLANID || !netdevcontract.ValidMAC(e.MAC) ||
			(e.Port != "" && !validPortName(e.Port)) {
			t.Fatalf("invalid entry %+v", e)
		}
		switch e.Type {
		case netdevcontract.MACDynamic, netdevcontract.MACStatic, netdevcontract.MACOther:
		default:
			t.Fatalf("unknown type in %+v", e)
		}
		k := macKey{e.VLAN, e.MAC}
		if _, dup := seen[k]; dup {
			t.Fatalf("duplicate entry %+v", e)
		}
		seen[k] = struct{}{}
	}
	validateDataset(t, netdevcontract.Observation{MACTable: netdevcontract.AvailableDataset(got)})
}

// validateDataset completes o with valid CBS observation metadata and
// fails the test when netdevcontract.ValidateObservation refuses it.
func validateDataset(t *testing.T, o netdevcontract.Observation) {
	t.Helper()
	o.DeviceID = "sw-test"
	o.Family = netdevcontract.FamilyCBS
	o.TrustGeneration = 1
	o.ObservedAt = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	if _, err := netdevcontract.ValidateObservation(o); err != nil {
		t.Fatalf("result refused by the contract: %v", err)
	}
}

func FuzzParseMACTable(f *testing.F) {
	f.Add([]byte{})
	f.Add(syntheticFixture(f, "mac_table_cbs350.txt"))
	f.Add(syntheticFixture(f, "mac_table_cbs250.txt"))
	f.Add(macTable([]string{"1", "00:00:5E:00:53:0G", "gi1", "dynamic"}, []string{"", docMAC(1), "CPU", "self"}))
	f.Add(macTable([]string{"4094", docMAC(2), "Po8", "STATIC"}, []string{"4094", docMAC(2), "Po8", "static"}))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, incomplete, err := ParseMACTable(in)
		if err != nil {
			if got != nil || incomplete {
				t.Fatalf("error %v with result %+v incomplete %v", err, got, incomplete)
			}
			return
		}
		checkMACInvariants(t, got)
	})
}

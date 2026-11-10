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

type lldpN = netdevcontract.LLDPNeighbor

type capList = []netdevcontract.LLDPCapability

var lldpWidths = []int{9, 17, 17, 40, 24, 5}

// lldpSummary builds a synthetic "show lldp neighbors" output from rows of
// six cells (port, device ID, port ID, system name, capabilities, TTL).
func lldpSummary(rows ...[]string) []byte {
	var b strings.Builder
	b.WriteString(fixedRow(lldpWidths, "Port", "Device ID", "Port ID", "System Name", "Capabilities", "TTL"))
	b.WriteString(dashRule(lldpWidths))
	for _, r := range rows {
		b.WriteString(fixedRow(lldpWidths, r...))
	}
	return []byte(b.String())
}

// lldpBlockText builds one neighbor of the detail form.
func lldpBlockText(chassis, portID, name, caps, addr string) string {
	return "Device ID: " + chassis + "\nPort ID: " + portID + "\nCapabilities: " + caps +
		"\nSystem Name: " + name + "\nSystem description: synthetic\nManagement address: " + addr +
		"\nTime To Live: 120\n\n"
}

func TestParseLLDPNeighborsFixtures(t *testing.T) {
	B, R, S, T, W := netdevcontract.CapBridge, netdevcontract.CapRouter, netdevcontract.CapStationOnly,
		netdevcontract.CapTelephone, netdevcontract.CapWLANAP
	tests := []struct {
		fixture string
		want    []lldpN
	}{
		{"lldp_neighbors_cbs350.txt", []lldpN{
			{LocalPort: "gi1/0/1", ChassisID: "00:00:5e:00:53:a1", PortID: "eth0", SystemName: "pve-node-a", Capabilities: capList{S}},
			{LocalPort: "gi1/0/2", ChassisID: "00:00:5e:00:53:a2", PortID: "eno1", SystemName: "pve-node-b", Capabilities: capList{B, S}},
			{LocalPort: "te1/0/1", ChassisID: "00:00:5e:00:53:b1", PortID: "gi1/0/24", SystemName: "core-sw-1", Capabilities: capList{B, R}},
			{LocalPort: "te1/0/1", ChassisID: "00:00:5e:00:53:b2", PortID: "gi1/0/23", SystemName: "core-sw-2", Capabilities: capList{B}},
			{LocalPort: "gi1/0/9", ChassisID: "00:00:5e:00:53:c1", PortID: "00:00:5e:00:53:c1", Capabilities: capList{T}},
		}},
		{"lldp_neighbors_cbs250.txt", []lldpN{
			{LocalPort: "gi8", ChassisID: "00:00:5e:00:53:b1", PortID: "gi1/0/8", SystemName: "core-sw-1", Capabilities: capList{B, R}},
			{LocalPort: "gi3", ChassisID: "00:00:5e:00:53:d1", PortID: "wlan0", SystemName: "ap-hall", Capabilities: capList{W, B}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighbors(syntheticFixture(t, tt.fixture))
			if err != nil || incomplete {
				t.Fatalf("err %v incomplete %v", err, incomplete)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v\nwant %+v", got, tt.want)
			}
			checkLLDPInvariants(t, got)
		})
	}
}

func TestParseLLDPNeighborDetailFixture(t *testing.T) {
	got, incomplete, err := ParseLLDPNeighborDetail("te1/0/1", syntheticFixture(t, "lldp_detail_cbs350.txt"))
	if err != nil || incomplete {
		t.Fatalf("err %v incomplete %v", err, incomplete)
	}
	want := []lldpN{
		{LocalPort: "te1/0/1", ChassisID: "00:00:5e:00:53:b1", PortID: "gi1/0/24", SystemName: "core-sw-1",
			ManagementAddress: "192.0.2.11", Capabilities: capList{netdevcontract.CapBridge, netdevcontract.CapRouter}},
		{LocalPort: "te1/0/1", ChassisID: "00:00:5e:00:53:b2", PortID: "gi1/0/23", SystemName: "core-sw-2",
			ManagementAddress: "2001:db8::b2", Capabilities: capList{netdevcontract.CapBridge}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	checkLLDPInvariants(t, got)
}

// hostileRefused are system names whose runes refuse the whole output:
// terminal escapes, bidi overrides, zero-width and separator runes.
var hostileRefused = map[string]string{
	"ansi escape":    "evil\x1b[2J\x1b]0;owned\x07",
	"bell":           "evil\x07",
	"bidi override":  "evil" + string(rune(0x202E)) + "gnp.exe",
	"bidi isolate":   "evil" + string(rune(0x2066)) + "x" + string(rune(0x2069)),
	"zero width":     "ev" + string(rune(0x200B)) + "il",
	"line separator": "evil" + string(rune(0x2028)) + "System Name: good",
	"nul":            "evil\x00",
	"del":            "evil\x7f",
}

// hostileDropped are system names that drop only their neighbor.
var hostileDropped = map[string]string{
	"replacement rune": "evil�",
	"too long":         strings.Repeat("a", netdevcontract.MaxLabelBytes+1),
	"tab":              "evil\tname",
}

// hostileKept are printable names that are kept verbatim: they are text,
// and rendering escapes them.
var hostileKept = []string{
	"<script>alert(1)</script>",
	"'; DROP TABLE devices; --",
	"{{.Secret}} ${jndi:ldap://x}",
	"../../etc/passwd",
	"ünïcødé-スイッチ",
	strings.Repeat("a", netdevcontract.MaxLabelBytes),
}

func TestParseLLDPNeighborDetailHostileSystemNames(t *testing.T) {
	good := lldpBlockText("00:00:5e:00:53:01", "eth0", "good", "Bridge", "192.0.2.1")
	for name, sys := range hostileRefused {
		t.Run("refused/"+name, func(t *testing.T) {
			in := good + lldpBlockText("00:00:5e:00:53:02", "eth1", sys, "Bridge", "192.0.2.2")
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(in))
			if err == nil || got != nil || incomplete {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
	for name, sys := range hostileDropped {
		t.Run("dropped/"+name, func(t *testing.T) {
			in := good + lldpBlockText("00:00:5e:00:53:02", "eth1", sys, "Bridge", "192.0.2.2")
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(in))
			if err != nil || !incomplete || len(got) != 1 || got[0].SystemName != "good" {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
	for _, sys := range hostileKept {
		t.Run("kept/"+sys[:min(len(sys), 16)], func(t *testing.T) {
			in := good + lldpBlockText("00:00:5e:00:53:02", "eth1", sys, "Bridge", "192.0.2.2")
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(in))
			if err != nil || incomplete || len(got) != 2 || got[1].SystemName != sys {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
			checkLLDPInvariants(t, got)
		})
	}
	// Hostile chassis and port IDs follow the same rule.
	for _, field := range []string{"chassis", "port"} {
		t.Run("dropped/"+field, func(t *testing.T) {
			chassis, port := "00:00:5e:00:53:02", "eth1"
			if field == "chassis" {
				chassis = "x�"
			} else {
				port = strings.Repeat("p", netdevcontract.MaxLabelBytes+1)
			}
			in := good + lldpBlockText(chassis, port, "n", "Bridge", "192.0.2.2")
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(in))
			if err != nil || !incomplete || len(got) != 1 {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
}

func TestParseLLDPNeighborsHostileSystemNames(t *testing.T) {
	good := []string{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "good", "B", "120"}
	row := func(sys string) []string {
		return []string{"gi1/0/2", "00:00:5e:00:53:02", "eth1", sys, "B", "120"}
	}
	for name, sys := range hostileRefused {
		t.Run("refused/"+name, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighbors(lldpSummary(good, row(sys)))
			if err == nil || got != nil || incomplete {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
	for name, sys := range map[string]string{
		"replacement rune": "evil�",
		"tab":              "evil\tname",
		"crosses gap":      strings.Repeat("x", lldpWidths[3]+2),
		"spills into caps": "evil" + strings.Repeat(" ", lldpWidths[3]-3) + "X",
	} {
		t.Run("dropped/"+name, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighbors(lldpSummary(good, row(sys)))
			if err != nil || !incomplete || len(got) != 1 || got[0].SystemName != "good" {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
	for _, sys := range []string{"<script>alert(1)</script>", "'; DROP TABLE x; --", "ünïcødé-スイッチ"} {
		t.Run("kept/"+sys, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighbors(lldpSummary(good, row(sys)))
			if err != nil || incomplete || len(got) != 2 || got[1].SystemName != sys {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
}

func TestParseLLDPNeighborsDropsMalformedRows(t *testing.T) {
	keep := []string{"gi1/0/7", "00:00:5e:00:53:07", "eth7", "keep", "B", "120"}
	tests := []struct {
		name string
		rows [][]string
	}{
		{"unknown local port", [][]string{{"eth0", "00:00:5e:00:53:01", "eth0", "n", "B", "120"}}},
		{"missing chassis", [][]string{{"gi1/0/1", "", "eth0", "n", "B", "120"}}},
		{"missing port id", [][]string{{"gi1/0/1", "00:00:5e:00:53:01", "", "n", "B", "120"}}},
		{"unknown capability", [][]string{{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "n", "X", "120"}}},
		{"repeated capability", [][]string{{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "n", "B, B", "120"}}},
		{"capability word", [][]string{{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "n", "Bridge", "120"}}},
		{"empty capability", [][]string{{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "n", "B,", "120"}}},
		// A system name wrapped onto a second line: the first line cannot
		// be trusted and the continuation has no port.
		{"wrapped name", [][]string{
			{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "a-long-name-that", "B", "120"},
			{"", "", "", "-wraps", "", ""},
		}},
		// Directly below the dash line: there is no row it can continue.
		{"orphan continuation", [][]string{{"", "", "", "-wraps", "", ""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := append(tt.rows, keep)
			got, incomplete, err := ParseLLDPNeighbors(lldpSummary(rows...))
			if err != nil {
				t.Fatal(err)
			}
			if !incomplete || len(got) != 1 || got[0].SystemName != "keep" {
				t.Fatalf("got %+v incomplete %v", got, incomplete)
			}
		})
	}
}

func TestParseLLDPNeighborsCapabilityLetters(t *testing.T) {
	got, incomplete, err := ParseLLDPNeighbors(lldpSummary(
		[]string{"gi1/0/1", "c1", "p1", "", "O, r, B, W, R, T, C, S", "120"},
		[]string{"gi1/0/2", "c2", "p2", "", "", "120"},
	))
	if err != nil || incomplete || len(got) != 2 {
		t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
	}
	want := capList{netdevcontract.CapOther, netdevcontract.CapRepeater, netdevcontract.CapBridge,
		netdevcontract.CapWLANAP, netdevcontract.CapRouter, netdevcontract.CapTelephone,
		netdevcontract.CapDOCSIS, netdevcontract.CapStationOnly}
	if !reflect.DeepEqual(got[0].Capabilities, want) || got[1].Capabilities != nil {
		t.Fatalf("capabilities %v / %v", got[0].Capabilities, got[1].Capabilities)
	}
}

func TestParseLLDPNeighborsDuplicatesDropEveryCopy(t *testing.T) {
	a := []string{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "a", "B", "120"}
	aOtherName := []string{"gi1/0/1", "00:00:5e:00:53:01", "eth0", "spoof", "R", "120"}
	samePeerOtherPort := []string{"gi1/0/2", "00:00:5e:00:53:01", "eth0", "a", "B", "120"}
	got, incomplete, err := ParseLLDPNeighbors(lldpSummary(a, aOtherName, samePeerOtherPort, a))
	if err != nil {
		t.Fatal(err)
	}
	if !incomplete || len(got) != 1 || got[0].LocalPort != "gi1/0/2" {
		t.Fatalf("got %+v incomplete %v", got, incomplete)
	}
}

func lldpRows(ports, perPort int) [][]string {
	var rows [][]string
	for p := 1; p <= ports; p++ {
		for n := range perPort {
			rows = append(rows, []string{fmt.Sprintf("gi1/0/%d", p), docMAC(n), fmt.Sprintf("eth%d", p), "", "B", "120"})
		}
	}
	return rows
}

func TestParseLLDPNeighborsLimits(t *testing.T) {
	perPort, perDevice := netdevcontract.MaxLLDPNeighborsPerPort, netdevcontract.MaxLLDPNeighborsPerDevice
	tests := []struct {
		name           string
		ports, perPort int
		want           int
		incomplete     bool
	}{
		{"per port at limit", 1, perPort, perPort, false},
		{"per port over limit", 1, perPort + 1, perPort, true},
		{"per port flood", 2, 300, 2 * perPort, true},
		{"per device at limit", perDevice / perPort, perPort, perDevice, false},
		{"per device over limit", perDevice/perPort + 1, perPort, perDevice, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighbors(lldpSummary(lldpRows(tt.ports, tt.perPort)...))
			if err != nil || len(got) != tt.want || incomplete != tt.incomplete {
				t.Fatalf("got %d neighbors incomplete %v err %v", len(got), incomplete, err)
			}
			checkLLDPInvariants(t, got)
		})
	}
	flood := append(lldpSummary(), strings.Repeat(" \n", lldpMaxLines)...)
	if _, _, err := ParseLLDPNeighbors(flood); !errors.Is(err, netdevcontract.ErrOverLimit) {
		t.Fatalf("line flood: err %v", err)
	}
}

func TestParseLLDPNeighborDetailPerPortLimit(t *testing.T) {
	// lldpBlockText is 8 lines, so the last size fills lldpDetailMaxLines.
	for _, n := range []int{netdevcontract.MaxLLDPNeighborsPerPort, netdevcontract.MaxLLDPNeighborsPerPort + 1,
		lldpDetailMaxBlocks, lldpDetailMaxBlocks + 1, lldpDetailMaxLines / 8} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var b strings.Builder
			for i := range n {
				b.WriteString(lldpBlockText(fmt.Sprintf("chassis-%d", i), "eth0", "n", "Bridge", "192.0.2.1"))
			}
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(b.String()))
			want := min(n, netdevcontract.MaxLLDPNeighborsPerPort)
			if err != nil || len(got) != want || incomplete != (n > want) {
				t.Fatalf("got %d neighbors incomplete %v err %v", len(got), incomplete, err)
			}
			checkLLDPInvariants(t, got)
		})
	}
}

func TestParseLLDPNeighborDetailFloodIsBounded(t *testing.T) {
	t.Run("1 MiB device id flood refused", func(t *testing.T) {
		var b strings.Builder
		for i := 0; b.Len() < netdevcontract.MaxCBSCommandOutputBytes-32; i++ {
			fmt.Fprintf(&b, "Device ID: %d\n", i)
		}
		in := []byte(b.String())
		var err error
		allocs := testing.AllocsPerRun(5, func() {
			_, _, err = ParseLLDPNeighborDetail("gi1/0/1", in)
		})
		if !errors.Is(err, netdevcontract.ErrOverLimit) {
			t.Fatalf("err %v", err)
		}
		// Refused before the output is split: no per-line allocation.
		if allocs > 16 {
			t.Fatalf("%v allocations for a refused flood", allocs)
		}
	})
	t.Run("device id flood at the line limit", func(t *testing.T) {
		var b strings.Builder
		for i := range lldpDetailMaxLines {
			fmt.Fprintf(&b, "Device ID: %d\n", i)
		}
		in := []byte(b.String())
		var got []lldpN
		var incomplete bool
		var err error
		allocs := testing.AllocsPerRun(3, func() {
			got, incomplete, err = ParseLLDPNeighborDetail("gi1/0/1", in)
		})
		// Every block lacks a port ID; none is kept.
		if err != nil || !incomplete || len(got) != 0 {
			t.Fatalf("got %d incomplete %v err %v", len(got), incomplete, err)
		}
		// A few allocations per line for the key, plus at most
		// lldpDetailMaxBlocks blocks.
		if limit := 4*lldpDetailMaxLines + 4*lldpDetailMaxBlocks; allocs > float64(limit) {
			t.Fatalf("%v allocations, limit %d", allocs, limit)
		}
	})
	t.Run("one line over the limit refused", func(t *testing.T) {
		in := strings.Repeat("Device ID: c\n", lldpDetailMaxLines+1)
		if _, _, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(in)); !errors.Is(err, netdevcontract.ErrOverLimit) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("lines after the block cap reach no block", func(t *testing.T) {
		var b strings.Builder
		for i := range lldpDetailMaxBlocks - 1 {
			fmt.Fprintf(&b, "Device ID: dropped-%d\n\n", i) // no port ID
		}
		b.WriteString("Device ID: last\nPort ID: p\n\n")
		// Beyond the cap: its Port ID must not count as a repeat for "last".
		b.WriteString("Device ID: extra\nPort ID: q\nSystem Name: forged\n")
		got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(b.String()))
		want := []lldpN{{LocalPort: "gi1/0/1", ChassisID: "last", PortID: "p"}}
		if err != nil || !incomplete || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
		}
	})
}

func TestParseLLDPNeighborDetailManagementAddress(t *testing.T) {
	tests := []struct {
		addr, want string
		dropped    bool
	}{
		{"192.0.2.10", "192.0.2.10", false},
		{"2001:DB8::0:1", "2001:db8::1", false},
		{"192.0.2.300", "", true},
		{"192.0.2.010", "", true},
		{"192.0.2.0/24", "", true},
		{"fe80::1%eth0", "", true},
		{"host.example", "", true},
		{"192.0.2.10 192.0.2.11", "", true},
		{"0xc0.0.2.1", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			in := lldpBlockText("00:00:5e:00:53:01", "eth0", "n", "Bridge", tt.addr)
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(in))
			if err != nil || len(got) != 1 || incomplete != tt.dropped || got[0].ManagementAddress != tt.want {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
			checkLLDPInvariants(t, got)
		})
	}
	// A repeated "Management address" keeps no address: one of the lines
	// may be forged by a wrapped description, and which one cannot be
	// told. The neighbor is kept without an address and incomplete is set.
	for name, block := range map[string]string{
		"forged before real": "Device ID: c1\nPort ID: p\nSystem description: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
			"Management address: 198.51.100.66\nManagement address: 192.0.2.1\n",
		"forged after real": "Device ID: c1\nPort ID: p\nManagement address: 192.0.2.1\nSystem description: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
			"Management address: 198.51.100.66\n",
		"invalid then valid": "Device ID: c1\nPort ID: p\nManagement address: bogus\nManagement address: 192.0.2.1\n",
		"same twice":         "Device ID: c1\nPort ID: p\nManagement address: 192.0.2.1\nManagement address: 192.0.2.1\n",
		"three lines":        "Device ID: c1\nPort ID: p\nManagement address: 192.0.2.1\nManagement address: 192.0.2.2\nManagement address: 192.0.2.3\n",
	} {
		t.Run("repeated/"+name, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(block))
			want := []lldpN{{LocalPort: "gi1/0/1", ChassisID: "c1", PortID: "p"}}
			if err != nil || !incomplete || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
}

func TestParseLLDPNeighborDetailDropsMalformedNeighbors(t *testing.T) {
	good := lldpBlockText("00:00:5e:00:53:01", "eth0", "good", "Bridge", "192.0.2.1")
	tests := []struct {
		name  string
		block string
	}{
		{"missing port id", "Device ID: c2\nSystem Name: n\n\n"},
		{"empty chassis", "Device ID:\nPort ID: p\n\n"},
		{"repeated system name", "Device ID: c2\nPort ID: p\nSystem Name: a\nSystem Name: b\n\n"},
		{"repeated port id", "Device ID: c2\nPort ID: p\nPort ID: q\n\n"},
		{"unknown capability", "Device ID: c2\nPort ID: p\nCapabilities: Toaster\n\n"},
		{"repeated capability", "Device ID: c2\nPort ID: p\nCapabilities: Bridge, bridge\n\n"},
		{"local port mismatch", "Device ID: c2\nPort ID: p\nLocal port: gi1/0/2\n\n"},
		{"wrapped system name", "Device ID: c2\nPort ID: p\nSystem Name: a-long-name-that\n-wraps here\n\n"},
		{"wrapped port id", "Device ID: c2\nPort ID: p\n  rest of the port id\n\n"},
		// A wrapped rest with a colon after a letter-led prefix looks like
		// an unknown key; directly after a kept value it is still a wrap.
		{"wrapped system name with colon", "Device ID: c2\nPort ID: p\nSystem Name: a-long-name-that\nwraps here: x\n\n"},
		{"wrapped port id with colon", "Device ID: c2\nPort ID: p-long\nwraps here: x\nSystem Name: n\n\n"},
		{"wrapped chassis id with colon", "Device ID: c2-long\nwraps here: x\nPort ID: p\n\n"},
		{"wrapped capabilities with colon", "Device ID: c2\nPort ID: p\nCapabilities: Bridge\nRouter: x\n\n"},
		{"wrapped system name, then colon line", "Device ID: c2\nPort ID: p\nSystem Name: a\n-wraps\nmore: x\n\n"},
		// A description wrapped so that a line starts with a kept key: the
		// repeat drops the neighbor rather than taking the forged value.
		{"forged key in description", "Device ID: c2\nPort ID: p\nSystem Name: real\nSystem description: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nSystem Name: forged\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(good+tt.block))
			if err != nil || !incomplete || len(got) != 1 || got[0].SystemName != "good" {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
	t.Run("kept key before first neighbor", func(t *testing.T) {
		got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte("System Name: stray\n\n"+good))
		if err != nil || !incomplete || len(got) != 1 {
			t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
		}
	})
	t.Run("ignored keys and wrapped description", func(t *testing.T) {
		in := "Port gi1/0/1 neighbors:\n\nDevice ID: c2\nPort ID: p\nLocal port: gi1/0/1\nSystem description: a\n wrapped: text\n more\nPort VLAN ID: 1\n"
		got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(in))
		want := []lldpN{{LocalPort: "gi1/0/1", ChassisID: "c2", PortID: "p"}}
		if err != nil || incomplete || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
		}
	})
	t.Run("duplicate neighbor", func(t *testing.T) {
		got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", []byte(good+good))
		if err != nil || !incomplete || len(got) != 0 {
			t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
		}
	})
}

func TestParseLLDPNeighborDetailRefusesOutput(t *testing.T) {
	good := []byte(lldpBlockText("c1", "p1", "n", "Bridge", "192.0.2.1"))
	tests := []struct {
		name string
		port string
		in   []byte
		want error
	}{
		{"empty", "gi1/0/1", nil, ErrNoLLDPDetail},
		{"no neighbor", "gi1/0/1", []byte("% No LLDP neighbors\n"), ErrNoLLDPDetail},
		{"bad local port", "eth0", good, nil},
		{"local port with escape", "gi1/0/1\x1b", good, nil},
		{"invalid utf-8", "gi1/0/1", append(good, 0xff), nil},
		{"over byte cap", "gi1/0/1", []byte(strings.Repeat("a\n", netdevcontract.MaxCBSCommandOutputBytes/2+1)), netdevcontract.ErrOverLimit},
		{"over line length", "gi1/0/1", []byte("Device ID: " + strings.Repeat("a", netdevcontract.MaxLineBytes)), netdevcontract.ErrOverLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighborDetail(tt.port, tt.in)
			if err == nil || got != nil || incomplete {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseLLDPNeighborsRefusesOutput(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":          nil,
		"no table":       []byte("LLDP is disabled\n"),
		"missing column": []byte("Port    Device ID\n------- -----------------\ngi1     c1\n"),
	} {
		t.Run(name, func(t *testing.T) {
			got, incomplete, err := ParseLLDPNeighbors(in)
			if !errors.Is(err, ErrNoTable) && !errors.Is(err, ErrUnrecognizedTable) || got != nil || incomplete {
				t.Fatalf("got %+v incomplete %v err %v", got, incomplete, err)
			}
		})
	}
	got, incomplete, err := ParseLLDPNeighbors(lldpSummary())
	if err != nil || incomplete || got == nil || len(got) != 0 {
		t.Fatalf("empty table: got %#v incomplete %v err %v", got, incomplete, err)
	}
}

func TestCapLLDPNeighborsMergesDetails(t *testing.T) {
	var merged []lldpN
	for p := 1; p <= 70; p++ {
		var b strings.Builder
		for i := range netdevcontract.MaxLLDPNeighborsPerPort {
			b.WriteString(lldpBlockText(fmt.Sprintf("c%d", i), "eth0", "", "", "192.0.2.1"))
		}
		got, incomplete, err := ParseLLDPNeighborDetail(fmt.Sprintf("gi1/0/%d", p), []byte(b.String()))
		if err != nil || incomplete {
			t.Fatalf("port %d: incomplete %v err %v", p, incomplete, err)
		}
		merged = append(merged, got...)
	}
	capped, dropped := CapLLDPNeighbors(merged)
	if !dropped || len(capped) != netdevcontract.MaxLLDPNeighborsPerDevice {
		t.Fatalf("merged %d -> %d dropped %v", len(merged), len(capped), dropped)
	}
	checkLLDPInvariants(t, capped)
	if got, dropped := CapLLDPNeighbors(nil); got == nil || len(got) != 0 || dropped {
		t.Fatalf("nil input: %#v %v", got, dropped)
	}
}

// checkLLDPInvariants checks what the LLDP parsers promise for a result
// and that it passes the netdevcontract observation validation.
func checkLLDPInvariants(t *testing.T, got []netdevcontract.LLDPNeighbor) {
	t.Helper()
	if len(got) > netdevcontract.MaxLLDPNeighborsPerDevice {
		t.Fatalf("%d neighbors over the device limit", len(got))
	}
	perPort := map[string]int{}
	seen := map[lldpKey]struct{}{}
	for _, n := range got {
		if !validLLDPStrings(n) {
			t.Fatalf("invalid neighbor %+v", n)
		}
		perPort[n.LocalPort]++
		if perPort[n.LocalPort] > netdevcontract.MaxLLDPNeighborsPerPort {
			t.Fatalf("over the per-port limit on %s", n.LocalPort)
		}
		k := lldpKey{n.LocalPort, n.ChassisID, n.PortID}
		if _, dup := seen[k]; dup {
			t.Fatalf("duplicate neighbor %+v", n)
		}
		seen[k] = struct{}{}
	}
	validateDataset(t, netdevcontract.Observation{LLDPNeighbors: netdevcontract.AvailableDataset(got)})
}

func FuzzParseLLDPNeighbors(f *testing.F) {
	f.Add([]byte{})
	f.Add(syntheticFixture(f, "lldp_neighbors_cbs350.txt"))
	f.Add(syntheticFixture(f, "lldp_neighbors_cbs250.txt"))
	f.Add(lldpSummary([]string{"gi1", "c", "p", "n�", "B, B", "1"}, []string{"", "", "", "x", "", ""}))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, incomplete, err := ParseLLDPNeighbors(in)
		if err != nil {
			if got != nil || incomplete {
				t.Fatalf("error %v with result %+v incomplete %v", err, got, incomplete)
			}
			return
		}
		checkLLDPInvariants(t, got)
	})
}

func FuzzParseLLDPNeighborDetail(f *testing.F) {
	f.Add([]byte{})
	f.Add(syntheticFixture(f, "lldp_detail_cbs350.txt"))
	f.Add([]byte("Device ID: c\nPort ID: p\nManagement address: fe80::1%x\nCapabilities: Station Only, Other\nLocal port: gi1/0/1\n"))
	f.Add([]byte("System Name: x\nDevice ID: c\nPort ID: p\nSystem Name: a\n b\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, incomplete, err := ParseLLDPNeighborDetail("gi1/0/1", in)
		if err != nil {
			if got != nil || incomplete {
				t.Fatalf("error %v with result %+v incomplete %v", err, got, incomplete)
			}
			return
		}
		for _, n := range got {
			if n.LocalPort != "gi1/0/1" {
				t.Fatalf("local port %q taken from device text", n.LocalPort)
			}
		}
		checkLLDPInvariants(t, got)
	})
}

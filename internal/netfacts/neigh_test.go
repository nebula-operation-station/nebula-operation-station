// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestParseNeighDebian12(t *testing.T) {
	res, err := ParseNeigh(readFixture(t, "debian12-neigh.json"))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	got := res.Entries
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Neighbor{
		{
			IP:    netip.MustParseAddr("192.168.178.1"),
			Dev:   "eth0",
			MAC:   net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56},
			State: []string{"REACHABLE"},
		},
		{
			IP:    netip.MustParseAddr("192.168.178.10"),
			Dev:   "eth0",
			MAC:   net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc},
			State: []string{"STALE"},
		},
		{
			IP:    netip.MustParseAddr("192.168.178.20"),
			Dev:   "eth0",
			State: []string{"FAILED"},
		},
		{
			IP:    netip.MustParseAddr("fe80::1"),
			Dev:   "eth0",
			MAC:   net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56},
			State: []string{"STALE"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseNeighUbuntu2404(t *testing.T) {
	res, err := ParseNeigh(readFixture(t, "ubuntu2404-neigh.json"))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	got := res.Entries
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Neighbor{
		{
			IP:    netip.MustParseAddr("10.0.0.1"),
			Dev:   "ens18",
			MAC:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			State: []string{"PERMANENT"},
		},
		{
			IP:    netip.MustParseAddr("10.0.0.7"),
			Dev:   "ens18",
			State: []string{"INCOMPLETE"},
		},
		{
			IP:    netip.MustParseAddr("10.0.0.9"),
			Dev:   "ens18",
			MAC:   net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
			State: []string{"DELAY"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseNeighEmptyArray(t *testing.T) {
	res, err := ParseNeigh(readFixture(t, "empty-neigh.json"))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	got := res.Entries
	if len(got) != 0 {
		t.Fatalf("got %d neighbors, want 0", len(got))
	}
}

func TestParseNeighSkipsEntriesWithoutValidIP(t *testing.T) {
	doc := `[
		{"dst":"10.0.0.1","dev":"eth0","state":["REACHABLE"]},
		{"dst":"not-an-ip","dev":"eth0","state":["REACHABLE"]},
		{"dev":"eth0","state":["REACHABLE"]},
		{"dst":42,"dev":"eth0","state":["REACHABLE"]},
		{"dst":"10.0.0.2","dev":"eth0","state":["STALE"]}
	]`
	res, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	got := res.Entries
	if len(got) != 2 {
		t.Fatalf("got %d neighbors, want 2: %+v", len(got), got)
	}
	if got[0].IP != (netip.MustParseAddr("10.0.0.1")) || got[1].IP != (netip.MustParseAddr("10.0.0.2")) {
		t.Fatalf("got IPs %v %v, want 10.0.0.1 10.0.0.2", got[0].IP, got[1].IP)
	}
	if !res.Incomplete || res.Dropped != 3 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 3", res.Incomplete, res.Dropped)
	}
}

func TestParseNeighDropsInvalidStrings(t *testing.T) {
	longDev := strings.Repeat("x", maxIfNameLen+1)
	doc := `[
		{"dst":"10.0.0.1","dev":"eth0","lladdr":"not-a-mac","state":["REACHABLE","bad\u0001state",""]},
		{"dst":"10.0.0.2","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff:00:11","state":["STALE"]},
		{"dst":"10.0.0.3","dev":"bad\u0001dev","lladdr":"aa:bb:cc:dd:ee:ff","state":["STALE"]},
		{"dst":"10.0.0.4","dev":"` + longDev + `","state":["STALE"]}
	]`
	res, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	got := res.Entries
	if len(got) != 2 {
		t.Fatalf("got %d neighbors, want 2: %+v", len(got), got)
	}
	if len(got[0].MAC) != 0 {
		t.Fatalf("invalid lladdr not dropped: %v", got[0].MAC)
	}
	if !reflect.DeepEqual(got[0].State, []string{"REACHABLE"}) {
		t.Fatalf("invalid states not dropped: %v", got[0].State)
	}
	if len(got[1].MAC) != 0 {
		t.Fatalf("8-byte lladdr not dropped: %v", got[1].MAC)
	}
	if !res.Incomplete || res.Dropped != 2 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 2", res.Incomplete, res.Dropped)
	}
}

func TestParseNeighTruncatesStateList(t *testing.T) {
	names := []string{"INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT", "NONE"}
	states := make([]string, 0, maxStates+4)
	for i := 0; i < maxStates+4; i++ {
		states = append(states, `"`+names[i%len(names)]+`"`)
	}
	doc := `[{"dst":"10.0.0.1","dev":"eth0","state":[` + strings.Join(states, ",") + `]}]`
	res, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	got := res.Entries
	if len(got) != 1 {
		t.Fatalf("got %d neighbors, want 1", len(got))
	}
	if len(got[0].State) != maxStates {
		t.Fatalf("got %d states, want %d", len(got[0].State), maxStates)
	}
	if got[0].State[0] != names[0] || got[0].State[maxStates-1] != names[maxStates-1] {
		t.Fatalf("state list truncated wrongly: %v", got[0].State)
	}
	if !res.Incomplete || res.Dropped != 0 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 0 (truncation is a loss)", res.Incomplete, res.Dropped)
	}
}

func TestParseNeighRejectsOversizeInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	copy(big, `[{"dst":"10.0.0.1","dev":"eth0"}]`)
	if _, err := ParseNeigh(big); err == nil {
		t.Fatal("expected error for input above the size limit")
	}
}

func TestParseNeighAcceptsMaxSizeInput(t *testing.T) {
	const head = `[{"dst":"10.0.0.1","dev":"eth0","pad":"`
	const tail = `"}`
	// The document must be exactly maxInputSize bytes; the pad is an
	// unknown field that the parser drops.
	doc := head + strings.Repeat("a", maxInputSize-len(head)-len(tail)-1) + tail + "]"
	if len(doc) != maxInputSize {
		t.Fatalf("test document is %d bytes, want %d", len(doc), maxInputSize)
	}
	res, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	got := res.Entries
	if len(got) != 1 || got[0].IP != (netip.MustParseAddr("10.0.0.1")) || got[0].Dev != "eth0" {
		t.Fatalf("got %+v, want one neighbor 10.0.0.1 on eth0", got)
	}
}

func TestParseNeighRejectsNonArray(t *testing.T) {
	for name, doc := range map[string]string{
		"malformed": `{"dst":`,
		"object":    `{"dst":"10.0.0.1"}`,
		"null":      `null`,
		"string":    `"hello"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNeigh([]byte(doc)); err == nil {
				t.Fatal("expected error for non-array input")
			}
		})
	}
	t.Run("raw control byte", func(t *testing.T) {
		doc := `[{"dst":"10.0.0.1","dev":"eth` + "\x01" + `0"}]`
		if _, err := ParseNeigh([]byte(doc)); err == nil {
			t.Fatal("expected error for raw control byte in JSON text")
		}
	})
}

func TestParseNeighRejectsHostileZone(t *testing.T) {
	for name, zone := range hostileZones() {
		t.Run(name, func(t *testing.T) {
			doc := `[{"dst":"fe80::1%` + zone + `","dev":"eth0"},{"dst":"10.0.0.1","dev":"eth0"}]`
			res, err := ParseNeigh([]byte(doc))
			if err != nil {
				t.Fatalf("ParseNeigh: %v", err)
			}
			want := []Neighbor{{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"}}
			if !reflect.DeepEqual(res.Entries, want) {
				t.Fatalf("got %+v, want only the good entry", res.Entries)
			}
			if !res.Incomplete || res.Dropped != 1 {
				t.Fatalf("Incomplete=%v Dropped=%d, want true 1", res.Incomplete, res.Dropped)
			}
		})
	}
}

func TestParseNeighAcceptsInterfaceZone(t *testing.T) {
	res, err := ParseNeigh([]byte(`[{"dst":"fe80::1%ens18","dev":"ens18"}]`))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	want := []Neighbor{{IP: netip.MustParseAddr("fe80::1%ens18"), Dev: "ens18"}}
	if !reflect.DeepEqual(res.Entries, want) || res.Incomplete {
		t.Fatalf("got %+v (Incomplete=%v), want %+v", res.Entries, res.Incomplete, want)
	}
}

func TestParseNeighDropsUnsafeUnicode(t *testing.T) {
	doc := `[
		{"dst":"10.0.0.1","dev":"eth\u00850"},
		{"dst":"10.0.0.2","dev":"eth\u202e0"},
		{"dst":"10.0.0.3","dev":"eth\u200b0"},
		{"dst":"10.0.0.4","dev":"eth0","state":["STALE\u2028x"]}
	]`
	res, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	want := []Neighbor{{IP: netip.MustParseAddr("10.0.0.4"), Dev: "eth0"}}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
	if !res.Incomplete || res.Dropped != 3 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 3", res.Incomplete, res.Dropped)
	}
}

func TestParseNeighRejectsTooManyEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"dst":"10.%d.%d.1","dev":"eth0","state":["REACHABLE"]}`, i/256, i%256)
	}
	b.WriteByte(']')
	if _, err := ParseNeigh([]byte(b.String())); err == nil {
		t.Fatalf("expected error for %d entries", maxEntries+1)
	}
}

func TestParseNeighDropsUnknownStates(t *testing.T) {
	doc := `[{"dst":"10.0.0.1","dev":"eth0","state":["REACHABLE","reachable","SPOOFED","` +
		strings.Repeat("A", 200) + `"]}]`
	res, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	if len(res.Entries) != 1 || !reflect.DeepEqual(res.Entries[0].State, []string{"REACHABLE"}) {
		t.Fatalf("got %+v, want only the known state REACHABLE", res.Entries)
	}
	if !res.Incomplete || res.Dropped != 0 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 0", res.Incomplete, res.Dropped)
	}
}

func TestParseNeighRejectsNonInterfaceDev(t *testing.T) {
	for name, dev := range map[string]string{
		"space":       "eth 0",
		"too long":    strings.Repeat("e", maxIfNameLen+1),
		"homoglyph":   "еth0",
		"private use": "eth0",
		"slash":       "eth/0",
	} {
		t.Run(name, func(t *testing.T) {
			doc := `[{"dst":"10.0.0.9","dev":"` + dev + `"},{"dst":"10.0.0.1","dev":"eth0"}]`
			res, err := ParseNeigh([]byte(doc))
			if err != nil {
				t.Fatalf("ParseNeigh: %v", err)
			}
			want := []Neighbor{{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"}}
			if !reflect.DeepEqual(res.Entries, want) || !res.Incomplete || res.Dropped != 1 {
				t.Fatalf("got %+v Incomplete=%v Dropped=%d, want only the good entry", res.Entries, res.Incomplete, res.Dropped)
			}
		})
	}
}

func TestParseNeighAcceptsInterfaceNames(t *testing.T) {
	for _, dev := range []string{"eth0", "ens18", "enp3s0f1", "br-1a2b3c4d5e6f", "wlan0.100", "veth_a-1"} {
		res, err := ParseNeigh([]byte(`[{"dst":"10.0.0.1","dev":"` + dev + `"}]`))
		if err != nil {
			t.Fatalf("ParseNeigh: %v", err)
		}
		if len(res.Entries) != 1 || res.Entries[0].Dev != dev || res.Incomplete {
			t.Fatalf("dev %q: got %+v (Incomplete=%v)", dev, res.Entries, res.Incomplete)
		}
	}
}

func TestParseNeighAcceptsMaxEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"dst":"10.%d.%d.1","dev":"eth0","state":["REACHABLE"]}`, i/256, i%256)
	}
	b.WriteByte(']')
	res, err := ParseNeigh([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	if len(res.Entries) != maxEntries || res.Incomplete {
		t.Fatalf("got %d entries (Incomplete=%v), want %d", len(res.Entries), res.Incomplete, maxEntries)
	}
}

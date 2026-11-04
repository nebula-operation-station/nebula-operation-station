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
	got, err := ParseNeigh(readFixture(t, "debian12-neigh.json"))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
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
	got, err := ParseNeigh(readFixture(t, "ubuntu2404-neigh.json"))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
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
			State: []string{"REACHABLE", "STALE"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseNeighEmptyArray(t *testing.T) {
	got, err := ParseNeigh(readFixture(t, "empty-neigh.json"))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d neighbors, want 0", len(got))
	}
}

func TestParseNeighSkipsEntriesWithoutValidIP(t *testing.T) {
	doc := `[
		{"ip":"10.0.0.1","dev":"eth0","state":["REACHABLE"]},
		{"ip":"not-an-ip","dev":"eth0","state":["REACHABLE"]},
		{"dev":"eth0","state":["REACHABLE"]},
		{"ip":42,"dev":"eth0","state":["REACHABLE"]},
		{"ip":"10.0.0.2","dev":"eth0","state":["STALE"]}
	]`
	got, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d neighbors, want 2: %+v", len(got), got)
	}
	if got[0].IP != (netip.MustParseAddr("10.0.0.1")) || got[1].IP != (netip.MustParseAddr("10.0.0.2")) {
		t.Fatalf("got IPs %v %v, want 10.0.0.1 10.0.0.2", got[0].IP, got[1].IP)
	}
}

func TestParseNeighDropsInvalidStrings(t *testing.T) {
	longDev := strings.Repeat("x", maxStringLen+1)
	doc := `[
		{"ip":"10.0.0.1","dev":"eth0","lladdr":"not-a-mac","state":["REACHABLE","bad\u0001state",""]},
		{"ip":"10.0.0.2","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff:00:11","state":["STALE"]},
		{"ip":"10.0.0.3","dev":"bad\u0001dev","lladdr":"aa:bb:cc:dd:ee:ff","state":["STALE"]},
		{"ip":"10.0.0.4","dev":"` + longDev + `","state":["STALE"]}
	]`
	got, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
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
}

func TestParseNeighTruncatesStateList(t *testing.T) {
	states := make([]string, 0, maxStates+4)
	for i := 0; i < maxStates+4; i++ {
		states = append(states, fmt.Sprintf(`"S%d"`, i))
	}
	doc := `[{"ip":"10.0.0.1","dev":"eth0","state":[` + strings.Join(states, ",") + `]}]`
	got, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d neighbors, want 1", len(got))
	}
	if len(got[0].State) != maxStates {
		t.Fatalf("got %d states, want %d", len(got[0].State), maxStates)
	}
	if got[0].State[0] != "S0" || got[0].State[maxStates-1] != fmt.Sprintf("S%d", maxStates-1) {
		t.Fatalf("state list truncated wrongly: %v", got[0].State)
	}
}

func TestParseNeighRejectsOversizeInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	copy(big, `[{"ip":"10.0.0.1","dev":"eth0"}]`)
	if _, err := ParseNeigh(big); err == nil {
		t.Fatal("expected error for input above the size limit")
	}
}

func TestParseNeighAcceptsMaxSizeInput(t *testing.T) {
	const head = `[{"ip":"10.0.0.1","dev":"eth0","pad":"`
	const tail = `"}`
	// The document must be exactly maxInputSize bytes; the pad is an
	// unknown field that the parser drops.
	doc := head + strings.Repeat("a", maxInputSize-len(head)-len(tail)-1) + tail + "]"
	if len(doc) != maxInputSize {
		t.Fatalf("test document is %d bytes, want %d", len(doc), maxInputSize)
	}
	got, err := ParseNeigh([]byte(doc))
	if err != nil {
		t.Fatalf("ParseNeigh: %v", err)
	}
	if len(got) != 1 || got[0].IP != (netip.MustParseAddr("10.0.0.1")) || got[0].Dev != "eth0" {
		t.Fatalf("got %+v, want one neighbor 10.0.0.1 on eth0", got)
	}
}

func TestParseNeighRejectsNonArray(t *testing.T) {
	for name, doc := range map[string]string{
		"malformed": `{"ip":`,
		"object":    `{"ip":"10.0.0.1"}`,
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
		doc := `[{"ip":"10.0.0.1","dev":"eth` + "\x01" + `0"}]`
		if _, err := ParseNeigh([]byte(doc)); err == nil {
			t.Fatal("expected error for raw control byte in JSON text")
		}
	})
}

func TestParseNeighRejectsTooManyEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ip":"10.%d.%d.1","dev":"eth0","state":["REACHABLE"]}`, i/256, i%256)
	}
	b.WriteByte(']')
	if _, err := ParseNeigh([]byte(b.String())); err == nil {
		t.Fatalf("expected error for %d entries", maxEntries+1)
	}
}

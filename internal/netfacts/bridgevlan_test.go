// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseBridgeVLANProxmox(t *testing.T) {
	res, err := ParseBridgeVLAN(readFixture(t, "proxmox-bridgevlan.json"))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := map[string][]BridgeVLAN{
		"eth0": {
			{ID: 1, PVID: true, Untagged: true},
			{ID: 100},
			{ID: 101},
		},
		"tap101": {
			{ID: 101, PVID: true, Untagged: true},
		},
	}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
}

func TestParseBridgeVLANFlatShapeMatchesListShape(t *testing.T) {
	list, err := ParseBridgeVLAN(readFixture(t, "proxmox-bridgevlan.json"))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN (list): %v", err)
	}
	flat, err := ParseBridgeVLAN(readFixture(t, "proxmox-bridgevlan-flat.json"))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN (flat): %v", err)
	}
	if !reflect.DeepEqual(list.Ports, flat.Ports) {
		t.Fatalf("list shape %+v != flat shape %+v", list.Ports, flat.Ports)
	}
	if flat.Incomplete || flat.Dropped != 0 {
		t.Fatalf("flat fixture marked Incomplete=%v Dropped=%d", flat.Incomplete, flat.Dropped)
	}
}

func TestParseBridgeVLANUbuntuVM(t *testing.T) {
	res, err := ParseBridgeVLAN(readFixture(t, "ubuntu-bridgevlan.json"))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if len(res.Ports) != 0 || res.Incomplete {
		t.Fatalf("got %+v (Incomplete=%v), want no ports", res.Ports, res.Incomplete)
	}
}

func TestParseBridgeVLANDockerHost(t *testing.T) {
	res, err := ParseBridgeVLAN(readFixture(t, "docker-bridgevlan.json"))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := map[string][]BridgeVLAN{
		"vethdeadbeef01": {{ID: 1, PVID: true, Untagged: true}},
		"vethcafe123456": {
			{ID: 1, PVID: true, Untagged: true},
			{ID: 200},
		},
	}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
}

func TestParseBridgeVLANMalformed(t *testing.T) {
	res, err := ParseBridgeVLAN(readFixture(t, "malformed-bridgevlan.json"))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if !res.Incomplete || res.Dropped != 3 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 3", res.Incomplete, res.Dropped)
	}
	want := map[string][]BridgeVLAN{
		"eth0": {
			{ID: 1, PVID: true, Untagged: true},
			{ID: 100},
		},
		"eth1": {{ID: 100}},
	}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
}

func TestParseBridgeVLANExpandsRange(t *testing.T) {
	doc := `[{"ifname":"eth0","vlans":[{"vlan":100,"vlanEnd":103,"flags":["Egress Untagged"]},{"vlan":1,"flags":["PVID","Egress Untagged"]}]}]`
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	want := map[string][]BridgeVLAN{
		"eth0": {
			{ID: 1, PVID: true, Untagged: true},
			{ID: 100, Untagged: true},
			{ID: 101, Untagged: true},
			{ID: 102, Untagged: true},
			{ID: 103, Untagged: true},
		},
	}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
	if res.Incomplete {
		t.Fatal("expected complete")
	}
}

func TestParseBridgeVLANMergesDuplicates(t *testing.T) {
	// The same VLAN id appears twice (a single and an overlapping range);
	// the flags are OR'd and the id is stored once.
	doc := `[{"ifname":"eth0","vlans":[{"vlan":10,"flags":["PVID"]},{"vlan":10,"vlanEnd":11,"flags":["Egress Untagged"]},{"vlan":11}]}]`
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	want := map[string][]BridgeVLAN{
		"eth0": {
			{ID: 10, PVID: true, Untagged: true},
			{ID: 11, Untagged: true},
		},
	}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
}

func TestParseBridgeVLANMergesAcrossElements(t *testing.T) {
	// The same port appears in two elements; its VLANs are unioned.
	doc := `[{"ifname":"eth0","vlans":[{"vlan":1}]},{"ifname":"eth0","vlans":[{"vlan":2,"flags":["PVID"]}]}]`
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	want := map[string][]BridgeVLAN{
		"eth0": {
			{ID: 1},
			{ID: 2, PVID: true},
		},
	}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
	if res.Incomplete {
		t.Fatal("expected complete")
	}
}

func TestParseBridgeVLANDropsOutOfRangeAndInverted(t *testing.T) {
	doc := `[{"ifname":"eth0","vlans":[{"vlan":4096},{"vlan":-1},{"vlan":100,"vlanEnd":50},{"vlan":200,"vlanEnd":4096},{"vlan":300}]}]`
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	// 4096, -1, the inverted 100..50, and the out-of-range end 4096 are
	// all dropped; only 300 survives.
	want := map[string][]BridgeVLAN{"eth0": {{ID: 300}}}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete for dropped vlans")
	}
}

func TestParseBridgeVLANTruncatesPortList(t *testing.T) {
	// Two full ranges report 8192 VLAN ids for one port; the total is
	// truncated at maxVLANsPerPort and the table is marked incomplete.
	doc := fmt.Sprintf(`[{"ifname":"eth0","vlans":[{"vlan":0,"vlanEnd":%d},{"vlan":0,"vlanEnd":%d}]}]`, maxVLANID, maxVLANID)
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if len(res.Ports["eth0"]) != maxVLANsPerPort {
		t.Fatalf("got %d vlans, want %d", len(res.Ports["eth0"]), maxVLANsPerPort)
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete for truncation")
	}
}

func TestParseBridgeVLANRejectsOversizeInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	copy(big, `[{"ifname":"eth0","vlans":[{"vlan":1}]}]`)
	if _, err := ParseBridgeVLAN(big); err == nil {
		t.Fatal("expected error for input above the size limit")
	}
}

func TestParseBridgeVLANRejectsNonArray(t *testing.T) {
	for name, doc := range map[string]string{
		"malformed": `{"ifname":`,
		"object":    `{"ifname":"eth0"}`,
		"null":      `null`,
		"string":    `"hello"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBridgeVLAN([]byte(doc)); err == nil {
				t.Fatal("expected error for non-array input")
			}
		})
	}
}

func TestParseBridgeVLANRejectsTooManyEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ifname":"eth%d","vlans":[{"vlan":1}]}`, i)
	}
	b.WriteByte(']')
	if _, err := ParseBridgeVLAN([]byte(b.String())); err == nil {
		t.Fatalf("expected error for %d entries", maxEntries+1)
	}
}

func TestParseBridgeVLANRejectsNonInterfaceName(t *testing.T) {
	for name, dev := range map[string]string{
		"space":    "eth 0",
		"too long": strings.Repeat("e", maxIfNameLen+1),
		"slash":    "eth/0",
	} {
		t.Run(name, func(t *testing.T) {
			doc := `[{"ifname":"` + dev + `","vlans":[{"vlan":1}]},{"ifname":"eth0","vlans":[{"vlan":1}]}]`
			res, err := ParseBridgeVLAN([]byte(doc))
			if err != nil {
				t.Fatalf("ParseBridgeVLAN: %v", err)
			}
			if len(res.Ports) != 1 {
				t.Fatalf("got ports %+v, want only eth0", res.Ports)
			}
			if !res.Incomplete || res.Dropped != 1 {
				t.Fatalf("Incomplete=%v Dropped=%d, want true 1", res.Incomplete, res.Dropped)
			}
		})
	}
}

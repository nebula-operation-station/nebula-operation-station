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

func TestParseBridgeVLANMixedShapesMarkIncomplete(t *testing.T) {
	// An element carrying both a "vlans" list and a flat "vlan" field
	// keeps the list and drops the flat field; the dropped field is a
	// loss, so the table is incomplete (the element itself is kept).
	doc := `[{"ifname":"eth0","vlan":7,"flags":["PVID"],"vlans":[{"vlan":1,"flags":["Egress Untagged"]}]}]`
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	want := map[string][]BridgeVLAN{
		"eth0": {{ID: 1, Untagged: true}},
	}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete for a mixed-shape element")
	}
	if res.Dropped != 0 {
		t.Fatalf("Dropped=%d, want 0 (the element is kept)", res.Dropped)
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

func TestParseBridgeVLANDropsReservedIDs(t *testing.T) {
	// 0 and 4095 are reserved; a range touching them is dropped whole.
	doc := `[{"ifname":"eth0","vlans":[{"vlan":0},{"vlan":4095},{"vlan":0,"vlanEnd":3},{"vlan":4090,"vlanEnd":4095},{"vlan":1},{"vlan":4094}]}]`
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	want := map[string][]BridgeVLAN{"eth0": {{ID: 1}, {ID: 4094}}}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete for reserved ids")
	}
}

func TestParseBridgeVLANRejectsEntryWithoutVLAN(t *testing.T) {
	// A "vlans" element without a "vlan" key is not VLAN 0.
	doc := `[{"ifname":"eth0","vlans":[{"flags":["PVID","Egress Untagged"]},{"vlanEnd":20},{"vlan":5}]}]`
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	want := map[string][]BridgeVLAN{"eth0": {{ID: 5}}}
	if !reflect.DeepEqual(res.Ports, want) {
		t.Fatalf("got %+v, want %+v", res.Ports, want)
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete for entries without a vlan id")
	}
}

func TestParseBridgeVLANDuplicatesDoNotTruncate(t *testing.T) {
	// The full range reported twice plus single duplicates is still
	// every id once: nothing is lost, so the table is complete.
	doc := fmt.Sprintf(`[{"ifname":"eth0","vlans":[{"vlan":%d,"vlanEnd":%d},{"vlan":%d,"vlanEnd":%d,"flags":["Egress Untagged"]},{"vlan":1,"flags":["PVID"]},{"vlan":%d}]}]`,
		minVLANID, maxVLANID, minVLANID, maxVLANID, maxVLANID)
	res, err := ParseBridgeVLAN([]byte(doc))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	vlans := res.Ports["eth0"]
	if n := maxVLANID - minVLANID + 1; len(vlans) != n {
		t.Fatalf("got %d vlans, want %d", len(vlans), n)
	}
	if res.Incomplete {
		t.Fatal("expected complete: duplicates are not a loss")
	}
	if v := vlans[0]; v.ID != 1 || !v.PVID || !v.Untagged {
		t.Fatalf("vlan 1 flags not merged: %+v", v)
	}
	if v := vlans[len(vlans)-1]; v.ID != maxVLANID || v.PVID || !v.Untagged {
		t.Fatalf("vlan %d flags: %+v", maxVLANID, v)
	}
}

// fullRangePorts builds a `bridge -j vlan` document of n ports, each
// carrying the full VLAN range once.
func fullRangePorts(n int) []byte {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ifname":"p%d","vlans":[{"vlan":%d,"vlanEnd":%d}]}`, i, minVLANID, maxVLANID)
	}
	b.WriteByte(']')
	return []byte(b.String())
}

func pairCount(ports map[string][]BridgeVLAN) int {
	n := 0
	for _, v := range ports {
		n += len(v)
	}
	return n
}

func TestParseBridgeVLANDocumentBudget(t *testing.T) {
	// maxEntries ports each with the full range would expand to about
	// 4M (port, vlan) pairs from ~55 KB of input. The document budget
	// caps the expansion and marks the table incomplete.
	doc := fullRangePorts(maxEntries)
	if len(doc) > 64*1024 {
		t.Fatalf("test document is %d bytes, expected a small input", len(doc))
	}
	res, err := ParseBridgeVLAN(doc)
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if n := pairCount(res.Ports); n != maxVLANsPerDoc {
		t.Fatalf("got %d (port, vlan) pairs, want the budget %d", n, maxVLANsPerDoc)
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete when the document budget is exhausted")
	}
}

func TestParseBridgeVLANDocumentBudgetFitsFullPorts(t *testing.T) {
	// A document exactly at the budget (64 ports with the full range,
	// the Proxmox VLAN-aware default) is complete.
	ports := maxVLANsPerDoc / (maxVLANID - minVLANID + 1)
	res, err := ParseBridgeVLAN(fullRangePorts(ports))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if res.Incomplete || len(res.Ports) != ports || pairCount(res.Ports) != ports*(maxVLANID-minVLANID+1) {
		t.Fatalf("Incomplete=%v ports=%d pairs=%d, want complete %d full ports", res.Incomplete, len(res.Ports), pairCount(res.Ports), ports)
	}
}

func TestParseBridgeVLANWorkBudget(t *testing.T) {
	// One port repeating the full range: few distinct pairs, but every
	// repetition is visited. The work budget stops the expansion.
	reps := maxVLANWorkPerDoc/(maxVLANID-minVLANID+1) + 2
	var b strings.Builder
	b.WriteString(`[{"ifname":"eth0","vlans":[`)
	for i := 0; i < reps; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"vlan":%d,"vlanEnd":%d}`, minVLANID, maxVLANID)
	}
	b.WriteString(`]}]`)
	if b.Len() > maxInputSize {
		t.Fatalf("test document is %d bytes, above maxInputSize", b.Len())
	}
	res, err := ParseBridgeVLAN([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseBridgeVLAN: %v", err)
	}
	if len(res.Ports["eth0"]) != maxVLANID-minVLANID+1 {
		t.Fatalf("got %d vlans, want the full range", len(res.Ports["eth0"]))
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete when the work budget is exhausted")
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

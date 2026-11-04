// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

func iptr(i int) *int { return &i }

func TestParseLinksProxmox(t *testing.T) {
	res, err := ParseLinks(readFixture(t, "proxmox-link.json"))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Link{
		{Name: "lo", MAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{Name: "eth0", MAC: net.HardwareAddr{0xbc, 0x24, 0x11, 0xaa, 0xbb, 0x01}},
		{
			Name:   "eth0.100",
			MAC:    net.HardwareAddr{0xbc, 0x24, 0x11, 0xaa, 0xbb, 0x01},
			Kind:   "vlan",
			VLANID: iptr(100),
			Parent: "eth0",
		},
		{
			Name: "vmbr0",
			MAC:  net.HardwareAddr{0xbc, 0x24, 0x11, 0xaa, 0xbb, 0x02},
			Kind: "bridge",
		},
		{
			Name:   "tap101",
			MAC:    net.HardwareAddr{0xba, 0xd0, 0x00, 0x10, 0x00, 0x01},
			Kind:   "tun",
			Master: "vmbr0",
		},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
}

func TestParseLinksUbuntuVM(t *testing.T) {
	res, err := ParseLinks(readFixture(t, "ubuntu-link.json"))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	// A plain VM has only physical interfaces: no kind, no VLAN id, no
	// parent, no master.
	for _, l := range res.Entries {
		if l.Kind != "" || l.VLANID != nil || l.Parent != "" || l.Master != "" {
			t.Fatalf("physical interface %q has virtual fields: %+v", l.Name, l)
		}
	}
	if len(res.Entries) != 2 {
		t.Fatalf("got %d interfaces, want 2: %+v", len(res.Entries), res.Entries)
	}
}

func TestParseLinksDockerHost(t *testing.T) {
	res, err := ParseLinks(readFixture(t, "docker-link.json"))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	byName := map[string]Link{}
	for _, l := range res.Entries {
		byName[l.Name] = l
	}
	// The bridges.
	if l := byName["docker0"]; l.Kind != "bridge" {
		t.Fatalf("docker0 kind: %+v", l)
	}
	if l := byName["br-1a2b3c4d5e6f"]; l.Kind != "bridge" {
		t.Fatalf("br-* kind: %+v", l)
	}
	// Bridge membership: each veth port's master is its bridge.
	if l := byName["vethdeadbeef01"]; l.Kind != "veth" || l.Master != "docker0" {
		t.Fatalf("vethdeadbeef01 membership: %+v", l)
	}
	if l := byName["vethcafe123456"]; l.Kind != "veth" || l.Master != "br-1a2b3c4d5e6f" {
		t.Fatalf("vethcafe123456 membership: %+v", l)
	}
}

func TestParseLinksMalformed(t *testing.T) {
	res, err := ParseLinks(readFixture(t, "malformed-link.json"))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}
	if !res.Incomplete || res.Dropped != 2 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 2", res.Incomplete, res.Dropped)
	}
	byName := map[string]Link{}
	for _, l := range res.Entries {
		byName[l.Name] = l
	}
	if len(res.Entries) != 4 {
		t.Fatalf("got %d interfaces, want 4: %+v", len(res.Entries), res.Entries)
	}
	// eth1 lost its MAC but keeps its master.
	if l := byName["eth1"]; len(l.MAC) != 0 || l.Master != "vmbr0" {
		t.Fatalf("eth1 MAC not dropped: %+v", l)
	}
	// eth2 lost its parent (bad name) but keeps its master.
	if l := byName["eth2"]; l.Parent != "" || l.Master != "vmbr0" {
		t.Fatalf("eth2 parent not dropped: %+v", l)
	}
	// eth3 has a vlan kind but an out-of-range id, so VLANID is dropped.
	if l := byName["eth3"]; l.Kind != "vlan" || l.VLANID != nil {
		t.Fatalf("eth3 vlan id not dropped: %+v", l)
	}
}

func TestParseLinksExtractsVLANID(t *testing.T) {
	for _, id := range []int{0, 1, 100, 4095} {
		doc := fmt.Sprintf(`[{"ifname":"eth0.%d","link":"eth0","linkinfo":{"info_kind":"vlan","info_data":{"id":%d}}}]`, id, id)
		res, err := ParseLinks([]byte(doc))
		if err != nil {
			t.Fatalf("ParseLinks: %v", err)
		}
		if len(res.Entries) != 1 || res.Entries[0].VLANID == nil || *res.Entries[0].VLANID != id {
			t.Fatalf("id %d: got %+v, want VLANID %d", id, res.Entries, id)
		}
		if res.Incomplete {
			t.Fatalf("id %d: expected complete, got Incomplete", id)
		}
	}
}

func TestParseLinksDropsOutOfRangeVLANID(t *testing.T) {
	for _, id := range []int{-1, 4096, 99999} {
		doc := fmt.Sprintf(`[{"ifname":"eth0.1","link":"eth0","linkinfo":{"info_kind":"vlan","info_data":{"id":%d}}}]`, id)
		res, err := ParseLinks([]byte(doc))
		if err != nil {
			t.Fatalf("ParseLinks: %v", err)
		}
		if len(res.Entries) != 1 || res.Entries[0].VLANID != nil {
			t.Fatalf("id %d: got %+v, want VLANID nil", id, res.Entries)
		}
		if !res.Incomplete {
			t.Fatalf("id %d: expected Incomplete", id)
		}
	}
}

func TestParseLinksRejectsOversizeInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	copy(big, `[{"ifname":"eth0"}]`)
	if _, err := ParseLinks(big); err == nil {
		t.Fatal("expected error for input above the size limit")
	}
}

func TestParseLinksRejectsNonArray(t *testing.T) {
	for name, doc := range map[string]string{
		"malformed": `{"ifname":`,
		"object":    `{"ifname":"eth0"}`,
		"null":      `null`,
		"string":    `"hello"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLinks([]byte(doc)); err == nil {
				t.Fatal("expected error for non-array input")
			}
		})
	}
}

func TestParseLinksRejectsTooManyEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ifname":"eth%d"}`, i)
	}
	b.WriteByte(']')
	if _, err := ParseLinks([]byte(b.String())); err == nil {
		t.Fatalf("expected error for %d entries", maxEntries+1)
	}
}

func TestParseLinksRejectsNonInterfaceName(t *testing.T) {
	for name, dev := range map[string]string{
		"space":    "eth 0",
		"too long": strings.Repeat("e", maxIfNameLen+1),
		"slash":    "eth/0",
	} {
		t.Run(name, func(t *testing.T) {
			doc := `[{"ifname":"` + dev + `"},{"ifname":"eth0"}]`
			res, err := ParseLinks([]byte(doc))
			if err != nil {
				t.Fatalf("ParseLinks: %v", err)
			}
			if len(res.Entries) != 1 || res.Entries[0].Name != "eth0" {
				t.Fatalf("got %+v, want only the good entry", res.Entries)
			}
			if !res.Incomplete || res.Dropped != 1 {
				t.Fatalf("Incomplete=%v Dropped=%d, want true 1", res.Incomplete, res.Dropped)
			}
		})
	}
}

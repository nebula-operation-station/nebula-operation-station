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
		{Name: "eth0", MAC: net.HardwareAddr{0xbc, 0x24, 0x11, 0xaa, 0xbb, 0x01}, Master: "vmbr0"},
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
		{
			Name:   "vxlan100",
			MAC:    net.HardwareAddr{0x5e, 0x3a, 0x91, 0x0c, 0x44, 0x01},
			Kind:   "vxlan",
			Master: "vmbr0",
		},
		{
			Name: "vxlan10100",
			MAC:  net.HardwareAddr{0x5e, 0x3a, 0x91, 0x0c, 0x44, 0x02},
			Kind: "vxlan",
		},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
	// Only the vlan device has a VLAN id: the bridge, tun and vxlan
	// devices all carry an info_data object (vxlan even an "id", its VNI),
	// which must not turn into a VLAN id.
	for _, l := range res.Entries {
		if l.Kind != "vlan" && l.VLANID != nil {
			t.Fatalf("%s (kind %q) has VLANID %d, want nil", l.Name, l.Kind, *l.VLANID)
		}
	}
}

func TestParseLinksIgnoresIDOfNonVLANKinds(t *testing.T) {
	for name, doc := range map[string]string{
		"bridge":       `[{"ifname":"vmbr0","linkinfo":{"info_kind":"bridge","info_data":{"forward_delay":1500,"stp_state":0,"priority":32768}}}]`,
		"tun":          `[{"ifname":"tap0","linkinfo":{"info_kind":"tun","info_data":{"type":"tap","pi":false,"vnet_hdr":true}}}]`,
		"vxlan small":  `[{"ifname":"vx0","linkinfo":{"info_kind":"vxlan","info_data":{"id":42,"port":4789}}}]`,
		"vxlan large":  `[{"ifname":"vx1","linkinfo":{"info_kind":"vxlan","info_data":{"id":10100,"port":4789}}}]`,
		"geneve":       `[{"ifname":"gnv0","linkinfo":{"info_kind":"geneve","info_data":{"id":7,"remote":"192.0.2.1"}}}]`,
		"empty object": `[{"ifname":"dummy0","linkinfo":{"info_kind":"dummy","info_data":{}}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			res, err := ParseLinks([]byte(doc))
			if err != nil {
				t.Fatalf("ParseLinks: %v", err)
			}
			if len(res.Entries) != 1 || res.Entries[0].VLANID != nil {
				t.Fatalf("got %+v, want one entry with VLANID nil", res.Entries)
			}
			if res.Incomplete {
				t.Fatal("expected complete")
			}
		})
	}
}

func TestParseLinksVLANWithoutIDIsIncomplete(t *testing.T) {
	for name, doc := range map[string]string{
		"no info_data": `[{"ifname":"eth0.5","link":"eth0","linkinfo":{"info_kind":"vlan"}}]`,
		"no id key":    `[{"ifname":"eth0.5","link":"eth0","linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q"}}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			res, err := ParseLinks([]byte(doc))
			if err != nil {
				t.Fatalf("ParseLinks: %v", err)
			}
			if len(res.Entries) != 1 || res.Entries[0].VLANID != nil || res.Entries[0].Kind != "vlan" {
				t.Fatalf("got %+v, want one vlan entry with VLANID nil", res.Entries)
			}
			if !res.Incomplete {
				t.Fatal("expected Incomplete for a vlan device without id")
			}
		})
	}
}

func TestParseLinksAcceptsNonEthernetLinkAddress(t *testing.T) {
	// iproute2 prints tunnel endpoints as IP literals and other link
	// types as hex bytes of their own length; none is a MAC, none is a
	// loss.
	doc := `[
		{"ifname":"sit0","link_type":"sit","address":"0.0.0.0","linkinfo":{"info_kind":"sit"}},
		{"ifname":"gre0","link_type":"gre","address":"0.0.0.0"},
		{"ifname":"ip6tnl0","link_type":"tunnel6","address":"::"},
		{"ifname":"gre1","link_type":"gre","address":"192.0.2.1"},
		{"ifname":"ib0","link_type":"infiniband","address":"00:00:01:04:fe:80:00:00:00:00:00:00:00:02:c9:03:00:0a:bc:de"}
	]`
	res, err := ParseLinks([]byte(doc))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 || len(res.Entries) != 5 {
		t.Fatalf("Incomplete=%v Dropped=%d entries=%d, want complete 5", res.Incomplete, res.Dropped, len(res.Entries))
	}
	for _, l := range res.Entries {
		if len(l.MAC) != 0 {
			t.Fatalf("%s: non-Ethernet address kept as MAC %v", l.Name, l.MAC)
		}
	}
}

func TestParseLinksMalformedLinkAddressIsIncomplete(t *testing.T) {
	for _, addr := range []string{"not-a-mac", "0:1:2", "zz:zz", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"} {
		doc := `[{"ifname":"eth0","address":"` + addr + `"}]`
		res, err := ParseLinks([]byte(doc))
		if err != nil {
			t.Fatalf("ParseLinks: %v", err)
		}
		if len(res.Entries) != 1 || len(res.Entries[0].MAC) != 0 || !res.Incomplete {
			t.Fatalf("%q: got %+v Incomplete=%v, want MAC dropped and Incomplete", addr, res.Entries, res.Incomplete)
		}
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
	for _, id := range []int{1, 100, 4094} {
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
	for _, id := range []int{-1, 0, 4095, 4096, 99999} {
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

func TestParseLinksInvalidKindIsDroppedAndIncomplete(t *testing.T) {
	long := strings.Repeat("a", maxKindLen+1)
	for _, kind := range []string{long, "vl\\u001ban", "vlan\\n", "VLAN", "br\\u202eidge", "vl\u00e4n", "v l"} {
		doc := `[{"ifname":"eth0","linkinfo":{"info_kind":"` + kind + `"}}]`
		res, err := ParseLinks([]byte(doc))
		if err != nil {
			t.Fatalf("%q: ParseLinks: %v", kind, err)
		}
		if len(res.Entries) != 1 || res.Entries[0].Kind != "" || !res.Incomplete {
			t.Fatalf("%q: got %+v Incomplete=%v, want kind dropped and Incomplete", kind, res.Entries, res.Incomplete)
		}
	}
	for _, kind := range []string{"vlan", "bridge", "ip6tnl", "ip6_vti", "team-slave", strings.Repeat("a", maxKindLen)} {
		doc := `[{"ifname":"eth0","linkinfo":{"info_kind":"` + kind + `","info_data":{"id":10}}}]`
		res, err := ParseLinks([]byte(doc))
		if err != nil {
			t.Fatalf("%q: ParseLinks: %v", kind, err)
		}
		if len(res.Entries) != 1 || res.Entries[0].Kind != kind || res.Incomplete {
			t.Fatalf("%q: got %+v Incomplete=%v, want kind kept and complete", kind, res.Entries, res.Incomplete)
		}
	}
}

func TestParseLinksEtherRequiresMAC(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "192.0.2.1", "::", "00:11:22:33", "00:00:01:04:fe:80:00:00:00:00:00:00:00:02:c9:03:00:0a:bc:de"} {
		doc := `[{"ifname":"eth0","link_type":"ether","address":"` + addr + `"}]`
		res, err := ParseLinks([]byte(doc))
		if err != nil {
			t.Fatalf("ParseLinks: %v", err)
		}
		if len(res.Entries) != 1 || len(res.Entries[0].MAC) != 0 || !res.Incomplete {
			t.Fatalf("%q on ether: got %+v Incomplete=%v, want MAC dropped and Incomplete", addr, res.Entries, res.Incomplete)
		}
	}
	res, err := ParseLinks([]byte(`[{"ifname":"eth0","link_type":"ether","address":"02:00:00:00:00:01"}]`))
	if err != nil || res.Incomplete || len(res.Entries) != 1 || res.Entries[0].MAC.String() != "02:00:00:00:00:01" {
		t.Fatalf("ether MAC: %+v err=%v", res, err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseAddrsProxmox(t *testing.T) {
	res, err := ParseAddrs(readFixture(t, "proxmox-addr.json"))
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Addr{
		{
			Name:  "lo",
			MAC:   net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			State: "UNKNOWN",
			Addrs: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/8"),
				netip.MustParsePrefix("::1/128"),
			},
		},
		{
			Name:  "eth0",
			MAC:   net.HardwareAddr{0xbc, 0x24, 0x11, 0xaa, 0xbb, 0x01},
			State: "UP",
			Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.178.10/24")},
		},
		{
			Name:  "eth0.100",
			MAC:   net.HardwareAddr{0xbc, 0x24, 0x11, 0xaa, 0xbb, 0x01},
			State: "UP",
			Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.100.2/24")},
		},
		{
			Name:  "vmbr0",
			MAC:   net.HardwareAddr{0xbc, 0x24, 0x11, 0xaa, 0xbb, 0x02},
			State: "UP",
			Addrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.178.2/24"),
				netip.MustParsePrefix("fe80::1/64"),
			},
		},
		{
			Name:  "tap101",
			MAC:   net.HardwareAddr{0xba, 0xd0, 0x00, 0x10, 0x00, 0x01},
			State: "UP",
			Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.101.5/24")},
		},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
}

func TestParseAddrsUbuntuVM(t *testing.T) {
	res, err := ParseAddrs(readFixture(t, "ubuntu-addr.json"))
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Addr{
		{
			Name:  "lo",
			MAC:   net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			State: "UNKNOWN",
			Addrs: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/8"),
				netip.MustParsePrefix("::1/128"),
			},
		},
		{
			Name:  "ens18",
			MAC:   net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56},
			State: "UP",
			Addrs: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.15/24"),
				netip.MustParsePrefix("fe80::5054:ff:fe12:3456/64"),
			},
		},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
}

func TestParseAddrsDockerHost(t *testing.T) {
	res, err := ParseAddrs(readFixture(t, "docker-addr.json"))
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	if len(res.Entries) != 4 {
		t.Fatalf("got %d interfaces, want 4: %+v", len(res.Entries), res.Entries)
	}
	byName := map[string]Addr{}
	for _, a := range res.Entries {
		byName[a.Name] = a
	}
	if a := byName["docker0"]; len(a.Addrs) != 1 || a.Addrs[0] != (netip.MustParsePrefix("172.17.0.1/16")) {
		t.Fatalf("docker0 addrs: %+v", a)
	}
	if a := byName["br-1a2b3c4d5e6f"]; len(a.Addrs) != 1 || a.Addrs[0] != (netip.MustParsePrefix("172.18.0.1/16")) {
		t.Fatalf("br-* addrs: %+v", a)
	}
}

func TestParseAddrsEmpty(t *testing.T) {
	res, err := ParseAddrs([]byte(`[]`))
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	if len(res.Entries) != 0 || res.Incomplete {
		t.Fatalf("got %+v (Incomplete=%v), want empty", res.Entries, res.Incomplete)
	}
}

func TestParseAddrsMalformed(t *testing.T) {
	res, err := ParseAddrs(readFixture(t, "malformed-addr.json"))
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	if !res.Incomplete || res.Dropped != 2 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 2", res.Incomplete, res.Dropped)
	}
	byName := map[string]Addr{}
	for _, a := range res.Entries {
		byName[a.Name] = a
	}
	if len(res.Entries) != 4 {
		t.Fatalf("got %d interfaces, want 4: %+v", len(res.Entries), res.Entries)
	}
	// eth0 is clean.
	if a := byName["eth0"]; len(a.Addrs) != 1 || a.State != "UP" || len(a.MAC) != 6 {
		t.Fatalf("eth0 not clean: %+v", a)
	}
	// eth1 lost its MAC (not-a-mac) but keeps its address.
	if a := byName["eth1"]; len(a.MAC) != 0 || len(a.Addrs) != 1 {
		t.Fatalf("eth1 MAC not dropped: %+v", a)
	}
	// eth2 lost its state (SPOOFED) but keeps its address.
	if a := byName["eth2"]; a.State != "" || len(a.Addrs) != 1 {
		t.Fatalf("eth2 state not dropped: %+v", a)
	}
	// eth3 lost every address (bad prefixlen, bad family, bad local).
	if a := byName["eth3"]; len(a.Addrs) != 0 {
		t.Fatalf("eth3 addresses not dropped: %+v", a)
	}
}

func TestParseAddrsDropsBadFamilyAndPrefix(t *testing.T) {
	doc := `[{
		"ifname":"eth0","operstate":"UP","addr_info":[
			{"family":"inet","local":"10.0.0.1","prefixlen":33},
			{"family":"inet","local":"10.0.0.2","prefixlen":-1},
			{"family":"inet6","local":"fe80::1","prefixlen":129},
			{"family":"inets","local":"10.0.0.3","prefixlen":24},
			{"family":"inet","local":"not-an-ip","prefixlen":24},
			{"family":"inet","local":"10.0.0.4","prefixlen":24},
			{"family":"inet6","local":"fe80::2","prefixlen":64}
		]
	}]`
	res, err := ParseAddrs([]byte(doc))
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.4/24"),
		netip.MustParsePrefix("fe80::2/64"),
	}
	if len(res.Entries) != 1 || !reflect.DeepEqual(res.Entries[0].Addrs, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
	if !res.Incomplete {
		t.Fatal("expected Incomplete for dropped addresses")
	}
}

func TestParseAddrsTruncatesAddrList(t *testing.T) {
	var b strings.Builder
	b.WriteString(`[{"ifname":"eth0","operstate":"UP","addr_info":[`)
	for i := 0; i < maxAddrsPerIf+5; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"family":"inet","local":"10.%d.%d.1","prefixlen":24}`, i/256, i%256)
	}
	b.WriteString(`]}]`)
	res, err := ParseAddrs([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	if len(res.Entries) != 1 || len(res.Entries[0].Addrs) != maxAddrsPerIf {
		t.Fatalf("got %d addrs, want %d", len(res.Entries[0].Addrs), maxAddrsPerIf)
	}
	if !res.Incomplete || res.Dropped != 0 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 0 (truncation is a loss)", res.Incomplete, res.Dropped)
	}
}

func TestParseAddrsRejectsOversizeInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	copy(big, `[{"ifname":"eth0"}]`)
	if _, err := ParseAddrs(big); err == nil {
		t.Fatal("expected error for input above the size limit")
	}
}

func TestParseAddrsRejectsNonArray(t *testing.T) {
	for name, doc := range map[string]string{
		"malformed": `{"ifname":`,
		"object":    `{"ifname":"eth0"}`,
		"null":      `null`,
		"string":    `"hello"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAddrs([]byte(doc)); err == nil {
				t.Fatal("expected error for non-array input")
			}
		})
	}
}

func TestParseAddrsRejectsTooManyEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ifname":"eth%d","operstate":"UP"}`, i)
	}
	b.WriteByte(']')
	if _, err := ParseAddrs([]byte(b.String())); err == nil {
		t.Fatalf("expected error for %d entries", maxEntries+1)
	}
}

func TestParseAddrsRejectsNonInterfaceName(t *testing.T) {
	for name, dev := range map[string]string{
		"space":     "eth 0",
		"too long":  strings.Repeat("e", maxIfNameLen+1),
		"homoglyph": "еth0",
		"slash":     "eth/0",
	} {
		t.Run(name, func(t *testing.T) {
			doc := `[{"ifname":"` + dev + `","operstate":"UP"},{"ifname":"eth0","operstate":"UP"}]`
			res, err := ParseAddrs([]byte(doc))
			if err != nil {
				t.Fatalf("ParseAddrs: %v", err)
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

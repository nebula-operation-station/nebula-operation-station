// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// These tests pin the size and format limits of assets, networks, MAC
// addresses and LAG port names exactly at the limit and one past it.

// limitAsset is a valid asset that the limit tests change one field at a time.
func limitAsset() Asset {
	return Asset{ID: "a", Name: "x", Kind: KindServer}
}

// limitNetwork is a valid network that the limit tests change one field at a time.
func limitNetwork() Network {
	return Network{ID: "n", Name: "N", Prefix: netip.MustParsePrefix("10.0.0.0/24")}
}

// hostnameOfLen returns a lowercase DNS name of exactly n bytes made of
// 63-byte labels (the longest label the hostname rule accepts).
func hostnameOfLen(t *testing.T, n int) string {
	t.Helper()
	var labels []string
	left := n
	for left > 0 {
		l := min(left, 63)
		labels = append(labels, strings.Repeat("a", l))
		left -= l
		if left > 0 {
			left-- // the dot between labels
		}
	}
	h := strings.Join(labels, ".")
	if len(h) != n {
		t.Fatalf("built hostname of %d bytes, want %d", len(h), n)
	}
	return h
}

func TestAssetLimitsAtBoundary(t *testing.T) {
	addrs := func(n int) []netip.Addr {
		out := make([]netip.Addr, n)
		for i := range out {
			out[i] = netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		}
		return out
	}
	tests := []struct {
		name    string
		mutate  func(a *Asset)
		wantErr bool
	}{
		{"id 63 bytes accepted", func(a *Asset) { a.ID = "a" + strings.Repeat("b", 62) }, false},
		{"id 64 bytes rejected", func(a *Asset) { a.ID = "a" + strings.Repeat("b", 63) }, true},
		{"name 128 bytes accepted", func(a *Asset) { a.Name = strings.Repeat("n", maxName) }, false},
		{"name 129 bytes rejected", func(a *Asset) { a.Name = strings.Repeat("n", maxName+1) }, true},
		{"notes 2000 bytes accepted", func(a *Asset) { a.Notes = strings.Repeat("n", maxNotes) }, false},
		{"notes 2001 bytes rejected", func(a *Asset) { a.Notes = strings.Repeat("n", maxNotes+1) }, true},
		{"hostname 253 bytes accepted", func(a *Asset) { a.Hostname = hostnameOfLen(t, 253) }, false},
		{"hostname 254 bytes rejected", func(a *Asset) { a.Hostname = hostnameOfLen(t, 254) }, true},
		{"hostname label 63 bytes accepted", func(a *Asset) { a.Hostname = strings.Repeat("a", 63) + ".lan" }, false},
		{"hostname label 64 bytes rejected", func(a *Asset) { a.Hostname = strings.Repeat("a", 64) + ".lan" }, true},
		{"host ID 63 bytes accepted", func(a *Asset) { a.HostID = "a" + strings.Repeat("b", 62) }, false},
		{"host ID 64 bytes rejected", func(a *Asset) { a.HostID = "a" + strings.Repeat("b", 63) }, true},
		{"16 addresses accepted", func(a *Asset) { a.Addresses = addrs(MaxAddresses) }, false},
		{"17 addresses rejected", func(a *Asset) { a.Addresses = addrs(MaxAddresses + 1) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := limitAsset()
			tt.mutate(&a)
			err := a.check()
			if (err != nil) != tt.wantErr {
				t.Fatalf("check() error = %v, want error %v", err, tt.wantErr)
			}
			var ve *ValidationError
			if err != nil && !errors.As(err, &ve) {
				t.Fatalf("check() error %T is not a *ValidationError", err)
			}
		})
	}
}

func TestAssetAddressLimitStoredThroughSave(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	var addrs []netip.Addr
	for i := range MaxAddresses {
		addrs = append(addrs, netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}))
	}
	if err := s.SaveAsset(ctx, Asset{ID: "full", Name: "Full", Kind: KindServer, Addresses: addrs}); err != nil {
		t.Fatalf("%d addresses rejected: %v", len(addrs), err)
	}
	got, err := s.Asset(ctx, "full")
	if err != nil || len(got.Addresses) != MaxAddresses {
		t.Fatalf("stored %d addresses, err %v", len(got.Addresses), err)
	}
	addrs = append(addrs, netip.AddrFrom4([4]byte{10, 0, 0, MaxAddresses + 1}))
	var ve *ValidationError
	if err := s.SaveAsset(ctx, Asset{ID: "full", Name: "Full", Kind: KindServer, Addresses: addrs}); !errors.As(err, &ve) {
		t.Fatalf("%d addresses accepted: %v", len(addrs), err)
	}
	// The rejected save must not have replaced the stored addresses.
	got, err = s.Asset(ctx, "full")
	if err != nil || len(got.Addresses) != MaxAddresses {
		t.Fatalf("after rejected save: %d addresses, err %v", len(got.Addresses), err)
	}
}

func TestNetworkLimitsAtBoundary(t *testing.T) {
	pools := func(n int) []Pool {
		out := make([]Pool, n)
		for i := range out {
			a := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
			out[i] = Pool{Name: fmt.Sprintf("p%d", i), First: a, Last: a}
		}
		return out
	}
	tests := []struct {
		name    string
		mutate  func(n *Network)
		wantErr bool
	}{
		{"id 63 bytes accepted", func(n *Network) { n.ID = "a" + strings.Repeat("b", 62) }, false},
		{"id 64 bytes rejected", func(n *Network) { n.ID = "a" + strings.Repeat("b", 63) }, true},
		{"name 128 bytes accepted", func(n *Network) { n.Name = strings.Repeat("n", maxName) }, false},
		{"name 129 bytes rejected", func(n *Network) { n.Name = strings.Repeat("n", maxName+1) }, true},
		{"notes 2000 bytes accepted", func(n *Network) { n.Notes = strings.Repeat("n", maxNotes) }, false},
		{"notes 2001 bytes rejected", func(n *Network) { n.Notes = strings.Repeat("n", maxNotes+1) }, true},
		{"16 pools accepted", func(n *Network) { n.Pools = pools(MaxPools) }, false},
		{"17 pools rejected", func(n *Network) { n.Pools = pools(MaxPools + 1) }, true},
		{"pool name 64 bytes accepted", func(n *Network) {
			a := netip.MustParseAddr("10.0.0.5")
			n.Pools = []Pool{{Name: strings.Repeat("p", 64), First: a, Last: a}}
		}, false},
		{"pool name 65 bytes rejected", func(n *Network) {
			a := netip.MustParseAddr("10.0.0.5")
			n.Pools = []Pool{{Name: strings.Repeat("p", 65), First: a, Last: a}}
		}, true},
		{"VLAN 0 (none) accepted", func(n *Network) { n.VLAN = 0 }, false},
		{"VLAN 4094 accepted", func(n *Network) { n.VLAN = 4094 }, false},
		{"VLAN 4095 rejected", func(n *Network) { n.VLAN = 4095 }, true},
		{"VLAN -1 rejected", func(n *Network) { n.VLAN = -1 }, true},
		{"IPv4 /8 accepted", func(n *Network) { n.Prefix = netip.MustParsePrefix("10.0.0.0/8") }, false},
		{"IPv4 /7 rejected", func(n *Network) { n.Prefix = netip.MustParsePrefix("10.0.0.0/7") }, true},
		{"IPv6 /32 accepted", func(n *Network) { n.Prefix = netip.MustParsePrefix("2001:db8::/32") }, false},
		{"IPv6 /31 rejected", func(n *Network) { n.Prefix = netip.MustParsePrefix("2000::/31") }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := limitNetwork()
			tt.mutate(&n)
			err := n.check()
			if (err != nil) != tt.wantErr {
				t.Fatalf("check() error = %v, want error %v", err, tt.wantErr)
			}
			var ve *ValidationError
			if err != nil && !errors.As(err, &ve) {
				t.Fatalf("check() error %T is not a *ValidationError", err)
			}
		})
	}
}

func TestNetworkListingLimitAtBoundary(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	nets := []Network{
		{ID: "v4max", Name: "V4 max", Prefix: netip.MustParsePrefix("10.0.0.0/22")},   // 1024 addresses
		{ID: "v4over", Name: "V4 over", Prefix: netip.MustParsePrefix("10.8.0.0/21")}, // 2048 addresses
		{ID: "v6max", Name: "V6 max", Prefix: netip.MustParsePrefix("2001:db8:1::/118")},
		{ID: "v6over", Name: "V6 over", Prefix: netip.MustParsePrefix("2001:db8:2::/117")},
	}
	for _, n := range nets {
		if err := s.SaveNetwork(ctx, n); err != nil {
			t.Fatalf("save %s: %v", n.ID, err)
		}
	}
	views, listed, err := s.Status(ctx, "v4max")
	if err != nil || !listed || len(views) != MaxListed {
		t.Fatalf("v4max: %d views, listed %v, err %v; want %d listed", len(views), listed, err, MaxListed)
	}
	views, listed, err = s.Status(ctx, "v6max")
	if err != nil || !listed || len(views) != MaxListed {
		t.Fatalf("v6max: %d views, listed %v, err %v; want %d listed", len(views), listed, err, MaxListed)
	}
	for _, id := range []string{"v4over", "v6over"} {
		views, listed, err := s.Status(ctx, id)
		if err != nil || listed || len(views) != 0 {
			t.Fatalf("%s: %d views, listed %v, err %v; want none listed", id, len(views), listed, err)
		}
	}
}

func TestNormalizeMACTable(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"empty input is accepted as no MAC", "", "", true},
		{"upper case colon form lowercased", "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff", true},
		{"hyphen form", "aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff", true},
		{"dot (Cisco) form", "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff", true},
		{"leading and trailing space trimmed", "  aa:bb:cc:dd:ee:ff\t", "aa:bb:cc:dd:ee:ff", true},
		{"only whitespace rejected", "   ", "", false},
		{"8-byte EUI-64 rejected", "00:11:22:33:44:55:66:77", "", false},
		{"20-byte InfiniBand address rejected", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33", "", false},
		{"five bytes rejected", "aa:bb:cc:dd:ee", "", false},
		{"trailing separator rejected", "aa:bb:cc:dd:ee:ff:", "", false},
		{"non-hex digit rejected", "zz:bb:cc:dd:ee:ff", "", false},
		{"inner space rejected", "aa: bb:cc:dd:ee:ff", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeMAC(tt.in)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("NormalizeMAC(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
			if !ok {
				return
			}
			// Normalising the result again must not change it.
			again, ok2 := NormalizeMAC(got)
			if !ok2 || again != got {
				t.Fatalf("NormalizeMAC(%q) not idempotent: (%q, %v)", got, again, ok2)
			}
		})
	}
}

func TestIsLAGPortTable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"port-channel with space", "Port-channel 1", true},
		{"port-channel without space", "port-channel1", true},
		{"port-channel upper case", "PORT-CHANNEL12", true},
		{"port-channel alone", "port-channel", false},
		{"port-channel with only a space", "port-channel ", false},
		{"port-channel with two numbers", "port-channel 1 2", false},
		{"port-channel with dash", "port-channel-1", false},
		{"po alone", "po", false},
		{"po with digit", "po1", true},
		{"Po with digit", "Po1", true},
		{"PO with two digits", "PO12", true},
		{"po with leading zero", "po01", true},
		{"po with trailing letter", "Po1x", false},
		{"power is not a LAG", "power1", false},
		{"po with space before digit", "po 1", false},
		{"po with leading space", " po1", false},
		{"po with non-ASCII digit", "po١", false},
		{"physical gigabit port", "GigabitEthernet1/0/1", false},
		{"empty name", "", false},
		{"lag prefix", "lag1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLAGPort(tt.in); got != tt.want {
				t.Fatalf("IsLAGPort(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func FuzzNormalizeMAC(f *testing.F) {
	for _, s := range []string{"", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff",
		" 00:11:22:33:44:55 ", "00:11:22:33:44:55:66:77", "zz", strings.Repeat("0", 200)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := NormalizeMAC(s)
		if !ok {
			if out != "" {
				t.Fatalf("NormalizeMAC(%q) rejected but returned %q", s, out)
			}
			return
		}
		if out == "" {
			if strings.TrimSpace(s) != "" {
				t.Fatalf("NormalizeMAC(%q) accepted non-blank input as empty", s)
			}
			return
		}
		hw, err := net.ParseMAC(out)
		if err != nil || len(hw) != 6 || hw.String() != out || out != strings.ToLower(out) {
			t.Fatalf("NormalizeMAC(%q) = %q, not a canonical 6-byte MAC", s, out)
		}
		again, ok2 := NormalizeMAC(out)
		if !ok2 || again != out {
			t.Fatalf("NormalizeMAC not idempotent: %q -> %q -> (%q, %v)", s, out, again, ok2)
		}
	})
}

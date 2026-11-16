// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// cats returns the categories of the matched entries, in order.
func cats(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Prefix.String()+"/"+e.Category)
	}
	return out
}

func mustMatcher(t *testing.T, es []Entry) *Matcher {
	t.Helper()
	m, err := NewMatcher(es)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

func TestLookupListsAllCoveringEntriesBroadestFirst(t *testing.T) {
	m := mustMatcher(t, []Entry{
		{Prefix: pfx("8.8.4.0/24"), Category: "c"},
		{Prefix: pfx("8.8.0.0/16"), Category: "x"},
		{Prefix: pfx("8.8.0.0/20"), Category: "b"},
		{Prefix: pfx("8.8.0.0/20"), Category: "a"},
	})
	tests := []struct {
		name string
		addr string
		want []string
	}{
		{"deepest and all covers", "8.8.4.1", []string{"8.8.0.0/16/x", "8.8.0.0/20/a", "8.8.0.0/20/b", "8.8.4.0/24/c"}},
		{"no /24 match", "8.8.5.1", []string{"8.8.0.0/16/x", "8.8.0.0/20/a", "8.8.0.0/20/b"}},
		{"only /16", "8.8.32.1", []string{"8.8.0.0/16/x"}},
		{"outside", "9.0.0.1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.Lookup(addr(tt.addr))
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if !reflect.DeepEqual(cats(got), tt.want) {
				t.Fatalf("Lookup(%s) = %v, want %v", tt.addr, cats(got), tt.want)
			}
		})
	}
}

func TestLookupPrefixLengthBoundaryV4AndV6(t *testing.T) {
	m := mustMatcher(t, []Entry{
		{Prefix: pfx("8.8.0.0/16"), Category: "v4"},
		{Prefix: pfx("2a00::/32"), Category: "v6-32"},
	})
	// /16 covers 8.8.x.x; the neighbour 8.9.x.x is not covered by it.
	if got, _ := m.Lookup(addr("8.8.200.1")); len(got) != 1 {
		t.Errorf("/16 must match 8.8.200.1, got %v", cats(got))
	}
	if got, _ := m.Lookup(addr("8.9.0.1")); len(got) != 0 {
		t.Errorf("/16 must not match 8.9.0.1, got %v", cats(got))
	}

	// 2a00::/32 fixes the first 32 bits: it covers 2a00:0::/32 but not the
	// neighbour 2a00:1::/32.
	if got, _ := m.Lookup(addr("2a00::1")); len(got) != 1 {
		t.Errorf("/32 must match 2a00::1, got %v", cats(got))
	}
	if got, _ := m.Lookup(addr("2a00:1::1")); len(got) != 0 {
		t.Errorf("/32 must not match 2a00:1::1, got %v", cats(got))
	}
}

// TestNewMatcherRefusesOverBroadPrefix: a prefix shorter than the minimum is
// refused by NewMatcher too, so a caller that skips Validate cannot turn one
// entry into a match for every address (/0) or a large block.
func TestNewMatcherRefusesOverBroadPrefix(t *testing.T) {
	bad := []string{"0.0.0.0/0", "8.0.0.0/8", "0.0.0.0/15", "::/0", "2a00::/31"}
	for _, p := range bad {
		if _, err := NewMatcher([]Entry{{Prefix: pfx(p), Category: "c"}}); !errors.Is(err, ErrInvalidPrefix) {
			t.Errorf("NewMatcher(%s): %v, want ErrInvalidPrefix", p, err)
		}
	}
	for _, p := range []string{"8.0.0.0/16", "2a00::/32"} {
		if _, err := NewMatcher([]Entry{{Prefix: pfx(p), Category: "c"}}); err != nil {
			t.Errorf("NewMatcher(%s) at minimum length: %v", p, err)
		}
	}
}

// genHosts returns n distinct IPv6 /128 entries under 2a00::/16.
func genHosts(n int) []Entry {
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		var b [16]byte
		b[0], b[1] = 0x2a, 0x00
		binary.BigEndian.PutUint32(b[12:], uint32(i))
		out = append(out, Entry{Prefix: netip.PrefixFrom(netip.AddrFrom16(b), 128), Category: "c"})
	}
	return out
}

// TestNewMatcherEntryCapBoundary: a matcher at MaxMatcherEntries builds, one
// more entry is refused with ErrMatcherTooLarge. Without the cap, a hostile
// feed of distinct /128 entries could build an unbounded trie.
func TestNewMatcherEntryCapBoundary(t *testing.T) {
	m, err := NewMatcher(genHosts(MaxMatcherEntries))
	if err != nil {
		t.Fatalf("at cap: %v", err)
	}
	if got, _ := m.Lookup(addr("2a00::")); len(got) != 1 {
		t.Fatalf("first host not matched at cap: %v", cats(got))
	}
	if _, err := NewMatcher(genHosts(MaxMatcherEntries + 1)); !errors.Is(err, ErrMatcherTooLarge) {
		t.Fatalf("cap+1: %v, want ErrMatcherTooLarge", err)
	}
}

func TestLookupIPv4MappedTreatedAsIPv4(t *testing.T) {
	m := mustMatcher(t, []Entry{{Prefix: pfx("8.8.4.0/24"), Category: "c"}})
	plain, _ := m.Lookup(addr("8.8.4.1"))
	mapped, err := m.Lookup(addr("::ffff:8.8.4.1"))
	if err != nil {
		t.Fatalf("mapped Lookup: %v", err)
	}
	if !reflect.DeepEqual(plain, mapped) || len(mapped) != 1 {
		t.Fatalf("mapped %v differs from plain %v", cats(mapped), cats(plain))
	}
	// An IPv4 entry must not match an IPv6 address that is not mapped.
	if got, _ := m.Lookup(addr("2001:db8::1")); len(got) != 0 {
		t.Fatalf("unmapped v6 matched v4 entry: %v", cats(got))
	}
}

func TestLookupRefusesZoneAndInvalidAddress(t *testing.T) {
	m := mustMatcher(t, []Entry{{Prefix: pfx("2a00::/32"), Category: "c"}})
	if _, err := m.Lookup(addr("2a00::1%eth0")); !errors.Is(err, ErrZonedAddress) {
		t.Fatalf("zoned address: %v, want ErrZonedAddress", err)
	}
	if _, err := m.Lookup(addr("::ffff:8.8.8.8%eth0")); !errors.Is(err, ErrZonedAddress) {
		t.Fatalf("zoned mapped address: %v, want ErrZonedAddress", err)
	}
	if _, err := m.Lookup(netip.Addr{}); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("zero address: %v, want ErrInvalidAddress", err)
	}
}

func TestNewMatcherRefusesInvalidPrefix(t *testing.T) {
	bad := []Entry{
		{},
		{Prefix: netip.PrefixFrom(addr("8.8.4.1"), 24)},
		{Prefix: netip.PrefixFrom(addr("::ffff:8.8.4.1"), 120)},
	}
	for i, e := range bad {
		if _, err := NewMatcher([]Entry{e}); !errors.Is(err, ErrInvalidPrefix) {
			t.Errorf("case %d: %v, want ErrInvalidPrefix", i, err)
		}
	}
}

func TestMatcherIsImmutable(t *testing.T) {
	in := []Entry{{Prefix: pfx("8.8.4.0/24"), Category: "c"}}
	m := mustMatcher(t, in)
	in[0].Category = "changed"
	in[0].Prefix = pfx("9.9.9.0/24")

	got, err := m.Lookup(addr("8.8.4.1"))
	if err != nil || len(got) != 1 || got[0].Category != "c" {
		t.Fatalf("input mutation leaked into matcher: %v %v", cats(got), err)
	}
	got[0].Category = "mutated"
	again, _ := m.Lookup(addr("8.8.4.1"))
	if again[0].Category != "c" {
		t.Fatalf("returned slice aliases matcher state: %v", cats(again))
	}
}

func TestMatcherOrderIndependent(t *testing.T) {
	base := []Entry{
		{Prefix: pfx("8.8.0.0/20"), Category: "x"},
		{Prefix: pfx("8.8.0.0/16"), Category: "b"},
		{Prefix: pfx("8.8.0.0/16"), Category: "a"},
		{Prefix: pfx("8.8.4.0/24"), Category: "c"},
		{Prefix: pfx("2a00::/32"), Category: "v6"},
	}
	rev := make([]Entry, len(base))
	for i := range base {
		rev[len(base)-1-i] = base[i]
	}
	m1 := mustMatcher(t, base)
	m2 := mustMatcher(t, rev)
	for _, a := range []string{"8.8.4.1", "8.8.9.9", "8.9.9.9", "2a00::5", "1.1.1.1"} {
		g1, _ := m1.Lookup(addr(a))
		g2, _ := m2.Lookup(addr(a))
		if !reflect.DeepEqual(g1, g2) {
			t.Fatalf("%s: order changed result %v vs %v", a, cats(g1), cats(g2))
		}
	}
}

func TestZeroMatcherMatchesNothing(t *testing.T) {
	var m Matcher
	got, err := m.Lookup(addr("8.8.4.1"))
	if err != nil || len(got) != 0 {
		t.Fatalf("zero Matcher: %v %v", cats(got), err)
	}
}

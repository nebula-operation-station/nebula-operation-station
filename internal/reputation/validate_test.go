// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"errors"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// pfx parses a literal prefix for a test table. Test literals only.
func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// noOverlap is an IPAM/NOS-path check that never matches.
func noOverlap(netip.Prefix) bool { return false }

// genEntries returns n distinct public-looking /24 entries (8.x.y.0/24).
func genEntries(n int) []Entry {
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{8, byte(i >> 8), byte(i), 0})
		out = append(out, Entry{Prefix: netip.PrefixFrom(a, 24), Category: "botnet_c2"})
	}
	return out
}

func TestMinPrefixConstants(t *testing.T) {
	if MinPrefixV4 != 16 {
		t.Errorf("MinPrefixV4 = %d, want 16 (ADR 0012 D6)", MinPrefixV4)
	}
	if MinPrefixV6 != 32 {
		t.Errorf("MinPrefixV6 = %d, want 32 (ADR 0012 D6)", MinPrefixV6)
	}
}

func TestPrefixMinimumBoundary(t *testing.T) {
	caps := Caps{PerFeed: 100, Total: 100}
	tests := []struct {
		name string
		p    string
		want Reason // ReasonNone = kept
	}{
		{"v4 /16 kept at minimum", "8.8.0.0/16", ReasonNone},
		{"v4 /15 dropped one below minimum", "8.8.0.0/15", ReasonTooBroad},
		{"v6 /32 kept at minimum", "2a00::/32", ReasonNone},
		{"v6 /31 dropped one below minimum", "2a00::/31", ReasonTooBroad},
		{"v4 /8 dropped", "8.0.0.0/8", ReasonTooBroad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Validate([]Entry{{Prefix: pfx(tt.p), Category: "c"}}, caps, noOverlap)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			checkReason(t, res, tt.want)
		})
	}
}

// checkReason asserts a single-entry result: kept when want is ReasonNone,
// otherwise dropped once with the given reason and counted under it.
func checkReason(t *testing.T, res Result, want Reason) {
	t.Helper()
	if want == ReasonNone {
		if len(res.Kept) != 1 || len(res.Dropped) != 0 {
			t.Fatalf("kept=%d dropped=%+v, want kept", len(res.Kept), res.Dropped)
		}
		return
	}
	if len(res.Kept) != 0 || len(res.Dropped) != 1 {
		t.Fatalf("kept=%d dropped=%+v, want dropped as %v", len(res.Kept), res.Dropped, want)
	}
	if got := res.Dropped[0].Reason; got != want {
		t.Fatalf("reason = %v, want %v", got, want)
	}
	if got := countFor(res.Counts, want); got != 1 {
		t.Fatalf("counter for %v = %d, want 1 (counts %+v)", want, got, res.Counts)
	}
}

func countFor(c Counts, r Reason) int {
	switch r {
	case ReasonInvalid:
		return c.Invalid
	case ReasonTooBroad:
		return c.TooBroad
	case ReasonSpecial:
		return c.Special
	case ReasonPrivate:
		return c.Private
	case ReasonCGNAT:
		return c.CGNAT
	case ReasonDocumentation:
		return c.Documentation
	case ReasonReserved:
		return c.Reserved
	case ReasonOverlap:
		return c.Overlap
	}
	return -1
}

// TestSpecialRangesInsideAndOutside checks every special range with one
// prefix inside it and prefixes just outside both edges (AGENTS: each
// category has a case knapp innerhalb and knapp außerhalb).
func TestSpecialRangesInsideAndOutside(t *testing.T) {
	tests := []struct {
		name string
		p    string
		want Reason
	}{
		// IPv4
		{"reserved this-network inside", "0.1.0.0/16", ReasonReserved},
		{"reserved this-network outside", "1.0.0.0/16", ReasonNone},
		{"private 10/8 inside", "10.0.0.0/24", ReasonPrivate},
		{"private 10/8 just below", "9.255.255.0/24", ReasonNone},
		{"private 10/8 just above", "11.0.0.0/24", ReasonNone},
		{"private 172.16/12 inside start", "172.16.0.0/16", ReasonPrivate},
		{"private 172.16/12 inside end", "172.31.255.0/24", ReasonPrivate},
		{"private 172.16/12 just below", "172.15.255.0/24", ReasonNone},
		{"private 172.16/12 just above", "172.32.0.0/16", ReasonNone},
		{"private 192.168/16 inside", "192.168.1.0/24", ReasonPrivate},
		{"private 192.168/16 just above", "192.169.0.0/24", ReasonNone},
		{"private 192.168/16 just below", "192.167.255.0/24", ReasonNone},
		{"CGNAT 100.64/10 inside start", "100.64.0.0/24", ReasonCGNAT},
		{"CGNAT 100.64/10 inside end", "100.127.255.0/24", ReasonCGNAT},
		{"CGNAT 100.64/10 just below", "100.63.255.0/24", ReasonNone},
		{"CGNAT 100.64/10 just above", "100.128.0.0/24", ReasonNone},
		{"special loopback inside", "127.0.0.0/24", ReasonSpecial},
		{"special loopback just above", "128.0.0.0/24", ReasonNone},
		{"special link-local inside", "169.254.0.0/24", ReasonSpecial},
		{"special link-local just above", "169.255.0.0/24", ReasonNone},
		{"special link-local just below", "169.253.255.0/24", ReasonNone},
		{"special benchmark inside", "198.19.255.0/24", ReasonSpecial},
		{"special benchmark just above", "198.20.0.0/24", ReasonNone},
		{"special benchmark just below", "198.17.255.0/24", ReasonNone},
		{"special multicast inside", "224.0.0.0/24", ReasonSpecial},
		{"special multicast just below", "223.255.255.0/24", ReasonNone},
		{"documentation 192.0.2/24 inside", "192.0.2.0/24", ReasonDocumentation},
		{"documentation 192.0.2/24 just above", "192.0.3.0/24", ReasonNone},
		{"documentation 198.51.100/24 inside", "198.51.100.0/24", ReasonDocumentation},
		{"documentation 203.0.113/24 inside", "203.0.113.0/24", ReasonDocumentation},
		{"documentation 203.0.113/24 just above", "203.0.114.0/24", ReasonNone},
		{"reserved IETF 192.0.0/24 inside", "192.0.0.0/24", ReasonReserved},
		{"reserved IETF 192.0.0/24 just above", "192.0.1.0/24", ReasonNone},
		{"reserved 6to4 relay inside", "192.88.99.0/24", ReasonReserved},
		{"reserved 6to4 relay just above", "192.88.100.0/24", ReasonNone},
		{"reserved class E inside", "240.0.0.0/24", ReasonReserved},
		{"reserved broadcast inside", "255.255.255.0/24", ReasonReserved},
		{"multicast just below class E", "239.255.255.0/24", ReasonSpecial},

		// IPv6
		{"v6 loopback inside", "::1/128", ReasonSpecial},
		{"v6 reserved ::/8 inside", "0:0:1::/48", ReasonReserved},
		{"v6 reserved ::/8 covering loopback is special", "::/32", ReasonSpecial},
		{"v6 NAT64 inside ::/8 reserved", "64:ff9b::/96", ReasonReserved},
		{"v6 discard inside", "100::/64", ReasonSpecial},
		{"v6 discard just above", "100:0:0:1::/64", ReasonNone},
		{"v6 IETF 2001::/23 inside", "2001:0:1::/48", ReasonReserved},
		{"v6 IETF 2001::/23 just above", "2001:200::/32", ReasonNone},
		{"v6 documentation 2001:db8 inside", "2001:db8::/32", ReasonDocumentation},
		{"v6 documentation 2001:db9 outside", "2001:db9::/32", ReasonNone},
		{"v6 documentation 3fff::/20 inside", "3fff::/32", ReasonDocumentation},
		{"v6 documentation 3fff::/20 just above", "3fff:1000::/32", ReasonNone},
		{"v6 SRv6 inside", "5f00::/32", ReasonReserved},
		{"v6 ULA fc00::/7 inside", "fc00::/48", ReasonPrivate},
		{"v6 ULA fd00::/8 inside", "fdff::/48", ReasonPrivate},
		{"v6 ULA just above", "fe00::/48", ReasonNone},
		{"v6 ULA just below", "fb00::/48", ReasonNone},
		{"v6 link-local fe80::/10 inside", "fe80::/64", ReasonSpecial},
		{"v6 link-local just above", "fec0::/64", ReasonNone},
		{"v6 multicast inside", "ff02::/64", ReasonSpecial},
		{"v6 mapped IPv4 refused", "::ffff:0:0/96", ReasonInvalid},
	}
	caps := Caps{PerFeed: 100, Total: 100}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Validate([]Entry{{Prefix: pfx(tt.p), Category: "c"}}, caps, noOverlap)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			checkReason(t, res, tt.want)
		})
	}
}

func TestIPAMOverlapDroppedAndCounted(t *testing.T) {
	ipam := pfx("20.1.0.0/16")
	overlaps := func(p netip.Prefix) bool { return p.Overlaps(ipam) }
	tests := []struct {
		name string
		p    string
		want Reason
	}{
		{"overlap equal", "20.1.0.0/16", ReasonOverlap},
		{"overlap inside", "20.1.128.0/24", ReasonOverlap},
		{"no overlap neighbour", "20.2.0.0/16", ReasonNone},
		{"no overlap neighbour below", "20.0.0.0/24", ReasonNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Validate([]Entry{{Prefix: pfx(tt.p), Category: "c"}}, Caps{PerFeed: 10, Total: 10}, overlaps)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			checkReason(t, res, tt.want)
		})
	}
}

func TestSpecialRangeTakesPrecedenceOverOverlapCheck(t *testing.T) {
	var asked []netip.Prefix
	ask := func(p netip.Prefix) bool { asked = append(asked, p); return false }
	res, err := Validate([]Entry{{Prefix: pfx("10.0.0.0/24"), Category: "c"}}, Caps{PerFeed: 10, Total: 10}, ask)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	checkReason(t, res, ReasonPrivate)
	if len(asked) != 0 {
		t.Fatalf("overlap check consulted for a special prefix: %v", asked)
	}
}

func TestInvalidEntriesDropped(t *testing.T) {
	tests := []struct {
		name string
		e    Entry
		want Reason
	}{
		{"host bits set", Entry{Prefix: pfx("8.8.0.1/16"), Category: "c"}, ReasonInvalid},
		{"zero prefix value", Entry{Category: "c"}, ReasonInvalid},
		{"empty category", Entry{Prefix: pfx("8.8.0.0/16")}, ReasonInvalid},
		{"upper-case category", Entry{Prefix: pfx("8.8.0.0/16"), Category: "Botnet"}, ReasonInvalid},
		{"category with space", Entry{Prefix: pfx("8.8.0.0/16"), Category: "bot net"}, ReasonInvalid},
		{"category too long", Entry{Prefix: pfx("8.8.0.0/16"), Category: string(make([]byte, MaxCategoryBytes+1))}, ReasonInvalid},
		{"category at limit", Entry{Prefix: pfx("8.8.0.0/16"), Category: fill('a', MaxCategoryBytes)}, ReasonNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Validate([]Entry{tt.e}, Caps{PerFeed: 10, Total: 10}, noOverlap)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			checkReason(t, res, tt.want)
		})
	}
}

func fill(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}

func TestPerFeedCapBoundary(t *testing.T) {
	const cap = 1000 // test value; the production cap is a caller parameter (ADR gives no value)
	caps := Caps{PerFeed: cap, Total: cap}

	res, err := Validate(genEntries(cap), caps, noOverlap)
	if err != nil {
		t.Fatalf("at cap: %v", err)
	}
	if len(res.Kept) != cap {
		t.Fatalf("kept = %d, want %d", len(res.Kept), cap)
	}

	res, err = Validate(genEntries(cap+1), caps, noOverlap)
	if !errors.Is(err, ErrOverCap) {
		t.Fatalf("cap+1 error = %v, want ErrOverCap", err)
	}
	if len(res.Kept) != 0 || len(res.Dropped) != 0 {
		t.Fatalf("over-cap snapshot must not be trimmed, got kept=%d dropped=%d", len(res.Kept), len(res.Dropped))
	}
}

func TestTotalCapBoundary(t *testing.T) {
	caps := Caps{PerFeed: 1000, Total: 1500}
	tests := []struct {
		name  string
		sizes []int
		err   error
	}{
		{"sum at total", []int{1000, 500}, nil},
		{"sum one above total", []int{1000, 501}, ErrTotalCap},
		{"single feed at total", []int{1500}, nil},
		{"empty set", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckTotal(tt.sizes, caps)
			if !errors.Is(err, tt.err) && !(err == nil && tt.err == nil) {
				t.Fatalf("CheckTotal = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestInvalidCapsRefused(t *testing.T) {
	if _, err := Validate(genEntries(1), Caps{PerFeed: 0, Total: 1}, noOverlap); !errors.Is(err, ErrInvalidCaps) {
		t.Fatalf("PerFeed 0: %v, want ErrInvalidCaps", err)
	}
	if err := CheckTotal([]int{1}, Caps{PerFeed: 1, Total: 0}); !errors.Is(err, ErrInvalidCaps) {
		t.Fatalf("Total 0: %v, want ErrInvalidCaps", err)
	}
	if _, err := Validate(genEntries(1), Caps{PerFeed: 1, Total: 1}, nil); !errors.Is(err, ErrNoOverlapCheck) {
		t.Fatalf("nil overlap func: %v, want ErrNoOverlapCheck", err)
	}
}

func TestDuplicatesMergedAndOrderIndependent(t *testing.T) {
	base := []Entry{
		{Prefix: pfx("8.8.0.0/16"), Category: "botnet_c2"},
		{Prefix: pfx("8.8.0.0/16"), Category: "botnet_c2"},
		{Prefix: pfx("8.9.0.0/16"), Category: "netblock"},
		{Prefix: pfx("2a00::/32"), Category: "botnet_c2"},
		{Prefix: pfx("10.0.0.0/24"), Category: "botnet_c2"},
	}
	caps := Caps{PerFeed: 10, Total: 10}
	want, err := Validate(base, caps, noOverlap)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(want.Kept) != 3 {
		t.Fatalf("kept = %d, want 3 after dedupe", len(want.Kept))
	}

	perms := [][]int{{4, 3, 2, 1, 0}, {2, 0, 4, 1, 3}, {1, 2, 3, 4, 0}}
	for _, perm := range perms {
		shuffled := make([]Entry, len(base))
		for i, j := range perm {
			shuffled[i] = base[j]
		}
		got, err := Validate(shuffled, caps, noOverlap)
		if err != nil {
			t.Fatalf("Validate(%v): %v", perm, err)
		}
		if !reflect.DeepEqual(got.Kept, want.Kept) || got.Counts != want.Counts {
			t.Fatalf("order %v changed result:\n got %+v\nwant %+v", perm, got, want)
		}
	}
}

func TestDroppedEntriesCarryReason(t *testing.T) {
	in := []Entry{
		{Prefix: pfx("10.0.0.0/24"), Category: "c"},
		{Prefix: pfx("8.0.0.0/8"), Category: "c"},
		{Prefix: pfx("8.8.0.0/16"), Category: "c"},
	}
	res, err := Validate(in, Caps{PerFeed: 10, Total: 10}, noOverlap)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	c := res.Counts
	if c.Private != 1 || c.TooBroad != 1 || len(res.Kept) != 1 {
		t.Fatalf("counts %+v kept %d, want private=1 toobroad=1 kept=1", c, len(res.Kept))
	}
	if len(res.Dropped) != 2 {
		t.Fatalf("dropped listed = %d, want 2", len(res.Dropped))
	}
}

func TestReasonStringNames(t *testing.T) {
	tests := []struct {
		r    Reason
		want string
	}{
		{ReasonNone, "none"},
		{ReasonInvalid, "invalid"},
		{ReasonTooBroad, "too-broad"},
		{ReasonSpecial, "special"},
		{ReasonPrivate, "private"},
		{ReasonCGNAT, "cgnat"},
		{ReasonDocumentation, "documentation"},
		{ReasonReserved, "reserved"},
		{ReasonOverlap, "overlap"},
		{Reason(200), "none"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("Reason(%d).String() = %q, want %q", uint8(tt.r), got, tt.want)
		}
	}
}

// TestDroppedInvalidCategoryIsSanitised: a dropped entry whose feed category
// failed validation must not carry the raw label into the admin listing.
// Without the fix the oversized, control-byte and non-UTF-8 labels come back
// verbatim in Dropped[i].Entry.Category.
func TestDroppedInvalidCategoryIsSanitised(t *testing.T) {
	bad := []string{strings.Repeat("A", 1<<16), "bad\x00\x1b[2J", "caf\xc3\xa9", "UPPER", ""}
	in := []Entry{{Prefix: pfx("10.0.0.0/24"), Category: "netblock"}}
	for _, c := range bad {
		in = append(in, Entry{Prefix: pfx("8.8.4.0/24"), Category: c})
	}
	res, err := Validate(in, Caps{PerFeed: 100, Total: 100}, noOverlap)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(res.Dropped) != len(in) {
		t.Fatalf("dropped = %d, want %d", len(res.Dropped), len(in))
	}
	sawPrivate := false
	for _, d := range res.Dropped {
		switch d.Reason {
		case ReasonInvalid:
			if d.Entry.Category != "" {
				t.Fatalf("invalid category kept in admin listing (len %d); must be empty", len(d.Entry.Category))
			}
		case ReasonPrivate:
			sawPrivate = true
			if d.Entry.Category != "netblock" {
				t.Fatalf("valid category altered: %q", d.Entry.Category)
			}
		default:
			t.Fatalf("unexpected reason %v", d.Reason)
		}
	}
	if !sawPrivate {
		t.Fatal("private drop missing from listing")
	}
}

// TestCheckTotalSumOverflowRefused: two counts whose sum wraps past MaxInt
// must still be refused. Without the fix the wrapped sum is -2 and passes.
func TestCheckTotalSumOverflowRefused(t *testing.T) {
	err := CheckTotal([]int{math.MaxInt, math.MaxInt}, Caps{PerFeed: 1, Total: 10})
	if !errors.Is(err, ErrTotalCap) {
		t.Fatalf("overflowing sum: %v, want ErrTotalCap", err)
	}
}

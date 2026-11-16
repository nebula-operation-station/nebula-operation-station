// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"cmp"
	"net/netip"
	"slices"
	"testing"
)

// Fuzz inputs are decoded into records of recordBytes each; the input is
// untrusted, so decoding is bounded by fuzzMaxEntries.
const (
	recordBytes    = 19
	fuzzMaxEntries = 32
)

// fuzzCategories mixes valid labels with invalid ones (upper case, empty).
var fuzzCategories = []string{"botnet_c2", "netblock", "a", "Bad", ""}

// decodeFuzzEntries turns raw bytes into entries. Prefix lengths are reduced
// modulo the family width, so most inputs are structurally valid; host bits
// are left set on purpose to exercise the canonical-prefix check.
func decodeFuzzEntries(data []byte) []Entry {
	var out []Entry
	for len(data) >= recordBytes && len(out) < fuzzMaxEntries {
		rec := data[:recordBytes]
		data = data[recordBytes:]
		var a netip.Addr
		bits := int(rec[17])
		if rec[0]&1 == 0 {
			a = netip.AddrFrom4([4]byte{rec[1], rec[2], rec[3], rec[4]})
			bits %= 33
		} else {
			var b [16]byte
			copy(b[:], rec[1:17])
			a = netip.AddrFrom16(b)
			bits %= 129
		}
		out = append(out, Entry{
			Prefix:   netip.PrefixFrom(a, bits),
			Category: fuzzCategories[int(rec[18])%len(fuzzCategories)],
		})
	}
	return out
}

// oracleOrder is the matcher's documented order: prefix length, then category.
func oracleOrder(a, b Entry) int {
	return cmp.Or(cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()), cmp.Compare(a.Category, b.Category))
}

// FuzzLookupMatchesLinearOracle checks Matcher.Lookup against a linear scan
// using netip.Prefix.Contains, for every entry's address and its IPv4-mapped
// form.
func FuzzLookupMatchesLinearOracle(f *testing.F) {
	f.Add([]byte{0, 8, 8, 4, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0})
	f.Add([]byte{1, 0x2a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 1, 1, 0x2a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		raw := decodeFuzzEntries(data)
		var entries []Entry
		for _, e := range raw {
			// NewMatcher refuses invalid, mapped and too-broad prefixes, so the
			// oracle is fed only what the matcher accepts.
			if !e.Prefix.IsValid() || e.Prefix.Addr().Is4In6() || e.Prefix.Bits() < minPrefixBits(e.Prefix.Addr()) {
				continue
			}
			entries = append(entries, Entry{Prefix: e.Prefix.Masked(), Category: e.Category})
		}
		m, err := NewMatcher(entries)
		if err != nil {
			t.Fatalf("NewMatcher on canonical entries: %v", err)
		}

		// Oracle input: the set without duplicates, as the matcher stores it.
		unique := map[Entry]struct{}{}
		var set []Entry
		for _, e := range entries {
			if _, dup := unique[e]; !dup {
				unique[e] = struct{}{}
				set = append(set, e)
			}
		}

		for _, e := range entries {
			for _, probe := range []netip.Addr{e.Prefix.Addr(), netip.AddrFrom16(e.Prefix.Addr().As16())} {
				if probe.Is4() {
					probe = netip.AddrFrom16(probe.As16()) // mapped form, looked up as IPv4
				}
				got, err := m.Lookup(probe)
				if err != nil {
					t.Fatalf("Lookup(%s): %v", probe, err)
				}
				var want []Entry
				for _, s := range set {
					if s.Prefix.Contains(probe.Unmap()) {
						want = append(want, s)
					}
				}
				slices.SortFunc(want, oracleOrder)
				if !slices.Equal(got, want) {
					t.Fatalf("Lookup(%s) = %v, oracle %v", probe, got, want)
				}
			}
		}
	})
}

// FuzzValidateNeverKeepsSpecialOverlap checks the invariants of Validate on
// arbitrary input: no kept prefix overlaps a special range, the minimum
// length holds, every kept prefix is canonical and not IPv4-mapped, and the
// counters match the dropped list.
func FuzzValidateNeverKeepsSpecialOverlap(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries := decodeFuzzEntries(data)
		caps := Caps{PerFeed: len(entries) + 1, Total: len(entries) + 1}
		// Deterministic overlap stand-in: flags every even-length prefix.
		overlaps := func(p netip.Prefix) bool { return p.Bits()%2 == 0 }

		res, err := Validate(entries, caps, overlaps)
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		for _, k := range res.Kept {
			p := k.Prefix
			if !p.IsValid() || p.Addr().Is4In6() || p.Masked() != p {
				t.Fatalf("kept non-canonical prefix %v", p)
			}
			if (p.Addr().Is4() && p.Bits() < MinPrefixV4) || (p.Addr().Is6() && p.Bits() < MinPrefixV6) {
				t.Fatalf("kept prefix %v below minimum length", p)
			}
			for _, s := range specialRanges {
				if p.Overlaps(s.prefix) {
					t.Fatalf("kept %v overlapping special range %v (%v)", p, s.prefix, s.reason)
				}
			}
			if overlaps(p) {
				t.Fatalf("kept %v flagged by overlap check", p)
			}
			if !validCategory(k.Category) {
				t.Fatalf("kept invalid category %q", k.Category)
			}
		}
		if got := res.Counts.total(); got != len(res.Dropped) {
			t.Fatalf("counters total %d, dropped list %d", got, len(res.Dropped))
		}
		if len(res.Kept)+len(res.Dropped) > len(entries) {
			t.Fatalf("kept %d + dropped %d exceeds input %d", len(res.Kept), len(res.Dropped), len(entries))
		}
	})
}

// fuzzSeedRecord builds one full recordBytes record: family flag, address
// bytes, prefix length byte and category index.
func fuzzSeedRecord(v6 bool, addr []byte, bits, cat byte) []byte {
	rec := make([]byte, recordBytes)
	if v6 {
		rec[0] = 1
	}
	copy(rec[1:17], addr)
	rec[17] = bits
	rec[18] = cat
	return rec
}

// fuzzSeeds are complete records. A seed shorter than recordBytes decodes to
// zero entries and exercises nothing (see TestFuzzSeedsDecodeToEntries).
var fuzzSeeds = [][]byte{
	fuzzSeedRecord(false, []byte{10, 0, 0, 0}, 24, 0),
	fuzzSeedRecord(false, []byte{8, 8, 4, 1}, 16, 1),
	fuzzSeedRecord(true, []byte{0xfe, 0x80}, 64, 0),
}

// TestFuzzSeedsDecodeToEntries: every Validate fuzz seed must yield an entry,
// otherwise the seed checks nothing.
func TestFuzzSeedsDecodeToEntries(t *testing.T) {
	for i, seed := range fuzzSeeds {
		if got := decodeFuzzEntries(seed); len(got) != 1 {
			t.Fatalf("seed %d decodes to %d entries, want 1", i, len(got))
		}
	}
}

// total sums every counter; used by the fuzz invariants.
func (c Counts) total() int {
	return c.Invalid + c.TooBroad + c.Special + c.Private + c.CGNAT + c.Documentation + c.Reserved + c.Overlap
}

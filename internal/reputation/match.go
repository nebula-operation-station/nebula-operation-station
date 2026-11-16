// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// Matcher errors. Callers branch with errors.Is.
var (
	// ErrInvalidPrefix refuses a prefix that is not canonical or is IPv4-mapped.
	ErrInvalidPrefix = errors.New("reputation: invalid matcher prefix")
	// ErrInvalidAddress refuses the zero netip.Addr.
	ErrInvalidAddress = errors.New("reputation: invalid address")
	// ErrZonedAddress refuses an address with an IPv6 zone.
	ErrZonedAddress = errors.New("reputation: zoned address refused")
	// ErrMatcherTooLarge refuses more entries than MaxMatcherEntries.
	ErrMatcherTooLarge = errors.New("reputation: too many entries for matcher")
)

// MaxMatcherEntries caps the entries one NewMatcher call accepts. A trie node
// is about 48 bytes and an IPv6 /128 entry adds up to 128 nodes, so the cap
// bounds the matcher at about 96 MiB whatever the feed contains (2^14 * 128 *
// 48 bytes). The Validate caps are caller-supplied; this one is fixed because
// it bounds memory on the matcher side.
const MaxMatcherEntries = 1 << 14

// minPrefixBits returns the shortest prefix length the matcher accepts for the
// family of a (ADR 0012 D6).
func minPrefixBits(a netip.Addr) int {
	if a.Is4() {
		return MinPrefixV4
	}
	return MinPrefixV6
}

// Matcher answers "which entries cover this address" for one set of entries.
// It is immutable after NewMatcher: Lookup only reads, and the zero value
// matches nothing. The IPv4 and IPv6 tries are separate binary tries over
// prefix bits.
type Matcher struct {
	v4 *trieNode
	v6 *trieNode
}

// trieNode is one bit position of the trie. entries holds the entries whose
// prefix ends at this node, in category order.
type trieNode struct {
	child   [2]*trieNode
	entries []Entry
}

// NewMatcher builds a matcher from entries. The input slice is not kept and
// may be reordered or reused by the caller; duplicates (same prefix and
// category) are merged, so any input order gives the same matcher. Entries
// are expected to be validated by Validate first. NewMatcher checks only that
// each prefix is canonical, not IPv4-mapped and at least MinPrefixV4 (IPv4) or
// MinPrefixV6 (IPv6) long, and that there are at most MaxMatcherEntries
// entries (ErrMatcherTooLarge). Special-range and overlap rules stay in Validate.
func NewMatcher(entries []Entry) (*Matcher, error) {
	if len(entries) > MaxMatcherEntries {
		return nil, fmt.Errorf("%d entries, cap %d: %w", len(entries), MaxMatcherEntries, ErrMatcherTooLarge)
	}
	sorted := slices.Clone(entries)
	for _, e := range sorted {
		p := e.Prefix
		if !p.IsValid() || p.Addr().Is4In6() || p.Masked() != p || p.Bits() < minPrefixBits(p.Addr()) {
			return nil, fmt.Errorf("entry %q: %w", p.String(), ErrInvalidPrefix)
		}
	}
	slices.SortFunc(sorted, compareEntries)

	m := &Matcher{v4: &trieNode{}, v6: &trieNode{}}
	for i, e := range sorted {
		if i > 0 && e == sorted[i-1] {
			continue
		}
		root := m.v4
		if e.Prefix.Addr().Is6() {
			root = m.v6
		}
		insert(root, e)
	}
	return m, nil
}

// insert places e at the node reached by following its prefix bits.
func insert(root *trieNode, e Entry) {
	bits := e.Prefix.Addr().AsSlice()
	n := root
	for i := 0; i < e.Prefix.Bits(); i++ {
		b := bitAt(bits, i)
		if n.child[b] == nil {
			n.child[b] = &trieNode{}
		}
		n = n.child[b]
	}
	n.entries = append(n.entries, e)
}

// bitAt returns bit i (0 = most significant) of a big-endian address.
func bitAt(addr []byte, i int) byte {
	return (addr[i/8] >> (7 - uint(i%8))) & 1
}

// Lookup returns every entry whose prefix covers addr, in a fixed order:
// shortest prefix first (broadest), then category. An IPv4-mapped IPv6
// address is looked up as IPv4. An address with an IPv6 zone is refused with
// ErrZonedAddress. The returned slice is a copy and may be modified.
func (m *Matcher) Lookup(addr netip.Addr) ([]Entry, error) {
	if !addr.IsValid() {
		return nil, ErrInvalidAddress
	}
	if addr.Zone() != "" {
		return nil, ErrZonedAddress
	}
	if m == nil {
		return nil, nil
	}
	addr = addr.Unmap()

	n := m.v6
	if addr.Is4() {
		n = m.v4
	}
	bits := addr.AsSlice()
	var out []Entry
	for depth := 0; n != nil; depth++ {
		out = append(out, n.entries...)
		if depth == len(bits)*8 {
			break
		}
		n = n.child[bitAt(bits, depth)]
	}
	return out, nil
}

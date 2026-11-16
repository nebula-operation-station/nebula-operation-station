// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Sentinel errors. Callers branch with errors.Is.
var (
	// ErrOverCap refuses a snapshot with more entries than Caps.PerFeed.
	ErrOverCap = errors.New("reputation: snapshot exceeds per-feed entry cap")
	// ErrTotalCap refuses a set of snapshots whose kept entries exceed Caps.Total.
	ErrTotalCap = errors.New("reputation: total entry cap exceeded")
	// ErrInvalidCaps refuses caps that are not positive.
	ErrInvalidCaps = errors.New("reputation: entry caps must be positive")
	// ErrNoOverlapCheck refuses a call without the IPAM/NOS-path check.
	ErrNoOverlapCheck = errors.New("reputation: overlap check is required")
)

// Reason names why an entry was dropped. ReasonNone means kept.
type Reason uint8

// Drop reasons. Each is counted separately in Counts.
const (
	ReasonNone Reason = iota
	ReasonInvalid
	ReasonTooBroad
	ReasonSpecial
	ReasonPrivate
	ReasonCGNAT
	ReasonDocumentation
	ReasonReserved
	ReasonOverlap
)

// String returns a fixed, lower-case name for the reason.
func (r Reason) String() string {
	switch r {
	case ReasonInvalid:
		return "invalid"
	case ReasonTooBroad:
		return "too-broad"
	case ReasonSpecial:
		return "special"
	case ReasonPrivate:
		return "private"
	case ReasonCGNAT:
		return "cgnat"
	case ReasonDocumentation:
		return "documentation"
	case ReasonReserved:
		return "reserved"
	case ReasonOverlap:
		return "overlap"
	}
	return "none"
}

// Entry is one normalised feed entry: a canonical prefix and a category.
type Entry struct {
	Prefix   netip.Prefix
	Category string
}

// Dropped is a rejected entry with the reason, listed for the admin. Category
// is empty when the feed label failed validation (ReasonInvalid), so no
// untrusted label text reaches the listing.
type Dropped struct {
	Entry  Entry
	Reason Reason
}

// Counts holds the number of dropped entries per reason.
type Counts struct {
	Invalid       int
	TooBroad      int
	Special       int
	Private       int
	CGNAT         int
	Documentation int
	Reserved      int
	Overlap       int
}

// Result is the outcome of Validate. Kept and Dropped are in canonical order,
// so the same set of input entries gives the same result in any input order.
type Result struct {
	Kept    []Entry
	Dropped []Dropped
	Counts  Counts
}

// specialRule maps one reserved address range to its drop reason. The table
// is checked in order and the first overlapping range decides the reason, so
// more specific ranges come before covering ones.
type specialRule struct {
	prefix netip.Prefix
	reason Reason
}

// specialRanges lists the ranges a snapshot prefix may not overlap (ADR 0012
// D6: special, private, CGNAT, documentation and reserved ranges). The
// literals are checked by tests, so a typo cannot reach runtime.
var specialRanges = []specialRule{
	{netip.MustParsePrefix("127.0.0.0/8"), ReasonSpecial},
	{netip.MustParsePrefix("169.254.0.0/16"), ReasonSpecial},
	{netip.MustParsePrefix("198.18.0.0/15"), ReasonSpecial},
	{netip.MustParsePrefix("224.0.0.0/4"), ReasonSpecial},
	{netip.MustParsePrefix("0.0.0.0/8"), ReasonReserved},
	{netip.MustParsePrefix("192.0.0.0/24"), ReasonReserved},
	{netip.MustParsePrefix("192.88.99.0/24"), ReasonReserved},
	{netip.MustParsePrefix("240.0.0.0/4"), ReasonReserved},
	{netip.MustParsePrefix("10.0.0.0/8"), ReasonPrivate},
	{netip.MustParsePrefix("172.16.0.0/12"), ReasonPrivate},
	{netip.MustParsePrefix("192.168.0.0/16"), ReasonPrivate},
	{netip.MustParsePrefix("100.64.0.0/10"), ReasonCGNAT},
	{netip.MustParsePrefix("192.0.2.0/24"), ReasonDocumentation},
	{netip.MustParsePrefix("198.51.100.0/24"), ReasonDocumentation},
	{netip.MustParsePrefix("203.0.113.0/24"), ReasonDocumentation},
	{netip.MustParsePrefix("::1/128"), ReasonSpecial},
	{netip.MustParsePrefix("::/8"), ReasonReserved},
	{netip.MustParsePrefix("100::/64"), ReasonSpecial},
	{netip.MustParsePrefix("2001::/23"), ReasonReserved},
	{netip.MustParsePrefix("2001:db8::/32"), ReasonDocumentation},
	{netip.MustParsePrefix("3fff::/20"), ReasonDocumentation},
	{netip.MustParsePrefix("5f00::/16"), ReasonReserved},
	{netip.MustParsePrefix("fc00::/7"), ReasonPrivate},
	{netip.MustParsePrefix("fe80::/10"), ReasonSpecial},
	{netip.MustParsePrefix("ff00::/8"), ReasonSpecial},
}

// Validate applies the NOS-side checks of ADR 0012 D6 to one feed snapshot.
// A snapshot with more than caps.PerFeed entries is refused whole with
// ErrOverCap. Otherwise each entry is kept or dropped and counted under its
// reason: invalid syntax or category, prefix shorter than the minimum,
// special/private/CGNAT/documentation/reserved range, or overlap with an
// IPAM network or the NOS path as reported by overlaps. The overlaps function
// must be non-nil; it is consulted only for entries that pass the other checks.
func Validate(entries []Entry, caps Caps, overlaps func(netip.Prefix) bool) (Result, error) {
	if caps.PerFeed <= 0 || caps.Total <= 0 {
		return Result{}, ErrInvalidCaps
	}
	if overlaps == nil {
		return Result{}, ErrNoOverlapCheck
	}
	if len(entries) > caps.PerFeed {
		return Result{}, fmt.Errorf("%d entries, cap %d: %w", len(entries), caps.PerFeed, ErrOverCap)
	}

	var res Result
	seen := make(map[Entry]struct{}, len(entries))
	for _, e := range entries {
		r := classify(e, overlaps)
		if r != ReasonNone {
			d := Dropped{Entry: e, Reason: r}
			if !validCategory(e.Category) {
				// The raw label is untrusted (possibly oversized or not text), so
				// the admin listing gets no category for it.
				d.Entry.Category = ""
			}
			res.Dropped = append(res.Dropped, d)
			res.Counts.add(r)
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		res.Kept = append(res.Kept, e)
	}

	slices.SortFunc(res.Kept, compareEntries)
	slices.SortFunc(res.Dropped, func(a, b Dropped) int {
		return cmp.Or(compareEntries(a.Entry, b.Entry), cmp.Compare(a.Reason, b.Reason))
	})
	return res, nil
}

// CheckTotal refuses a set of snapshots whose kept entry counts sum above
// caps.Total (ErrTotalCap). It does not trim; the caller keeps the previous
// snapshot set in that case.
func CheckTotal(keptPerFeed []int, caps Caps) error {
	if caps.Total <= 0 {
		return ErrInvalidCaps
	}
	// The running sum never exceeds caps.Total, so comparing n against the
	// remaining room cannot overflow, even for very large counts.
	sum := 0
	for _, n := range keptPerFeed {
		if n < 0 {
			return fmt.Errorf("negative entry count %d: %w", n, ErrInvalidCaps)
		}
		if n > caps.Total-sum {
			return fmt.Errorf("entries exceed cap %d: %w", caps.Total, ErrTotalCap)
		}
		sum += n
	}
	return nil
}

// classify returns the drop reason for e, or ReasonNone when e is kept.
// The checks run in ADR order; the overlap function runs last.
func classify(e Entry, overlaps func(netip.Prefix) bool) Reason {
	p := e.Prefix
	if !p.IsValid() || p.Addr().Is4In6() || p.Masked() != p || !validCategory(e.Category) {
		return ReasonInvalid
	}
	if (p.Addr().Is4() && p.Bits() < MinPrefixV4) || (p.Addr().Is6() && p.Bits() < MinPrefixV6) {
		return ReasonTooBroad
	}
	for _, s := range specialRanges {
		if p.Overlaps(s.prefix) {
			return s.reason
		}
	}
	if overlaps(p) {
		return ReasonOverlap
	}
	return ReasonNone
}

// validCategory accepts 1 to MaxCategoryBytes bytes of lower-case ASCII
// letters, digits, '-' and '_'. Feed text is rendered as text only.
func validCategory(c string) bool {
	if len(c) == 0 || len(c) > MaxCategoryBytes {
		return false
	}
	for i := 0; i < len(c); i++ {
		b := c[i]
		switch {
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '_':
		default:
			return false
		}
	}
	return true
}

// compareEntries orders by address, then prefix length, then category.
func compareEntries(a, b Entry) int {
	return cmp.Or(
		a.Prefix.Addr().Compare(b.Prefix.Addr()),
		cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()),
		strings.Compare(a.Category, b.Category),
	)
}

func (c *Counts) add(r Reason) {
	switch r {
	case ReasonInvalid:
		c.Invalid++
	case ReasonTooBroad:
		c.TooBroad++
	case ReasonSpecial:
		c.Special++
	case ReasonPrivate:
		c.Private++
	case ReasonCGNAT:
		c.CGNAT++
	case ReasonDocumentation:
		c.Documentation++
	case ReasonReserved:
		c.Reserved++
	case ReasonOverlap:
		c.Overlap++
	}
}

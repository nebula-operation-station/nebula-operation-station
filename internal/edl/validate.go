// SPDX-License-Identifier: AGPL-3.0-or-later

package edl

import (
	"errors"
	"fmt"
	"net/netip"
)

// Sentinel errors, one per refusal reason, so callers can branch with errors.Is.
var (
	// ErrInvalidEntry means the entry is the zero prefix or otherwise unusable.
	ErrInvalidEntry = errors.New("edl: invalid entry")
	// ErrInvalidRefusal means an injected refusal prefix is invalid. The check
	// fails closed instead of silently refusing nothing.
	ErrInvalidRefusal = errors.New("edl: invalid refusal prefix")
	// ErrSpecialRange means the entry overlaps a private, reserved or special range.
	ErrSpecialRange = errors.New("edl: entry overlaps a private, reserved or special range")
	// ErrIPAMNetwork means the entry overlaps an IPAM network.
	ErrIPAMNetwork = errors.New("edl: entry overlaps an IPAM network")
	// ErrNOSPath means the entry overlaps the NOS path.
	ErrNOSPath = errors.New("edl: entry overlaps the NOS path")
	// ErrFirewallAddress means the entry overlaps an address of the firewall.
	ErrFirewallAddress = errors.New("edl: entry overlaps a firewall address")
	// ErrProtectedTarget means the entry overlaps a configured protected destination.
	ErrProtectedTarget = errors.New("edl: entry overlaps a protected destination")
)

// Refusals holds the injected prefixes that entries must not overlap. Each
// field is one refusal reason from ADR 0012 D7. The special-range table is
// fixed in this package.
type Refusals struct {
	// IPAM lists the networks known to the IPAM.
	IPAM []netip.Prefix
	// NOSPath lists the addresses on the NOS path.
	NOSPath []netip.Prefix
	// FirewallAddresses lists the firewall's own addresses.
	FirewallAddresses []netip.Prefix
	// ProtectedTargets lists DNS upstreams, update mirrors, feed origins,
	// NetBird management and operator-listed destinations.
	ProtectedTargets []netip.Prefix
}

// specialRanges is the fixed table of private, reserved and special-purpose
// ranges (IANA IPv4 and IPv6 special-purpose registries). Constant literals, so
// parsing at init cannot fail for runtime input.
var specialRanges = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),       // this network
	netip.MustParsePrefix("10.0.0.0/8"),      // private
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (CGNAT)
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // private
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation (TEST-NET-1)
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("192.168.0.0/16"),  // private
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation (TEST-NET-3)
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes broadcast
	// IPv6
	netip.MustParsePrefix("::/96"),          // unspecified, IPv4-compatible (deprecated)
	netip.MustParsePrefix("::ffff:0:0/96"),  // IPv4-mapped
	netip.MustParsePrefix("64:ff9b::/96"),   // IPv4/IPv6 translation
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use translation
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/23"),      // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("2002::/16"),      // 6to4
	netip.MustParsePrefix("3fff::/20"),      // documentation
	netip.MustParsePrefix("fc00::/7"),       // unique local
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("fec0::/10"),      // site-local (deprecated)
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

// Check reports whether entry may be added to or published in a list. It
// returns nil when entry overlaps none of the special ranges or injected
// refusals in r. An overlap counts in both directions: the entry may contain
// a refused prefix, or lie inside one. The entry is judged by its masked
// network. Every error wraps one of the sentinel errors above.
func Check(entry netip.Prefix, r Refusals) error {
	if !entry.IsValid() {
		return fmt.Errorf("%w: zero prefix", ErrInvalidEntry)
	}
	if err := r.validate(); err != nil {
		return err
	}
	e := entry.Masked()
	if firstOverlap(e, specialRanges) {
		return fmt.Errorf("%w: %s", ErrSpecialRange, e)
	}
	if firstOverlap(e, r.IPAM) {
		return fmt.Errorf("%w: %s", ErrIPAMNetwork, e)
	}
	if firstOverlap(e, r.NOSPath) {
		return fmt.Errorf("%w: %s", ErrNOSPath, e)
	}
	if firstOverlap(e, r.FirewallAddresses) {
		return fmt.Errorf("%w: %s", ErrFirewallAddress, e)
	}
	if firstOverlap(e, r.ProtectedTargets) {
		return fmt.Errorf("%w: %s", ErrProtectedTarget, e)
	}
	return nil
}

// validate fails if any injected refusal prefix is invalid.
func (r Refusals) validate() error {
	for _, set := range [][]netip.Prefix{r.IPAM, r.NOSPath, r.FirewallAddresses, r.ProtectedTargets} {
		for _, p := range set {
			if !p.IsValid() {
				return ErrInvalidRefusal
			}
		}
	}
	return nil
}

// firstOverlap reports whether e overlaps any prefix in set.
func firstOverlap(e netip.Prefix, set []netip.Prefix) bool {
	for _, p := range set {
		if overlaps(e, p.Masked()) {
			return true
		}
	}
	return false
}

// overlaps reports whether two masked prefixes share an address. Prefixes of
// the same family overlap exactly when the shorter one contains the longer
// one's network address.
func overlaps(a, b netip.Prefix) bool {
	if a.Addr().BitLen() != b.Addr().BitLen() {
		return false
	}
	if a.Bits() <= b.Bits() {
		return a.Contains(b.Addr())
	}
	return b.Contains(a.Addr())
}

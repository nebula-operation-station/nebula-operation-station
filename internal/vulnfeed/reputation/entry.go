// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrMalformedEntry is returned for an entry or record that breaks the
// entry rules. The message never repeats the untrusted text.
var ErrMalformedEntry = errors.New("reputation: malformed feed entry")

// Entry is one normalised feed entry: a network and the category of the
// feed that lists it.
type Entry struct {
	// Prefix is the masked network (host bits are zero).
	Prefix netip.Prefix
	// Category is the fixed category of the feed.
	Category Category
}

// ParseEntry normalises one entry text to a masked prefix. It accepts an
// IPv4 or IPv6 address, optionally with a prefix length, surrounded by
// blanks. A bare address becomes a host prefix (/32 or /128). Host bits are
// masked, so the result is the network the entry names.
//
// It rejects zones, IPv4-mapped IPv6 spellings and the default routes
// (/0), since they do not name one network the way the feed means it.
func ParseEntry(text string) (netip.Prefix, error) {
	t := strings.Trim(text, " \t")
	if t == "" || len(t) > maxEntryTextBytes {
		return netip.Prefix{}, malformed("entry is empty or too long")
	}
	var p netip.Prefix
	if strings.Contains(t, "/") {
		parsed, err := netip.ParsePrefix(t)
		if err != nil {
			return netip.Prefix{}, malformed("entry is not an address prefix")
		}
		p = parsed
	} else {
		addr, err := netip.ParseAddr(t)
		if err != nil {
			return netip.Prefix{}, malformed("entry is not an address")
		}
		// Checked before PrefixFrom, which drops the zone.
		if addr.Zone() != "" {
			return netip.Prefix{}, malformed("entry has an IPv6 zone")
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	addr := p.Addr()
	switch {
	case addr.Zone() != "":
		return netip.Prefix{}, malformed("entry has an IPv6 zone")
	case addr.Is4In6():
		return netip.Prefix{}, malformed("entry is an IPv4-mapped IPv6 address")
	case p.Bits() == 0:
		return netip.Prefix{}, malformed("entry is a default route")
	}
	return p.Masked(), nil
}

// malformed wraps ErrMalformedEntry with a fixed reason. The reason is a
// constant, so no feed text reaches the error.
func malformed(reason string) error {
	return fmt.Errorf("%w: %s", ErrMalformedEntry, reason)
}

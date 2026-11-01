// SPDX-License-Identifier: AGPL-3.0-or-later

// Package invsort orders inventory host names the way an operator
// expects them: IP addresses compare numerically (IPv4 before IPv6,
// IPs before non-IPs), everything else compares in natural order
// (digit runs as numbers, case-insensitive), so "192.168.0.25" comes
// before "192.168.0.221" and "node2" before "node10".
package invsort

import (
	"net/netip"
	"strings"
	"unicode"
)

// Less reports whether a sorts before b. It is a strict weak ordering:
// irreflexive, antisymmetric, and transitive, so it is safe as a
// sort.Slice comparator.
func Less(a, b string) bool {
	ia, oka := parseAddr(a)
	ib, okb := parseAddr(b)
	switch {
	case oka && okb:
		if ia.Is4() != ib.Is4() {
			return ia.Is4() // IPv4 before IPv6
		}
		return ia.Less(ib)
	case oka:
		return true // IPs before non-IPs
	case okb:
		return false
	}
	return naturalLess(a, b)
}

// parseAddr parses s as a bare IP address (no port, no whitespace).
func parseAddr(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// naturalLess reports whether a sorts before b in natural order:
// digit runs compare as numbers (leading zeros ignored), all other
// characters compare case-insensitively, and a prefix sorts before its
// extensions.
func naturalLess(a, b string) bool {
	ra := []rune(a)
	rb := []rune(b)
	i, j := 0, 0
	for i < len(ra) && j < len(rb) {
		if isASCIIDigit(ra[i]) && isASCIIDigit(rb[j]) {
			da, ni := digitRun(ra, i)
			db, nj := digitRun(rb, j)
			if c := compareDigits(da, db); c != 0 {
				return c < 0
			}
			i, j = ni, nj
			continue
		}
		la := unicode.ToLower(ra[i])
		lb := unicode.ToLower(rb[j])
		if la != lb {
			return la < lb
		}
		i++
		j++
	}
	return len(ra) < len(rb)
}

// digitRun returns the ASCII digit run at i with its leading zeros
// stripped, and the index just past the run.
func digitRun(r []rune, i int) (string, int) {
	j := i
	for j < len(r) && isASCIIDigit(r[j]) {
		j++
	}
	k := i
	for k < j && r[k] == '0' {
		k++
	}
	return string(r[k:j]), j
}

// compareDigits compares two zero-stripped digit runs as numbers:
// shorter (after stripping) means smaller, then lexicographic.
func compareDigits(a, b string) int {
	switch {
	case len(a) != len(b):
		if len(a) < len(b) {
			return -1
		}
		return 1
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func isASCIIDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

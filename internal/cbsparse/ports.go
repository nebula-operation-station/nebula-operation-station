// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// portMaxDigits bounds one number of a CBS port name (unit, slot, port or
// channel). Real values have one or two digits.
const portMaxDigits = 3

// portListMaxTokens bounds the comma-separated entries of one VLAN port
// list cell, so that a hostile list is refused before it is expanded.
const portListMaxTokens = netdevcontract.MaxInterfacesPerDevice

// parsePortName validates a CBS port name and splits it into the prefix
// up to its last number and that number. Accepted forms (*verify* in
// ND-03 against lab output):
//
//   - gi<p>, te<p>              CBS250 and stand-alone CBS350 numbering
//   - gi<u>/<s>/<p>, te<u>/<s>/<p>  CBS350 unit/slot/port numbering
//   - Po<n>                     port channel (LAG)
//
// Every number is decimal without a leading zero and at most
// portMaxDigits digits; the slot may be 0, every other number is at least
// 1. Any other syntax (other prefixes, case, separators) is unknown.
func parsePortName(s string) (prefix string, last int, ok bool) {
	var rest string
	var slashForm bool
	switch {
	case strings.HasPrefix(s, "gi"), strings.HasPrefix(s, "te"):
		rest, slashForm = s[2:], true
	case strings.HasPrefix(s, "Po"):
		rest = s[2:]
	default:
		return "", 0, false
	}
	comps := strings.Split(rest, "/")
	if len(comps) != 1 && (!slashForm || len(comps) != 3) {
		return "", 0, false
	}
	for i, c := range comps {
		n, ok := parseDecimal(c, portMaxDigits)
		if !ok {
			return "", 0, false
		}
		isSlot := len(comps) == 3 && i == 1
		if n == 0 && !isSlot {
			return "", 0, false
		}
		last = n
	}
	if !netdevcontract.ValidInterfaceName(s) {
		return "", 0, false
	}
	return s[:len(s)-len(comps[len(comps)-1])], last, true
}

// validPortName reports whether s is an accepted CBS port name.
func validPortName(s string) bool {
	_, _, ok := parsePortName(s)
	return ok
}

// parsePortList expands a CBS port list such as "gi1/0/1-4,te1/0/1,Po1-2"
// into port names in list order. A range varies the last number of the
// port name ("gi1/0/1-4" is gi1/0/1 to gi1/0/4). An empty list is valid
// and has no ports. ok is false for an empty entry, an unknown port name,
// a reversed range, a port listed twice, or more than
// MaxInterfacesPerDevice ports; the range size is checked before the
// range is expanded.
func parsePortList(s string) ([]string, bool) {
	if s == "" {
		return nil, true
	}
	tokens := strings.Split(s, ",")
	if netdevcontract.CheckCount("port list entries", len(tokens), portListMaxTokens) != nil {
		return nil, false
	}
	var ports []string
	seen := map[string]struct{}{}
	for _, tok := range tokens {
		base, hiText, isRange := strings.Cut(tok, "-")
		prefix, lo, ok := parsePortName(base)
		if !ok {
			return nil, false
		}
		hi := lo
		if isRange {
			if hi, ok = parseDecimal(hiText, portMaxDigits); !ok || hi < lo {
				return nil, false
			}
		}
		if netdevcontract.CheckCount("port list ports", len(ports)+hi-lo+1, netdevcontract.MaxInterfacesPerDevice) != nil {
			return nil, false
		}
		for n := lo; n <= hi; n++ {
			name := prefix + strconv.Itoa(n)
			if _, dup := seen[name]; dup {
				return nil, false
			}
			seen[name] = struct{}{}
			ports = append(ports, name)
		}
	}
	return ports, true
}

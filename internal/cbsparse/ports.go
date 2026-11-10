// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
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

var (
	// errPortList reports a malformed port list.
	errPortList = errors.New("malformed port list")
	// errMembershipCap reports that expanding a port list would exceed the
	// membership budget of the parse.
	errMembershipCap = errors.New("port membership cap reached")
)

// parsePortList expands a CBS port list such as "gi1/0/1-4,te1/0/1,Po1-2"
// into port names in list order. A range varies the last number of the
// port name ("gi1/0/1-4" is gi1/0/1 to gi1/0/4). An empty list is valid
// and has no ports.
//
// The error is errPortList for an empty entry, an unknown port name, a
// reversed range, a port listed twice, or more than
// MaxInterfacesPerDevice ports. budget is the number of ports the caller
// may still expand: every entry is charged against it before it is
// expanded, and an entry larger than what is left is errMembershipCap.
// The per-list limit is checked first, so an over-long list is always
// errPortList. On error the ports are nil; the budget keeps the charges
// of the entries already expanded.
func parsePortList(s string, budget *int) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	tokens := strings.Split(s, ",")
	if netdevcontract.CheckCount("port list entries", len(tokens), portListMaxTokens) != nil {
		return nil, errPortList
	}
	var ports []string
	seen := map[string]struct{}{}
	for _, tok := range tokens {
		base, hiText, isRange := strings.Cut(tok, "-")
		prefix, lo, ok := parsePortName(base)
		if !ok {
			return nil, errPortList
		}
		hi := lo
		if isRange {
			if hi, ok = parseDecimal(hiText, portMaxDigits); !ok || hi < lo {
				return nil, errPortList
			}
		}
		n := hi - lo + 1
		if netdevcontract.CheckCount("port list ports", len(ports)+n, netdevcontract.MaxInterfacesPerDevice) != nil {
			return nil, errPortList
		}
		if n > *budget {
			return nil, errMembershipCap
		}
		*budget -= n
		for p := lo; p <= hi; p++ {
			name := prefix + strconv.Itoa(p)
			if _, dup := seen[name]; dup {
				return nil, errPortList
			}
			seen[name] = struct{}{}
			ports = append(ports, name)
		}
	}
	return ports, nil
}

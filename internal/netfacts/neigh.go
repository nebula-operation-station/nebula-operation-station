// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
)

// Neighbor is one entry of the host's neighbor (ARP/NDP) table.
type Neighbor struct {
	// IP is the neighbor's IP address.
	IP netip.Addr
	// Dev is the interface the neighbor is reachable on.
	Dev string
	// MAC is the link-layer address; empty while the entry is
	// INCOMPLETE or FAILED, when the host reported none, or when the
	// reported address is not a 6-byte Ethernet MAC.
	MAC net.HardwareAddr
	// State holds the NUD states the host reported (REACHABLE, STALE,
	// FAILED, INCOMPLETE, ...), in host order, at most maxStates.
	State []string
}

// neighDoc is the permissive shape of one `ip -j neigh` array element.
// Unknown fields are dropped (spec 09).
type neighDoc struct {
	IP     string   `json:"ip"`
	Dev    string   `json:"dev"`
	LLAddr string   `json:"lladdr"`
	State  []string `json:"state"`
}

// unmarshalArray decodes raw as a JSON array of raw elements. A null or
// non-array document is an error, never an empty list (spec 09: incomplete
// data is marked, not presented as a complete empty dataset).
func unmarshalArray(raw []byte, what string) ([]json.RawMessage, error) {
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, fmt.Errorf("parse %s: %w", what, err)
	}
	if elems == nil {
		return nil, fmt.Errorf("parse %s: input is not a JSON array", what)
	}
	return elems, nil
}

// ParseNeigh parses the JSON array printed by `ip -j neigh`.
//
// Entries without a valid IP or without a valid device are skipped. An
// invalid or non-Ethernet link-layer address is dropped (MAC stays empty).
// Invalid state strings are dropped and the state list is truncated at
// maxStates. Input above maxInputSize, a document that is not a JSON
// array, or a document with more than maxEntries valid entries is an
// error. One bad entry never discards the rest of the table.
func ParseNeigh(raw []byte) ([]Neighbor, error) {
	if len(raw) > maxInputSize {
		return nil, fmt.Errorf("neighbor document exceeds %d bytes", maxInputSize)
	}
	elems, err := unmarshalArray(raw, "neighbors")
	if err != nil {
		return nil, err
	}
	out := make([]Neighbor, 0, len(elems))
	for _, e := range elems {
		var d neighDoc
		if err := json.Unmarshal(e, &d); err != nil {
			continue
		}
		ip, err := netip.ParseAddr(d.IP)
		if err != nil {
			continue
		}
		if !printable(d.Dev, maxStringLen) {
			continue
		}
		n := Neighbor{IP: ip, Dev: d.Dev}
		if d.LLAddr != "" {
			if mac, err := net.ParseMAC(d.LLAddr); err == nil && len(mac) == 6 {
				n.MAC = mac
			}
		}
		for _, s := range d.State {
			if len(n.State) >= maxStates {
				break
			}
			if printable(s, maxStringLen) {
				n.State = append(n.State, s)
			}
		}
		if len(out) >= maxEntries {
			return nil, fmt.Errorf("neighbor list exceeds %d entries", maxEntries)
		}
		out = append(out, n)
	}
	return out, nil
}

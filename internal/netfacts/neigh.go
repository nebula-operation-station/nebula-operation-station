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
	// Dev is the interface the neighbor is reachable on (a Linux
	// interface name, see validIfName).
	Dev string
	// MAC is the link-layer address; empty while the entry is
	// INCOMPLETE or FAILED, when the host reported none, or when the
	// reported address is not a 6-byte Ethernet MAC.
	MAC net.HardwareAddr
	// State holds the known NUD states the host reported (REACHABLE,
	// STALE, FAILED, INCOMPLETE, ...; see nudStates), in host order, at
	// most maxStates.
	State []string
}

// nudStates are the neighbor state names iproute2 prints (nud_state_n2a).
// Any other state string from the host is dropped.
var nudStates = map[string]bool{
	"INCOMPLETE": true,
	"REACHABLE":  true,
	"STALE":      true,
	"DELAY":      true,
	"PROBE":      true,
	"FAILED":     true,
	"NOARP":      true,
	"PERMANENT":  true,
	"NONE":       true,
}

// neighDoc is the permissive shape of one `ip -j neigh` array element,
// e.g. {"dst":"10.0.0.1","dev":"eth0","lladdr":"...","router":null,
// "state":["REACHABLE"]}.
// Unknown fields are dropped (spec 09).
type neighDoc struct {
	IP     string   `json:"dst"` // iproute2 prints the neighbor address as "dst"
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

// NeighborTable is the parsed neighbor table of one `ip -j neigh`
// document.
type NeighborTable struct {
	// Entries holds the valid neighbors in host order.
	Entries []Neighbor
	// Dropped counts array elements that were skipped as malformed.
	Dropped int
	// Incomplete is true when the host reported data the parser did not
	// keep: a skipped element (Dropped > 0), an invalid link-layer
	// address, an invalid state, or a state list truncated at maxStates.
	// An incomplete table must be presented as such, never as the
	// complete table (spec 09).
	Incomplete bool
}

// ParseNeigh parses the JSON array printed by `ip -j neigh`.
//
// Entries without a valid IP (including an IPv6 zone that is not a short
// interface name) or without a valid interface name as device are skipped
// and counted in Dropped. An invalid or non-Ethernet link-layer address is
// dropped (MAC stays empty). State strings that are not known NUD state
// names are dropped and the state list is
// truncated at maxStates. Every such loss sets Incomplete. Input above
// maxInputSize, a document that is not a JSON array, or an array with
// more than maxEntries elements is an error. One bad entry never discards
// the rest of the table.
func ParseNeigh(raw []byte) (NeighborTable, error) {
	if len(raw) > maxInputSize {
		return NeighborTable{}, fmt.Errorf("neighbor document exceeds %d bytes", maxInputSize)
	}
	elems, err := unmarshalArray(raw, "neighbors")
	if err != nil {
		return NeighborTable{}, err
	}
	if len(elems) > maxEntries {
		return NeighborTable{}, fmt.Errorf("neighbor list exceeds %d entries", maxEntries)
	}
	t := NeighborTable{Entries: make([]Neighbor, 0, len(elems))}
	for _, e := range elems {
		n, lossy, ok := parseNeighEntry(e)
		if !ok {
			t.Dropped++
			t.Incomplete = true
			continue
		}
		if lossy {
			t.Incomplete = true
		}
		t.Entries = append(t.Entries, n)
	}
	return t, nil
}

// parseNeighEntry parses one neighbor element. ok is false for skipped
// elements; lossy is true when fields of a kept entry were dropped.
func parseNeighEntry(e json.RawMessage) (n Neighbor, lossy, ok bool) {
	var d neighDoc
	if err := json.Unmarshal(e, &d); err != nil {
		return Neighbor{}, false, false
	}
	ip, ok := parseHostAddr(d.IP)
	if !ok {
		return Neighbor{}, false, false
	}
	if !validIfName(d.Dev) {
		return Neighbor{}, false, false
	}
	n = Neighbor{IP: ip, Dev: d.Dev}
	if d.LLAddr != "" {
		if mac, err := net.ParseMAC(d.LLAddr); err == nil && len(mac) == 6 {
			n.MAC = mac
		} else {
			lossy = true
		}
	}
	for _, s := range d.State {
		if len(n.State) >= maxStates {
			lossy = true
			break
		}
		if nudStates[s] {
			n.State = append(n.State, s)
		} else {
			lossy = true
		}
	}
	return n, lossy, true
}

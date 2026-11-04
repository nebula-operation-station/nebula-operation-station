// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
)

// Addr is one interface from `ip -j addr`.
type Addr struct {
	// Name is the interface name (a Linux interface name, see
	// validIfName).
	Name string
	// MAC is the link-layer address; empty when the host reported none
	// or the reported address is not a 6-byte Ethernet MAC.
	MAC net.HardwareAddr
	// State is the operational state the host reported (UP, DOWN,
	// UNKNOWN, ...; see operStates); empty when the host reported none
	// or an unknown state name.
	State string
	// Addrs holds the interface's addresses as prefixes, in host order,
	// at most maxAddrsPerIf. iproute2 prints each address as a bare
	// "local" plus a separate "prefixlen"; the two are combined here.
	Addrs []netip.Prefix
}

// AddrTable is the parsed interface/address list of one `ip -j addr`
// document.
type AddrTable struct {
	// Entries holds the valid interfaces in host order.
	Entries []Addr
	// Dropped counts array elements that were skipped as malformed.
	Dropped int
	// Incomplete is true when the host reported data the parser did not
	// keep: a skipped element (Dropped > 0), an invalid link-layer
	// address, an unknown state, or an address list truncated at
	// maxAddrsPerIf. An incomplete table must be presented as such,
	// never as the complete table (spec 09).
	Incomplete bool
}

// addrDoc is the permissive shape of one `ip -j addr` array element,
// e.g. {"ifname":"eth0","address":"bc:24:11:..","operstate":"UP",
// "addr_info":[{"family":"inet","local":"192.168.0.37","prefixlen":24}]}.
// Unknown fields are dropped (spec 09).
type addrDoc struct {
	IfName    string        `json:"ifname"`
	Address   string        `json:"address"` // the interface's MAC
	OperState string        `json:"operstate"`
	AddrInfo  []addrInfoDoc `json:"addr_info"`
}

// addrInfoDoc is one element of an interface's "addr_info" list. iproute2
// prints the address as a bare "local" and the prefix length as a
// separate "prefixlen" integer; the family selects the bit width.
type addrInfoDoc struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}

// operStates are the operational state names iproute2 prints
// (if_oper_state_n2a). Any other state string from the host is dropped.
var operStates = map[string]bool{
	"UNKNOWN":        true,
	"NOTPRESENT":     true,
	"DOWN":           true,
	"LOWERLAYERDOWN": true,
	"TESTING":        true,
	"DORMANT":        true,
	"UP":             true,
	"STANDBY":        true,
	"POSTPONED":      true,
}

// ParseAddrs parses the JSON array printed by `ip -j addr`.
//
// Each element is one interface. An element without a valid interface
// name is skipped and counted in Dropped. The link-layer address is kept
// only when it is a 6-byte Ethernet MAC; the state only when it is a
// known operational state name. Each "addr_info" entry is combined into a
// prefix from its bare "local" address and "prefixlen"; an entry with an
// invalid address, a prefixlen outside the address family's bit width, or
// a family that is neither inet nor inet6 is dropped, and the list is
// truncated at maxAddrsPerIf. Every such loss sets Incomplete. Input
// above maxInputSize, a document that is not a JSON array, or an array
// with more than maxEntries elements is an error. One bad entry never
// discards the rest of the table.
func ParseAddrs(raw []byte) (AddrTable, error) {
	if len(raw) > maxInputSize {
		return AddrTable{}, fmt.Errorf("addr document exceeds %d bytes", maxInputSize)
	}
	elems, err := unmarshalArray(raw, "addrs")
	if err != nil {
		return AddrTable{}, err
	}
	if len(elems) > maxEntries {
		return AddrTable{}, fmt.Errorf("addr list exceeds %d entries", maxEntries)
	}
	t := AddrTable{Entries: make([]Addr, 0, len(elems))}
	for _, e := range elems {
		a, lossy, ok := parseAddrEntry(e)
		if !ok {
			t.Dropped++
			t.Incomplete = true
			continue
		}
		if lossy {
			t.Incomplete = true
		}
		t.Entries = append(t.Entries, a)
	}
	return t, nil
}

// parseAddrEntry parses one `ip -j addr` element. ok is false for skipped
// elements; lossy is true when fields of a kept entry were dropped.
func parseAddrEntry(e json.RawMessage) (a Addr, lossy, ok bool) {
	var d addrDoc
	if err := json.Unmarshal(e, &d); err != nil {
		return Addr{}, false, false
	}
	if !validIfName(d.IfName) {
		return Addr{}, false, false
	}
	a = Addr{Name: d.IfName}
	if d.Address != "" {
		if mac, err := net.ParseMAC(d.Address); err == nil && len(mac) == 6 {
			a.MAC = mac
		} else {
			lossy = true
		}
	}
	if d.OperState != "" {
		if operStates[d.OperState] {
			a.State = d.OperState
		} else {
			lossy = true
		}
	}
	for _, info := range d.AddrInfo {
		if len(a.Addrs) >= maxAddrsPerIf {
			lossy = true
			break
		}
		p, ok := parseAddrInfo(info)
		if !ok {
			lossy = true
			continue
		}
		a.Addrs = append(a.Addrs, p)
	}
	return a, lossy, true
}

// parseAddrInfo combines one "addr_info" entry into a prefix. ok is false
// when the family is not inet/inet6, the local address is invalid, or the
// prefixlen is outside the family's bit width.
func parseAddrInfo(info addrInfoDoc) (netip.Prefix, bool) {
	ip, ok := parseHostAddr(info.Local)
	if !ok {
		return netip.Prefix{}, false
	}
	var maxBits int
	switch info.Family {
	case "inet":
		if !ip.Is4() {
			return netip.Prefix{}, false
		}
		maxBits = 32
	case "inet6":
		if ip.Is4() {
			return netip.Prefix{}, false
		}
		maxBits = 128
	default:
		return netip.Prefix{}, false
	}
	if info.PrefixLen < 0 || info.PrefixLen > maxBits {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, info.PrefixLen), true
}

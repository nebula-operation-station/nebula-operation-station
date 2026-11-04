// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"sort"
)

// BridgeVLAN is one VLAN a bridge port carries.
type BridgeVLAN struct {
	// ID is the 802.1Q VLAN id (0..maxVLANID).
	ID int
	// PVID is true when this VLAN is the port's native (PVID) VLAN.
	PVID bool
	// Untagged is true when frames of this VLAN leave the port
	// untagged (egress-untagged).
	Untagged bool
}

// BridgeVLANTable is the parsed `bridge -j vlan` document: for each
// bridge port, the VLANs it carries.
type BridgeVLANTable struct {
	// Ports maps a port name to the VLANs the port carries, sorted by
	// VLAN id. A port appears only when it carries at least one valid
	// VLAN.
	Ports map[string][]BridgeVLAN
	// Dropped counts array elements that were skipped as malformed.
	Dropped int
	// Incomplete is true when the host reported data the parser did not
	// keep: a skipped element (Dropped > 0), an out-of-range VLAN id, an
	// invalid range, or a port's VLAN list truncated at
	// maxVLANsPerPort. An incomplete table must be presented as such,
	// never as the complete table (spec 09).
	Incomplete bool
}

// bridgeVLANDoc is the permissive shape of one `bridge -j vlan` array
// element. It accepts both shapes iproute2 has printed:
//
//   - per-port object with a "vlans" list, e.g.
//     {"ifname":"br0","vlans":[{"vlan":1,"flags":["PVID","Egress
//     Untagged"]},{"vlan":100}]};
//   - flat per-(port, vlan) object, e.g.
//     {"ifname":"br0","vlan":1,"flags":["PVID","Egress Untagged"]}.
//
// When "vlans" is present it wins; otherwise the flat "vlan" field is
// used. Unknown fields are dropped (spec 09).
type bridgeVLANDoc struct {
	IfName  string         `json:"ifname"`
	VLANs   []vlanEntryDoc `json:"vlans"`
	VLAN    *int           `json:"vlan"`
	VLANEnd *int           `json:"vlanEnd"`
	Flags   []string       `json:"flags"`
}

// vlanEntryDoc is one element of a port's "vlans" list. A range is
// expressed as "vlan" (start) plus an optional "vlanEnd" (end, inclusive).
type vlanEntryDoc struct {
	VLAN    int      `json:"vlan"`
	VLANEnd *int     `json:"vlanEnd"`
	Flags   []string `json:"flags"`
}

// ParseBridgeVLAN parses the JSON array printed by `bridge -j vlan`.
//
// Each element is a bridge port (or a single port/VLAN pair in the flat
// shape). An element without a valid port name, or with no VLAN
// information, is skipped and counted in Dropped. VLAN ids outside
// 0..maxVLANID and inverted ranges are dropped; a range is expanded into
// one VLAN per id; duplicate ids on a port are merged (flags OR'd); and a
// port's total VLAN count (after range expansion) is truncated at
// maxVLANsPerPort. Every such loss sets Incomplete. Input above
// maxInputSize, a document that is not a JSON array, or an array with
// more than maxEntries elements is an error. One bad entry never
// discards the rest of the table.
func ParseBridgeVLAN(raw []byte) (BridgeVLANTable, error) {
	if len(raw) > maxInputSize {
		return BridgeVLANTable{}, fmt.Errorf("bridge vlan document exceeds %d bytes", maxInputSize)
	}
	elems, err := unmarshalArray(raw, "bridge vlans")
	if err != nil {
		return BridgeVLANTable{}, err
	}
	if len(elems) > maxEntries {
		return BridgeVLANTable{}, fmt.Errorf("bridge vlan list exceeds %d entries", maxEntries)
	}
	t := BridgeVLANTable{Ports: make(map[string][]BridgeVLAN)}
	// acc collects a port's VLANs by id while parsing, so duplicates and
	// overlapping ranges merge before the sorted slice is built.
	acc := make(map[string]map[int]*BridgeVLAN)
	// iters counts the total VLAN ids a port has reported (after range
	// expansion), bounding the work a hostile port list can force.
	iters := make(map[string]int)
	for _, e := range elems {
		var d bridgeVLANDoc
		if err := json.Unmarshal(e, &d); err != nil {
			t.Dropped++
			t.Incomplete = true
			continue
		}
		if !validIfName(d.IfName) {
			t.Dropped++
			t.Incomplete = true
			continue
		}
		entries := d.VLANs
		flat := len(entries) == 0 && d.VLAN != nil
		if !flat && len(entries) == 0 {
			// No VLAN information in this element.
			t.Dropped++
			t.Incomplete = true
			continue
		}
		m := acc[d.IfName]
		if m == nil {
			m = make(map[int]*BridgeVLAN)
			acc[d.IfName] = m
		}
		it := iters[d.IfName]
		if flat {
			if lossy := addVLAN(m, d.VLAN, d.VLANEnd, d.Flags, &it); lossy {
				t.Incomplete = true
			}
		}
		for _, en := range entries {
			if lossy := addVLAN(m, &en.VLAN, en.VLANEnd, en.Flags, &it); lossy {
				t.Incomplete = true
			}
		}
		iters[d.IfName] = it
	}
	for port, m := range acc {
		if len(m) == 0 {
			continue
		}
		vlans := make([]BridgeVLAN, 0, len(m))
		for _, v := range m {
			vlans = append(vlans, *v)
		}
		sort.Slice(vlans, func(i, j int) bool { return vlans[i].ID < vlans[j].ID })
		t.Ports[port] = vlans
	}
	return t, nil
}

// addVLAN records one VLAN (or range, when end is not nil) on port m,
// merging with any existing entry for the same id. iters counts the total
// VLAN ids the port has reported (after range expansion) and bounds the
// work at maxVLANsPerPort. It reports lossy=true when the start or end id
// is out of range, the range is inverted, or the port's total VLAN count
// was truncated at maxVLANsPerPort.
func addVLAN(m map[int]*BridgeVLAN, start, end *int, flags []string, iters *int) (lossy bool) {
	if start == nil || *start < 0 || *start > maxVLANID {
		return true
	}
	lo, hi := *start, *start
	if end != nil {
		if *end < 0 || *end > maxVLANID || *end < lo {
			return true
		}
		hi = *end
	}
	pvid, untagged := vlanFlagBits(flags)
	for id := lo; id <= hi; id++ {
		if *iters >= maxVLANsPerPort {
			lossy = true
			break
		}
		*iters++
		v := m[id]
		if v == nil {
			v = &BridgeVLAN{ID: id}
			m[id] = v
		}
		v.PVID = v.PVID || pvid
		v.Untagged = v.Untagged || untagged
	}
	return lossy
}

// vlanFlagBits maps the flag names iproute2 prints (bridge_print_vlan_flags)
// to the PVID and egress-untagged bits. Unknown flags are ignored.
func vlanFlagBits(flags []string) (pvid, untagged bool) {
	for _, f := range flags {
		switch f {
		case "PVID":
			pvid = true
		case "Egress Untagged":
			untagged = true
		}
	}
	return pvid, untagged
}

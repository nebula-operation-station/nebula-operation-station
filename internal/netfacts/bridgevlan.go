// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"sort"
)

// BridgeVLAN is one VLAN a bridge port carries.
type BridgeVLAN struct {
	// ID is the 802.1Q VLAN id (minVLANID..maxVLANID).
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
	// keep: a skipped element (Dropped > 0), a missing or out-of-range
	// VLAN id, an invalid range, or VLANs dropped once the document hit
	// maxVLANsPerDoc or maxVLANWorkPerDoc. An incomplete table must be
	// presented as such, never as the complete table (spec 09).
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
// VLAN is nil when the key is absent; such an entry is rejected.
type vlanEntryDoc struct {
	VLAN    *int     `json:"vlan"`
	VLANEnd *int     `json:"vlanEnd"`
	Flags   []string `json:"flags"`
}

// ParseBridgeVLAN parses the JSON array printed by `bridge -j vlan`.
//
// Each element is a bridge port (or a single port/VLAN pair in the flat
// shape). An element without a valid port name, or with no VLAN
// information, is skipped and counted in Dropped. Entries without a VLAN
// id, VLAN ids outside minVLANID..maxVLANID and inverted ranges are
// dropped; a range is expanded into one VLAN per id; duplicate ids on a
// port are merged (flags OR'd). The document as a whole expands to at most
// maxVLANsPerDoc distinct (port, VLAN) pairs and visits at most
// maxVLANWorkPerDoc ids (duplicates included); VLANs beyond either budget
// are dropped. Every such loss sets Incomplete. Input above
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
	// acc collects a port's VLAN flags by id while parsing, so duplicates
	// and overlapping ranges merge before the sorted slice is built.
	acc := make(map[string]map[int]vlanBits)
	b := vlanBudget{distinct: maxVLANsPerDoc, work: maxVLANWorkPerDoc}
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
			m = make(map[int]vlanBits)
			acc[d.IfName] = m
		}
		if flat {
			if lossy := addVLAN(m, d.VLAN, d.VLANEnd, d.Flags, &b); lossy {
				t.Incomplete = true
			}
		}
		for _, en := range entries {
			if lossy := addVLAN(m, en.VLAN, en.VLANEnd, en.Flags, &b); lossy {
				t.Incomplete = true
			}
		}
	}
	for port, m := range acc {
		if len(m) == 0 {
			continue
		}
		vlans := make([]BridgeVLAN, 0, len(m))
		for id, bits := range m {
			vlans = append(vlans, BridgeVLAN{ID: id, PVID: bits&vlanPVID != 0, Untagged: bits&vlanUntagged != 0})
		}
		sort.Slice(vlans, func(i, j int) bool { return vlans[i].ID < vlans[j].ID })
		t.Ports[port] = vlans
	}
	return t, nil
}

// vlanBits holds a bridge port VLAN's flags while parsing.
type vlanBits uint8

const (
	vlanPVID vlanBits = 1 << iota
	vlanUntagged
)

// vlanBudget is the remaining per-document expansion budget of
// ParseBridgeVLAN: distinct counts the (port, VLAN) pairs that may still be
// added, work the ids that may still be visited (duplicates included).
type vlanBudget struct {
	distinct int
	work     int
}

// addVLAN records one VLAN (or range, when end is not nil) on port m,
// merging with any existing entry for the same id. It reports lossy=true
// when the start id is missing, the start or end id is out of range, the
// range is inverted, or VLANs were dropped because the document budget b
// ran out. Only distinct new ids consume b.distinct; every visited id
// consumes b.work.
func addVLAN(m map[int]vlanBits, start, end *int, flags []string, b *vlanBudget) (lossy bool) {
	if start == nil || *start < minVLANID || *start > maxVLANID {
		return true
	}
	lo, hi := *start, *start
	if end != nil {
		if *end < minVLANID || *end > maxVLANID || *end < lo {
			return true
		}
		hi = *end
	}
	var bits vlanBits
	pvid, untagged := vlanFlagBits(flags)
	if pvid {
		bits |= vlanPVID
	}
	if untagged {
		bits |= vlanUntagged
	}
	for id := lo; id <= hi; id++ {
		if b.work <= 0 {
			return true
		}
		b.work--
		old, seen := m[id]
		if !seen {
			if b.distinct <= 0 {
				lossy = true
				continue
			}
			b.distinct--
		}
		m[id] = old | bits
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

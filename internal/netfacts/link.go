// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"net"
)

// Link is one interface from `ip -j -d link`.
type Link struct {
	// Name is the interface name (a Linux interface name, see
	// validIfName).
	Name string
	// Kind is the link kind the host reported (vlan, bridge, veth, tun,
	// wireguard, ...); empty for a physical interface, which iproute2
	// prints without a "linkinfo" object, or when the reported kind is
	// longer than maxKindLen.
	Kind string
	// VLANID is the 802.1Q VLAN id of a vlan device (info_kind "vlan")
	// from linkinfo.info_data.id, when the host reported one within
	// minVLANID..maxVLANID; nil otherwise. The "id" of other kinds (the
	// VNI of a vxlan or geneve device) is not a VLAN id and is ignored.
	VLANID *int
	// Parent is the underlying device the interface is built on, as
	// printed in the top-level "link" field (a device name); empty when
	// the host reported none. For a vlan device this is the parent
	// interface.
	Parent string
	// Master is the device the interface is enslaved to, as printed in
	// the top-level "master" field (a device name); empty when the host
	// reported none. For a bridge port this is the bridge, which is how
	// bridge membership is reported.
	Master string
	// MAC is the link-layer address; empty when the host reported none
	// or the reported address is not a 6-byte Ethernet MAC (a tunnel's IP
	// literal or an InfiniBand address is left out without marking the
	// table incomplete, see parseLinkLayerAddr).
	MAC net.HardwareAddr
}

// LinkTable is the parsed interface list of one `ip -j -d link` document.
type LinkTable struct {
	// Entries holds the valid interfaces in host order.
	Entries []Link
	// Dropped counts array elements that were skipped as malformed.
	Dropped int
	// Incomplete is true when the host reported data the parser did not
	// keep: a skipped element (Dropped > 0), an invalid link-layer
	// address, or a vlan device whose VLAN id is missing or out of range. An incomplete table must be
	// presented as such, never as the complete table (spec 09).
	Incomplete bool
}

// linkDoc is the permissive shape of one `ip -j -d link` array element.
// "link" and "master" are device names (iproute2 resolves the ifindices
// to names); "link" is null when the interface has no parent. Unknown
// fields are dropped (spec 09).
type linkDoc struct {
	IfName   string       `json:"ifname"`
	Address  string       `json:"address"` // the interface's MAC
	Link     string       `json:"link"`    // parent device name (null -> "")
	Master   string       `json:"master"`  // master device name
	LinkInfo *linkInfoDoc `json:"linkinfo"`
}

// linkInfoDoc is the permissive shape of the "linkinfo" object that
// iproute2 prints for a virtual device. The kind is under "info_kind" and
// the kind-specific data under "info_data".
type linkInfoDoc struct {
	InfoKind string       `json:"info_kind"`
	InfoData *linkDataDoc `json:"info_data"`
}

// linkDataDoc is the permissive shape of "info_data". For a vlan device it
// carries the 802.1Q id; other kinds carry other fields, which are
// dropped. ID is nil when the key is absent; it is read only for
// info_kind "vlan" (a vxlan or geneve "id" is a VNI).
type linkDataDoc struct {
	ID *int `json:"id"`
}

// ParseLinks parses the JSON array printed by `ip -j -d link`.
//
// Each element is one interface. An element without a valid interface
// name is skipped and counted in Dropped. The kind is read from
// linkinfo.info_kind (empty for a physical interface), the VLAN id of a
// vlan device from linkinfo.info_data.id (kept only when it is present and
// within minVLANID..maxVLANID; ignored for every other kind), the
// parent from the top-level "link" field and the master from the top-level
// "master" field (both device names, validated as interface names). The
// link-layer address is kept only when it is a 6-byte Ethernet MAC
// (another well-formed link-layer address, see parseLinkLayerAddr, is left
// out without loss). Every
// such loss sets Incomplete. Input above maxInputSize, a document that is
// not a JSON array, or an array with more than maxEntries elements is an
// error. One bad entry never discards the rest of the table.
func ParseLinks(raw []byte) (LinkTable, error) {
	if len(raw) > maxInputSize {
		return LinkTable{}, fmt.Errorf("link document exceeds %d bytes", maxInputSize)
	}
	elems, err := unmarshalArray(raw, "links")
	if err != nil {
		return LinkTable{}, err
	}
	if len(elems) > maxEntries {
		return LinkTable{}, fmt.Errorf("link list exceeds %d entries", maxEntries)
	}
	t := LinkTable{Entries: make([]Link, 0, len(elems))}
	for _, e := range elems {
		l, lossy, ok := parseLinkEntry(e)
		if !ok {
			t.Dropped++
			t.Incomplete = true
			continue
		}
		if lossy {
			t.Incomplete = true
		}
		t.Entries = append(t.Entries, l)
	}
	return t, nil
}

// parseLinkEntry parses one `ip -j -d link` element. ok is false for
// skipped elements; lossy is true when fields of a kept entry were
// dropped.
func parseLinkEntry(e json.RawMessage) (l Link, lossy, ok bool) {
	var d linkDoc
	if err := json.Unmarshal(e, &d); err != nil {
		return Link{}, false, false
	}
	if !validIfName(d.IfName) {
		return Link{}, false, false
	}
	l = Link{Name: d.IfName}
	if d.Address != "" {
		mac, known := parseLinkLayerAddr(d.Address)
		l.MAC = mac
		if !known {
			lossy = true
		}
	}
	// Parent and master are device names from the host; keep them only
	// when they are valid interface names (an empty value is the
	// "none" case, not a loss).
	if d.Link != "" {
		if validIfName(d.Link) {
			l.Parent = d.Link
		} else {
			lossy = true
		}
	}
	if d.Master != "" {
		if validIfName(d.Master) {
			l.Master = d.Master
		} else {
			lossy = true
		}
	}
	if d.LinkInfo != nil {
		if d.LinkInfo.InfoKind != "" && len(d.LinkInfo.InfoKind) <= maxKindLen {
			l.Kind = d.LinkInfo.InfoKind
		} else if d.LinkInfo.InfoKind != "" {
			lossy = true
		}
		if d.LinkInfo.InfoKind == "vlan" {
			// A vlan device always carries its id; a missing or
			// out-of-range id is a loss.
			var id *int
			if d.LinkInfo.InfoData != nil {
				id = d.LinkInfo.InfoData.ID
			}
			if id != nil && *id >= minVLANID && *id <= maxVLANID {
				v := *id
				l.VLANID = &v
			} else {
				lossy = true
			}
		}
	}
	return l, lossy, true
}

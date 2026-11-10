// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// ZoneType is the network type of a PAN-OS zone.
type ZoneType string

// Zone types NOS reads. A zone whose network element is missing or of
// another type (for example tunnel or external) has the empty type and no
// interfaces: its content is outside the allowlist.
const (
	ZoneLayer3      ZoneType = "layer3"
	ZoneLayer2      ZoneType = "layer2"
	ZoneVirtualWire ZoneType = "virtual-wire"
	ZoneTap         ZoneType = "tap"
)

// Zone is one PAN-OS zone: its name, network type and member interfaces in
// device order (ADR 0010 D4: name and member interfaces only).
type Zone struct {
	Name       string
	Type       ZoneType
	Interfaces []string
}

// ZoneSet is the parsed zone list of the supported vsys. Incomplete is set
// when the zone list or one zone's interface list exceeded its limit
// (netdevcontract.MaxZones, MaxFirewallInterfaces); List then holds the
// entries up to the limit and must not be treated as complete.
type ZoneSet struct {
	List       []Zone
	Incomplete bool
}

// Contract converts the zones to the netdevcontract form (which has no
// zone type).
func (s ZoneSet) Contract() []netdevcontract.Zone {
	out := make([]netdevcontract.Zone, 0, len(s.List))
	for _, z := range s.List {
		out = append(out, netdevcontract.Zone{Name: z.Name, Interfaces: append([]string(nil), z.Interfaces...)})
	}
	return out
}

// ParseZones parses the zones of a configuration response: a read of the
// vsys1 zone subtree or of the whole vsys. It performs no I/O. The response
// is limit-checked and decoded by decodeConfig; names must follow the
// PAN-OS name rules (ValidateName), interface names
// netdevcontract.ValidInterfaceName, and an interface may belong to one
// zone only.
func ParseZones(data []byte) (ZoneSet, error) {
	sec, incomplete, err := decodeConfig(data)
	if err != nil {
		return ZoneSet{}, fmt.Errorf("parse zones: %w", err)
	}
	if sec.Zone == nil {
		return ZoneSet{Incomplete: incomplete}, nil
	}
	entries := sec.Zone.Entries
	set := ZoneSet{Incomplete: incomplete}
	if netdevcontract.CheckCount("zones", len(entries), netdevcontract.MaxZones) != nil {
		entries, set.Incomplete = entries[:netdevcontract.MaxZones], true
	}
	names := make(map[string]struct{}, len(entries))
	owner := make(map[string]struct{})
	set.List = make([]Zone, 0, len(entries))
	for i, e := range entries {
		z, truncated, err := parseZone(e)
		if err != nil {
			return ZoneSet{}, fmt.Errorf("parse zones: zone %d: %w", i, err)
		}
		if _, dup := names[z.Name]; dup {
			return ZoneSet{}, fmt.Errorf("parse zones: zone %d: %w: name duplicated", i, ErrInvalidConfig)
		}
		names[z.Name] = struct{}{}
		for _, itf := range z.Interfaces {
			if _, dup := owner[itf]; dup {
				return ZoneSet{}, fmt.Errorf("parse zones: zone %d: %w: interface in more than one zone", i, ErrInvalidConfig)
			}
			owner[itf] = struct{}{}
		}
		set.Incomplete = set.Incomplete || truncated
		set.List = append(set.List, z)
	}
	return set, nil
}

// parseZone validates one zone entry.
func parseZone(e xmlZone) (Zone, bool, error) {
	if ValidateName(e.Name) != nil {
		return Zone{}, false, fmt.Errorf("%w: invalid name", ErrInvalidConfig)
	}
	z := Zone{Name: e.Name}
	if len(e.Network) > 1 {
		return Zone{}, false, fmt.Errorf("%w: network repeated", ErrInvalidConfig)
	}
	if len(e.Network) == 0 {
		return z, false, nil
	}
	n := e.Network[0]
	var members *xmlMembers
	for _, c := range []struct {
		t ZoneType
		m []xmlMembers
	}{{ZoneLayer3, n.Layer3}, {ZoneLayer2, n.Layer2}, {ZoneVirtualWire, n.VirtualWire}, {ZoneTap, n.Tap}} {
		if len(c.m) == 0 {
			continue
		}
		if members != nil {
			return Zone{}, false, fmt.Errorf("%w: more than one network type", ErrInvalidConfig)
		}
		if len(c.m) > 1 {
			return Zone{}, false, fmt.Errorf("%w: %s repeated", ErrInvalidConfig, c.t)
		}
		z.Type, members = c.t, &c.m[0]
	}
	if members == nil {
		return z, false, nil
	}
	in := members.Members
	truncated := false
	if netdevcontract.CheckCount("zone interfaces", len(in), netdevcontract.MaxFirewallInterfaces) != nil {
		in, truncated = in[:netdevcontract.MaxFirewallInterfaces], true
	}
	seen := make(map[string]struct{}, len(in))
	for j, itf := range in {
		if !netdevcontract.ValidInterfaceName(itf) {
			return Zone{}, false, fmt.Errorf("%w: interface %d: invalid name", ErrInvalidConfig, j)
		}
		if _, dup := seen[itf]; dup {
			return Zone{}, false, fmt.Errorf("%w: interface %d: duplicated", ErrInvalidConfig, j)
		}
		seen[itf] = struct{}{}
		z.Interfaces = append(z.Interfaces, itf)
	}
	return z, truncated, nil
}

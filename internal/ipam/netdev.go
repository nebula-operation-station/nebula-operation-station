// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
)

// Switch data in IPAM (ADR 0010 D4 "Integration points", ticket ND-18
// part 1).
//
// Switch MAC and VLAN tables only produce hints next to IPAM data. Nothing
// here writes IPAM: no asset, network, entry, placement or role is
// created or changed, and a device is never linked to an asset by its
// MAC. The readers below have no write methods. The explicit, admin
// confirmed device ↔ asset link with the MAC as a suggestion (ADR 0010
// D4, ND-18 part 2) lives in netdevlink.go.

// SourceMACTable labels data taken from a CBS MAC address table.
const SourceMACTable = "cbs-mac-table"

// SourceVLANTable labels data taken from a CBS VLAN table.
const SourceVLANTable = "cbs-vlan-table"

// SourceSwitches labels a hint resting on all switch MAC and VLAN tables
// together.
const SourceSwitches = "cbs-mac-table+cbs-vlan-table"

// UplinkMACThreshold is the number of distinct MACs a switch port may
// carry before it is treated as an uplink: a port with more MACs than
// this leads to further switches or hypervisors, so a MAC learned there
// says nothing about where the endpoint is plugged in.
const UplinkMACThreshold = 8

// MACTable is the current MAC table dataset of one switch as stored by
// the netdevinventory store (read only). Its entries were validated by
// netdevcontract but remain untrusted device text.
type MACTable struct {
	DeviceID   string
	State      netdevinventory.DatasetState
	ObservedAt time.Time
	Entries    netdevinventory.MACRows
}

// VLANTable is the current VLAN dataset of one switch as stored by the
// netdevinventory store (read only). VLAN names are untrusted device text.
type VLANTable struct {
	DeviceID   string
	State      netdevinventory.DatasetState
	ObservedAt time.Time
	VLANs      netdevinventory.VLANRows
}

// SwitchMACReader reads the current MAC tables of all switches. It is a
// read-only view of the netdevinventory store.
type SwitchMACReader interface {
	MACTables(ctx context.Context) ([]MACTable, error)
}

// SwitchVLANReader reads the current MAC and VLAN tables of all switches.
// It is the read-only view of the netdevinventory store that VLANHints
// uses.
type SwitchVLANReader interface {
	SwitchMACReader
	VLANTables(ctx context.Context) ([]VLANTable, error)
}

// Reader reads assets and networks. *Store implements it; VLANHints uses
// nothing else of IPAM.
type Reader interface {
	Assets(ctx context.Context) ([]Asset, error)
	Networks(ctx context.Context) ([]Network, error)
}

// VLANHintKind says which comparison of ADR 0010 D4 produced a VLANHint.
type VLANHintKind string

// VLAN hint kinds.
const (
	// HintAssetPortVLAN: an IPAM asset's MAC was learned on a switch edge
	// port only in VLANs other than the VLAN of the IPAM network holding
	// the asset's address.
	HintAssetPortVLAN VLANHintKind = "asset-port-vlan"
	// HintSwitchVLANWithoutNetwork: a VLAN exists on a switch (VLAN table
	// or a dynamically learned MAC) but no IPAM network carries it.
	HintSwitchVLANWithoutNetwork VLANHintKind = "switch-vlan-without-network"
	// HintNetworkVLANNotOnSwitch: an IPAM network carries a VLAN that no
	// switch reports.
	HintNetworkVLANNotOnSwitch VLANHintKind = "network-vlan-not-on-switch"
)

// VLANHint is one VLAN difference between switch data and IPAM (ADR 0010
// D4). It is a hint for the admin, never an edit. Which fields are set
// depends on Kind:
//
//   - HintAssetPortVLAN: AssetID, MAC, Address, NetworkID, NetworkVLAN,
//     DeviceID, Port, SwitchVLAN.
//   - HintSwitchVLANWithoutNetwork: DeviceID, SwitchVLAN, SwitchVLANName.
//   - HintNetworkVLANNotOnSwitch: NetworkID, NetworkVLAN.
type VLANHint struct {
	Kind        VLANHintKind
	AssetID     string
	MAC         string
	Address     netip.Addr
	NetworkID   string
	NetworkVLAN int
	DeviceID    string
	Port        string
	SwitchVLAN  int
	// SwitchVLANName is the switch's VLAN name: untrusted device text,
	// render as text only.
	SwitchVLANName string
	// Source labels where the switch side came from: SourceMACTable,
	// SourceVLANTable, or SourceSwitches for HintNetworkVLANNotOnSwitch.
	Source string
	// State and ObservedAt are those of the switch dataset the hint rests
	// on, so a stale or partial table is shown as such. For
	// HintNetworkVLANNotOnSwitch they are the least fresh state and the
	// oldest observation over all switch datasets read.
	State      netdevinventory.DatasetState
	ObservedAt time.Time
}

// IsDynamicMAC reports whether e was learned dynamically. Static and
// "other" entries (the switch's own, management or configured MACs) say
// nothing about where an endpoint is plugged in and are ignored for
// endpoints, uplink detection and hints.
func IsDynamicMAC(e netdevcontract.MACEntry) bool {
	return e.Type == netdevcontract.MACDynamic
}

// IsLAGPort reports whether name is a CBS port-channel (LAG) interface.
func IsLAGPort(name string) bool {
	n := strings.ToLower(name)
	if rest, ok := strings.CutPrefix(n, "port-channel"); ok {
		return rest != "" && allDigits(strings.TrimSpace(rest))
	}
	if rest, ok := strings.CutPrefix(n, "po"); ok {
		return rest != "" && allDigits(rest)
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// UplinkPorts returns the ports of one MAC table that are treated as
// uplinks: LAG ports and ports with more than UplinkMACThreshold distinct
// dynamically learned MACs. MACs learned there do not locate an endpoint.
func UplinkPorts(entries []netdevcontract.MACEntry) map[string]bool {
	macs := map[string]map[string]struct{}{}
	up := map[string]bool{}
	for _, e := range entries {
		if e.Port == "" {
			continue
		}
		if IsLAGPort(e.Port) {
			up[e.Port] = true
			continue
		}
		if !IsDynamicMAC(e) {
			continue
		}
		m, ok := NormalizeMAC(e.MAC)
		if !ok || m == "" {
			continue
		}
		set := macs[e.Port]
		if set == nil {
			set = map[string]struct{}{}
			macs[e.Port] = set
		}
		set[m] = struct{}{}
	}
	for port, set := range macs {
		if len(set) > UplinkMACThreshold {
			up[port] = true
		}
	}
	return up
}

// assetAddr is one (asset, address) pair keyed by the asset's MAC.
type assetAddr struct {
	assetID string
	addr    netip.Addr
}

// portMAC is one MAC learned on one edge port of one switch.
type portMAC struct {
	device, port, mac string
}

// portMACSeen is what a MAC table says about one portMAC: the VLANs it was
// learned in and the dataset it came from.
type portMACSeen struct {
	vlans      map[int]struct{}
	state      netdevinventory.DatasetState
	observedAt time.Time
}

// switchVLAN is one VLAN reported by one switch.
type switchVLAN struct {
	device string
	vlan   int
}

// switchVLANSeen is the dataset a switchVLAN was taken from.
type switchVLANSeen struct {
	name       string
	source     string
	state      netdevinventory.DatasetState
	observedAt time.Time
}

// stateRank orders dataset states from most to least trustworthy; an
// unknown state ranks last.
func stateRank(s netdevinventory.DatasetState) int {
	switch s {
	case netdevinventory.StateFresh:
		return 0
	case netdevinventory.StatePartial:
		return 1
	case netdevinventory.StateStale:
		return 2
	default:
		return 3
	}
}

// VLANHints compares switch VLAN data with IPAM and returns the hints of
// ADR 0010 D4, all only read from sw and im:
//
//   - HintAssetPortVLAN for every IPAM asset MAC learned on a switch edge
//     port when none of the VLANs it was learned in on that port is the
//     VLAN of the most specific IPAM network holding the asset's address;
//   - HintSwitchVLANWithoutNetwork for every VLAN a switch reports (VLAN
//     table or dynamic MAC entry) that no IPAM network carries;
//   - HintNetworkVLANNotOnSwitch for every IPAM network VLAN that no switch
//     reports.
//
// Networks without a VLAN, assets without a MAC or address, MACs on uplink
// or LAG ports, static and "other" MAC entries and entries not bound to a
// port give no asset hint. Without any switch dataset there is no hint at
// all: "not on any switch" needs at least one switch read.
func VLANHints(ctx context.Context, sw SwitchVLANReader, im Reader) ([]VLANHint, error) {
	if sw == nil || im == nil {
		return nil, errors.New("ipam: vlan hints: nil reader")
	}
	macTables, err := sw.MACTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("ipam: vlan hints: read switch mac tables: %w", err)
	}
	vlanTables, err := sw.VLANTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("ipam: vlan hints: read switch vlan tables: %w", err)
	}
	if len(macTables) == 0 && len(vlanTables) == 0 {
		return nil, nil
	}
	assets, err := im.Assets(ctx)
	if err != nil {
		return nil, fmt.Errorf("ipam: vlan hints: read assets: %w", err)
	}
	nets, err := im.Networks(ctx)
	if err != nil {
		return nil, fmt.Errorf("ipam: vlan hints: read networks: %w", err)
	}

	// What the switches report, per (device, VLAN) and per (device, port,
	// MAC), plus the least fresh state and oldest observation overall.
	seenVLAN := map[switchVLAN]switchVLANSeen{}
	seenPort := map[portMAC]*portMACSeen{}
	worst, oldest := netdevinventory.StateFresh, time.Time{}
	note := func(s netdevinventory.DatasetState, at time.Time) {
		if stateRank(s) > stateRank(worst) {
			worst = s
		}
		if oldest.IsZero() || (!at.IsZero() && at.Before(oldest)) {
			oldest = at
		}
	}
	for _, t := range vlanTables {
		note(t.State, t.ObservedAt)
		for _, v := range t.VLANs {
			if v.ID == 0 {
				continue
			}
			seenVLAN[switchVLAN{t.DeviceID, int(v.ID)}] = switchVLANSeen{
				name: v.Name, source: SourceVLANTable, state: t.State, observedAt: t.ObservedAt,
			}
		}
	}
	for _, t := range macTables {
		note(t.State, t.ObservedAt)
		uplinks := UplinkPorts(t.Entries)
		for _, e := range t.Entries {
			if !IsDynamicMAC(e) || e.VLAN == 0 {
				continue
			}
			k := switchVLAN{t.DeviceID, int(e.VLAN)}
			if _, ok := seenVLAN[k]; !ok {
				seenVLAN[k] = switchVLANSeen{source: SourceMACTable, state: t.State, observedAt: t.ObservedAt}
			}
			if e.Port == "" || uplinks[e.Port] {
				continue
			}
			m, ok := NormalizeMAC(e.MAC)
			if !ok || m == "" {
				continue
			}
			pk := portMAC{t.DeviceID, e.Port, m}
			ps := seenPort[pk]
			if ps == nil {
				ps = &portMACSeen{vlans: map[int]struct{}{}, state: t.State, observedAt: t.ObservedAt}
				seenPort[pk] = ps
			}
			ps.vlans[int(e.VLAN)] = struct{}{}
		}
	}

	var hints []VLANHint

	// Set level, switch side: VLANs no IPAM network carries.
	netVLANs := map[int]struct{}{}
	for _, n := range nets {
		if n.VLAN != 0 {
			netVLANs[n.VLAN] = struct{}{}
		}
	}
	anyVLAN := map[int]struct{}{}
	for k, s := range seenVLAN {
		anyVLAN[k.vlan] = struct{}{}
		if _, ok := netVLANs[k.vlan]; ok {
			continue
		}
		hints = append(hints, VLANHint{
			Kind: HintSwitchVLANWithoutNetwork, DeviceID: k.device, SwitchVLAN: k.vlan, SwitchVLANName: s.name,
			Source: s.source, State: s.state, ObservedAt: s.observedAt,
		})
	}

	// Set level, IPAM side: network VLANs no switch reports.
	for _, n := range nets {
		if n.VLAN == 0 {
			continue
		}
		if _, ok := anyVLAN[n.VLAN]; ok {
			continue
		}
		hints = append(hints, VLANHint{
			Kind: HintNetworkVLANNotOnSwitch, NetworkID: n.ID, NetworkVLAN: n.VLAN,
			Source: SourceSwitches, State: worst, ObservedAt: oldest,
		})
	}

	// Per asset: MAC on an edge port only in VLANs other than its network's.
	byMAC := map[string][]assetAddr{}
	for _, a := range assets {
		m, ok := NormalizeMAC(a.MAC)
		if !ok || m == "" {
			continue
		}
		for _, ad := range a.Addresses {
			byMAC[m] = append(byMAC[m], assetAddr{assetID: a.ID, addr: ad.Unmap()})
		}
	}
	for pk, ps := range seenPort {
		for _, aa := range byMAC[pk.mac] {
			n, ok := containingNetwork(nets, aa.addr)
			if !ok || n.VLAN == 0 {
				continue
			}
			if _, match := ps.vlans[n.VLAN]; match {
				continue
			}
			for v := range ps.vlans {
				hints = append(hints, VLANHint{
					Kind: HintAssetPortVLAN, AssetID: aa.assetID, MAC: pk.mac, Address: aa.addr,
					NetworkID: n.ID, NetworkVLAN: n.VLAN,
					DeviceID: pk.device, Port: pk.port, SwitchVLAN: v,
					Source: SourceMACTable, State: ps.state, ObservedAt: ps.observedAt,
				})
			}
		}
	}

	sort.Slice(hints, func(i, j int) bool {
		a, b := hints[i], hints[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		if a.NetworkID != b.NetworkID {
			return a.NetworkID < b.NetworkID
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.SwitchVLAN != b.SwitchVLAN {
			return a.SwitchVLAN < b.SwitchVLAN
		}
		return a.Address.Less(b.Address)
	})
	return hints, nil
}

// containingNetwork returns the most specific network whose prefix holds
// ad. Two networks with the same most specific prefix are ambiguous and
// give no network.
func containingNetwork(nets []Network, ad netip.Addr) (Network, bool) {
	best, bits, tie := Network{}, -1, false
	for _, n := range nets {
		if !n.Prefix.IsValid() || !n.Prefix.Contains(ad) {
			continue
		}
		switch b := n.Prefix.Bits(); {
		case b > bits:
			best, bits, tie = n, b, false
		case b == bits:
			tie = true
		}
	}
	if bits < 0 || tie {
		return Network{}, false
	}
	return best, true
}

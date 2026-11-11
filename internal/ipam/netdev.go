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

// Switch data in IPAM (ADR 0010 D4 "Integration points", ticket ND-18).
//
// Switch MAC tables only produce hints next to IPAM data. Nothing here
// writes IPAM: no asset, network, entry, placement or role is created or
// changed, and a device is never linked to an asset by its MAC. The
// readers below have no write methods.

// SourceMACTable labels data taken from a CBS MAC address table.
const SourceMACTable = "cbs-mac-table"

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

// SwitchMACReader reads the current MAC tables of all switches. It is a
// read-only view of the netdevinventory store.
type SwitchMACReader interface {
	MACTables(ctx context.Context) ([]MACTable, error)
}

// Reader reads assets and networks. *Store implements it; VLANHints uses
// nothing else of IPAM.
type Reader interface {
	Assets(ctx context.Context) ([]Asset, error)
	Networks(ctx context.Context) ([]Network, error)
}

// VLANHint reports that an IPAM asset's MAC was learned on a switch edge
// port in a VLAN other than the VLAN of the IPAM network holding the
// asset's address. It is a hint for the admin, never an edit.
type VLANHint struct {
	AssetID     string
	MAC         string
	Address     netip.Addr
	NetworkID   string
	NetworkVLAN int
	DeviceID    string
	Port        string
	PortVLAN    int
	// Source labels where the switch side came from (SourceMACTable).
	Source string
	// State and ObservedAt are those of the MAC table dataset, so a stale
	// or partial table is shown as such.
	State      netdevinventory.DatasetState
	ObservedAt time.Time
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
// MACs. MACs learned there do not locate an endpoint.
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

// VLANHints compares the switch port VLAN of every IPAM asset MAC learned
// on a switch edge port with the VLAN of the most specific IPAM network
// holding the asset's address, and returns a hint for every difference.
// Networks without a VLAN, assets without a MAC or address, MACs on
// uplink or LAG ports and entries not bound to a port give no hint. It
// only reads sw and im.
func VLANHints(ctx context.Context, sw SwitchMACReader, im Reader) ([]VLANHint, error) {
	if sw == nil || im == nil {
		return nil, errors.New("ipam: vlan hints: nil reader")
	}
	tables, err := sw.MACTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("ipam: vlan hints: read switch mac tables: %w", err)
	}
	if len(tables) == 0 {
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
	if len(byMAC) == 0 {
		return nil, nil
	}
	var hints []VLANHint
	for _, t := range tables {
		uplinks := UplinkPorts(t.Entries)
		for _, e := range t.Entries {
			if e.Port == "" || uplinks[e.Port] {
				continue
			}
			m, ok := NormalizeMAC(e.MAC)
			if !ok || m == "" {
				continue
			}
			for _, aa := range byMAC[m] {
				n, ok := containingNetwork(nets, aa.addr)
				if !ok || n.VLAN == 0 || n.VLAN == int(e.VLAN) {
					continue
				}
				hints = append(hints, VLANHint{
					AssetID: aa.assetID, MAC: m, Address: aa.addr,
					NetworkID: n.ID, NetworkVLAN: n.VLAN,
					DeviceID: t.DeviceID, Port: e.Port, PortVLAN: int(e.VLAN),
					Source: SourceMACTable, State: t.State, ObservedAt: t.ObservedAt,
				})
			}
		}
	}
	sort.SliceStable(hints, func(i, j int) bool {
		a, b := hints[i], hints[j]
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.PortVLAN != b.PortVLAN {
			return a.PortVLAN < b.PortVLAN
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

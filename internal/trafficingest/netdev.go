// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// Switch data on the traffic map (ADR 0010 D4 "Integration points",
// ADR 0009 "LLDP switch-port mapping", ticket ND-18 part 1).
//
// SwitchEndpoints turns the stored CBS MAC tables and LLDP neighbors into
// traffic map facts: which MAC sits on which switch edge port, and which
// LLDP neighbor a port reports. Everything is labelled with its source.
// Nothing is written: no endpoint, asset, host, placement or port role is
// created, and switch or LLDP data never links anything to an asset or a
// host. The only links shown are the ones the traffic store already holds
// for the MAC (set by the server through SetEndpointLinks or owned by a
// managed host by the server's own records).

// TierSwitch is the source tier of an endpoint learned from a switch MAC
// table.
const TierSwitch = "switch"

// SourceMACTable labels endpoints taken from a CBS MAC address table.
const SourceMACTable = ipam.SourceMACTable

// SourceLLDP labels port mappings taken from LLDP neighbor data, which
// any device on the wire can forge.
const SourceLLDP = "lldp"

// LLDPTable is the current LLDP neighbor dataset of one switch as stored
// by the netdevinventory store (read only). Everything but the local port
// was sent by an arbitrary device and is doubly untrusted.
type LLDPTable struct {
	DeviceID   string
	State      netdevinventory.DatasetState
	ObservedAt time.Time
	Neighbors  netdevinventory.LLDPRows
}

// SwitchReader is the read-only view of the netdevinventory store that
// SwitchEndpoints uses: the current MAC tables and LLDP neighbors of all
// switches.
type SwitchReader interface {
	ipam.SwitchMACReader
	LLDPTables(ctx context.Context) ([]LLDPTable, error)
}

// EndpointLinks looks up the traffic store endpoint of a MAC and with it
// the links the server confirmed. *trafficstore.Store implements it.
type EndpointLinks interface {
	LookupEndpoint(ctx context.Context, mac string, addr netip.Addr) (trafficstore.Endpoint, bool, error)
}

// SwitchEndpoint is one MAC learned on a switch edge port.
type SwitchEndpoint struct {
	MAC      string
	DeviceID string
	Port     string
	VLAN     int
	// Tier is TierSwitch and Source is SourceMACTable.
	Tier   string
	Source string
	// State and ObservedAt are those of the MAC table dataset.
	State      netdevinventory.DatasetState
	ObservedAt time.Time
	// EndpointID, IPAMAssetID and HostID come from the traffic store's
	// existing record for the MAC; empty when there is none or when no
	// link was confirmed. Switch data never sets them.
	EndpointID  string
	IPAMAssetID string
	HostID      string
	// LinkLookedUp reports whether the traffic store was asked for this
	// MAC; false when no EndpointLinks was given or the lookup cap was hit.
	LinkLookedUp bool
}

// SwitchLink is one LLDP neighbor seen on a local switch port. The remote
// values are the neighbor's own claims, shown with their source.
type SwitchLink struct {
	DeviceID         string
	LocalPort        string
	RemoteChassisID  string
	RemotePortID     string
	RemoteSystemName string
	// Source is SourceLLDP.
	Source     string
	State      netdevinventory.DatasetState
	ObservedAt time.Time
}

// SwitchMap is the switch part of the traffic map.
type SwitchMap struct {
	Endpoints []SwitchEndpoint
	Links     []SwitchLink
	// LinkState says how complete the traffic store lookup was: empty
	// when no EndpointLinks was given, netdevinventory.StateFresh when
	// every distinct MAC was looked up, netdevinventory.StatePartial when
	// MaxSwitchEndpointLookups was hit and some endpoints carry no
	// lookup result (their LinkLookedUp is false).
	LinkState netdevinventory.DatasetState
}

// MaxSwitchEndpointLookups bounds the traffic store lookups of one
// SwitchEndpoints call. Each distinct MAC is looked up once whatever the
// number of switches, ports and VLANs it appears on; MACs beyond the
// limit (in MAC order) are shown without links and the map is marked
// partial.
const MaxSwitchEndpointLookups = 2048

// SwitchEndpoints reads the switch MAC tables and LLDP neighbors through
// sw and returns the dynamically learned MACs on edge ports (uplink and
// LAG ports are left out, see ipam.UplinkPorts; static and "other"
// entries are ignored, see ipam.IsDynamicMAC) and the LLDP port mapping.
// links may be nil; when set, the traffic store record of each distinct
// MAC (at most MaxSwitchEndpointLookups lookups) supplies the endpoint ID
// and its confirmed IPAM asset and host links. LLDP data is never looked
// up or linked. It only reads sw and links.
func SwitchEndpoints(ctx context.Context, sw SwitchReader, links EndpointLinks) (SwitchMap, error) {
	if sw == nil {
		return SwitchMap{}, errors.New("trafficingest: switch endpoints: nil reader")
	}
	tables, err := sw.MACTables(ctx)
	if err != nil {
		return SwitchMap{}, fmt.Errorf("trafficingest: switch endpoints: read mac tables: %w", err)
	}
	lldp, err := sw.LLDPTables(ctx)
	if err != nil {
		return SwitchMap{}, fmt.Errorf("trafficingest: switch endpoints: read lldp neighbors: %w", err)
	}
	var out SwitchMap
	for _, t := range tables {
		uplinks := ipam.UplinkPorts(t.Entries)
		for _, e := range t.Entries {
			if e.Port == "" || uplinks[e.Port] || !ipam.IsDynamicMAC(e) {
				continue
			}
			mac := normalizeMAC(e.MAC)
			if mac == "" {
				continue
			}
			out.Endpoints = append(out.Endpoints, SwitchEndpoint{
				MAC: mac, DeviceID: t.DeviceID, Port: e.Port, VLAN: int(e.VLAN),
				Tier: TierSwitch, Source: SourceMACTable,
				State: t.State, ObservedAt: t.ObservedAt,
			})
		}
	}
	if links != nil {
		state, err := lookupSwitchLinks(ctx, links, out.Endpoints)
		if err != nil {
			return SwitchMap{}, err
		}
		out.LinkState = state
	}
	for _, t := range lldp {
		for _, n := range t.Neighbors {
			out.Links = append(out.Links, SwitchLink{
				DeviceID: t.DeviceID, LocalPort: n.LocalPort,
				RemoteChassisID: n.ChassisID, RemotePortID: n.PortID, RemoteSystemName: n.SystemName,
				Source: SourceLLDP, State: t.State, ObservedAt: t.ObservedAt,
			})
		}
	}
	sort.SliceStable(out.Endpoints, func(i, j int) bool {
		a, b := out.Endpoints[i], out.Endpoints[j]
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.VLAN != b.VLAN {
			return a.VLAN < b.VLAN
		}
		return a.MAC < b.MAC
	})
	sort.SliceStable(out.Links, func(i, j int) bool {
		a, b := out.Links[i], out.Links[j]
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.LocalPort != b.LocalPort {
			return a.LocalPort < b.LocalPort
		}
		return a.RemoteChassisID < b.RemoteChassisID
	})
	return out, nil
}

// lookupSwitchLinks looks up each distinct MAC of eps once, in MAC order,
// stopping after MaxSwitchEndpointLookups lookups, and copies the result
// into every endpoint with that MAC. It returns StatePartial when MACs were
// left without a lookup.
func lookupSwitchLinks(ctx context.Context, links EndpointLinks, eps []SwitchEndpoint) (netdevinventory.DatasetState, error) {
	byMAC := map[string][]int{}
	for i := range eps {
		byMAC[eps[i].MAC] = append(byMAC[eps[i].MAC], i)
	}
	macs := make([]string, 0, len(byMAC))
	for m := range byMAC {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	state := netdevinventory.StateFresh
	if len(macs) > MaxSwitchEndpointLookups {
		macs, state = macs[:MaxSwitchEndpointLookups], netdevinventory.StatePartial
	}
	for _, m := range macs {
		ep, ok, err := links.LookupEndpoint(ctx, m, netip.Addr{})
		if err != nil {
			return "", fmt.Errorf("trafficingest: switch endpoints: look up %s: %w", m, err)
		}
		for _, i := range byMAC[m] {
			se := &eps[i]
			se.LinkLookedUp = true
			if ok {
				se.EndpointID, se.IPAMAssetID, se.HostID = ep.ID, ep.IPAMAssetID, ep.HostID
			}
		}
	}
	return state, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netdevadapt connects the netdevinventory store to the consumers
// of switch data: the IPAM VLAN hints (ipam.SwitchVLANReader) and the traffic
// map (trafficingest.SwitchReader). It lives apart from both packages because
// those import netdevinventory, so the adapter cannot live there.
//
// The adapter only reads. It returns the current dataset of every switch
// that has one, with its state and observation time as stored, and omits a
// switch without a current dataset (unavailable is not empty, ADR 0010 D3).
// Device text is passed on unchanged; consumers render it as text only.
package netdevadapt

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
)

// Switches reads the current switch MAC, VLAN and LLDP tables from a
// netdevinventory store. It has no write methods.
type Switches struct {
	store *netdevinventory.Store
}

// New returns the read-only switch adapter over store.
func New(store *netdevinventory.Store) (*Switches, error) {
	if store == nil {
		return nil, errors.New("netdevadapt: nil inventory store")
	}
	return &Switches{store: store}, nil
}

// MACTables implements ipam.SwitchMACReader and trafficingest.SwitchReader.
// Entries are in a fixed order: VLAN, MAC, port.
func (a *Switches) MACTables(ctx context.Context) ([]ipam.MACTable, error) {
	tables, err := a.store.CurrentMACTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("netdevadapt: mac tables: %w", err)
	}
	out := make([]ipam.MACTable, 0, len(tables))
	for _, t := range tables {
		rows := append(netdevinventory.MACRows(nil), t.Rows...)
		sort.SliceStable(rows, func(i, j int) bool {
			x, y := rows[i], rows[j]
			if x.VLAN != y.VLAN {
				return x.VLAN < y.VLAN
			}
			if x.MAC != y.MAC {
				return x.MAC < y.MAC
			}
			return x.Port < y.Port
		})
		out = append(out, ipam.MACTable{DeviceID: t.DeviceID, State: t.State, ObservedAt: t.ObservedAt, Entries: rows})
	}
	return out, nil
}

// VLANTables implements ipam.SwitchVLANReader. VLANs are in ID order.
func (a *Switches) VLANTables(ctx context.Context) ([]ipam.VLANTable, error) {
	tables, err := a.store.CurrentVLANTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("netdevadapt: vlan tables: %w", err)
	}
	out := make([]ipam.VLANTable, 0, len(tables))
	for _, t := range tables {
		rows := append(netdevinventory.VLANRows(nil), t.Rows...)
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		out = append(out, ipam.VLANTable{DeviceID: t.DeviceID, State: t.State, ObservedAt: t.ObservedAt, VLANs: rows})
	}
	return out, nil
}

// LLDPTables implements trafficingest.SwitchReader. Neighbors are ordered
// by local port, then chassis ID, then port ID; duplicates keep their
// stored order.
func (a *Switches) LLDPTables(ctx context.Context) ([]trafficingest.LLDPTable, error) {
	tables, err := a.store.CurrentLLDPTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("netdevadapt: lldp tables: %w", err)
	}
	out := make([]trafficingest.LLDPTable, 0, len(tables))
	for _, t := range tables {
		rows := append(netdevinventory.LLDPRows(nil), t.Rows...)
		sort.SliceStable(rows, func(i, j int) bool {
			x, y := rows[i], rows[j]
			if x.LocalPort != y.LocalPort {
				return x.LocalPort < y.LocalPort
			}
			if x.ChassisID != y.ChassisID {
				return x.ChassisID < y.ChassisID
			}
			return x.PortID < y.PortID
		})
		out = append(out, trafficingest.LLDPTable{DeviceID: t.DeviceID, State: t.State, ObservedAt: t.ObservedAt, Neighbors: rows})
	}
	return out, nil
}

// Compile-time checks: one adapter serves both consumers.
var (
	_ ipam.SwitchVLANReader      = (*Switches)(nil)
	_ trafficingest.SwitchReader = (*Switches)(nil)
)

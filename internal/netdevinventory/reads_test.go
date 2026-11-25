// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

func TestListDevicesRefusesBadLimit(t *testing.T) {
	s, _, _ := newTestStore(t)
	for _, limit := range []int{0, -1, MaxListDevices + 1} {
		if _, err := s.ListDevices(context.Background(), limit); err == nil {
			t.Fatalf("ListDevices(limit %d) succeeded, want an error", limit)
		}
	}
}

// TestListDevicesEmptyOneAndLimitHit covers the three list cases: no device,
// one device, and more devices than the limit (only limit come back, in
// device ID order).
func TestListDevicesEmptyOneAndLimitHit(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)

	got, err := s.ListDevices(ctx, 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty store: %d devices, err %v; want none and no error", len(got), err)
	}

	addDevice(t, s, cbsDevice())
	got, err = s.ListDevices(ctx, 10)
	if err != nil || len(got) != 1 || got[0].DeviceID != "sw-core" {
		t.Fatalf("one device: %+v, err %v", got, err)
	}
	if got[0].Origin != OriginCollectorReported || got[0].ReportedAt.IsZero() {
		t.Fatalf("one device lacks its report: origin %q reported %v", got[0].Origin, got[0].ReportedAt)
	}

	addDevice(t, s, panosDevice())
	extra := cbsDevice()
	extra.DeviceID = "sw-aaa"
	addDevice(t, s, extra)
	got, err = s.ListDevices(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].DeviceID != "fw-edge" || got[1].DeviceID != "sw-aaa" {
		ids := make([]string, 0, len(got))
		for _, d := range got {
			ids = append(ids, d.DeviceID)
		}
		t.Fatalf("limit 2 of 3 devices: %v, want [fw-edge sw-aaa]", ids)
	}
}

// TestListDevicesStateFollowsReport: ListDevices applies the same report rule
// as GetDevice.
func TestListDevicesStateFollowsReport(t *testing.T) {
	ctx := context.Background()
	s, _, clock := newTestStore(t)
	base := *clock
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), refAt(base)); err != nil {
		t.Fatal(err)
	}
	mustReplace(t, s, "sw-core", ReadVLANs, base, false, VLANRows{{ID: 1, Name: "default"}})
	*clock = base.Add(DeviceReportStaleAfter + time.Minute)
	mustReplace(t, s, "sw-core", ReadVLANs, *clock, false, VLANRows{{ID: 1, Name: "default"}})
	got, err := s.ListDevices(ctx, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("ListDevices: %+v, err %v", got, err)
	}
	if got[0].State != DeviceStale {
		t.Fatalf("State = %v, want stale by report age", got[0].State)
	}
}

// TestDeviceReadsWithoutDatasetReportNotFound: every per-device read reports
// ErrDatasetNotFound when no dataset is stored, including for a device the
// server does not know. Nothing is returned as if it were empty.
func TestDeviceReadsWithoutDatasetReportNotFound(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	addDevice(t, s, panosDevice())

	for _, dev := range []string{"sw-core", "fw-edge", "unknown-device"} {
		if _, err := s.Facts(ctx, dev); !errors.Is(err, ErrDatasetNotFound) {
			t.Errorf("Facts(%s) err = %v, want ErrDatasetNotFound", dev, err)
		}
		if _, err := s.VLANs(ctx, dev); !errors.Is(err, ErrDatasetNotFound) {
			t.Errorf("VLANs(%s) err = %v, want ErrDatasetNotFound", dev, err)
		}
		if _, err := s.Ports(ctx, dev); !errors.Is(err, ErrDatasetNotFound) {
			t.Errorf("Ports(%s) err = %v, want ErrDatasetNotFound", dev, err)
		}
		if _, _, err := s.MACEntries(ctx, dev, 0, 10); !errors.Is(err, ErrDatasetNotFound) {
			t.Errorf("MACEntries(%s) err = %v, want ErrDatasetNotFound", dev, err)
		}
		if _, err := s.LLDPNeighbors(ctx, dev); !errors.Is(err, ErrDatasetNotFound) {
			t.Errorf("LLDPNeighbors(%s) err = %v, want ErrDatasetNotFound", dev, err)
		}
		if _, err := s.FirewallPolicy(ctx, dev); !errors.Is(err, ErrDatasetNotFound) {
			t.Errorf("FirewallPolicy(%s) err = %v, want ErrDatasetNotFound", dev, err)
		}
	}
}

// TestDeviceReadsEmptyCompleteReadIsEmpty: a complete read that found nothing
// is a dataset with no rows, not a missing one.
func TestDeviceReadsEmptyCompleteReadIsEmpty(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{})
	mustReplace(t, s, "sw-core", ReadPorts, testBase, false, PortRows{})
	mustReplace(t, s, "sw-core", ReadMACTable, testBase, false, MACRows{})

	if got, err := s.VLANs(ctx, "sw-core"); err != nil || len(got) != 0 {
		t.Fatalf("VLANs of empty read: %v, err %v", got, err)
	}
	if got, err := s.Ports(ctx, "sw-core"); err != nil || len(got) != 0 {
		t.Fatalf("Ports of empty read: %v, err %v", got, err)
	}
	if got, total, err := s.MACEntries(ctx, "sw-core", 0, 10); err != nil || len(got) != 0 || total != 0 {
		t.Fatalf("MACEntries of empty read: %v total %d, err %v", got, total, err)
	}
}

func TestFactsOneDeviceRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	want := netdevcontract.Facts{Model: "C9300-24P", FirmwareVersion: "17.9.4", Serial: "FDO2101",
		Hostname: "core1", UptimeSeconds: u64p(86400), ManagementAddresses: []string{"192.168.1.2"}}
	mustReplace(t, s, "sw-core", ReadFacts, testBase, false, FactsRows{Facts: want})

	got, err := s.Facts(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != want.Model || got.FirmwareVersion != want.FirmwareVersion || got.Serial != want.Serial ||
		got.Hostname != want.Hostname || got.UptimeSeconds == nil || *got.UptimeSeconds != 86400 ||
		len(got.ManagementAddresses) != 1 || got.ManagementAddresses[0] != "192.168.1.2" {
		t.Fatalf("Facts = %+v, want %+v", got, want)
	}
}

func TestVLANsAndPortsOneDeviceRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 1, Name: "default"}, {ID: 20, Name: "lab"}})
	mustReplace(t, s, "sw-core", ReadPorts, testBase, false, PortRows{
		{Name: "Gi1/0/1", AdminState: netdevcontract.LinkUp, OperState: netdevcontract.LinkUp,
			SpeedMbps: u64p(1000), Mode: netdevcontract.ModeAccess, AccessVLAN: u16p(20), Description: "nas"},
		{Name: "Gi1/0/2", AdminState: netdevcontract.LinkDown, OperState: netdevcontract.LinkDown,
			Mode: netdevcontract.ModeTrunk, NativeVLAN: u16p(1), AllowedVLANs: []uint16{1, 20}},
	})

	vlans, err := s.VLANs(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if len(vlans) != 2 || vlans[0].ID != 1 || vlans[1].ID != 20 || vlans[1].Name != "lab" {
		t.Fatalf("VLANs = %+v", vlans)
	}

	ports, err := s.Ports(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 {
		t.Fatalf("Ports = %+v, want 2", ports)
	}
	if p := ports[0]; p.Name != "Gi1/0/1" || p.SpeedMbps == nil || *p.SpeedMbps != 1000 ||
		p.AccessVLAN == nil || *p.AccessVLAN != 20 || p.Description != "nas" || p.Mode != netdevcontract.ModeAccess {
		t.Fatalf("port 0 = %+v", p)
	}
	if p := ports[1]; p.Name != "Gi1/0/2" || p.NativeVLAN == nil || *p.NativeVLAN != 1 || len(p.AllowedVLANs) != 2 ||
		p.AllowedVLANs[1] != 20 || p.SpeedMbps != nil {
		t.Fatalf("port 1 = %+v", p)
	}
}

// TestMACEntriesPagingAndLimitHit: MACEntries returns at most limit entries
// from offset in stored order, and the total of all present entries.
func TestMACEntriesPagingAndLimitHit(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	rows := MACRows{mac(1), mac(2), mac(3)}
	mustReplace(t, s, "sw-core", ReadMACTable, testBase, false, rows)

	tests := []struct {
		name      string
		offset    int
		limit     int
		wantLen   int
		wantTotal int
	}{
		{"first page cut at limit", 0, 2, 2, 3},
		{"second page", 2, 2, 1, 3},
		{"offset past the end", 3, 2, 0, 3},
		{"whole table", 0, netdevcontract.MaxMACEntriesPerDevice, 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, total, err := s.MACEntries(ctx, "sw-core", tt.offset, tt.limit)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.wantLen || total != tt.wantTotal {
				t.Fatalf("got %d entries, total %d; want %d and %d", len(got), total, tt.wantLen, tt.wantTotal)
			}
		})
	}

	for _, bad := range []struct{ offset, limit int }{{-1, 10}, {0, 0}, {0, netdevcontract.MaxMACEntriesPerDevice + 1}} {
		if _, _, err := s.MACEntries(ctx, "sw-core", bad.offset, bad.limit); err == nil {
			t.Fatalf("MACEntries(offset %d, limit %d) succeeded, want an error", bad.offset, bad.limit)
		}
	}
}

// TestLLDPNeighborsLimitHit: a partial read carries rows it did not cover, so
// the current table can hold more rows than the contract allows. The read
// returns no more than netdevcontract.MaxLLDPNeighborsPerDevice of them.
func TestLLDPNeighborsLimitHit(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	n := netdevcontract.MaxLLDPNeighborsPerDevice
	first := make(LLDPRows, 0, n)
	second := make(LLDPRows, 0, n)
	for i := range n {
		first = append(first, lldpNeighbor(i, "a"))
		second = append(second, lldpNeighbor(i, "b"))
	}
	mustReplace(t, s, "sw-core", ReadLLDPNeighbors, testBase, false, first)
	mustReplace(t, s, "sw-core", ReadLLDPNeighbors, testBase.Add(time.Minute), true, second)

	got, err := s.LLDPNeighbors(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != netdevcontract.MaxLLDPNeighborsPerDevice {
		t.Fatalf("LLDPNeighbors returned %d rows, want the limit %d", len(got), netdevcontract.MaxLLDPNeighborsPerDevice)
	}
}

func lldpNeighbor(i int, tag string) netdevcontract.LLDPNeighbor {
	return netdevcontract.LLDPNeighbor{
		LocalPort:    fmt.Sprintf("Gi1/0/%d", i+1),
		ChassisID:    fmt.Sprintf("00:11:22:33:44:%02x", i%256),
		PortID:       fmt.Sprintf("Gi0/%d-%s", i, tag),
		SystemName:   "peer",
		Capabilities: []netdevcontract.LLDPCapability{netdevcontract.CapBridge},
	}
}

// TestFirewallPolicyRoundTripInStoredOrder: the policy comes back with its
// rules in stored order and every part of it.
func TestFirewallPolicyRoundTripInStoredOrder(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, false, policy("b-rule", "a-rule"))

	got, err := s.FirewallPolicy(ctx, "fw-edge")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SecurityRules) != 2 || got.SecurityRules[0].Name != "b-rule" || got.SecurityRules[1].Name != "a-rule" {
		t.Fatalf("rules = %+v, want b-rule then a-rule", got.SecurityRules)
	}
	if r := got.SecurityRules[1]; len(r.From) != 1 || r.From[0] != "trust" || r.Action != netdevcontract.ActionAllow {
		t.Fatalf("rule columns not decoded: %+v", r)
	}
	if len(got.NATRules) != 1 || got.NATRules[0].Name != "outbound" {
		t.Fatalf("nat rules = %+v", got.NATRules)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Value != "192.168.1.0/24" {
		t.Fatalf("addresses = %+v", got.Addresses)
	}
	if len(got.AddressGroups) != 1 || len(got.AddressGroups[0].Static) != 1 {
		t.Fatalf("address groups = %+v", got.AddressGroups)
	}
	if len(got.Services) != 1 || got.Services[0].Port != "80,443" {
		t.Fatalf("services = %+v", got.Services)
	}
	if len(got.Zones) != 1 || got.Zones[0].Name != "trust" {
		t.Fatalf("zones = %+v", got.Zones)
	}
	if len(got.Interfaces) != 1 || got.Interfaces[0].VLANTag == nil || *got.Interfaces[0].VLANTag != 20 {
		t.Fatalf("interfaces = %+v", got.Interfaces)
	}
}

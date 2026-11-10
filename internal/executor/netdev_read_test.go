// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// cbsReads and panosReads are the typed reads of each family.
var (
	cbsReads = []pb.NetDeviceRead{
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP,
	}
	panosReads = []pb.NetDeviceRead{
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS,
	}
)

// TestNetDeviceReadFamilyCoversEveryEnumValue: every non-zero enum value
// of the descriptor has a family, and only those values do.
func TestNetDeviceReadFamilyCoversEveryEnumValue(t *testing.T) {
	vals := pb.NetDeviceRead(0).Descriptor().Values()
	for i := 0; i < vals.Len(); i++ {
		r := pb.NetDeviceRead(vals.Get(i).Number())
		fam, ok := netDeviceReadFamily(r)
		if r == pb.NetDeviceRead_NET_DEVICE_READ_UNSPECIFIED {
			if ok {
				t.Errorf("UNSPECIFIED has family %q", fam)
			}
			continue
		}
		if !ok {
			t.Errorf("%v has no family", r)
		}
	}
	for _, r := range cbsReads {
		if fam, _ := netDeviceReadFamily(r); fam != netdevcontract.FamilyCBS {
			t.Errorf("%v family %q, want cbs", r, fam)
		}
	}
	for _, r := range panosReads {
		if fam, _ := netDeviceReadFamily(r); fam != netdevcontract.FamilyPANOS {
			t.Errorf("%v family %q, want panos", r, fam)
		}
	}
}

// TestReadNetDeviceRefusesMalformedRequest: a nil request, a malformed
// device id and an unspecified or unknown enum value are InvalidArgument,
// decided before any store access (the service has no store here).
func TestReadNetDeviceRefusesMalformedRequest(t *testing.T) {
	svc := &Service{}
	for _, tc := range []struct {
		name string
		in   *pb.ReadNetDeviceRequest
	}{
		{"nil", nil},
		{"empty id", &pb.ReadNetDeviceRequest{Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION}},
		{"malformed id", &pb.ReadNetDeviceRequest{DeviceId: "../sw1", Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION}},
		{"long id", &pb.ReadNetDeviceRequest{DeviceId: strings.Repeat("a", netdevcontract.MaxDeviceIDBytes+1), Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION}},
		{"unspecified read", &pb.ReadNetDeviceRequest{DeviceId: "sw1"}},
		{"unknown read 11", &pb.ReadNetDeviceRequest{DeviceId: "sw1", Read: pb.NetDeviceRead(11)}},
		{"unknown read 999", &pb.ReadNetDeviceRequest{DeviceId: "sw1", Read: pb.NetDeviceRead(999)}},
		{"negative read", &pb.ReadNetDeviceRequest{DeviceId: "sw1", Read: pb.NetDeviceRead(-1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.ReadNetDevice(context.Background(), tc.in)
			if status.Code(err) != codes.InvalidArgument || got != nil {
				t.Fatalf("got %v, %v; want InvalidArgument and no reply", got, err)
			}
		})
	}
}

// TestReadNetDeviceRefusesBlockedAndRemovedDevices: a blocked device is
// FailedPrecondition, a removed (tombstoned) or unknown device NotFound, a
// read of the other family InvalidArgument; a live device with a matching
// read under an approved device read lease answers Unimplemented (device
// I/O comes with ND-14). No reply is returned in any case and no error
// repeats a vault reference.
func TestReadNetDeviceRefusesBlockedAndRemovedDevices(t *testing.T) {
	ge := newNetDevGrantEnv(t)
	e := &netDevTestEnv{db: ge.db, vault: ge.svc.vault, reg: &NetDeviceRegistry{Store: ge.db, Vault: ge.svc.vault}}
	ctx := context.Background()
	ge.grant(schedgrant.NetDeviceDefaultRunBudget, 900, permit.DefaultReadGrantLifetime,
		ge.target("core-sw", schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs,
			schedgrant.NetDeviceReadCBSInterfaces, schedgrant.NetDeviceReadCBSMACTable, schedgrant.NetDeviceReadCBSLLDP),
		ge.target("edge-fw", schedgrant.NetDeviceReadPANOSZones, schedgrant.NetDeviceReadPANOSObjects,
			schedgrant.NetDeviceReadPANOSSecurityRules, schedgrant.NetDeviceReadPANOSNATRules, schedgrant.NetDeviceReadPANOSRuleHitCounts))
	blockedReq := cbsReq("blocked-sw", "10.20.0.3")
	blockedReq.Pin = strings.Repeat("ab", 32)
	if _, err := e.reg.RegisterNetDevice(ctx, blockedReq); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.BlockNetDevice("blocked-sw", "pin mismatch"); err != nil {
		t.Fatal(err)
	}
	goneReq := cbsReq("old-sw", "10.20.0.9")
	goneReq.Pin = strings.Repeat("cd", 32)
	gone, err := e.reg.RegisterNetDevice(ctx, goneReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.TombstoneNetDevice("old-sw"); err != nil {
		t.Fatal(err)
	}

	svc := ge.svc
	type tc struct {
		id   string
		read pb.NetDeviceRead
		want codes.Code
	}
	var cases []tc
	for _, r := range cbsReads {
		cases = append(cases,
			tc{"core-sw", r, codes.Unimplemented},
			tc{"edge-fw", r, codes.InvalidArgument},
			tc{"blocked-sw", r, codes.FailedPrecondition},
			tc{"old-sw", r, codes.NotFound},
			tc{"no-such-sw", r, codes.NotFound},
		)
	}
	for _, r := range panosReads {
		cases = append(cases,
			tc{"edge-fw", r, codes.Unimplemented},
			tc{"core-sw", r, codes.InvalidArgument},
			tc{"blocked-sw", r, codes.FailedPrecondition},
			tc{"old-sw", r, codes.NotFound},
		)
	}
	for _, c := range cases {
		got, err := svc.ReadNetDevice(ctx, &pb.ReadNetDeviceRequest{DeviceId: c.id, Read: c.read})
		if status.Code(err) != c.want || got != nil {
			t.Errorf("%s %v: got %v, %v; want %v and no reply", c.id, c.read, got, err, c.want)
			continue
		}
		for _, ref := range []string{gone.DigestKeyRef, gone.FingerprintKeyRef, "netdev-"} {
			if ref != "" && strings.Contains(err.Error(), ref) {
				t.Errorf("%s %v: error repeats %q", c.id, c.read, ref)
			}
		}
	}
}

// TestReadNetDeviceFailsClosedWithoutStore: a valid request against a
// service without a registry is Internal with the fixed message.
func TestReadNetDeviceFailsClosedWithoutStore(t *testing.T) {
	got, err := (&Service{}).ReadNetDevice(context.Background(), &pb.ReadNetDeviceRequest{DeviceId: "sw1", Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION})
	if status.Code(err) != codes.Internal || got != nil || status.Convert(err).Message() != netDevRPCFailed {
		t.Fatalf("got %v, %v; want Internal %q", got, err, netDevRPCFailed)
	}
}

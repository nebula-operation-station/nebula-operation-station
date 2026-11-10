// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Network device typed reads (ADR 0010 D4; ND-12 part 1).
//
// ReadNetDevice is callable by the netdev-collector and the admin only
// (MethodRoles). It validates the request, refuses unknown reads, unknown,
// removed and blocked devices and a read of the other device family, then
// requires an approved device read lease and spends it
// (checkNetDeviceGrant, ND-13), then answers Unimplemented. Device I/O and
// the collector schedule (ND-14) come later.

// netDeviceReadFamilies maps every typed read to the one device family it
// applies to. A value missing here is not a read and is refused.
var netDeviceReadFamilies = map[pb.NetDeviceRead]netdevcontract.Family{
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION:           netdevcontract.FamilyCBS,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS:             netdevcontract.FamilyCBS,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES:        netdevcontract.FamilyCBS,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE:         netdevcontract.FamilyCBS,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP:              netdevcontract.FamilyCBS,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES:           netdevcontract.FamilyPANOS,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS:         netdevcontract.FamilyPANOS,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES:  netdevcontract.FamilyPANOS,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES:       netdevcontract.FamilyPANOS,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS: netdevcontract.FamilyPANOS,
}

// netDeviceReadFamily returns the device family of a typed read and false
// for UNSPECIFIED or any value outside the closed set.
func netDeviceReadFamily(r pb.NetDeviceRead) (netdevcontract.Family, bool) {
	f, ok := netDeviceReadFamilies[r]
	return f, ok
}

// ValidateReadNetDeviceRequest validates a ReadNetDevice request and
// returns a codes.InvalidArgument status error for a nil request, a
// malformed device_id (netdevcontract.ValidDeviceID) or a read outside the
// closed NetDeviceRead set. It reads no state.
func ValidateReadNetDeviceRequest(req *pb.ReadNetDeviceRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "read network device: request is nil")
	}
	if !netdevcontract.ValidDeviceID(req.DeviceId) {
		return status.Error(codes.InvalidArgument, "read network device: malformed device_id")
	}
	if _, ok := netDeviceReadFamily(req.Read); !ok {
		return status.Error(codes.InvalidArgument, "read network device: unknown read")
	}
	return nil
}

// ReadNetDevice runs one typed read against one registered device. It
// refuses every request it cannot serve or that no device read lease
// authorizes, and answers Unimplemented for the rest after recording the
// spend; it never dials a device and never opens a credential.
//
// TODO(ND-13/ND-14): ReadNetDeviceResponse bounds none of its repeated or
// string fields, so the per-read entry and byte limits of ADR 0010 D4
// (e.g. the 8,192 MAC-entry cap) must be enforced here, as named
// constants, when device I/O lands.
func (s *Service) ReadNetDevice(ctx context.Context, in *pb.ReadNetDeviceRequest) (*pb.ReadNetDeviceResponse, error) {
	if err := ValidateReadNetDeviceRequest(in); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, s.netDevReadFailed(ErrNetDevNoStore)
	}
	dev, ok, err := s.db.GetNetDevice(in.DeviceId)
	if err != nil {
		return nil, s.netDevReadFailed(fmt.Errorf("load network device %s: %w", in.DeviceId, err))
	}
	switch {
	case !ok || dev.TombstonedAt != nil:
		return nil, status.Error(codes.NotFound, "read network device: device not found")
	case dev.Blocked:
		return nil, status.Error(codes.FailedPrecondition, "read network device: device is blocked")
	}
	if fam, _ := netDeviceReadFamily(in.Read); fam != dev.Family {
		return nil, status.Error(codes.InvalidArgument, "read network device: read does not apply to the device family")
	}
	if _, err := s.checkNetDeviceGrant(ctx, in.DeviceId, in.Read, s.clock()); err != nil {
		st := netDeviceGrantStatus(err)
		if status.Code(st) == codes.Internal {
			return nil, s.netDevReadFailed(err)
		}
		return nil, st
	}
	// The read is authorized and its spend is recorded; device I/O comes
	// with ND-14.
	return nil, status.Error(codes.Unimplemented, "read network device: device reads are not implemented yet (ND-14)")
}

// netDevReadFailed logs an internal read failure and returns the fixed
// message; store errors are not passed to the caller.
func (s *Service) netDevReadFailed(err error) error {
	if s.log != nil {
		s.log.Error("netdev: read failed", "error", err.Error())
	}
	return status.Error(codes.Internal, netDevRPCFailed)
}

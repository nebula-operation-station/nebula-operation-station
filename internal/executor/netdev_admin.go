// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Network device administration RPCs (ADR 0010 D1, D2; ND-11 part 1).
//
// Every method is admin-only through the role table (MethodRoles), exactly
// like the PVE admin methods; the peercred interceptor refuses every other
// caller before a handler runs. Part 1 wires the surface: ListNetDevices
// reads the ND-10 registry, every other method answers Unimplemented
// until its lifecycle step lands.
//
// Secrets arrive only in the request fields marked SECRET (secret bytes);
// the handlers wipe them on return and never put them, a user name or a
// vault reference into a reply, an error or a log line. Replies carry
// ids, endpoint, pins, trust generation and credential version only.

// netDevRPCFailed is the fixed message of an internal failure: store and
// vault errors are not passed to the caller.
const netDevRPCFailed = "network device operation failed"

// errNetDevNoStore is returned when the service has no executor database.
var errNetDevNoStore = errors.New("executor: network device registry has no store")

// netDevUnimplemented is the answer of a method whose lifecycle step is
// not wired yet.
func netDevUnimplemented(method string) error {
	return status.Error(codes.Unimplemented, method+" is not implemented yet (ND-11)")
}

// ProbeNetDevice will probe a device endpoint without credentials.
func (s *Service) ProbeNetDevice(context.Context, *pb.ProbeNetDeviceRequest) (*pb.ProbeNetDeviceResponse, error) {
	return nil, netDevUnimplemented("ProbeNetDevice")
}

// RegisterNetDevice will register a probed device in the ND-10 registry.
func (s *Service) RegisterNetDevice(context.Context, *pb.RegisterNetDeviceRequest) (*pb.RegisterNetDeviceResponse, error) {
	return nil, netDevUnimplemented("RegisterNetDevice")
}

// SetNetDeviceCredential will store a device read credential. The secret
// buffer is wiped on return.
func (s *Service) SetNetDeviceCredential(_ context.Context, in *pb.SetNetDeviceCredentialRequest) (*pb.SetNetDeviceCredentialResponse, error) {
	defer clear(in.GetSecret())
	return nil, netDevUnimplemented("SetNetDeviceCredential")
}

// RotateNetDeviceCredential will replace a device read credential. The
// secret buffer is wiped on return.
func (s *Service) RotateNetDeviceCredential(_ context.Context, in *pb.RotateNetDeviceCredentialRequest) (*pb.RotateNetDeviceCredentialResponse, error) {
	defer clear(in.GetSecret())
	return nil, netDevUnimplemented("RotateNetDeviceCredential")
}

// ProposeNetDeviceRepin will propose a re-pin and return a HIGH permit
// bound to the device, its trust generation and both pins (ADR 0010 D1,
// mirroring ProposePVERepin).
func (s *Service) ProposeNetDeviceRepin(context.Context, *pb.ProposeNetDeviceRepinRequest) (*pb.ProposeNetDeviceRepinResponse, error) {
	return nil, netDevUnimplemented("ProposeNetDeviceRepin")
}

// CommitNetDeviceRepin will replace a device trust pin only under the
// approved, unexpired permit of a matching proposal (mirroring
// CommitPVERepin).
func (s *Service) CommitNetDeviceRepin(context.Context, *pb.CommitNetDeviceRepinRequest) (*pb.CommitNetDeviceRepinResponse, error) {
	return nil, netDevUnimplemented("CommitNetDeviceRepin")
}

// BlockNetDevice will block every dial to a device.
func (s *Service) BlockNetDevice(context.Context, *pb.BlockNetDeviceRequest) (*pb.BlockNetDeviceResponse, error) {
	return nil, netDevUnimplemented("BlockNetDevice")
}

// UnblockNetDevice will lift a device block.
func (s *Service) UnblockNetDevice(context.Context, *pb.UnblockNetDeviceRequest) (*pb.UnblockNetDeviceResponse, error) {
	return nil, netDevUnimplemented("UnblockNetDevice")
}

// RemoveNetDevice will remove a device.
func (s *Service) RemoveNetDevice(context.Context, *pb.RemoveNetDeviceRequest) (*pb.RemoveNetDeviceResponse, error) {
	return nil, netDevUnimplemented("RemoveNetDevice")
}

// ListNetDevices returns the metadata of every live registry device,
// ordered by id. It fails closed: any store error, invalid row or missing
// credential vault entry returns no devices.
func (s *Service) ListNetDevices(ctx context.Context, _ *pb.ListNetDevicesRequest) (*pb.ListNetDevicesResponse, error) {
	out, err := s.listNetDevices(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Error("netdev: list failed", "error", err.Error())
		}
		return nil, status.Error(codes.Internal, netDevRPCFailed)
	}
	return out, nil
}

func (s *Service) listNetDevices(ctx context.Context) (*pb.ListNetDevicesResponse, error) {
	if s.db == nil {
		return nil, errNetDevNoStore
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := s.db.ListNetDevices()
	if err != nil {
		return nil, err
	}
	out := &pb.ListNetDevicesResponse{}
	for _, d := range rows {
		var version int64
		if d.CredentialRef != "" {
			sec, err := s.db.GetSecret(d.CredentialRef)
			if err != nil {
				return nil, fmt.Errorf("credential version of network device %s: %w", d.ID, err)
			}
			version = sec.Version
		}
		out.Devices = append(out.Devices, netDeviceInfo(d, version))
	}
	return out, nil
}

// netDeviceInfo is the reply form of a registry row. It deliberately
// leaves out the credential, digest and fingerprint key references.
func netDeviceInfo(d executordb.NetDevice, credentialVersion int64) *pb.NetDeviceInfo {
	return &pb.NetDeviceInfo{
		DeviceId:          d.ID,
		Family:            string(d.Family),
		Label:             d.Label,
		EndpointIp:        d.EndpointIP,
		Port:              uint32(d.Port),
		PinKind:           string(d.PinKind),
		TrustPin:          d.PinValue,
		TrustGeneration:   d.TrustGeneration,
		Blocked:           d.Blocked,
		BlockReason:       d.BlockReason,
		CredentialVersion: credentialVersion,
		CreatedAtUnix:     d.CreatedAt.Unix(),
		UpdatedAtUnix:     d.UpdatedAt.Unix(),
	}
}

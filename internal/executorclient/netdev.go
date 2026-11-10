// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Typed convenience wrappers for the network device collector and admin
// reads (ADR 0010 D4, ND-12). They build the request and delegate to the
// ListNetDevices and ReadNetDevice pass-throughs, so the per-call timeout
// and the error mapping are the same as for every other RPC. Request and
// reply contents are never logged: replies carry untrusted device output.

// ListNetDeviceInfos returns the metadata of every live network device
// (roles: admin, netdev-collector). On error the slice is nil.
func (c *Client) ListNetDeviceInfos(ctx context.Context) ([]*pb.NetDeviceInfo, error) {
	resp, err := c.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetDevices(), nil
}

// ReadNetDeviceByID runs one typed read against one registered device
// (roles: admin, netdev-collector). The executor validates deviceID and
// read; until device I/O lands (ND-13/ND-14) a valid read fails with the
// gRPC Unimplemented status as cause.
func (c *Client) ReadNetDeviceByID(ctx context.Context, deviceID string, read pb.NetDeviceRead) (*pb.ReadNetDeviceResponse, error) {
	return c.ReadNetDevice(ctx, &pb.ReadNetDeviceRequest{DeviceId: deviceID, Read: read})
}

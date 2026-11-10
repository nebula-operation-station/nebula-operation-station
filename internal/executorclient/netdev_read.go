// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ReadNetDevice runs one typed network device read (ADR 0010 D4, ND-12).
// Role: admin, netdev-collector. The executor answers Unimplemented for
// every valid read until device I/O lands (ND-13/ND-14).
func (c *Client) ReadNetDevice(ctx context.Context, in *pb.ReadNetDeviceRequest, opts ...grpc.CallOption) (*pb.ReadNetDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ReadNetDevice(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

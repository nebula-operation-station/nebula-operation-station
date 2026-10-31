// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// GetSessionState reports the executor's authoritative privileged session
// state (server and admin roles): whether the session is active, its
// expiry, the executor-configured duration and the remaining time. The
// server displays these values; it cannot choose or extend the duration.
func (c *Client) GetSessionState(ctx context.Context, in *pb.GetSessionStateRequest, opts ...grpc.CallOption) (*pb.GetSessionStateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetSessionState(ctx, in, opts...)
	return resp, mapError(err)
}

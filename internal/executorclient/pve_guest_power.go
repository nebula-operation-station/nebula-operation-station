// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// pveGuestPowerCommitWait is the extra time a power commit may take: the
// executor waits for the PVE task (a graceful shutdown can take minutes);
// a task still running then stays open for reconciliation.
const pveGuestPowerCommitWait = 10 * time.Minute

// ProposePVEGuestPower proposes a typed guest power action (server and
// admin roles). The executor binds the exact guest and sets the risk.
func (c *Client) ProposePVEGuestPower(ctx context.Context, in *pb.ProposePVEGuestPowerRequest, opts ...grpc.CallOption) (*pb.ProposePVEGuestPowerResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposePVEGuestPower(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitPVEGuestPower runs an approved guest power action (admin role).
// It waits for the PVE task, so it gets a longer timeout.
func (c *Client) CommitPVEGuestPower(ctx context.Context, in *pb.CommitPVEGuestPowerRequest, opts ...grpc.CallOption) (*pb.CommitPVEGuestPowerResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+pveGuestPowerCommitWait)
	defer cancel()
	resp, err := c.rpc.CommitPVEGuestPower(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

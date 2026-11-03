// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ProposePVEGuestSnapshot proposes a typed guest snapshot action (create,
// delete or rollback of one exact snapshot). The executor binds the disk
// set or the exact snapshot and sets the risk.
func (c *Client) ProposePVEGuestSnapshot(ctx context.Context, in *pb.ProposePVEGuestSnapshotRequest, opts ...grpc.CallOption) (*pb.ProposePVEGuestSnapshotResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposePVEGuestSnapshot(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitPVEGuestSnapshot runs an approved guest snapshot action. It waits
// for the PVE task, so it gets the longer power commit timeout.
func (c *Client) CommitPVEGuestSnapshot(ctx context.Context, in *pb.CommitPVEGuestSnapshotRequest, opts ...grpc.CallOption) (*pb.CommitPVEGuestSnapshotResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+pveGuestPowerCommitWait)
	defer cancel()
	resp, err := c.rpc.CommitPVEGuestSnapshot(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

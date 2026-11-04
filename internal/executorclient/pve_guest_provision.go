// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// pveGuestProvisionCommitWait is the extra time a provisioning commit may
// take: the executor waits for the clone, config, resize and start tasks
// in turn, each up to its task wait bound (a full clone can take many
// minutes), so the deadline is the executor's whole run bound
// (30 min before, shorter than one run). Should the call still end
// earlier, the executor replies with the step states shortly before the
// deadline; a task still running stays open and is reconciled by the
// executor, never resent.
const pveGuestProvisionCommitWait = executor.PveGuestProvisionRunBound

// ProposePVEGuestProvision proposes a guest provisioning (server and admin
// roles, ADR 0008 section 3). The executor binds the template record,
// reserves the VMID and sets the risk.
func (c *Client) ProposePVEGuestProvision(ctx context.Context, in *pb.ProposePVEGuestProvisionRequest, opts ...grpc.CallOption) (*pb.ProposePVEGuestProvisionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposePVEGuestProvision(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitPVEGuestProvision runs an approved guest provisioning (server and
// admin roles; the executor requires the approved permit). It waits for the
// PVE tasks, so it gets a longer timeout.
func (c *Client) CommitPVEGuestProvision(ctx context.Context, in *pb.CommitPVEGuestProvisionRequest, opts ...grpc.CallOption) (*pb.CommitPVEGuestProvisionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+pveGuestProvisionCommitWait)
	defer cancel()
	resp, err := c.rpc.CommitPVEGuestProvision(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

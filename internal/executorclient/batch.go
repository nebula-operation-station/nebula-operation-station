// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ProposeBatch proposes a complete bounded batch plan (server role). The
// executor derives risk and binds the approval requirement.
func (c *Client) ProposeBatch(ctx context.Context, in *pb.ProposeBatchRequest, opts ...grpc.CallOption) (*pb.ProposeBatchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposeBatch(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitBatch relays a user-verified assertion for the batch-bound challenge
// (server role). The executor verifies it; this is never a server approval.
func (c *Client) CommitBatch(ctx context.Context, in *pb.CommitBatchRequest, opts ...grpc.CallOption) (*pb.CommitBatchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitBatch(ctx, in, opts...)
	return resp, mapError(err)
}

// ReviewBatch retrieves the complete frozen plan for local review (admin role).
func (c *Client) ReviewBatch(ctx context.Context, in *pb.ReviewBatchRequest, opts ...grpc.CallOption) (*pb.ReviewBatchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ReviewBatch(ctx, in, opts...)
	return resp, mapError(err)
}

// ApproveBatchCLI approves a locally reviewed batch digest (admin role only).
func (c *Client) ApproveBatchCLI(ctx context.Context, in *pb.ApproveBatchCLIRequest, opts ...grpc.CallOption) (*pb.ApproveBatchCLIResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ApproveBatchCLI(ctx, in, opts...)
	return resp, mapError(err)
}

// GetBatchStatus confirms a batch is approved and fresh and returns its
// parent/member linkage (server and admin roles).
func (c *Client) GetBatchStatus(ctx context.Context, in *pb.GetBatchStatusRequest, opts ...grpc.CallOption) (*pb.GetBatchStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetBatchStatus(ctx, in, opts...)
	return resp, mapError(err)
}

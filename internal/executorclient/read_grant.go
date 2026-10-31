// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ProposeReadGrant proposes a frozen read-grant document (server role).
func (c *Client) ProposeReadGrant(ctx context.Context, in *pb.ProposeReadGrantRequest, opts ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposeReadGrant(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitReadGrant relays an assertion for executor UV verification (server role).
func (c *Client) CommitReadGrant(ctx context.Context, in *pb.CommitReadGrantRequest, opts ...grpc.CallOption) (*pb.CommitReadGrantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitReadGrant(ctx, in, opts...)
	return resp, mapError(err)
}

// ListPendingReadGrants retrieves complete proposals for local review (admin role).
func (c *Client) ListPendingReadGrants(ctx context.Context, in *pb.ListPendingReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListPendingReadGrantsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListPendingReadGrants(ctx, in, opts...)
	return resp, mapError(err)
}

// ApproveReadGrantCLI approves a locally reviewed digest (admin role only).
func (c *Client) ApproveReadGrantCLI(ctx context.Context, in *pb.ApproveReadGrantCLIRequest, opts ...grpc.CallOption) (*pb.ApproveReadGrantCLIResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ApproveReadGrantCLI(ctx, in, opts...)
	return resp, mapError(err)
}

// ListReadGrants lists approved read grants (server and admin roles).
func (c *Client) ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListReadGrants(ctx, in, opts...)
	return resp, mapError(err)
}

// RevokeReadGrant revokes authority without an assertion (server and admin roles).
func (c *Client) RevokeReadGrant(ctx context.Context, in *pb.RevokeReadGrantRequest, opts ...grpc.CallOption) (*pb.RevokeReadGrantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RevokeReadGrant(ctx, in, opts...)
	return resp, mapError(err)
}

// RunReadGrant executes one scheduled or on-demand read (server role).
// Like RunScheduled it allows the bounded remote run plus the call timeout.
func (c *Client) RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	t := time.Duration(in.GetTimeoutSeconds()) * time.Second
	if t <= 0 || t > 10*time.Minute {
		t = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+t)
	defer cancel()
	resp, err := c.rpc.RunReadGrant(ctx, in, opts...)
	return resp, mapError(err)
}

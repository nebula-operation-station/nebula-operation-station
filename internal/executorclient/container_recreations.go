// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Container recreation RPCs (ADR 0006 P2-04/P2-05, cu03). Plain
// pass-throughs that keep the generated interface implemented; the
// executor's role table decides who may call them (list and resolve:
// server and admin, recovery plans: admin only).

// ListContainerRecreations lists sanitized recreation rows.
func (c *Client) ListContainerRecreations(ctx context.Context, in *pb.ListContainerRecreationsRequest, opts ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListContainerRecreations(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// SetContainerRecoveryPlan records a unit's recovery plan (admin role).
func (c *Client) SetContainerRecoveryPlan(ctx context.Context, in *pb.SetContainerRecoveryPlanRequest, opts ...grpc.CallOption) (*pb.SetContainerRecoveryPlanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.SetContainerRecoveryPlan(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ClearContainerRecoveryPlan removes a unit's recovery plan (admin role).
func (c *Client) ClearContainerRecoveryPlan(ctx context.Context, in *pb.ClearContainerRecoveryPlanRequest, opts ...grpc.CallOption) (*pb.ClearContainerRecoveryPlanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ClearContainerRecoveryPlan(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ResolveContainerRecreation resolves an uncertain recreation row from a
// retained docker.update_preview run.
func (c *Client) ResolveContainerRecreation(ctx context.Context, in *pb.ResolveContainerRecreationRequest, opts ...grpc.CallOption) (*pb.ResolveContainerRecreationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ResolveContainerRecreation(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Standalone container definition RPCs (ADR 0006 P2-03, cu05). Plain
// pass-throughs that keep the generated interface implemented; the
// executor's role table admits only the admin role.

// PutContainerDefinition stores a new definition version in the executor
// vault (admin role).
func (c *Client) PutContainerDefinition(ctx context.Context, in *pb.PutContainerDefinitionRequest, opts ...grpc.CallOption) (*pb.PutContainerDefinitionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.PutContainerDefinition(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// RemoveContainerDefinition removes a definition or one older version
// (admin role).
func (c *Client) RemoveContainerDefinition(ctx context.Context, in *pb.RemoveContainerDefinitionRequest, opts ...grpc.CallOption) (*pb.RemoveContainerDefinitionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemoveContainerDefinition(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ListContainerDefinitions lists definition metadata (admin role).
func (c *Client) ListContainerDefinitions(ctx context.Context, in *pb.ListContainerDefinitionsRequest, opts ...grpc.CallOption) (*pb.ListContainerDefinitionsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListContainerDefinitions(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

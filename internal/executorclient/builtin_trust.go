// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ReviewBuiltinTrust retrieves the complete review of the executor's local
// built-in release bundle (admin role only). It commits nothing.
func (c *Client) ReviewBuiltinTrust(ctx context.Context, in *pb.ReviewBuiltinTrustRequest, opts ...grpc.CallOption) (*pb.ReviewBuiltinTrustResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ReviewBuiltinTrust(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitBuiltinTrust commits the reviewed built-in trust change bound to the
// confirmed manifest digest (admin role only). The server role cannot reach
// it: there is no server bulk trust.
func (c *Client) CommitBuiltinTrust(ctx context.Context, in *pb.CommitBuiltinTrustRequest, opts ...grpc.CallOption) (*pb.CommitBuiltinTrustResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitBuiltinTrust(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// GetBuiltinTrustStatus reads which built-in versions are trusted and which
// are not (server and admin roles). Metadata only; it grants nothing.
func (c *Client) GetBuiltinTrustStatus(ctx context.Context, in *pb.GetBuiltinTrustStatusRequest, opts ...grpc.CallOption) (*pb.GetBuiltinTrustStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetBuiltinTrustStatus(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// UnpinBuiltinVersion clears the saved retention pin of one old built-in
// version (admin role only). It deletes and revokes nothing.
func (c *Client) UnpinBuiltinVersion(ctx context.Context, in *pb.UnpinBuiltinVersionRequest, opts ...grpc.CallOption) (*pb.UnpinBuiltinVersionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.UnpinBuiltinVersion(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ReviewRootRotation is admin-only on the executor; the server role is
// always refused. It exists so the client implements the interface.
func (c *Client) ReviewRootRotation(ctx context.Context, in *pb.ReviewRootRotationRequest, opts ...grpc.CallOption) (*pb.ReviewRootRotationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ReviewRootRotation(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitRootRotation is admin-only on the executor; the server role is
// always refused. It exists so the client implements the interface.
func (c *Client) CommitRootRotation(ctx context.Context, in *pb.CommitRootRotationRequest, opts ...grpc.CallOption) (*pb.CommitRootRotationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitRootRotation(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Private registry RPCs (ADR 0006, P1-32). These are plain pass-throughs
// that keep the generated interface implemented; the executor's role table
// decides who may call them (credential administration is admin-only, the
// server can only list metadata and request typed reads).

// AddPrivateRegistry stores a private registry and its credential in the
// executor vault (admin role).
func (c *Client) AddPrivateRegistry(ctx context.Context, in *pb.AddPrivateRegistryRequest, opts ...grpc.CallOption) (*pb.AddPrivateRegistryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.AddPrivateRegistry(ctx, in, opts...)
	return resp, mapError(err)
}

// RotatePrivateRegistryCredential replaces a private registry credential
// (admin role).
func (c *Client) RotatePrivateRegistryCredential(ctx context.Context, in *pb.RotatePrivateRegistryCredentialRequest, opts ...grpc.CallOption) (*pb.RotatePrivateRegistryCredentialResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RotatePrivateRegistryCredential(ctx, in, opts...)
	return resp, mapError(err)
}

// RemovePrivateRegistry removes a private registry and its credential
// (admin role).
func (c *Client) RemovePrivateRegistry(ctx context.Context, in *pb.RemovePrivateRegistryRequest, opts ...grpc.CallOption) (*pb.RemovePrivateRegistryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemovePrivateRegistry(ctx, in, opts...)
	return resp, mapError(err)
}

// ListPrivateRegistries lists private registry metadata without
// credentials (server and admin roles).
func (c *Client) ListPrivateRegistries(ctx context.Context, in *pb.ListPrivateRegistriesRequest, opts ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListPrivateRegistries(ctx, in, opts...)
	return resp, mapError(err)
}

// ReadPrivateRegistry asks the executor for one typed, sanitized private
// registry metadata read (server and admin roles).
func (c *Client) ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest, opts ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ReadPrivateRegistry(ctx, in, opts...)
	return resp, mapError(err)
}

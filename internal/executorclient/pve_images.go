// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The image preparation RPCs (ADR 0008 amendment 2, PV-03a) are plain
// pass-throughs here so that *Client keeps implementing the generated
// interface. The executor handlers, and with them the commit wait bound of
// a preparation (image download and import), follow in later tickets.

// ProposePVEImagePrepare proposes a pve.image.prepare (server and admin
// roles). The executor resolves the catalog image and sets the risk.
func (c *Client) ProposePVEImagePrepare(ctx context.Context, in *pb.ProposePVEImagePrepareRequest, opts ...grpc.CallOption) (*pb.ProposePVEImagePrepareResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposePVEImagePrepare(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitPVEImagePrepare runs an approved image preparation (server and
// admin roles; the executor requires the approved permit).
func (c *Client) CommitPVEImagePrepare(ctx context.Context, in *pb.CommitPVEImagePrepareRequest, opts ...grpc.CallOption) (*pb.CommitPVEImagePrepareResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitPVEImagePrepare(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ListPVEImages lists the image catalog and the prepared template records
// (server and admin roles, read-only).
func (c *Client) ListPVEImages(ctx context.Context, in *pb.ListPVEImagesRequest, opts ...grpc.CallOption) (*pb.ListPVEImagesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListPVEImages(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// AddPVELocalImage adds a local image entry (admin role only).
func (c *Client) AddPVELocalImage(ctx context.Context, in *pb.AddPVELocalImageRequest, opts ...grpc.CallOption) (*pb.AddPVELocalImageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.AddPVELocalImage(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// RemovePVELocalImage removes a local image entry (admin role only).
func (c *Client) RemovePVELocalImage(ctx context.Context, in *pb.RemovePVELocalImageRequest, opts ...grpc.CallOption) (*pb.RemovePVELocalImageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemovePVELocalImage(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// pveImagePrepareCommitWait is the extra time an image preparation commit may
// take. The executor runs three steps in turn (the image download, the
// template VM creation with its import, and the template conversion), each
// waiting up to one PVE task wait bound, which is not exported. The
// executor's provisioning run bound covers four such steps plus the reads
// around them, so it is a safe upper bound for three. A dedicated exported
// image bound in the executor would replace this (follow-up, executor path
// is protected).
const pveImagePrepareCommitWait = executor.PveGuestProvisionRunBound

// The image preparation RPCs (ADR 0008 amendment 2, PV-03f) are forwarded
// here, except the local-entry RPCs, which are not forwarded (see
// AddPVELocalImage and RemovePVELocalImage).

// ProposePVEImagePrepare proposes a pve.image.prepare (server and admin
// roles). The executor resolves the catalog image and sets the risk.
func (c *Client) ProposePVEImagePrepare(ctx context.Context, in *pb.ProposePVEImagePrepareRequest, opts ...grpc.CallOption) (*pb.ProposePVEImagePrepareResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposePVEImagePrepare(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitPVEImagePrepare runs an approved image preparation (server and
// admin roles; the executor requires the approved permit). It waits for the
// download, import and template tasks, so it gets a longer timeout
// (pveImagePrepareCommitWait); a default-length deadline would cancel a
// real preparation part-way through.
func (c *Client) CommitPVEImagePrepare(ctx context.Context, in *pb.CommitPVEImagePrepareRequest, opts ...grpc.CallOption) (*pb.CommitPVEImagePrepareResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+pveImagePrepareCommitWait)
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

// AddPVELocalImage is not forwarded: local image entries are written only by
// the admin role over the admin socket (ADR 0008 amendment 2, PV-03f, D3 (a)),
// and this client serves the server role. It returns ErrPermissionDenied
// without calling the executor, so no caller of this client can add a local
// entry. The method stays because *Client must implement the generated
// interface. The admin CLI uses the raw generated client on its own socket
// and does not go through here.
func (c *Client) AddPVELocalImage(_ context.Context, _ *pb.AddPVELocalImageRequest, _ ...grpc.CallOption) (*pb.AddPVELocalImageResponse, error) {
	return nil, fmt.Errorf("add pve local image: not forwarded by executorclient: %w", ErrPermissionDenied)
}

// RemovePVELocalImage is not forwarded, for the same reason as
// AddPVELocalImage: it returns ErrPermissionDenied without a call, and the
// admin CLI uses the raw generated client over the admin socket.
func (c *Client) RemovePVELocalImage(_ context.Context, _ *pb.RemovePVELocalImageRequest, _ ...grpc.CallOption) (*pb.RemovePVELocalImageResponse, error) {
	return nil, fmt.Errorf("remove pve local image: not forwarded by executorclient: %w", ErrPermissionDenied)
}

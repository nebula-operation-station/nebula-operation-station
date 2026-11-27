// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The server forwards the image preparation RPCs (ADR 0008 amendment 2,
// PV-03g). It never approves: a commit runs only with the execution digest
// the user approved, and the executor checks the permit. Local catalog
// entries are not forwarded at all (admin socket only, D3 (a)).

// Errors the UI tells apart. Each is returned wrapped together with the
// executor error it came from, so errors.Is finds the sentinel and the
// cause stays available for logs.
var (
	// ErrImageUnknown: the image ID is not in the executor's catalog.
	ErrImageUnknown = errors.New("image is not in the catalog")
	// ErrImageAlreadyPrepared: a template for this image already exists on
	// the storage.
	ErrImageAlreadyPrepared = errors.New("image is already prepared on this storage")
	// ErrImageRemoteChanged: the PVE remote, node or storage changed since
	// the proposal; propose again.
	ErrImageRemoteChanged = errors.New("pve remote, node or storage changed; propose again")
	// ErrImageTemplateChanged: the prepared template is gone or no longer
	// matches its record.
	ErrImageTemplateChanged = errors.New("prepared template is gone or changed")
	// ErrImageExecutorUnavailable: the executor could not be reached. The
	// caller learned nothing and changed nothing; it is never an empty list.
	ErrImageExecutorUnavailable = errors.New("executor unreachable; nothing was listed or changed")
	// ErrImageNotApproved: a commit lacked the spec or the approved
	// execution digest, so it was not sent.
	ErrImageNotApproved = errors.New("commit needs the proposed spec and the approved execution digest")
)

// The image RPCs send these fixed texts (internal/executor pve_rpc.go,
// pveImagePrepareRPCError). They are matched inside the error text; the
// executor never sends remote-supplied text in them.
const (
	imageTextUnknown  = "the image is not in the catalog"
	imageTextPrepared = "already prepared on this storage"
	imageTextRemote   = "node, storage or remote changed"
	imageTextTemplate = "template is gone or changed"
)

// pveImageExecutor is the part of the executor the image RPCs use.
type pveImageExecutor interface {
	ProposePVEImagePrepare(context.Context, *pb.ProposePVEImagePrepareRequest, ...grpc.CallOption) (*pb.ProposePVEImagePrepareResponse, error)
	CommitPVEImagePrepare(context.Context, *pb.CommitPVEImagePrepareRequest, ...grpc.CallOption) (*pb.CommitPVEImagePrepareResponse, error)
	ListPVEImages(context.Context, *pb.ListPVEImagesRequest, ...grpc.CallOption) (*pb.ListPVEImagesResponse, error)
}

// proposeImagePrepare forwards a preparation proposal and returns the
// executor's answer unchanged.
func proposeImagePrepare(ctx context.Context, x pveImageExecutor, in *pb.ProposePVEImagePrepareRequest) (*pb.ProposePVEImagePrepareResponse, error) {
	out, err := x.ProposePVEImagePrepare(ctx, in)
	if err != nil {
		return nil, classifyImageError(err)
	}
	return out, nil
}

// commitImagePrepare forwards the run of an approved preparation. It refuses
// before any call when the spec or the approved execution digest is missing,
// so the server cannot send a commit the user did not approve.
func commitImagePrepare(ctx context.Context, x pveImageExecutor, in *pb.CommitPVEImagePrepareRequest) (*pb.CommitPVEImagePrepareResponse, error) {
	if in.GetSpec() == nil || in.GetExecutionDigest() == "" {
		return nil, ErrImageNotApproved
	}
	out, err := x.CommitPVEImagePrepare(ctx, in)
	if err != nil {
		return nil, classifyImageError(err)
	}
	return out, nil
}

// listImages forwards the catalog and template read and returns the
// executor's answer unchanged. A failed read returns an error and no list.
func listImages(ctx context.Context, x pveImageExecutor) (*pb.ListPVEImagesResponse, error) {
	out, err := x.ListPVEImages(ctx, &pb.ListPVEImagesRequest{})
	if err != nil {
		return nil, classifyImageError(err)
	}
	return out, nil
}

// classifyImageError maps an executor failure to the image sentinel the UI
// branches on. An unreachable executor is checked first and is never
// reported as an empty result. Other failures pass through unchanged, so
// their typed executorclient codes (for example permission denied) still
// match.
func classifyImageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errNotConnected) || errors.Is(err, executorclient.ErrUnavailable) || status.Code(err) == codes.Unavailable {
		return fmt.Errorf("%w: %w", ErrImageExecutorUnavailable, err)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, imageTextUnknown):
		return fmt.Errorf("%w: %w", ErrImageUnknown, err)
	case strings.Contains(msg, imageTextPrepared):
		return fmt.Errorf("%w: %w", ErrImageAlreadyPrepared, err)
	case strings.Contains(msg, imageTextRemote):
		return fmt.Errorf("%w: %w", ErrImageRemoteChanged, err)
	case strings.Contains(msg, imageTextTemplate):
		return fmt.Errorf("%w: %w", ErrImageTemplateChanged, err)
	}
	return err
}

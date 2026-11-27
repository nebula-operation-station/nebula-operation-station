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
// PV-03g). It never approves: it forwards the user's approved spec and
// execution digest, and the executor checks the permit. The server only checks
// that both are present before a commit is sent. Local catalog entries are not
// forwarded at all (admin socket only, D3 (a)).

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
	// ErrImageExecutorUnavailable: the executor could not be reached (no
	// connection, dial failure, or no answer before the deadline). The
	// executor did not receive the call, or the call was a read, so nothing
	// was listed or changed. It is never an empty list.
	ErrImageExecutorUnavailable = errors.New("executor unreachable; nothing was listed or changed")
	// ErrImageBusy: the executor answered that another mutation of the node
	// is in progress. The executor is reachable; try again later.
	ErrImageBusy = errors.New("the node is busy with another change; try again later")
	// ErrImageTryAgain: the executor answered that it could not read the
	// prepared template or its records right now. The executor is reachable;
	// try again later.
	ErrImageTryAgain = errors.New("the executor could not read the image records right now; try again later")
	// ErrImageOutcomeUnknown: a commit was sent and the answer is missing or
	// uncertain, so the executor may or may not have prepared the image.
	// Check the image status before retrying.
	ErrImageOutcomeUnknown = errors.New("outcome unknown; check the image status before you retry")
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
	// Unavailable answers from the executor. They are sent while the
	// executor is reachable, so they are never "executor unreachable".
	imageTextBusy    = "another mutation of the node is in progress"
	imageTextUnread  = "the prepared template could not be read"
	imageTextRecords = "the template or job records are unavailable"
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
// before any call when the spec or the approved execution digest is missing.
// The check is presence only; the executor's permit decides whether the
// digest approves this exact run.
func commitImagePrepare(ctx context.Context, x pveImageExecutor, in *pb.CommitPVEImagePrepareRequest) (*pb.CommitPVEImagePrepareResponse, error) {
	if err := checkImageCommitInput(in); err != nil {
		return nil, err
	}
	out, err := x.CommitPVEImagePrepare(ctx, in)
	if err != nil {
		return nil, classifyCommitImageError(err)
	}
	return out, nil
}

// checkImageCommitInput refuses a commit that lacks the spec or the execution
// digest. It runs before any call, on the production forwarding path too (see
// lazyExecutor.CommitPVEImagePrepare).
func checkImageCommitInput(in *pb.CommitPVEImagePrepareRequest) error {
	if in.GetSpec() == nil || in.GetExecutionDigest() == "" {
		return ErrImageNotApproved
	}
	return nil
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

// classifyImageError maps the failure of a read or a proposal to the image
// sentinel the UI branches on. Nothing is changed by these calls, so
// ErrImageExecutorUnavailable ("nothing was listed or changed") is accurate
// for every transport failure.
func classifyImageError(err error) error {
	return classifyImage(err, false)
}

// classifyCommitImageError maps the failure of a commit. A commit that was
// sent and got no clear answer may have changed the node, so a transport
// failure or an unclear executor answer is ErrImageOutcomeUnknown and never
// "nothing was changed". Only a missing connection (nothing sent) and the
// executor's own refusals are reported as such.
func classifyCommitImageError(err error) error {
	return classifyImage(err, true)
}

// unknownOutcome wraps a failure of a sent commit. Its text is the sentinel
// alone: the executor's text may claim that nothing was recorded, which the
// server cannot verify after a commit was sent. The cause stays in the chain
// for logs.
func unknownOutcome(cause error) error {
	return &imageOutcomeError{cause: cause}
}

// imageOutcomeError is the error returned by unknownOutcome.
type imageOutcomeError struct{ cause error }

// Error shows the UI text only.
func (e *imageOutcomeError) Error() string { return ErrImageOutcomeUnknown.Error() }

// Unwrap returns the sentinel and the executor's error.
func (e *imageOutcomeError) Unwrap() []error { return []error{ErrImageOutcomeUnknown, e.cause} }

// classifyImage is the shared mapping. The executor's answer is matched
// first, by its fixed text; only then is a gRPC Unavailable or a deadline
// treated as a transport failure. Other failures pass through unchanged, so
// their typed executorclient codes (for example permission denied) still
// match.
func classifyImage(err error, commit bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errNotConnected) {
		// No connection: the call was never sent.
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
	case strings.Contains(msg, imageTextBusy):
		return fmt.Errorf("%w: %w", ErrImageBusy, err)
	case strings.Contains(msg, imageTextUnread), strings.Contains(msg, imageTextRecords):
		// The executor answered after the mutation may already have run
		// (for a commit), so the outcome is not known.
		if commit {
			return unknownOutcome(err)
		}
		return fmt.Errorf("%w: %w", ErrImageTryAgain, err)
	}
	if isImageTransportFailure(err) {
		if commit {
			return unknownOutcome(err)
		}
		return fmt.Errorf("%w: %w", ErrImageExecutorUnavailable, err)
	}
	return err
}

// isImageTransportFailure reports an Unavailable or deadline failure whose
// text is not one of the executor's image answers above. The executor sends
// only those fixed texts for the image RPCs, so the rest comes from the
// transport (no connection, a closed socket, no answer before the deadline).
func isImageTransportFailure(err error) bool {
	return status.Code(err) == codes.Unavailable ||
		errors.Is(err, executorclient.ErrUnavailable) ||
		errors.Is(err, executorclient.ErrDeadlineExceeded)
}

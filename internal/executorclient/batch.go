// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ProposeBatch proposes a complete bounded batch plan (server role). The
// executor derives risk and binds the approval requirement.
func (c *Client) ProposeBatch(ctx context.Context, in *pb.ProposeBatchRequest, opts ...grpc.CallOption) (*pb.ProposeBatchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposeBatch(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// CommitBatch relays a user-verified assertion for the batch-bound challenge
// (server role). The executor verifies it; this is never a server approval.
func (c *Client) CommitBatch(ctx context.Context, in *pb.CommitBatchRequest, opts ...grpc.CallOption) (*pb.CommitBatchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitBatch(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ReviewBatch retrieves the complete frozen plan for local review (admin role).
func (c *Client) ReviewBatch(ctx context.Context, in *pb.ReviewBatchRequest, opts ...grpc.CallOption) (*pb.ReviewBatchResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ReviewBatch(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// ApproveBatchCLI approves a locally reviewed batch digest (admin role only).
func (c *Client) ApproveBatchCLI(ctx context.Context, in *pb.ApproveBatchCLIRequest, opts ...grpc.CallOption) (*pb.ApproveBatchCLIResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ApproveBatchCLI(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// GetBatchStatus confirms a batch is approved and fresh and returns its
// parent/member linkage (server and admin roles).
func (c *Client) GetBatchStatus(ctx context.Context, in *pb.GetBatchStatusRequest, opts ...grpc.CallOption) (*pb.GetBatchStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetBatchStatus(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// GetBatchCredentialVersions reads the executor's current versions of SSH
// credential references for a batch plan (server and admin roles,
// read-only; versions and public-key fingerprints only).
func (c *Client) GetBatchCredentialVersions(ctx context.Context, in *pb.GetBatchCredentialVersionsRequest, opts ...grpc.CallOption) (*pb.GetBatchCredentialVersionsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetBatchCredentialVersions(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// RunBatchMember runs one claimed member of an approved batch (server
// role). Its deadline covers the member's run timeout plus a margin, like
// RunAttached, never the short default call timeout.
func (c *Client) RunBatchMember(ctx context.Context, in *pb.RunBatchMemberRequest, opts ...grpc.CallOption) (*pb.RunBatchMemberResponse, error) {
	t := time.Duration(in.GetTimeoutSeconds()) * time.Second
	if t <= 0 || t > 10*time.Minute {
		t = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, t+time.Minute)
	defer cancel()
	resp, err := c.rpc.RunBatchMember(ctx, in, opts...)
	return resp, mapCallError(ctx, err)
}

// BatchCredentialReader reads the executor's batch credential versions.
// Client satisfies it.
type BatchCredentialReader interface {
	GetBatchCredentialVersions(ctx context.Context, in *pb.GetBatchCredentialVersionsRequest, opts ...grpc.CallOption) (*pb.GetBatchCredentialVersionsResponse, error)
}

// CredentialVersion returns the executor's current batch version of one
// credential reference (executions.BatchOptions.CredentialVersion). A
// missing, mismatched, zero or out-of-range version (above
// canonical.MaxCredentialVersion, which a canonical batch rejects) is an
// error: a batch never binds a guessed or truncated version.
func CredentialVersion(ctx context.Context, r BatchCredentialReader, ref string) (uint64, error) {
	resp, err := r.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{CredentialRefs: []string{ref}})
	if err != nil {
		return 0, fmt.Errorf("read credential version: %w", err)
	}
	vs := resp.GetVersions()
	if len(vs) != 1 || vs[0].GetCredentialRef() != ref || vs[0].GetVersion() == 0 {
		return 0, errors.New("read credential version: the executor returned no version for the reference")
	}
	if vs[0].GetVersion() > canonical.MaxCredentialVersion {
		return 0, errors.New("read credential version: the executor returned a version outside the batch range")
	}
	return vs[0].GetVersion(), nil
}

// BatchesAvailable reports whether the executor runs batches end to end:
// true only when it advertises batch_execution_available. It is false when
// the executor does not implement the credential-version read or has no
// batch authority configured (Unimplemented), and also when it serves the
// read and approves batches but does not execute approved members, since a
// batch proposed there would be approved and never run. Any other failure,
// such as a locked keyring or an unreachable executor, is returned as an
// error so callers can tell a transient condition from a missing capability.
func BatchesAvailable(ctx context.Context, r BatchCredentialReader) (bool, error) {
	resp, err := r.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{})
	switch {
	case err == nil:
		return resp.GetBatchExecutionAvailable(), nil
	case status.Code(err) == codes.Unimplemented:
		return false, nil
	default:
		return false, fmt.Errorf("probe batch support: %w", err)
	}
}

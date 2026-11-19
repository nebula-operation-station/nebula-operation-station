// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// RejectPending rejects a pending execution permit or batch plan (ADR 0007
// amendment R1-R7, spec 07 v29-07-01). The role comes from the peer
// credentials the socket authenticated, never from the request; the
// method table admits only server and admin, and any other role is
// refused here as well. Rejecting only removes authority: the request
// carries no approval data, and nothing here can approve.
func (s *Service) RejectPending(ctx context.Context, req *pb.RejectPendingRequest) (*pb.RejectPendingResponse, error) {
	role, err := rejectRole(ctx)
	if err != nil {
		return nil, err
	}
	d, err := canonical.ParseDigest(req.GetDigest())
	if err != nil {
		return nil, toStatus(&permit.Error{Code: permit.CodeInvalidRequest, Detail: "malformed digest"})
	}
	r, err := batch.RejectPending(s.auth, s.batchAuth, permit.RejectRequest{
		Digest:      d,
		Reason:      req.GetReason(),
		RelayedUser: req.GetRelayedUser(),
		Role:        role,
		Who:         callerName(ctx),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.RejectPendingResponse{State: pb.PermitState_PERMIT_STATE_REJECTED, Kind: proposalKindToProto(r.Kind)}, nil
}

// rejectRole maps the authenticated caller to a rejecting role.
func rejectRole(ctx context.Context) (permit.RejectRole, error) {
	c, ok := peercred.CallerFrom(ctx)
	if !ok {
		return "", status.Error(codes.PermissionDenied, "unauthenticated caller")
	}
	switch c.Role {
	case peercred.RoleServer:
		return permit.RejectRoleServer, nil
	case peercred.RoleAdmin:
		return permit.RejectRoleAdmin, nil
	default:
		return "", status.Error(codes.PermissionDenied, "role may not reject")
	}
}

func rejectRoleToProto(r permit.RejectRole) pb.RejectingRole {
	switch r {
	case permit.RejectRoleServer:
		return pb.RejectingRole_REJECTING_ROLE_SERVER
	case permit.RejectRoleAdmin:
		return pb.RejectingRole_REJECTING_ROLE_ADMIN
	default:
		return pb.RejectingRole_REJECTING_ROLE_UNSPECIFIED
	}
}

func proposalKindToProto(k permit.ProposalKind) pb.ProposalKind {
	switch k {
	case permit.ProposalExecution:
		return pb.ProposalKind_PROPOSAL_KIND_EXECUTION
	case permit.ProposalBatch:
		return pb.ProposalKind_PROPOSAL_KIND_BATCH
	default:
		return pb.ProposalKind_PROPOSAL_KIND_UNSPECIFIED
	}
}

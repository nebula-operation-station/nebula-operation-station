// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"slices"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// maxBatchNotExecutedReason bounds the server's reason for a member it
// cannot hand over (RunBatchMemberRequest.not_executed_reason).
const maxBatchNotExecutedReason = 256

// validBatchReason reports whether r is a non-empty, bounded, printable
// UTF-8 text: no control characters, so it cannot forge log lines.
func validBatchReason(r string, limit int) bool {
	if r == "" || len(r) > limit || !utf8.ValidString(r) {
		return false
	}
	for _, c := range r {
		if !unicode.IsPrint(c) {
			return false
		}
	}
	return true
}

// validateBatchNotExecuted checks a not-executed report: the member is
// named, the reason is bounded and printable, and nothing that could run
// is supplied.
func validateBatchNotExecuted(req *pb.RunBatchMemberRequest) (canonical.Digest, error) {
	if err := validateBatchMessage(req); err != nil {
		return canonical.Digest{}, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return canonical.Digest{}, err
	}
	id := req.GetMemberId()
	if id == "" || len(id) > maxBatchMemberIDBytes || !utf8.ValidString(id) {
		return canonical.Digest{}, status.Error(codes.InvalidArgument, "batch: invalid member ID")
	}
	if !validBatchReason(req.GetNotExecutedReason(), maxBatchNotExecutedReason) {
		return canonical.Digest{}, status.Errorf(codes.InvalidArgument, "batch: not-executed reason must be printable UTF-8 of at most %d bytes", maxBatchNotExecutedReason)
	}
	if len(req.GetArtifact()) != 0 || len(req.GetEndpoints()) != 0 || req.GetTimeoutSeconds() != 0 {
		return canonical.Digest{}, status.Error(codes.InvalidArgument, "batch: a not-executed report carries no artifact, endpoints or timeout")
	}
	return d, nil
}

// reportBatchMemberNotExecuted spends a member the server cannot hand over
// without running anything: it claims the member's single-use permit (so
// the member can never run afterwards), records it failed in the rollout
// (the approved stop policy applies) and audits the server's reason.
// Refusals before the claim are error statuses, as in RunBatchMember.
func (s *Service) reportBatchMemberNotExecuted(ctx context.Context, req *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
	d, err := validateBatchNotExecuted(req)
	if err != nil {
		return nil, err
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	if s.batchRun == nil {
		return nil, errBatchExecutionUnconfigured
	}
	ap, err := s.batchAuth.Check(ctx, d)
	if err != nil {
		return nil, batchStatus(err)
	}
	index := slices.IndexFunc(ap.Plan.Members, func(m canonical.BatchMember) bool { return m.MemberID == req.GetMemberId() })
	if index < 0 {
		return nil, status.Error(codes.NotFound, "batch: no such member in the approved plan")
	}
	member := ap.Plan.Members[index]
	if _, err := s.batchAuth.ClaimMember(ctx, d, index, member); err != nil {
		return nil, batchStatus(err)
	}
	execID := member.Request.ExecutionID
	s.batchAuth.RecordOutcome(execID, member.MemberID, permit.OutcomeFailed)
	detail := "not executed: the server could not hand the member over: " + req.GetNotExecutedReason()
	s.log.Warn("audit", "kind", "batch_member_not_executed", "batch", d.String(), "member", member.MemberID, "execution", execID,
		"detail", detail)
	return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED, ExecutionId: execID,
		Class: classBatchNotExecuted, Detail: detail, ExitCode: -1}, nil
}

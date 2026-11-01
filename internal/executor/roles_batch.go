// SPDX-License-Identifier: AGPL-3.0-or-later
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// SetBatchAuthority wires the batch read-grant authority (ADR 0007, E19b).
// It must be called before the server starts serving; after that the batch
// RPCs are live. A nil authority leaves the batch RPCs Unimplemented.
func (s *Service) SetBatchAuthority(a *batch.Authority) { s.batchAuth = a }

func (s *Service) batchAuthority() *batch.Authority { return s.batchAuth }

// validateBatchMessage enforces the executor-wide message bound on a batch
// request. The gRPC layer already caps messages at MaxMessageSize; this is
// defense in depth and keeps the handler honest under direct calls.
func validateBatchMessage(m proto.Message) error {
	if m == nil {
		return status.Error(codes.InvalidArgument, "batch: request is nil")
	}
	if !m.ProtoReflect().IsValid() || proto.Size(m) > MaxMessageSize {
		return status.Error(codes.InvalidArgument, "batch: request exceeds the message bound")
	}
	return nil
}

// parseBatchDigest parses a 64-character lowercase hex batch digest.
func parseBatchDigest(s string) (canonical.Digest, error) {
	if !canonical.ValidSHA256Hex(s) {
		return canonical.Digest{}, errors.New("invalid batch digest")
	}
	return canonical.ParseDigest(s)
}

// batchPlanToProto renders the complete bounded plan: the parent batch, its
// members (each bound by its stage plan hash), and the stage/dependency graph
// that links them. Nothing is truncated.
func batchPlanToProto(plan canonical.Batch) *pb.BatchPlan {
	out := &pb.BatchPlan{
		BatchId:  plan.BatchID,
		ExpiryUnix: plan.ExpiryUnix,
	}
	for _, m := range plan.Members {
		out.Members = append(out.Members, &pb.BatchMember{
			MemberId:      m.MemberID,
			ActionId:      m.Request.ActionID,
			ModuleVersion: m.Request.ModuleVersion,
			Risk:          riskToProto(m.Request.RiskClass),
			HostIds:       hostIDs(m.Request.ResolvedTargets),
			StagePlanHash: m.Request.StagePlanHash,
		})
	}
	for _, st := range plan.StagePlan.Stages {
		out.Stages = append(out.Stages, &pb.BatchStage{
			StageId:           st.StageID,
			Gate:              st.Gate,
			MemberIds:         append([]string(nil), st.MemberIDs...),
			RequiredPostchecks: append([]string(nil), st.RequiredPostchecks...),
		})
	}
	for _, d := range plan.StagePlan.Dependencies {
		out.Dependencies = append(out.Dependencies, &pb.BatchDependency{
			MemberId:  d.MemberID,
			DependsOn: append([]string(nil), d.DependsOn...),
		})
	}
	return out
}

// hostIDs extracts the host IDs from a member's resolved targets, in order.
func hostIDs(targets []canonical.Target) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.HostID)
	}
	return out
}

// batchStatus maps batch authority errors to gRPC codes. The admin-UID and
// CRITICAL-member rejections are sentinel errors without a permit code, so
// they are mapped explicitly; everything else carries a permit code.
func batchStatus(err error) error {
	switch {
	case errors.Is(err, batch.ErrAdminRequired):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, batch.ErrCritical):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return toStatus(err)
	}
}

// ProposeBatch validates the complete bounded plan and records a proposal.
// The authority alone chooses and binds the approval requirement; a LOW plan
// is approved immediately, otherwise a fresh challenge is returned.
func (s *Service) ProposeBatch(ctx context.Context, req *pb.ProposeBatchRequest) (*pb.ProposeBatchResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	a := s.batchAuthority()
	if a == nil {
		return nil, status.Error(codes.Unimplemented, "batch: authority not configured")
	}
	inputs := make([]batch.MemberInput, len(req.GetMembers()))
	for i, m := range req.GetMembers() {
		inputs[i] = batch.MemberInput{
			MemberID:       m.GetMemberId(),
			Artifact:       m.GetArtifact(),
			ParametersJSON: m.GetParametersJson(),
		}
	}
	ap, err := a.Propose(ctx, req.GetBatchJson(), inputs)
	if err != nil {
		return nil, batchStatus(err)
	}
	out := &pb.ProposeBatchResponse{
		BatchDigest:         ap.Digest.String(),
		CanonicalBatch:      ap.Canonical,
		Plan:                batchPlanToProto(ap.Plan),
		Risk:                riskToProto(ap.Risk),
		ApprovalRequirement: requirementToProto(ap.Requirement),
		State:               stateToProto(ap.State),
	}
	if len(ap.Challenge) > 0 {
		out.Challenge = ap.Challenge
		out.ChallengeExpiryUnix = ap.ApprovalExpiry.Unix()
		opts, err := s.reg.RequestOptions(ap.Challenge, ap.ApprovalExpiry.Sub(s.clock()))
		if err != nil {
			return nil, status.Error(codes.Internal, "batch: request options unavailable")
		}
		out.RequestOptionsJson = opts
	}
	return out, nil
}

// CommitBatch relays a fresh user-verified assertion. The executor verifies
// the batch-bound challenge; this is never a server approval.
func (s *Service) CommitBatch(ctx context.Context, req *pb.CommitBatchRequest) (*pb.CommitBatchResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	raw := req.GetAssertionJson()
	if !canonical.ValidSHA256Hex(req.GetBatchDigest()) ||
		len(raw) == 0 || len(raw) > webauthnverify.MaxAssertionSize ||
		!utf8.Valid(raw) || !json.Valid(raw) {
		return nil, status.Error(codes.InvalidArgument, "batch: invalid digest or assertion")
	}
	a := s.batchAuthority()
	if a == nil {
		return nil, status.Error(codes.Unimplemented, "batch: authority not configured")
	}
	d, err := canonical.ParseDigest(req.GetBatchDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "batch: invalid digest")
	}
	ap, err := a.SubmitAssertion(ctx, d, raw)
	if err != nil {
		return nil, batchStatus(err)
	}
	return &pb.CommitBatchResponse{State: stateToProto(ap.State)}, nil
}

// ReviewBatch returns the complete frozen plan for local admin review.
func (s *Service) ReviewBatch(ctx context.Context, req *pb.ReviewBatchRequest) (*pb.ReviewBatchResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "batch: invalid digest")
	}
	a := s.batchAuthority()
	if a == nil {
		return nil, status.Error(codes.Unimplemented, "batch: authority not configured")
	}
	uid, ok := peercred.CallerFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "batch: no caller")
	}
	ap, err := a.ReviewCLI(ctx, d, uid.UID)
	if err != nil {
		return nil, batchStatus(err)
	}
	out := &pb.ReviewBatchResponse{
		BatchDigest:        ap.Digest.String(),
		CanonicalBatch:     ap.Canonical,
		Plan:               batchPlanToProto(ap.Plan),
		Risk:               riskToProto(ap.Risk),
		State:              stateToProto(ap.State),
		ApprovedBy:         ap.ApprovedBy,
		ApprovalExpiryUnix: ap.ApprovalExpiry.Unix(),
	}
	for _, p := range ap.Parameters {
		out.MemberParameters = append(out.MemberParameters, p)
	}
	for _, f := range ap.Findings {
		mf := &pb.BatchMemberFindings{}
		for _, finding := range f {
			mf.Findings = append(mf.Findings, &pb.BatchFinding{
				Category: finding.Category,
				Risk:     riskToProto(finding.Risk),
				Line:     int32(finding.Line),
				Excerpt:  finding.Excerpt,
			})
		}
		out.MemberFindings = append(out.MemberFindings, mf)
	}
	return out, nil
}

// ApproveBatchCLI approves the locally reviewed digest. Admin only; the
// server can never approve a batch.
func (s *Service) ApproveBatchCLI(ctx context.Context, req *pb.ApproveBatchCLIRequest) (*pb.ApproveBatchCLIResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "batch: invalid digest")
	}
	a := s.batchAuthority()
	if a == nil {
		return nil, status.Error(codes.Unimplemented, "batch: authority not configured")
	}
	uid, ok := peercred.CallerFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "batch: no caller")
	}
	ap, err := a.ApproveCLI(ctx, d, uid.UID)
	if err != nil {
		return nil, batchStatus(err)
	}
	return &pb.ApproveBatchCLIResponse{State: stateToProto(ap.State), ApprovedBy: ap.ApprovedBy}, nil
}

// GetBatchStatus confirms the batch is approved and fresh, with the
// parent/member linkage. The server polls this before dispatch.
func (s *Service) GetBatchStatus(ctx context.Context, req *pb.GetBatchStatusRequest) (*pb.GetBatchStatusResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "batch: invalid digest")
	}
	a := s.batchAuthority()
	if a == nil {
		return nil, status.Error(codes.Unimplemented, "batch: authority not configured")
	}
	ap, err := a.Check(ctx, d)
	if err != nil {
		return nil, batchStatus(err)
	}
	out := &pb.GetBatchStatusResponse{
		BatchDigest:        ap.Digest.String(),
		State:              stateToProto(ap.State),
		Risk:               riskToProto(ap.Risk),
		BatchId:            ap.Plan.BatchID,
		ApprovedBy:         ap.ApprovedBy,
		ApprovalExpiryUnix: ap.ApprovalExpiry.Unix(),
		ExpiryUnix:         ap.Plan.ExpiryUnix,
	}
	for _, m := range ap.Plan.Members {
		out.MemberIds = append(out.MemberIds, m.MemberID)
	}
	return out, nil
}

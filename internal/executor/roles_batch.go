// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// maxBatchMemberIDBytes bounds a member ID in a ProposeBatch input before the
// canonical parser sees it; canonical identifiers are far shorter.
const maxBatchMemberIDBytes = 256

// errBatchUnconfigured is returned while no batch authority is wired.
var errBatchUnconfigured = status.Error(codes.Unimplemented, "batch: authority not configured")

// SetBatchAuthority wires the batch approval authority (ADR 0007, E19b). It
// must be called before the server starts serving. A nil authority leaves the
// batch RPCs Unimplemented. The caller owns the authority's Lock lifecycle.
func (s *Service) SetBatchAuthority(a *batch.Authority) { s.batchAuth = a }

// validateBatchMessage enforces the executor-wide message bound on a batch
// request. The gRPC layer already caps messages at MaxMessageSize; this is
// defense in depth for direct calls.
func validateBatchMessage(m proto.Message) error {
	if m == nil || !m.ProtoReflect().IsValid() || proto.Size(m) > MaxMessageSize {
		return status.Error(codes.InvalidArgument, "batch: missing or oversize request")
	}
	return nil
}

// validateProposeBatch rejects oversize or malformed proposals before any
// authority work: the raw plan is bounded by the canonical input limit, the
// member inputs by the canonical member limit, and every member's artifact
// and parameter document by the single-request limits. The canonical parser
// and the authority repeat the complete validation.
func validateProposeBatch(req *pb.ProposeBatchRequest) error {
	if err := validateBatchMessage(req); err != nil {
		return err
	}
	raw := req.GetBatchJson()
	if len(raw) == 0 || len(raw) > canonical.MaxBatchInputSize || !utf8.Valid(raw) {
		return status.Error(codes.InvalidArgument, "batch: plan missing, oversize or not UTF-8")
	}
	members := req.GetMembers()
	if len(members) < 1 || len(members) > canonical.MaxBatchMembers {
		return status.Errorf(codes.InvalidArgument, "batch: member count must be 1..%d", canonical.MaxBatchMembers)
	}
	for _, m := range members {
		id := m.GetMemberId()
		if id == "" || len(id) > maxBatchMemberIDBytes || !utf8.ValidString(id) {
			return status.Error(codes.InvalidArgument, "batch: invalid member ID")
		}
		if len(m.GetArtifact()) == 0 || len(m.GetArtifact()) > permit.MaxArtifactSize {
			return status.Error(codes.InvalidArgument, "batch: member artifact missing or oversize")
		}
		if p := m.GetParametersJson(); len(p) == 0 || len(p) > canonical.MaxParametersSize || !utf8.Valid(p) {
			return status.Error(codes.InvalidArgument, "batch: member parameters missing, oversize or not UTF-8")
		}
	}
	return nil
}

// parseBatchDigest parses the 64-character lowercase hex batch digest.
func parseBatchDigest(s string) (canonical.Digest, error) {
	d, err := canonical.ParseDigest(s)
	if err != nil {
		return canonical.Digest{}, status.Error(codes.InvalidArgument, "batch: invalid digest")
	}
	return d, nil
}

// batchCaller returns the authenticated local peer UID. It never reads a
// request field: the admin identity comes from peer credentials only.
func batchCaller(ctx context.Context) (uint32, error) {
	c, ok := peercred.CallerFrom(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "batch: no authenticated caller")
	}
	return c.UID, nil
}

// unixOrZero renders an unset time as 0 rather than a negative Unix value.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// batchPlanToProto renders the complete bounded plan: the parent batch, every
// member (each bound to the parent by its stage plan hash and execution ID),
// and the complete stage/dependency graph. Nothing is truncated.
func batchPlanToProto(plan canonical.Batch) *pb.BatchPlan {
	out := &pb.BatchPlan{
		BatchId:       plan.BatchID,
		BatchVersion:  plan.BatchVersion,
		ExpiryUnix:    plan.ExpiryUnix,
		StagePlanHash: plan.StagePlanHash,
		Members:       make([]*pb.BatchMember, 0, len(plan.Members)),
		Stages:        make([]*pb.BatchStage, 0, len(plan.StagePlan.Stages)),
		Dependencies:  make([]*pb.BatchDependency, 0, len(plan.StagePlan.Dependencies)),
	}
	for _, m := range plan.Members {
		hosts := make([]string, 0, len(m.Request.ResolvedTargets))
		for _, t := range m.Request.ResolvedTargets {
			hosts = append(hosts, t.HostID)
		}
		out.Members = append(out.Members, &pb.BatchMember{
			MemberId:       m.MemberID,
			ActionId:       m.Request.ActionID,
			ModuleVersion:  m.Request.ModuleVersion,
			Risk:           riskToProto(m.Request.RiskClass),
			HostIds:        hosts,
			StagePlanHash:  m.Request.StagePlanHash,
			ExecutionId:    m.Request.ExecutionID,
			ArtifactSha256: m.Request.ArtifactSHA256,
			ParametersHash: m.Request.ParametersHash,
			CredentialRefs: append([]string(nil), m.Request.CredentialRefs...),
		})
	}
	for _, st := range plan.StagePlan.Stages {
		out.Stages = append(out.Stages, &pb.BatchStage{
			StageId:              st.StageID,
			Gate:                 st.Gate,
			MemberIds:            append([]string(nil), st.MemberIDs...),
			RequiredPostchecks:   append([]string(nil), st.RequiredPostchecks...),
			FailureThreshold:     int32(st.FailureThreshold),
			UnreachableThreshold: int32(st.UnreachableThreshold),
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

// batchStatus maps batch authority errors to gRPC codes. The admin-UID and
// CRITICAL rejections are sentinel errors without a permit code; everything
// else carries a permit code.
func batchStatus(err error) error {
	switch {
	case errors.Is(err, batch.ErrAdminRequired):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, batch.ErrCritical):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, batch.ErrInvalidated):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return toStatus(err)
	}
}

// ProposeBatch validates the complete bounded plan and records a proposal
// (server role). The authority alone derives risk and binds the approval
// requirement; a LOW plan inside a privileged session is approved at once,
// otherwise a fresh batch-bound challenge or local CLI approval is required.
func (s *Service) ProposeBatch(ctx context.Context, req *pb.ProposeBatchRequest) (*pb.ProposeBatchResponse, error) {
	if err := validateProposeBatch(req); err != nil {
		return nil, err
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	inputs := make([]batch.MemberInput, len(req.GetMembers()))
	for i, m := range req.GetMembers() {
		inputs[i] = batch.MemberInput{MemberID: m.GetMemberId(), Artifact: m.GetArtifact(), ParametersJSON: m.GetParametersJson()}
	}
	ap, err := s.batchAuth.Propose(ctx, req.GetBatchJson(), inputs)
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

// CommitBatch relays a fresh user-verified assertion (server role). The
// executor verifies it against the batch-bound challenge; the server itself
// can never approve a batch.
func (s *Service) CommitBatch(ctx context.Context, req *pb.CommitBatchRequest) (*pb.CommitBatchResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return nil, err
	}
	raw := req.GetAssertionJson()
	if len(raw) == 0 || len(raw) > webauthnverify.MaxAssertionSize || !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, status.Error(codes.InvalidArgument, "batch: invalid assertion")
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	ap, err := s.batchAuth.SubmitAssertion(ctx, d, raw)
	if err != nil {
		return nil, batchStatus(err)
	}
	return &pb.CommitBatchResponse{State: stateToProto(ap.State)}, nil
}

// ReviewBatch returns the complete frozen plan, member parameters and scanner
// findings for local review (admin role). The authority additionally requires
// the configured executor-local admin UID from peer credentials.
func (s *Service) ReviewBatch(ctx context.Context, req *pb.ReviewBatchRequest) (*pb.ReviewBatchResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return nil, err
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	uid, err := batchCaller(ctx)
	if err != nil {
		return nil, err
	}
	ap, err := s.batchAuth.ReviewCLI(ctx, d, uid)
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
		ApprovalExpiryUnix: unixOrZero(ap.ApprovalExpiry),
		MemberParameters:   ap.Parameters,
		MemberFindings:     make([]*pb.BatchMemberFindings, 0, len(ap.Findings)),
	}
	for _, fs := range ap.Findings {
		mf := &pb.BatchMemberFindings{Findings: make([]*pb.BatchFinding, 0, len(fs))}
		for _, f := range fs {
			mf.Findings = append(mf.Findings, &pb.BatchFinding{
				Category: f.Category,
				Risk:     riskToProto(f.Risk),
				Line:     int32(f.Line),
				Excerpt:  f.Excerpt,
			})
		}
		out.MemberFindings = append(out.MemberFindings, mf)
	}
	return out, nil
}

// ApproveBatchCLI approves a locally reviewed digest (admin role only). The
// authority requires the configured executor-local admin UID from peer
// credentials; the server role cannot reach this method.
func (s *Service) ApproveBatchCLI(ctx context.Context, req *pb.ApproveBatchCLIRequest) (*pb.ApproveBatchCLIResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return nil, err
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	uid, err := batchCaller(ctx)
	if err != nil {
		return nil, err
	}
	ap, err := s.batchAuth.ApproveCLI(ctx, d, uid)
	if err != nil {
		return nil, batchStatus(err)
	}
	return &pb.ApproveBatchCLIResponse{State: stateToProto(ap.State), ApprovedBy: ap.ApprovedBy}, nil
}

// GetBatchStatus confirms that a batch is approved and still fresh, with the
// parent/member linkage (server and admin roles). It grants nothing: member
// dispatch performs its own claim and checks.
func (s *Service) GetBatchStatus(ctx context.Context, req *pb.GetBatchStatusRequest) (*pb.GetBatchStatusResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return nil, err
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	ap, err := s.batchAuth.Check(ctx, d)
	if err != nil {
		return nil, batchStatus(err)
	}
	out := &pb.GetBatchStatusResponse{
		BatchDigest:        ap.Digest.String(),
		State:              stateToProto(ap.State),
		Risk:               riskToProto(ap.Risk),
		BatchId:            ap.Plan.BatchID,
		ApprovedBy:         ap.ApprovedBy,
		ApprovalExpiryUnix: unixOrZero(ap.ApprovalExpiry),
		ExpiryUnix:         ap.Plan.ExpiryUnix,
		StagePlanHash:      ap.Plan.StagePlanHash,
		MemberIds:          make([]string, 0, len(ap.Plan.Members)),
		MemberExecutionIds: make([]string, 0, len(ap.Plan.Members)),
	}
	for _, m := range ap.Plan.Members {
		out.MemberIds = append(out.MemberIds, m.MemberID)
		out.MemberExecutionIds = append(out.MemberExecutionIds, m.Request.ExecutionID)
	}
	return out, nil
}

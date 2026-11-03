// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Local batch stage gates (ADR 0007, E14). The existing admin-only
// ApproveGateCLI and the read-only GetRollout serve batches as well: a digest
// the batch authority holds is a batch digest and never reaches the host stage
// engine. In a batch rollout the stage name is the stage ID, the "hosts" of a
// stage are its member IDs, and GATE_KIND_SKIP_HOST names a member ID. The
// server's browser gate RPCs (BeginGate, CommitGate) are not routed here.

// batchHolds reports whether d names a batch the batch authority holds, in
// any state. Only CodeNotFound means "not a batch"; every other error (wrong
// state, expired) belongs to the batch and is returned.
func (s *Service) batchHolds(d canonical.Digest) (bool, error) {
	if s.batchAuth == nil {
		return false, nil
	}
	_, err := s.batchAuth.Rollout(d)
	if permit.CodeOf(err) == permit.CodeNotFound {
		return false, nil
	}
	if err != nil {
		return true, batchStatus(err)
	}
	return true, nil
}

// batchGateFromProto converts a gate for a batch rollout. Open-stage names a
// stage from 2 and no member; skip names one bounded member ID and no stage.
// The authority checks both against the plan.
func batchGateFromProto(g *pb.Gate) (batch.Gate, error) {
	if g == nil {
		return batch.Gate{}, status.Error(codes.InvalidArgument, "gate is required")
	}
	switch g.GetKind() {
	case pb.GateKind_GATE_KIND_OPEN_STAGE:
		if g.GetHostId() != "" || g.GetStage() < 2 || g.GetStage() > canonical.MaxBatchStages {
			return batch.Gate{}, status.Error(codes.InvalidArgument, "open_stage names a stage from 2 and no member")
		}
		return batch.Gate{Kind: batch.GateOpenStage, Stage: int(g.GetStage())}, nil
	case pb.GateKind_GATE_KIND_SKIP_HOST:
		id := g.GetHostId()
		if g.GetStage() != 0 || id == "" || len(id) > maxBatchMemberIDBytes || !utf8.ValidString(id) {
			return batch.Gate{}, status.Error(codes.InvalidArgument, "skip names one member and no stage")
		}
		return batch.Gate{Kind: batch.GateSkipMember, MemberID: id}, nil
	}
	return batch.Gate{}, status.Error(codes.InvalidArgument, "unknown gate kind")
}

// batchRolloutResponse renders a batch rollout with its complete stage plan.
// The plan comes from Check, which also revalidates trust and risk: a change
// revokes the batch instead of showing a stale rollout.
func (s *Service) batchRolloutResponse(ctx context.Context, d canonical.Digest) (*pb.Rollout, error) {
	ap, err := s.batchAuth.Check(ctx, d)
	if err != nil {
		return nil, batchStatus(err)
	}
	r, err := s.batchAuth.Rollout(d)
	if err != nil {
		return nil, batchStatus(err)
	}
	stages := ap.Plan.StagePlan.Stages
	if len(stages) != len(r.Stages) {
		return nil, status.Error(codes.Internal, "batch: rollout does not match the plan")
	}
	out := &pb.Rollout{OpenStage: uint32(r.Open + 1), Stopped: r.Stopped, Aborted: r.Aborted,
		GateRequirement: requirementToProto(r.GateRequirement), Stages: make([]*pb.StageStatus, 0, len(stages))}
	for i, st := range stages {
		v := r.Stages[i]
		ss := &pb.StageStatus{
			Stage: &pb.PlanStage{Name: st.StageID, HostIds: append([]string(nil), st.MemberIDs...),
				MaxFailed: uint32(st.FailureThreshold), MaxUnreachable: uint32(st.UnreachableThreshold), ContinueMode: st.Gate},
			Open: v.Open, Passed: v.Passed,
		}
		for _, mid := range st.MemberIDs {
			if o, ok := v.Outcomes[mid]; ok {
				ss.Outcomes = append(ss.Outcomes, &pb.HostOutcome{HostId: mid, Outcome: string(o)})
			}
		}
		out.Stages = append(out.Stages, ss)
	}
	return out, nil
}

// batchGetRollout serves GetRollout for a batch digest. handled is false when
// the digest is not a batch, so the host stage engine answers.
func (s *Service) batchGetRollout(ctx context.Context, d canonical.Digest) (resp *pb.GetRolloutResponse, handled bool, err error) {
	if held, err := s.batchHolds(d); !held || err != nil {
		return nil, held, err
	}
	r, err := s.batchRolloutResponse(ctx, d)
	if err != nil {
		return nil, true, err
	}
	return &pb.GetRolloutResponse{Rollout: r}, true, nil
}

// batchApproveGateCLI applies a batch stage gate as the executor-local admin
// (hardened CLI path). The admin UID comes from peer credentials only and the
// authority compares it with the configured admin UID. handled is false when
// the digest is not a batch, so the host stage engine answers.
func (s *Service) batchApproveGateCLI(ctx context.Context, d canonical.Digest, g *pb.Gate) (resp *pb.ApproveGateCLIResponse, handled bool, err error) {
	if held, err := s.batchHolds(d); !held || err != nil {
		return nil, held, err
	}
	gate, err := batchGateFromProto(g)
	if err != nil {
		return nil, true, err
	}
	uid, err := batchCaller(ctx)
	if err != nil {
		return nil, true, err
	}
	if err := s.batchAuth.ApproveGateCLI(d, gate, uid); err != nil {
		return nil, true, batchStatus(err)
	}
	r, err := s.batchRolloutResponse(ctx, d)
	if err != nil {
		return nil, true, err
	}
	return &pb.ApproveGateCLIResponse{Rollout: r}, true, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

// Stage engine RPCs (spec 07, Milestone 6). The rules live in
// internal/permit; this file converts.

func gateFromProto(g *pb.Gate) (permit.Gate, error) {
	if g == nil {
		return permit.Gate{}, status.Error(codes.InvalidArgument, "gate is required")
	}
	switch g.GetKind() {
	case pb.GateKind_GATE_KIND_OPEN_STAGE:
		if g.GetHostId() != "" || g.GetStage() < 2 || g.GetStage() > stageplan.MaxStages {
			return permit.Gate{}, status.Error(codes.InvalidArgument, "open_stage names a stage from 2 and no host")
		}
		return permit.Gate{Kind: permit.GateOpenStage, Stage: int(g.GetStage())}, nil
	case pb.GateKind_GATE_KIND_SKIP_HOST:
		if g.GetStage() != 0 || !canonical.ValidHostID(g.GetHostId()) {
			return permit.Gate{}, status.Error(codes.InvalidArgument, "skip_host names a valid host and no stage")
		}
		return permit.Gate{Kind: permit.GateSkipHost, Host: g.GetHostId()}, nil
	}
	return permit.Gate{}, status.Error(codes.InvalidArgument, "unknown gate kind")
}

func planToProto(plan []stageplan.Stage) []*pb.PlanStage {
	out := make([]*pb.PlanStage, 0, len(plan))
	for _, st := range plan {
		out = append(out, &pb.PlanStage{Name: st.Name, HostIds: append([]string(nil), st.Hosts...), MaxFailed: uint32(st.MaxFailed),
			MaxUnreachable: uint32(st.MaxUnreachable), ContinueMode: st.Continue, TimeoutSeconds: uint32(st.TimeoutS)})
	}
	return out
}

func (s *Service) rolloutResponse(d canonical.Digest) (*pb.Rollout, error) {
	r, err := s.auth.Rollout(d)
	if err != nil {
		return nil, toStatus(err)
	}
	out := &pb.Rollout{OpenStage: uint32(r.Open + 1), Stopped: r.Stopped, Aborted: r.Aborted,
		GateRequirement: requirementToProto(r.GateRequirement)}
	for _, st := range r.Stages {
		ss := &pb.StageStatus{Stage: planToProto([]stageplan.Stage{st.Stage})[0], Open: st.Open, Passed: st.Passed}
		for _, h := range st.Stage.Hosts {
			if o, ok := st.Outcomes[h]; ok {
				ss.Outcomes = append(ss.Outcomes, &pb.HostOutcome{HostId: h, Outcome: string(o)})
			}
		}
		out.Stages = append(out.Stages, ss)
	}
	return out, nil
}

func (s *Service) digestAndGate(digest string, g *pb.Gate) (canonical.Digest, permit.Gate, error) {
	d, err := canonical.ParseDigest(digest)
	if err != nil {
		return canonical.Digest{}, permit.Gate{}, status.Error(codes.InvalidArgument, err.Error())
	}
	gate, err := gateFromProto(g)
	return d, gate, err
}

// BeginGate checks a gate and returns what it needs (server role).
func (s *Service) BeginGate(_ context.Context, req *pb.BeginGateRequest) (*pb.BeginGateResponse, error) {
	d, g, err := s.digestAndGate(req.GetExecutionDigest(), req.GetGate())
	if err != nil {
		return nil, err
	}
	gc, err := s.auth.BeginGate(d, g)
	if err != nil {
		return nil, toStatus(err)
	}
	out := &pb.BeginGateResponse{ApprovalRequirement: requirementToProto(gc.Requirement)}
	if len(gc.Challenge) > 0 {
		out.Challenge, out.ChallengeExpiryUnix = gc.Challenge, gc.Expiry.Unix()
		opts, err := s.reg.RequestOptions(gc.Challenge, time.Until(gc.Expiry))
		if err != nil {
			return nil, status.Error(codes.Internal, "request options")
		}
		out.RequestOptionsJson = opts
	}
	return out, nil
}

// CommitGate applies a gate from the web UI (server role).
func (s *Service) CommitGate(_ context.Context, req *pb.CommitGateRequest) (*pb.CommitGateResponse, error) {
	d, g, err := s.digestAndGate(req.GetExecutionDigest(), req.GetGate())
	if err != nil {
		return nil, err
	}
	if err := s.auth.CommitGate(d, g, req.GetAssertionJson()); err != nil {
		return nil, toStatus(err)
	}
	r, err := s.rolloutResponse(d)
	if err != nil {
		return nil, err
	}
	return &pb.CommitGateResponse{Rollout: r}, nil
}

// ApproveGateCLI applies a gate from the hardened CLI path (admin role).
func (s *Service) ApproveGateCLI(ctx context.Context, req *pb.ApproveGateCLIRequest) (*pb.ApproveGateCLIResponse, error) {
	d, g, err := s.digestAndGate(req.GetExecutionDigest(), req.GetGate())
	if err != nil {
		return nil, err
	}
	if err := s.auth.ApproveGateCLI(d, g, callerName(ctx)); err != nil {
		return nil, toStatus(err)
	}
	r, err := s.rolloutResponse(d)
	if err != nil {
		return nil, err
	}
	return &pb.ApproveGateCLIResponse{Rollout: r}, nil
}

// AbortRollout stops a rollout (server role).
func (s *Service) AbortRollout(ctx context.Context, req *pb.AbortRolloutRequest) (*pb.AbortRolloutResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.auth.Abort(d, callerName(ctx)); err != nil {
		return nil, toStatus(err)
	}
	r, err := s.rolloutResponse(d)
	if err != nil {
		return nil, err
	}
	return &pb.AbortRolloutResponse{Rollout: r}, nil
}

// GetRollout returns the executor's view of a rollout (server, admin).
func (s *Service) GetRollout(_ context.Context, req *pb.GetRolloutRequest) (*pb.GetRolloutResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	r, err := s.rolloutResponse(d)
	if err != nil {
		return nil, err
	}
	return &pb.GetRolloutResponse{Rollout: r}, nil
}

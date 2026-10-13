// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Admin RPCs for the executor-held risk data (H01). The method-role table
// restricts them to the admin role; every change is audited.

func (s *Service) TrustArtifact(ctx context.Context, req *pb.TrustArtifactRequest) (*pb.TrustArtifactResponse, error) {
	risk, err := riskFromProto(req.GetRiskClass())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	art := req.GetArtifact()
	if len(art) == 0 || len(art) > permit.MaxArtifactSize {
		return nil, status.Errorf(codes.InvalidArgument, "artifact size %d outside 1..%d", len(art), permit.MaxArtifactSize)
	}
	sum := sha256.Sum256(art)
	if exp := req.GetExpectedSha256(); exp != "" && exp != hex.EncodeToString(sum[:]) {
		return nil, status.Errorf(codes.InvalidArgument, "artifact hashes to %x, caller expected %s; nothing stored", sum, exp)
	}
	a := executordb.TrustedArtifact{
		SHA256:        hex.EncodeToString(sum[:]),
		ActionID:      req.GetActionId(),
		ModuleVersion: req.GetModuleVersion(),
		Risk:          risk,
		Label:         req.GetLabel(),
		TrustedBy:     callerName(ctx),
	}
	if err := s.db.TrustArtifact(a); err != nil {
		return nil, s.adminStoreError("trust_artifact", err)
	}
	s.log.Info("audit", "kind", "artifact_trusted", "by", a.TrustedBy, "artifact_sha256", a.SHA256,
		"action", a.ActionID, "version", a.ModuleVersion, "risk", string(a.Risk), "label", a.Label)
	return &pb.TrustArtifactResponse{ArtifactSha256: a.SHA256}, nil
}

func (s *Service) UntrustArtifact(ctx context.Context, req *pb.UntrustArtifactRequest) (*pb.UntrustArtifactResponse, error) {
	removed, err := s.db.UntrustArtifact(req.GetArtifactSha256(), req.GetActionId(), req.GetModuleVersion())
	if err != nil {
		return nil, s.adminStoreError("untrust_artifact", err)
	}
	if removed {
		s.log.Info("audit", "kind", "artifact_untrusted", "by", callerName(ctx), "artifact_sha256", req.GetArtifactSha256(),
			"action", req.GetActionId(), "version", req.GetModuleVersion())
	}
	return &pb.UntrustArtifactResponse{Removed: removed}, nil
}

func (s *Service) ListTrustedArtifacts(_ context.Context, _ *pb.ListTrustedArtifactsRequest) (*pb.ListTrustedArtifactsResponse, error) {
	list, err := s.db.ListTrustedArtifacts()
	if err != nil {
		return nil, s.adminStoreError("list_trusted_artifacts", err)
	}
	out := &pb.ListTrustedArtifactsResponse{}
	for _, a := range list {
		out.Artifacts = append(out.Artifacts, &pb.TrustedArtifact{
			ArtifactSha256: a.SHA256, ActionId: a.ActionID, ModuleVersion: a.ModuleVersion,
			RiskClass: riskToProto(a.Risk), Label: a.Label, TrustedAtUnix: a.TrustedAt.Unix(), TrustedBy: a.TrustedBy,
		})
	}
	return out, nil
}

func (s *Service) SetHostCriticality(ctx context.Context, req *pb.SetHostCriticalityRequest) (*pb.SetHostCriticalityResponse, error) {
	host, who := req.GetHostId(), callerName(ctx)
	if !canonical.ValidHostID(host) {
		return nil, status.Errorf(codes.InvalidArgument, "host_id %q is malformed", host)
	}
	if req.GetClear() {
		if req.GetCriticality() != pb.RiskClass_RISK_CLASS_UNSPECIFIED || req.GetHostKeyFingerprint() != "" {
			return nil, status.Error(codes.InvalidArgument, "clear takes only host_id")
		}
		removed, err := s.db.ClearHostCriticality(host)
		if err != nil {
			return nil, s.adminStoreError("clear_host_criticality", err)
		}
		if removed {
			s.log.Info("audit", "kind", "host_criticality_cleared", "by", who, "host", host)
		}
		return &pb.SetHostCriticalityResponse{Changed: removed}, nil
	}
	c, err := riskFromProto(req.GetCriticality())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	fp, err := s.db.SetHostCriticality(host, req.GetHostKeyFingerprint(), c, who)
	if err != nil {
		return nil, s.adminStoreError("set_host_criticality", err)
	}
	s.log.Info("audit", "kind", "host_criticality_set", "by", who, "host", host, "fingerprint", fp, "criticality", string(c))
	return &pb.SetHostCriticalityResponse{Changed: true, HostKeyFingerprint: fp}, nil
}

func (s *Service) ListHostCriticality(_ context.Context, _ *pb.ListHostCriticalityRequest) (*pb.ListHostCriticalityResponse, error) {
	list, err := s.db.ListHostCriticality()
	if err != nil {
		return nil, s.adminStoreError("list_host_criticality", err)
	}
	out := &pb.ListHostCriticalityResponse{}
	for _, h := range list {
		out.Hosts = append(out.Hosts, &pb.HostCriticality{
			HostId: h.HostID, HostKeyFingerprint: h.HostKeyFingerprint, Criticality: riskToProto(h.Criticality),
			UpdatedAtUnix: h.UpdatedAt.Unix(), UpdatedBy: h.UpdatedBy,
		})
	}
	return out, nil
}

// adminStoreError maps executordb errors for the admin role, which runs on
// the executor host and may see the detail.
func (s *Service) adminStoreError(op string, err error) error {
	if errors.Is(err, executordb.ErrInvalid) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	s.log.Error("audit", "kind", "store_error", "op", op, "detail", err.Error())
	return status.Error(codes.Unavailable, "storage_error: "+err.Error())
}

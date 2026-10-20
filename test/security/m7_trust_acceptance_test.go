// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// M7-4: a runbook version trusted from the browser with the security key
// runs at its declared risk; without the key, it stays HIGH.
func TestM7_TrustFromTheBrowser(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	h.setCriticality("dockerflux", riskLow)
	h.setCriticality("strompi", riskLow)
	trust := &pb.BeginTrustArtifactRequest{Artifact: script, ActionId: testAction, ModuleVersion: testVersion, RiskClass: riskLow, Label: "runbook test v1"}

	_, err := h.client.BeginTrustArtifact(h.ctx(), trust)
	wantCode(t, err, codes.FailedPrecondition, "session")
	h.openSession()
	if err := h.proposeErr(riskLow); err == nil {
		t.Fatal("untrusted script proposed as LOW")
	}
	bad := &pb.BeginTrustArtifactRequest{Artifact: script, ActionId: testAction, ModuleVersion: testVersion, RiskClass: riskLow, Label: "evil\x1b[2J"}
	_, err = h.client.BeginTrustArtifact(h.ctx(), bad)
	wantCode(t, err, codes.InvalidArgument, "label")

	b, err := h.client.BeginTrustArtifact(h.ctx(), trust)
	if err != nil || b.GetArtifactSha256() != hexSum(script) || len(b.GetRequestOptionsJson()) == 0 {
		t.Fatalf("%v %v", b, err)
	}
	// An assertion over another challenge does not trust anything.
	_, err = h.client.CommitTrustArtifact(h.ctx(), &pb.CommitTrustArtifactRequest{TrustId: b.GetTrustId(), AssertionJson: h.sign([]byte("other challenge 32 bytes long!!"))})
	wantCode(t, err, codes.PermissionDenied, "")
	if g, _ := h.client.GetArtifactTrust(h.ctx(), &pb.GetArtifactTrustRequest{ArtifactSha256: hexSum(script), ActionId: testAction, ModuleVersion: testVersion}); g.GetTrusted() {
		t.Fatal("trusted without the key")
	}

	b, _ = h.client.BeginTrustArtifact(h.ctx(), trust)
	if _, err := h.client.CommitTrustArtifact(h.ctx(), &pb.CommitTrustArtifactRequest{TrustId: b.GetTrustId(), AssertionJson: h.sign(b.GetChallenge())}); err != nil {
		t.Fatal(err)
	}
	g, err := h.client.GetArtifactTrust(h.ctx(), &pb.GetArtifactTrustRequest{ArtifactSha256: hexSum(script), ActionId: testAction, ModuleVersion: testVersion})
	if err != nil || !g.GetTrusted() || g.GetRiskClass() != riskLow {
		t.Fatalf("%v %v", g, err)
	}
	h.requireAudit("artifact_trusted", "webauthn:", "runbook test v1")
	if err := h.proposeErr(riskLow); err != nil {
		t.Fatalf("trusted LOW script: %v", err)
	}
}

func TestM7_BrowserTrustIsServerOnly(t *testing.T) {
	uid := uint32(os.Getuid())
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleAdmin}}})
	_, err := h.client.BeginTrustArtifact(h.ctx(), &pb.BeginTrustArtifactRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.CommitTrustArtifact(h.ctx(), &pb.CommitTrustArtifactRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}

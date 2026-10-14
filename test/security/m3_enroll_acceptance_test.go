// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func (h *harness) approveProposal(p *pb.ProposeExecutionResponse) {
	h.t.Helper()
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
		ExecutionDigest: p.GetExecutionDigest(), AssertionJson: h.sign(p.GetChallenge()),
	}); err != nil {
		h.t.Fatal(err)
	}
}

func okHosts(in []*pb.EnrollHost) []*pb.EnrollHost {
	var out []*pb.EnrollHost
	for _, x := range in {
		if x.GetError() == "" {
			out = append(out, x)
		}
	}
	return out
}

// Bulk enrollment pins exactly the keys the executor read and the user
// approved (with user verification), once; a changed list or key pins
// nothing that was not approved.
func TestM3_BulkEnrollmentPinsOnlyWhatWasApproved(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	h.openSession()
	a := hostruntest.Start(t, h.userKey)
	b, stopB, err := hostruntest.Serve(h.userKey)
	if err != nil {
		t.Fatal(err)
	}
	defer stopB()
	h.pinnedRunHost("old")

	p, err := h.client.ProposeEnroll(h.ctx(), &pb.ProposeEnrollRequest{Hosts: []*pb.EnrollHost{
		{HostId: "a", Endpoint: a.Addr}, {HostId: "b", Endpoint: b.Addr},
		{HostId: "down", Endpoint: closedPort(t)}, {HostId: "old", Endpoint: a.Addr}, {HostId: "-x", Endpoint: a.Addr},
	}})
	if err != nil {
		t.Fatal(err)
	}
	errs := map[string]string{}
	for _, x := range p.GetHosts() {
		errs[x.GetHostId()] = x.GetError()
	}
	if errs["a"] != "" || errs["b"] != "" || errs["down"] == "" || errs["old"] != "already pinned" || errs["-x"] == "" {
		t.Fatalf("probe results %v", errs)
	}
	perm := p.GetPermit()
	if perm.GetRiskClass() != pb.RiskClass_RISK_CLASS_HIGH || perm.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
		t.Fatalf("permit %v", perm)
	}
	approved := okHosts(p.GetHosts())
	if len(approved) != 2 || approved[0].GetSshUser() != "nebula" || approved[0].GetCredentialRef() != "nebula-default" {
		t.Fatalf("approved hosts %v", approved)
	}

	// Not approved yet.
	_, err = h.client.CommitEnroll(h.ctx(), &pb.CommitEnrollRequest{ExecutionDigest: perm.GetExecutionDigest(), Hosts: approved})
	if err == nil {
		t.Fatal("commit before approval")
	}
	h.approveProposal(perm)

	// A list that differs from the approval (another user) pins nothing.
	changed := []*pb.EnrollHost{approved[0], {HostId: approved[1].GetHostId(), Endpoint: approved[1].GetEndpoint(),
		SshUser: "root", CredentialRef: approved[1].GetCredentialRef(), Fingerprint: approved[1].GetFingerprint()}}
	_, err = h.client.CommitEnroll(h.ctx(), &pb.CommitEnrollRequest{ExecutionDigest: perm.GetExecutionDigest(), Hosts: changed})
	wantCode(t, err, codes.PermissionDenied, "")
	if l, _ := h.client.ListHostKeys(h.ctx(), &pb.ListHostKeysRequest{}); len(l.GetHosts()) != 1 {
		t.Fatalf("pinned after a changed list: %v", l.GetHosts())
	}

	// b's endpoint is gone at commit: a is pinned, b is not.
	stopB()
	c, err := h.client.CommitEnroll(h.ctx(), &pb.CommitEnrollRequest{ExecutionDigest: perm.GetExecutionDigest(), Hosts: approved})
	if err != nil {
		t.Fatal(err)
	}
	res := map[string]*pb.EnrollResult{}
	for _, r := range c.GetResults() {
		res[r.GetHostId()] = r
	}
	if !res["a"].GetPinned() || !res["a"].GetLoginOk() || res["b"].GetPinned() || res["b"].GetError() == "" {
		t.Fatalf("results %v", c.GetResults())
	}
	if pin := h.pinOf("a"); pin.GetFingerprint() != approved[0].GetFingerprint() {
		t.Fatalf("pin %v", pin)
	}
	h.requireAudit("host_key_pinned", "enroll:")

	// Used once.
	_, err = h.client.CommitEnroll(h.ctx(), &pb.CommitEnrollRequest{ExecutionDigest: perm.GetExecutionDigest(), Hosts: approved})
	wantCode(t, err, codes.PermissionDenied, "")
}

func TestM3_EnrollActionIsReservedAndBounded(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	r := h.request(pb.RiskClass_RISK_CLASS_HIGH)
	r.ActionId = "nebula.host_key.enroll"
	_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: []byte(`{}`)})
	wantCode(t, err, codes.InvalidArgument, "reserved")
	many := make([]*pb.EnrollHost, 51)
	for i := range many {
		many[i] = &pb.EnrollHost{HostId: "h", Endpoint: "127.0.0.1:1"}
	}
	_, err = h.client.ProposeEnroll(h.ctx(), &pb.ProposeEnrollRequest{Hosts: many})
	wantCode(t, err, codes.InvalidArgument, "50")
}

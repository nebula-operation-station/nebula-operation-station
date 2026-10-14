// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// blockedHost pins a host on one SSH server and lets it present another
// server's key, which blocks it (spec 08). It returns the host, the new
// server and a function that stops the new server.
func (h *harness) blockedHost(id string) (runHost, runHost, func()) {
	h.t.Helper()
	host := h.pinnedRunHost(id)
	srv2, stop, err := hostruntest.Serve(h.userKey)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(stop)
	newKey := h.probe(srv2.Addr)
	if r := h.testConn(id, srv2.Addr); r.GetFailureClass() != "host_key_mismatch" {
		h.t.Fatalf("expected a mismatch, got %v", r)
	}
	return host, runHost{id: id, fp: newKey.GetFingerprint(), endpoint: srv2.Addr, srv: srv2}, stop
}

func (h *harness) pinOf(id string) *pb.HostKeyPin {
	h.t.Helper()
	l, err := h.client.ListHostKeys(h.ctx(), &pb.ListHostKeysRequest{})
	if err != nil {
		h.t.Fatal(err)
	}
	for _, p := range l.GetHosts() {
		if p.GetHostId() == id {
			return p
		}
	}
	h.t.Fatalf("no pin for %s", id)
	return nil
}

// A blocked host is re-pinned to the key it presented only through a
// user-verified approval of a request the executor built from its own
// block record; the approval is used once.
func TestM3_RepinNeedsAUserVerifiedApprovalOfTheExecutorsRecord(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	h.openSession() // browser approvals need the privileged session
	host := h.pinnedRunHost("web")
	_, err := h.client.ProposeRepin(h.ctx(), &pb.ProposeRepinRequest{HostId: "web"})
	wantCode(t, err, codes.FailedPrecondition, "host_not_blocked")

	old, presented, _ := h.blockedHost("web2")
	_ = host
	p, err := h.client.ProposeRepin(h.ctx(), &pb.ProposeRepinRequest{HostId: "web2"})
	if err != nil {
		t.Fatal(err)
	}
	perm := p.GetPermit()
	if perm.GetRiskClass() != pb.RiskClass_RISK_CLASS_HIGH || perm.GetState() != pb.PermitState_PERMIT_STATE_PENDING ||
		p.GetPin().GetBlockedFingerprint() != presented.fp || p.GetPin().GetFingerprint() != old.fp {
		t.Fatalf("proposal %v", p)
	}
	// The parameters the admin approves name both keys and the endpoint.
	if c := string(perm.GetCanonicalRequest()); !strings.Contains(c, `"action_id":"nebula.host_key.repin"`) {
		t.Fatalf("canonical request %s", c)
	}

	// Not approved yet: nothing happens.
	_, err = h.client.CommitRepin(h.ctx(), &pb.CommitRepinRequest{ExecutionDigest: perm.GetExecutionDigest(), HostId: "web2"})
	if err == nil || h.pinOf("web2").GetFingerprint() != old.fp {
		t.Fatalf("commit before approval: %v", err)
	}

	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
		ExecutionDigest: perm.GetExecutionDigest(), AssertionJson: h.sign(perm.GetChallenge()),
	}); err != nil {
		t.Fatal(err)
	}
	c, err := h.client.CommitRepin(h.ctx(), &pb.CommitRepinRequest{ExecutionDigest: perm.GetExecutionDigest(), HostId: "web2"})
	if err != nil {
		t.Fatal(err)
	}
	if c.GetPin().GetFingerprint() != presented.fp || c.GetPin().GetBlocked() {
		t.Fatalf("pin after repin %v", c.GetPin())
	}
	h.requireAudit("host_key_repinned", "web2")

	// Used once.
	_, err = h.client.CommitRepin(h.ctx(), &pb.CommitRepinRequest{ExecutionDigest: perm.GetExecutionDigest(), HostId: "web2"})
	wantCode(t, err, codes.FailedPrecondition, "host_not_blocked")

	// The new key is the pin now: an approved run goes to the new server.
	d := h.approvedRun(presented)
	r, err := h.client.RunAttached(h.ctx(), runReq(d, presented, runScript, credRef))
	if err != nil || r.GetClass() != "success" {
		t.Fatalf("run on the re-pinned host: %v %v", r, err)
	}
}

// The server cannot create a re-pin permit of its own: the action
// namespace is reserved for the executor.
func TestM3_RepinActionIsReserved(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	r := h.request(pb.RiskClass_RISK_CLASS_HIGH)
	r.ActionId = "nebula.host_key.repin"
	_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: []byte(`{}`)})
	wantCode(t, err, codes.InvalidArgument, "reserved")
}

// A re-pin approved for one state does nothing in another: a host that was
// re-pinned or blocked anew meanwhile, or an endpoint that is gone.
func TestM3_RepinCommitsOnlyTheApprovedState(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	h.openSession()
	approved := func(id string) string {
		p, err := h.client.ProposeRepin(h.ctx(), &pb.ProposeRepinRequest{HostId: id})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
			ExecutionDigest: p.GetPermit().GetExecutionDigest(), AssertionJson: h.sign(p.GetPermit().GetChallenge()),
		}); err != nil {
			t.Fatal(err)
		}
		return p.GetPermit().GetExecutionDigest()
	}

	// Endpoint gone at commit: nothing changes, and the approval is used.
	old, _, stop := h.blockedHost("gone")
	d := approved("gone")
	stop()
	_, err := h.client.CommitRepin(h.ctx(), &pb.CommitRepinRequest{ExecutionDigest: d, HostId: "gone"})
	wantCode(t, err, codes.Unavailable, "repin_probe_failed")
	if p := h.pinOf("gone"); p.GetFingerprint() != old.fp || !p.GetBlocked() {
		t.Fatalf("pin changed: %v", p)
	}
	_, err = h.client.CommitRepin(h.ctx(), &pb.CommitRepinRequest{ExecutionDigest: d, HostId: "gone"})
	wantCode(t, err, codes.PermissionDenied, "")

	// Re-pinned by the admin and blocked by another key since the approval:
	// the approval does not fit the new record.
	old2, _, _ := h.blockedHost("moved")
	d = approved("moved")
	if _, err := h.client.UnpinHostKey(h.ctx(), &pb.UnpinHostKeyRequest{HostId: "moved", ExpectedFingerprint: old2.fp}); err != nil {
		t.Fatal(err)
	}
	h.pin("moved", h.probe(old2.endpoint))
	third, stop3, err := hostruntest.Serve(h.userKey)
	if err != nil {
		t.Fatal(err)
	}
	defer stop3()
	h.testConn("moved", third.Addr)
	_, err = h.client.CommitRepin(h.ctx(), &pb.CommitRepinRequest{ExecutionDigest: d, HostId: "moved"})
	wantCode(t, err, codes.PermissionDenied, "")
	if p := h.pinOf("moved"); p.GetFingerprint() != old2.fp || !p.GetBlocked() {
		t.Fatalf("pin changed: %v", p)
	}
}

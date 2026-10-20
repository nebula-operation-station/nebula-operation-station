// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

const schedGrantID = "00000000-0000-4000-8000-00000000c0de"

func (h *harness) grantFor(host runHost, script []byte) []byte {
	h.t.Helper()
	ph, err := canonical.HashParameters(runParamsProposed)
	if err != nil {
		h.t.Fatal(err)
	}
	d := schedgrant.Doc{Grant: schedgrant.Format, ID: schedGrantID,
		Actions:      []schedgrant.Action{{ActionID: "test.run", ModuleVersion: "1.0.0", ArtifactSHA256: hexSum(script), ParametersHash: ph}},
		Targets:      []canonical.Target{{HostID: host.id, HostKeyFingerprint: host.fp}},
		MinIntervalS: 3600, ExpiryUnix: time.Now().Add(24 * time.Hour).Unix()}
	b, err := json.Marshal(d)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

// lowRunHost pins a run host and makes test.run with runScript LOW there:
// the artifact trusted as LOW (read-only) and the host recorded LOW.
func (h *harness) lowRunHost(id string) runHost {
	h.t.Helper()
	host := h.pinnedRunHost(id)
	if _, err := h.client.TrustArtifact(h.ctx(), &pb.TrustArtifactRequest{ActionId: "test.run", ModuleVersion: "1.0.0",
		RiskClass: pb.RiskClass_RISK_CLASS_LOW, Artifact: runScript, Label: "schedule test", ExpectedSha256: hexSum(runScript)}); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: id, HostKeyFingerprint: host.fp,
		Criticality: pb.RiskClass_RISK_CLASS_LOW}); err != nil {
		h.t.Fatal(err)
	}
	return host
}

func scheduledRun(host runHost, script []byte) *pb.RunScheduledRequest {
	r := runReq("", host, script, credRef)
	return &pb.RunScheduledRequest{GrantId: schedGrantID, Run: r.GetRun(), Endpoints: r.GetEndpoints()}
}

// A schedule grant runs exactly the approved LOW actions on the approved
// hosts, at most once per interval, until it is revoked; approving it
// needs a user-verified assertion over its own challenge.
func TestScheduleGrantRunsOnlyWhatWasApproved(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.lowRunHost("sched")

	// Not before approval.
	_, err := h.client.RunScheduled(h.ctx(), scheduledRun(host, runScript))
	wantCode(t, err, codes.NotFound, "")

	h.openSession()
	p, err := h.client.ProposeScheduleGrant(h.ctx(), &pb.ProposeScheduleGrantRequest{GrantJson: h.grantFor(host, runScript)})
	if err != nil || len(p.GetChallenge()) != 32 || p.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		t.Fatalf("%v %v", p, err)
	}
	c, err := h.client.CommitScheduleGrant(h.ctx(), &pb.CommitScheduleGrantRequest{GrantDigest: p.GetGrantDigest(), AssertionJson: h.sign(p.GetChallenge())})
	if err != nil || c.GetGrant().GetGrantId() != schedGrantID {
		t.Fatalf("%v %v", c, err)
	}
	h.requireAudit("schedule_grant_approved", schedGrantID)

	r, err := h.client.RunScheduled(h.ctx(), scheduledRun(host, runScript))
	if err != nil || r.GetResult().GetClass() != "success" || r.GetExecutionId() == "" {
		t.Fatalf("%v %v", r, err)
	}
	_, err = h.client.RunScheduled(h.ctx(), scheduledRun(host, runScript))
	wantCode(t, err, codes.ResourceExhausted, "interval")
	other := []byte("#!/bin/sh\necho other\n")
	_, err = h.client.RunScheduled(h.ctx(), scheduledRun(host, other))
	wantCode(t, err, codes.PermissionDenied, "")
	if _, err := h.client.RevokeScheduleGrant(h.ctx(), &pb.RevokeScheduleGrantRequest{GrantId: schedGrantID}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.RunScheduled(h.ctx(), scheduledRun(host, runScript))
	wantCode(t, err, codes.PermissionDenied, "")
	if n := len(host.srv.Commands()); n != 1 {
		t.Fatalf("%d commands on the host", n)
	}
	l, err := h.client.ListScheduleGrants(h.ctx(), &pb.ListScheduleGrantsRequest{})
	if err != nil || len(l.GetGrants()) != 1 || l.GetGrants()[0].GetRevokedUnix() == 0 {
		t.Fatalf("%v %v", l, err)
	}
}

// Only actions the executor itself rates LOW on every target can be
// scheduled; the targets must be pinned with the granted key.
func TestScheduleGrantRefusesWhatIsNotLowOrNotPinned(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	h.openSession()
	host := h.pinnedRunHost("plain") // artifact not trusted: HIGH
	_, err := h.client.ProposeScheduleGrant(h.ctx(), &pb.ProposeScheduleGrantRequest{GrantJson: h.grantFor(host, runScript)})
	wantCode(t, err, codes.InvalidArgument, "not LOW")
	low := h.lowRunHost("low")
	moved := low
	// Another fingerprint: change its first character (to one it is not).
	c := "Z"
	if low.fp[7] == 'Z' {
		c = "Y"
	}
	moved.fp = "SHA256:" + c + low.fp[8:]
	_, err = h.client.ProposeScheduleGrant(h.ctx(), &pb.ProposeScheduleGrantRequest{GrantJson: h.grantFor(moved, runScript)})
	wantCode(t, err, codes.InvalidArgument, "")
	// A grant's challenge cannot be used without the privileged session.
	p, err := h.client.ProposeScheduleGrant(h.ctx(), &pb.ProposeScheduleGrantRequest{GrantJson: h.grantFor(low, runScript)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.CommitScheduleGrant(h.ctx(), &pb.CommitScheduleGrantRequest{GrantDigest: p.GetGrantDigest(), AssertionJson: h.sign(p.GetChallenge())})
	wantCode(t, err, codes.NotFound, "")
}

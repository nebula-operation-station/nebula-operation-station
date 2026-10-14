// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

var (
	// The script echoes what the host received.
	runScript = []byte("#!/bin/sh\nprintf 'ran %s\\n' \"$NEBULA_EXECUTION_ID\" >&2\ncat \"$NEBULA_PARAMS\"\n")
	// Same parameters as the proposal, but spelled differently: the hash is
	// equal after canonicalization, the bytes are not.
	runParamsProposed = []byte(`{"b":[1,2],"a":"x"}`)
	runParamsRequest  = []byte("{ \"a\" : \"x\",\n \"b\" : [1, 2] }")
)

type runHost struct {
	id, fp, endpoint string
	srv              *hostruntest.Server
}

// pinnedRunHost starts an exec-capable SSH server and pins it as id.
func (h *harness) pinnedRunHost(id string) runHost {
	h.t.Helper()
	srv := hostruntest.Start(h.t, h.userKey)
	p := h.pin(id, h.probe(srv.Addr))
	return runHost{id: id, fp: p.GetFingerprint(), endpoint: srv.Addr, srv: srv}
}

// approvedRun proposes the run script for host as HIGH (an unknown host
// is HIGH) and approves it with the browser assertion.
func (h *harness) approvedRun(host runHost, credRefs ...string) string {
	h.t.Helper()
	if len(credRefs) == 0 {
		credRefs = []string{credRef}
	}
	ph, err := canonical.HashParameters(runParamsProposed)
	if err != nil {
		h.t.Fatal(err)
	}
	req := &pb.ExecutionRequest{
		ExecutionId: fmt.Sprintf("00000000-0000-4000-8000-%012d", execCounter.Add(1)),
		ActionId:    "test.run", ModuleVersion: "1.0.0",
		ArtifactSha256:  hexSum(runScript),
		ParametersHash:  ph,
		CredentialRefs:  credRefs,
		RiskClass:       pb.RiskClass_RISK_CLASS_HIGH,
		StagePlanHash:   strings.Repeat("c", 64),
		ExpiryUnix:      time.Now().Add(time.Hour).Unix(),
		ResolvedTargets: []*pb.Target{{HostId: host.id, HostKeyFingerprint: host.fp}},
	}
	h.openSession()
	p, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req, ParametersJson: runParamsProposed})
	if err != nil {
		h.t.Fatalf("propose: %v", err)
	}
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
		ExecutionDigest: p.GetExecutionDigest(), AssertionJson: h.sign(p.GetChallenge()),
	}); err != nil {
		h.t.Fatalf("approve: %v", err)
	}
	return p.GetExecutionDigest()
}

func runReq(digest string, host runHost, artifact []byte, credential string) *pb.RunAttachedRequest {
	return &pb.RunAttachedRequest{
		Run: &pb.AuthorizeRunRequest{ExecutionDigest: digest, HostId: host.id, HostKeyFingerprint: host.fp,
			ActionId: "test.run", ModuleVersion: "1.0.0", Artifact: artifact, ParametersJson: runParamsRequest, CredentialRef: credential},
		Endpoints: []string{host.endpoint},
	}
}

// The approved script runs once on the pinned host, with the parameters
// the executor held since the proposal (spec 07, m0 gap "Permit.Parameters").
func TestM4_RunAttachedRunsTheApprovedScriptOnce(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedRun(host)

	r, err := h.client.RunAttached(h.ctx(), runReq(d, host, runScript, credRef))
	if err != nil {
		t.Fatal(err)
	}
	if r.GetClass() != "success" || string(r.GetResult()) != `{"a":"x","b":[1,2]}` || !strings.HasPrefix(string(r.GetLog()), "ran 00000000-0000-4000-8000-") ||
		r.GetEndpoint() != host.endpoint {
		t.Fatalf("run: %+v", r)
	}
	h.requireAudit("run_finished", "runhost", "success")
	if n := len(host.srv.Commands()); n != 1 {
		t.Fatalf("%d commands on the host", n)
	}

	_, err = h.client.RunAttached(h.ctx(), runReq(d, host, runScript, credRef))
	wantCode(t, err, codes.PermissionDenied, "")
	if n := len(host.srv.Commands()); n != 1 {
		t.Fatal("a second run reached the host")
	}
}

// Anything that differs from the approval stops the run before the host is
// contacted, and the host stays usable for the approved run.
func TestM4_RunAttachedRefusesBeforeConnecting(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedRun(host)

	_, err := h.client.RunAttached(h.ctx(), runReq(d, host, []byte("#!/bin/sh\nrm -rf /\n"), credRef))
	wantCode(t, err, codes.PermissionDenied, "")
	other := host
	other.fp = "SHA256:" + strings.Repeat("A", 43)
	_, err = h.client.RunAttached(h.ctx(), runReq(d, other, runScript, credRef))
	wantCode(t, err, codes.PermissionDenied, "")
	bad := runReq(d, host, runScript, credRef)
	bad.Endpoints = []string{"not an endpoint!"}
	_, err = h.client.RunAttached(h.ctx(), bad)
	wantCode(t, err, codes.InvalidArgument, "")
	long := runReq(d, host, runScript, credRef)
	long.TimeoutSeconds = 3600
	_, err = h.client.RunAttached(h.ctx(), long)
	wantCode(t, err, codes.InvalidArgument, "durable")

	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.RunAttached(h.ctx(), runReq(d, host, runScript, credRef))
	wantCode(t, err, codes.FailedPrecondition, "vault_locked")
	if n := len(host.srv.Commands()); n != 0 {
		t.Fatalf("host contacted %d times", n)
	}
}

// The connection uses the pin's credential; a permit for another
// credential cannot make the executor use the pinned one.
func TestM4_RunAttachedNeedsThePinnedCredential(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedRun(host, "other-key")
	_, err := h.client.RunAttached(h.ctx(), runReq(d, host, runScript, "other-key"))
	wantCode(t, err, codes.PermissionDenied, "credential_mismatch")
	if len(host.srv.Commands()) != 0 {
		t.Fatal("host contacted")
	}
}

// A failure after authorization is a result class, and the permit's host
// is used up: an unreachable host is not retried with the same permit.
func TestM4_RunAttachedConnectionFailureUsesTheHost(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedRun(host)
	down := host
	down.endpoint = closedPort(t)
	r, err := h.client.RunAttached(h.ctx(), runReq(d, down, runScript, credRef))
	if err != nil || r.GetClass() != "network_unreachable" {
		t.Fatalf("unreachable: %v %v", r, err)
	}
	_, err = h.client.RunAttached(h.ctx(), runReq(d, host, runScript, credRef))
	wantCode(t, err, codes.PermissionDenied, "")
}

func TestM4_RunAttachedIsServerOnly(t *testing.T) {
	uid := uint32(os.Getuid())
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleAdmin}}})
	_, err := h.client.RunAttached(h.ctx(), &pb.RunAttachedRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}

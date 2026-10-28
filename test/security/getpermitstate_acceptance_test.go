// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"bytes"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Issue #78: the server must see an approval made on the executor host
// (hardened path) by asking for the permit state. GetPermitState is
// read-only, allowed for the server and admin roles, and reveals nothing
// but the state.

// A valid 64-hex digest that no permit matches.
const neverProposedDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// The state follows the permit: PENDING after a proposal, APPROVED after a
// CLI approval.
func TestGetPermitStateFollowsThePermit(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	d := p.GetExecutionDigest()

	got, err := h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: d})
	wantCode(t, err, codes.OK, "")
	if got.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
		t.Fatalf("want PENDING before approval, got %v", got.GetState())
	}

	if _, err := h.client.ApproveCLI(h.ctx(), &pb.ApproveCLIRequest{ExecutionDigest: d}); err != nil {
		t.Fatalf("approve cli: %v", err)
	}
	got, err = h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: d})
	wantCode(t, err, codes.OK, "")
	if got.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		t.Fatalf("want APPROVED after CLI approval, got %v", got.GetState())
	}
}

// No live permit answers UNSPECIFIED, not an error: a digest that was never
// proposed and a permit revoked by Lock give the same answer. A permit past
// its approval window is collected by the same code (gcLocked) and so
// answers UNSPECIFIED too; the collection itself is covered by the permit
// expiry tests.
func TestGetPermitStateIsUnspecifiedWithoutALivePermit(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	// Never proposed.
	got, err := h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: neverProposedDigest})
	wantCode(t, err, codes.OK, "")
	if got.GetState() != pb.PermitState_PERMIT_STATE_UNSPECIFIED {
		t.Fatalf("want UNSPECIFIED for a never-proposed digest, got %v", got.GetState())
	}

	// Revoked by Lock.
	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatalf("lock: %v", err)
	}
	got, err = h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: p.GetExecutionDigest()})
	wantCode(t, err, codes.OK, "")
	if got.GetState() != pb.PermitState_PERMIT_STATE_UNSPECIFIED {
		t.Fatalf("want UNSPECIFIED after Lock, got %v", got.GetState())
	}
}

// The response carries only the state: no challenge, no canonical request,
// no parameters.
func TestGetPermitStateRevealsNothingButTheState(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))

	got, err := h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: p.GetExecutionDigest()})
	wantCode(t, err, codes.OK, "")
	raw, err := proto.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, p.GetChallenge()) {
		t.Fatal("response leaks the challenge")
	}
	if bytes.Contains(raw, p.GetCanonicalRequest()) {
		t.Fatal("response leaks the canonical request")
	}
	if bytes.Contains(raw, params) {
		t.Fatal("response leaks the parameters")
	}
}

// A malformed digest is a client error, not a state answer.
func TestGetPermitStateRejectsAMalformedDigest(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	_, err := h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: "nothex"})
	wantCode(t, err, codes.InvalidArgument, "")
}

// The server role may read the state (and the admin role may too); an
// unknown UID is rejected as for every method.
func TestGetPermitStateRoles(t *testing.T) {
	// Server role: may propose and read the state.
	hs := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}})
	ps := hs.propose(hs.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	got, err := hs.client.GetPermitState(hs.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: ps.GetExecutionDigest()})
	wantCode(t, err, codes.OK, "")
	if got.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
		t.Fatalf("server role: want PENDING, got %v", got.GetState())
	}

	// Admin role: may read the state (no permit exists, so UNSPECIFIED).
	ha := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}}})
	got, err = ha.client.GetPermitState(ha.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: neverProposedDigest})
	wantCode(t, err, codes.OK, "")
	if got.GetState() != pb.PermitState_PERMIT_STATE_UNSPECIFIED {
		t.Fatalf("admin role: want UNSPECIFIED, got %v", got.GetState())
	}

	// Unknown UID: rejected.
	other := uint32(os.Getuid()) + 1
	hu := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{other: {peercred.RoleServer, peercred.RoleAdmin}}})
	_, err = hu.client.GetPermitState(hu.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: neverProposedDigest})
	wantRejectedPeer(t, err)
}

// Reading the state changes nothing: a pending permit is still approvable
// and an approved permit still authorizes exactly one run per host.
func TestGetPermitStateDoesNotChangeThePermit(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	d := p.GetExecutionDigest()

	// Several reads in a row.
	for i := 0; i < 3; i++ {
		got, err := h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: d})
		wantCode(t, err, codes.OK, "")
		if got.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
			t.Fatalf("read %d: want PENDING, got %v", i, got.GetState())
		}
	}

	// The CLI approval still works after the reads.
	if _, err := h.client.ApproveCLI(h.ctx(), &pb.ApproveCLIRequest{ExecutionDigest: d}); err != nil {
		t.Fatalf("approve cli after reads: %v", err)
	}
	if _, err := h.client.GetPermitState(h.ctx(), &pb.GetPermitStateRequest{ExecutionDigest: d}); err != nil {
		t.Fatalf("read after approval: %v", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Acceptance tests for the pve-collector role boundary (ADR 0006, P1-05).
// These tests are protected: a change that weakens or deletes one needs
// human review (see AGENTS.md).
package security

import (
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func validReadPVE() *pb.ReadPVERequest {
	return &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES}
}

// TestPVECollectorBoundary is the acceptance test for the pve-collector
// role. The test process runs as the pve-collector UID: it may call ONLY
// ListPVERemotes and ReadPVE and is denied PermissionDenied for every
// other method of the executor service.
func TestPVECollectorBoundary(t *testing.T) {
	h := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RolePVECollector}},
	})

	// The two PVE read methods are allowed. The executor answers
	// Unimplemented until the pveapi wiring lands (P1-07); what matters
	// here is that the role table does not reject the calls.
	if _, err := h.client.ListPVERemotes(h.ctx(), &pb.ListPVERemotesRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("collector ListPVERemotes: want Unimplemented (allowed, not wired), got %v", err)
	}
	if _, err := h.client.ReadPVE(h.ctx(), validReadPVE()); status.Code(err) != codes.Unimplemented {
		t.Fatalf("collector ReadPVE: want Unimplemented (allowed, not wired), got %v", err)
	}

	// Loop over every method of the executor service: the collector is
	// denied for all of them except the two PVE read methods.
	conn, err := grpc.NewClient("unix://"+h.socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for method := range executor.MethodRoles() {
		err := conn.Invoke(h.ctx(), method, &pb.GetStatusRequest{}, &pb.GetStatusResponse{})
		allowed := method == pb.ExecutorService_ListPVERemotes_FullMethodName ||
			method == pb.ExecutorService_ReadPVE_FullMethodName
		if allowed {
			if status.Code(err) == codes.PermissionDenied {
				t.Errorf("%s: collector wants allowed, got PermissionDenied", method)
			}
			continue
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: collector wants PermissionDenied, got %v", method, err)
		}
	}
}

// TestPVECollectorUnknownUIDDenied: a UID that holds no role is dropped
// during the handshake, before any request is read, for the PVE methods
// as for every other method.
func TestPVECollectorUnknownUIDDenied(t *testing.T) {
	other := uint32(os.Getuid()) + 1
	h := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{other: {peercred.RolePVECollector}},
	})
	if _, err := h.client.ListPVERemotes(h.ctx(), &pb.ListPVERemotesRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("unknown UID ListPVERemotes: want Unavailable (handshake rejection), got %v", err)
	}
	if _, err := h.client.ReadPVE(h.ctx(), validReadPVE()); status.Code(err) != codes.Unavailable {
		t.Fatalf("unknown UID ReadPVE: want Unavailable (handshake rejection), got %v", err)
	}
	h.requireHandshakeRejection(uint32(os.Getuid()))
}

func TestPVECollectorNodesRejectsGuestParameter(t *testing.T) {
	h := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RolePVECollector}},
	})
	for _, vmid := range []uint64{0, 100} {
		req := validReadPVE()
		req.Params = &pb.ReadPVERequest_Guest{Guest: &pb.PVEReadGuestParams{Vmid: vmid}}
		if _, err := h.client.ReadPVE(h.ctx(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("NODES with guest vmid %d: want InvalidArgument, got %v", vmid, err)
		}
	}
}

// TestPVEReadServerAndAdminAccess pins the other two rows of the PVE read
// role table (ADR 0006, P1-05): the server role may call ListPVERemotes
// but not ReadPVE; the admin role may call both; malformed ReadPVE
// requests are rejected with InvalidArgument.
func TestPVEReadServerAndAdminAccess(t *testing.T) {
	// Server role: ListPVERemotes allowed, ReadPVE denied.
	hs := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}},
	})
	if _, err := hs.client.ListPVERemotes(hs.ctx(), &pb.ListPVERemotesRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("server ListPVERemotes: want Unimplemented (allowed, not wired), got %v", err)
	}
	if _, err := hs.client.ReadPVE(hs.ctx(), validReadPVE()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server ReadPVE: want PermissionDenied, got %v", err)
	}

	// Admin role: both allowed; malformed requests rejected.
	ha := newHarness(t, harnessOptions{
		uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}},
	})
	if _, err := ha.client.ListPVERemotes(ha.ctx(), &pb.ListPVERemotesRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("admin ListPVERemotes: want Unimplemented (allowed, not wired), got %v", err)
	}
	if _, err := ha.client.ReadPVE(ha.ctx(), validReadPVE()); status.Code(err) != codes.Unimplemented {
		t.Fatalf("admin ReadPVE: want Unimplemented (allowed, not wired), got %v", err)
	}
	if _, err := ha.client.ReadPVE(ha.ctx(), &pb.ReadPVERequest{RemoteId: "pve-1"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin ReadPVE without method: want InvalidArgument, got %v", err)
	}
	if _, err := ha.client.ReadPVE(ha.ctx(), &pb.ReadPVERequest{RemoteId: "PVE-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin ReadPVE with bad remote id: want InvalidArgument, got %v", err)
	}
}

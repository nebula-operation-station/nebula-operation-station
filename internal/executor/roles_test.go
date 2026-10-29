// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestMethodRolesServerReadAccess pins the read-only access the web server
// needs for the Settings page (issue #72): the server role may list the
// registered WebAuthn credentials and read the TOTP status, and nothing
// else in the WebAuthn/TOTP area. The server already sees credential IDs
// in the request options of logins and privileged sessions (decision 37);
// labels, AAGUIDs and creation data are not secrets, and the TOTP status
// is a boolean.
func TestMethodRolesServerReadAccess(t *testing.T) {
	const serverUID, adminUID uint32 = 10001, 10002
	policy := peercred.NewPolicy(
		map[uint32][]peercred.Role{
			serverUID: {peercred.RoleServer},
			adminUID:  {peercred.RoleAdmin},
		},
		MethodRoles(),
	)

	allowed := []string{
		pb.ExecutorService_ListWebAuthnCredentials_FullMethodName,
		pb.ExecutorService_GetTOTPStatus_FullMethodName,
	}
	for _, method := range allowed {
		if _, ok := policy.Allowed(serverUID, method); !ok {
			t.Errorf("server role may not call %s, want allowed", method)
		}
		if _, ok := policy.Allowed(adminUID, method); !ok {
			t.Errorf("admin role may not call %s, want allowed", method)
		}
	}

	// The rest of the WebAuthn and TOTP area stays admin-only: the server
	// may neither create codes, remove credentials, nor set up or remove
	// TOTP.
	for _, method := range []string{
		pb.ExecutorService_CreateRegistrationCode_FullMethodName,
		pb.ExecutorService_RemoveWebAuthnCredential_FullMethodName,
		pb.ExecutorService_BeginTOTPSetup_FullMethodName,
		pb.ExecutorService_ConfirmTOTPSetup_FullMethodName,
		pb.ExecutorService_RemoveTOTP_FullMethodName,
	} {
		if _, ok := policy.Allowed(serverUID, method); ok {
			t.Errorf("server role may call %s, want admin-only", method)
		}
	}
}

// TestMethodRolesPVEReadSurface pins the PVE read role table (ADR 0006,
// P1-05): the entries are final. pve-collector may call ONLY
// ListPVERemotes and ReadPVE; server may call ListPVERemotes (metadata);
// admin may call both. Remote management is not part of this surface.
func TestMethodRolesPVEReadSurface(t *testing.T) {
	const (
		serverUID uint32 = 20001
		adminUID  uint32 = 20002
		collUID   uint32 = 20003
	)
	policy := peercred.NewPolicy(
		map[uint32][]peercred.Role{
			serverUID: {peercred.RoleServer},
			adminUID:  {peercred.RoleAdmin},
			collUID:   {peercred.RolePVECollector},
		},
		MethodRoles(),
	)

	// Exact role sets for the two PVE methods.
	want := map[string][]peercred.Role{
		pb.ExecutorService_ListPVERemotes_FullMethodName: {peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector},
		pb.ExecutorService_ReadPVE_FullMethodName:        {peercred.RolePVECollector, peercred.RoleAdmin},
	}
	for method, roles := range MethodRoles() {
		w, ok := want[method]
		if !ok {
			continue
		}
		if len(roles) != len(w) {
			t.Errorf("%s: roles = %v, want exactly %v", method, roles, w)
			continue
		}
		for _, r := range w {
			if !slices.Contains(roles, r) {
				t.Errorf("%s: roles = %v, want %v to be allowed", method, roles, r)
			}
		}
	}

	// The collector may call ONLY the two PVE read methods: loop over every
	// method in the table.
	for method := range MethodRoles() {
		_, allowed := policy.Allowed(collUID, method)
		if (method == pb.ExecutorService_ListPVERemotes_FullMethodName ||
			method == pb.ExecutorService_ReadPVE_FullMethodName) != allowed {
			t.Errorf("pve-collector may call %s: got allowed=%v, want %v",
				method, allowed,
				method == pb.ExecutorService_ListPVERemotes_FullMethodName ||
					method == pb.ExecutorService_ReadPVE_FullMethodName)
		}
	}

	// Server: ListPVERemotes yes, ReadPVE no.
	if _, ok := policy.Allowed(serverUID, pb.ExecutorService_ListPVERemotes_FullMethodName); !ok {
		t.Error("server role may not call ListPVERemotes, want allowed")
	}
	if _, ok := policy.Allowed(serverUID, pb.ExecutorService_ReadPVE_FullMethodName); ok {
		t.Error("server role may call ReadPVE, want denied")
	}

	// Admin: both.
	for _, method := range []string{
		pb.ExecutorService_ListPVERemotes_FullMethodName,
		pb.ExecutorService_ReadPVE_FullMethodName,
	} {
		if _, ok := policy.Allowed(adminUID, method); !ok {
			t.Errorf("admin role may not call %s, want allowed", method)
		}
	}
}

// TestValidateReadPVERequest pins the ReadPVE request validation (ADR 0006,
// P1-05): malformed requests are rejected with InvalidArgument.
func TestValidateReadPVERequest(t *testing.T) {
	guest := func(vmid uint64) *pb.PVEReadGuestParams { return &pb.PVEReadGuestParams{Vmid: vmid} }
	node := func(name string) *pb.PVEReadNodeParams { return &pb.PVEReadNodeParams{Node: name} }

	tests := []struct {
		name    string
		req     *pb.ReadPVERequest
		wantErr bool
	}{
		{name: "nil request", req: nil, wantErr: true},
		{name: "empty remote id", req: &pb.ReadPVERequest{Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES}, wantErr: true},
		{name: "uppercase remote id", req: &pb.ReadPVERequest{RemoteId: "PVE1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES}, wantErr: true},
		{name: "remote id too long", req: &pb.ReadPVERequest{RemoteId: "a0123456789012345678901234567890123456789012345678901234567890123", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES}, wantErr: true},
		{name: "unspecified method", req: &pb.ReadPVERequest{RemoteId: "pve-1"}, wantErr: true},
		{name: "unknown method", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod(99)}, wantErr: true},
		{name: "nodes ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES}, wantErr: false},
		{name: "nodes with valid node", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Node{Node: node("node1")}}, wantErr: false},
		{name: "nodes with empty node", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Node{Node: node("")}}, wantErr: true},
		{name: "nodes with bad node", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Node{Node: node("Node 1")}}, wantErr: true},
		{name: "guests ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUESTS}, wantErr: false},
		{name: "guests with guest param", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUESTS, Params: &pb.ReadPVERequest_Guest{Guest: guest(100)}}, wantErr: true},
		{name: "guests with node param", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUESTS, Params: &pb.ReadPVERequest_Node{Node: node("node1")}}, wantErr: true},
		{name: "storage ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_STORAGE}, wantErr: false},
		{name: "cluster ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER}, wantErr: false},
		{name: "tasks ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_TASKS}, wantErr: false},
		{name: "metrics ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_METRICS}, wantErr: false},
		{name: "metrics with guest param", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_METRICS, Params: &pb.ReadPVERequest_Guest{Guest: guest(100)}}, wantErr: true},
		{name: "guest config ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, Params: &pb.ReadPVERequest_Guest{Guest: guest(100)}}, wantErr: false},
		{name: "guest config without guest", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG}, wantErr: true},
		{name: "guest config vmid zero", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, Params: &pb.ReadPVERequest_Guest{Guest: guest(0)}}, wantErr: true},
		{name: "guest config with node param", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, Params: &pb.ReadPVERequest_Node{Node: node("node1")}}, wantErr: true},
		{name: "guest agent ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, Params: &pb.ReadPVERequest_Guest{Guest: guest(101)}}, wantErr: false},
		{name: "guest agent without guest", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT}, wantErr: true},
		{name: "snapshots ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, Params: &pb.ReadPVERequest_Guest{Guest: guest(102)}}, wantErr: false},
		{name: "snapshots without guest", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS}, wantErr: true},
		{name: "backups ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, Params: &pb.ReadPVERequest_Guest{Guest: guest(103)}}, wantErr: false},
		{name: "backups without guest", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReadPVERequest(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want InvalidArgument, got nil")
				}
				if code := status.Code(err); code != codes.InvalidArgument {
					t.Fatalf("want codes.InvalidArgument, got %v", code)
				}
				return
			}
			if err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

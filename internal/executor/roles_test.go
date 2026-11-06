// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
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

// TestMethodRolesServerMayReadSSHPublicKey pins the read-grant follow-up
// (ADR 0007, E06): the server may read the executor's SSH public key,
// because read-grant-v2 binds every target to the key's SHA-256
// fingerprint (credential_version). It is a public key; the change grants
// nothing else. Approve and key/vault administration methods stay
// admin-only.
func TestMethodRolesServerMayReadSSHPublicKey(t *testing.T) {
	const serverUID, adminUID uint32 = 30001, 30002
	policy := peercred.NewPolicy(
		map[uint32][]peercred.Role{
			serverUID: {peercred.RoleServer},
			adminUID:  {peercred.RoleAdmin},
		},
		MethodRoles(),
	)

	roles := MethodRoles()[pb.ExecutorService_GetSSHPublicKey_FullMethodName]
	if len(roles) != 2 || !slices.Contains(roles, peercred.RoleServer) || !slices.Contains(roles, peercred.RoleAdmin) {
		t.Fatalf("GetSSHPublicKey roles = %v, want exactly [server admin]", roles)
	}
	for _, uid := range []uint32{serverUID, adminUID} {
		if _, ok := policy.Allowed(uid, pb.ExecutorService_GetSSHPublicKey_FullMethodName); !ok {
			t.Errorf("uid %d may not call GetSSHPublicKey, want allowed", uid)
		}
	}

	for _, method := range []string{
		pb.ExecutorService_ApproveReadGrantCLI_FullMethodName,
		pb.ExecutorService_ListPendingReadGrants_FullMethodName,
		pb.ExecutorService_ApproveScheduleGrantCLI_FullMethodName,
		pb.ExecutorService_ApproveCLI_FullMethodName,
		pb.ExecutorService_ApproveGateCLI_FullMethodName,
		pb.ExecutorService_ApproveBatchCLI_FullMethodName,
		pb.ExecutorService_ReviewBatch_FullMethodName,
		pb.ExecutorService_ListPending_FullMethodName,
		pb.ExecutorService_Unlock_FullMethodName,
		pb.ExecutorService_PinHostKey_FullMethodName,
		pb.ExecutorService_UnpinHostKey_FullMethodName,
		pb.ExecutorService_TestConnection_FullMethodName,
		pb.ExecutorService_InitVault_FullMethodName,
		pb.ExecutorService_SetSecret_FullMethodName,
		pb.ExecutorService_ListSecrets_FullMethodName,
		pb.ExecutorService_TrustArtifact_FullMethodName,
		pb.ExecutorService_AddSigner_FullMethodName,
	} {
		if _, ok := policy.Allowed(serverUID, method); ok {
			t.Errorf("server role may call %s, want admin-only", method)
		}
		if _, ok := policy.Allowed(adminUID, method); !ok {
			t.Errorf("admin role may not call %s, want allowed", method)
		}
	}
}

// TestMethodRolesPVEReadSurface pins the PVE read role table (ADR 0006,
// P1-05): the entries are final. pve-collector may call ONLY
// ListPVERemotes and ReadPVE, plus ListReadGrants (read-only grant
// metadata for on-demand live reads, autopilot lv00); server may call
// ListPVERemotes (metadata); admin may call both. Remote management is not
// part of this surface.
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

	// The collector may call ONLY the two PVE read methods and
	// ListReadGrants: loop over every method in the table.
	collectorAllowed := map[string]bool{
		pb.ExecutorService_ListPVERemotes_FullMethodName: true,
		pb.ExecutorService_ReadPVE_FullMethodName:        true,
		pb.ExecutorService_ListReadGrants_FullMethodName: true,
	}
	for method := range MethodRoles() {
		_, allowed := policy.Allowed(collUID, method)
		if collectorAllowed[method] != allowed {
			t.Errorf("pve-collector may call %s: got allowed=%v, want %v",
				method, allowed, collectorAllowed[method])
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

// TestMethodRolesCollectorMayListReadGrants pins the read-grant listing
// for the pve-collector (autopilot lv00): the collector checks on-demand
// live requests against read-grant leases itself, so a server-supplied
// target list never widens what is read. It may list approved grants
// (metadata, read-only) and nothing else in the read-grant, schedule-grant
// or batch area; the server still may not call ReadPVE.
func TestMethodRolesCollectorMayListReadGrants(t *testing.T) {
	const (
		serverUID uint32 = 40001
		adminUID  uint32 = 40002
		collUID   uint32 = 40003
	)
	policy := peercred.NewPolicy(
		map[uint32][]peercred.Role{
			serverUID: {peercred.RoleServer},
			adminUID:  {peercred.RoleAdmin},
			collUID:   {peercred.RolePVECollector},
		},
		MethodRoles(),
	)

	roles := MethodRoles()[pb.ExecutorService_ListReadGrants_FullMethodName]
	want := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector}
	if len(roles) != len(want) {
		t.Fatalf("ListReadGrants roles = %v, want exactly %v", roles, want)
	}
	for _, r := range want {
		if !slices.Contains(roles, r) {
			t.Errorf("ListReadGrants roles = %v, want %v to be allowed", roles, r)
		}
	}
	for _, uid := range []uint32{serverUID, adminUID, collUID} {
		if _, ok := policy.Allowed(uid, pb.ExecutorService_ListReadGrants_FullMethodName); !ok {
			t.Errorf("uid %d may not call ListReadGrants, want allowed", uid)
		}
	}

	// The collector may never propose, commit, approve, revoke or run a
	// grant, list pending grants, or touch schedule grants or batches.
	for _, method := range []string{
		pb.ExecutorService_ProposeReadGrant_FullMethodName,
		pb.ExecutorService_CommitReadGrant_FullMethodName,
		pb.ExecutorService_ListPendingReadGrants_FullMethodName,
		pb.ExecutorService_ApproveReadGrantCLI_FullMethodName,
		pb.ExecutorService_RevokeReadGrant_FullMethodName,
		pb.ExecutorService_RunReadGrant_FullMethodName,
		pb.ExecutorService_ProposeScheduleGrant_FullMethodName,
		pb.ExecutorService_CommitScheduleGrant_FullMethodName,
		pb.ExecutorService_ListPendingScheduleGrants_FullMethodName,
		pb.ExecutorService_ApproveScheduleGrantCLI_FullMethodName,
		pb.ExecutorService_ListScheduleGrants_FullMethodName,
		pb.ExecutorService_RevokeScheduleGrant_FullMethodName,
		pb.ExecutorService_RunScheduled_FullMethodName,
		pb.ExecutorService_ProposeBatch_FullMethodName,
		pb.ExecutorService_CommitBatch_FullMethodName,
		pb.ExecutorService_ReviewBatch_FullMethodName,
		pb.ExecutorService_ApproveBatchCLI_FullMethodName,
		pb.ExecutorService_GetBatchStatus_FullMethodName,
	} {
		if _, ok := policy.Allowed(collUID, method); ok {
			t.Errorf("pve-collector may call %s, want denied", method)
		}
	}

	// The server still never calls ReadPVE.
	if _, ok := policy.Allowed(serverUID, pb.ExecutorService_ReadPVE_FullMethodName); ok {
		t.Error("server role may call ReadPVE, want denied")
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
		{name: "nodes with mixed-case node", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Node{Node: node("ProxmoxBAI")}}, wantErr: false},
		{name: "nodes with malformed mixed-case node", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Node{Node: node("../ProxmoxBAI")}}, wantErr: true},
		{name: "nodes with empty node", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Node{Node: node("")}}, wantErr: true},
		{name: "nodes with bad node", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Node{Node: node("Node 1")}}, wantErr: true},
		{name: "nodes with guest", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Guest{Guest: guest(100)}}, wantErr: true},
		{name: "nodes with empty guest", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Guest{Guest: guest(0)}}, wantErr: true},
		{name: "nodes with nil guest", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Guest{}}, wantErr: true},
		{name: "guests ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUESTS}, wantErr: false},
		{name: "guests with guest param", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUESTS, Params: &pb.ReadPVERequest_Guest{Guest: guest(100)}}, wantErr: true},
		{name: "guests with node param", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUESTS, Params: &pb.ReadPVERequest_Node{Node: node("node1")}}, wantErr: true},
		{name: "storage ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_STORAGE}, wantErr: false},
		{name: "cluster ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER}, wantErr: false},
		{name: "tasks ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_TASKS}, wantErr: false},
		// METRICS names one exact target (spec 17 telemetry lease); the
		// earlier parameterless shape is rejected.
		{name: "metrics ok", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_METRICS, Params: &pb.ReadPVERequest_Metrics{Metrics: &pb.PVEReadMetricsParams{Node: "node1", Kind: "node"}}}, wantErr: false},
		{name: "metrics without target", req: &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_METRICS}, wantErr: true},
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

// TestMethodRolesCoverEveryRPC: every method and stream of the executor
// service has a role-table entry with at least one role, and the table
// names no method the service does not have. A missing entry would make an
// RPC unreachable (the interceptor denies it for everyone) without any
// test noticing.
func TestMethodRolesCoverEveryRPC(t *testing.T) {
	roles := MethodRoles()
	desc := pb.ExecutorService_ServiceDesc
	full := map[string]bool{}
	for _, m := range desc.Methods {
		full["/"+desc.ServiceName+"/"+m.MethodName] = true
	}
	for _, s := range desc.Streams {
		full["/"+desc.ServiceName+"/"+s.StreamName] = true
	}
	if len(full) == 0 {
		t.Fatal("service descriptor has no methods")
	}
	for m := range full {
		if len(roles[m]) == 0 {
			t.Errorf("%s has no role-table entry", m)
		}
	}
	for m := range roles {
		if !full[m] {
			t.Errorf("role table names unknown method %s", m)
		}
	}
}

// TestMethodRolesGuestSnapshotThroughInterceptor: through the real
// interceptor and role table, the server and the admin may propose a
// guest snapshot action, only the admin may commit it, and every other
// role (and an unknown UID) is denied before the handler runs.
func TestMethodRolesGuestSnapshotThroughInterceptor(t *testing.T) {
	const (
		serverUID uint32 = 30001
		adminUID  uint32 = 30002
		collUID   uint32 = 30003
		discUID   uint32 = 30004
		otherUID  uint32 = 30999
	)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
		collUID:   {peercred.RolePVECollector},
		discUID:   {peercred.Role("discovery")},
	}, MethodRoles())
	propose := pb.ExecutorService_ProposePVEGuestSnapshot_FullMethodName
	commit := pb.ExecutorService_CommitPVEGuestSnapshot_FullMethodName
	allowed := map[string]map[uint32]bool{
		propose: {serverUID: true, adminUID: true},
		commit:  {adminUID: true},
	}
	for method, ok := range allowed {
		for _, uid := range []uint32{serverUID, adminUID, collUID, discUID, otherUID} {
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
			reached := false
			_, err := policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
				func(ctx context.Context, _ any) (any, error) {
					reached = true
					if c, has := peercred.CallerFrom(ctx); !has || c.UID != uid {
						t.Errorf("%s uid %d: caller %+v", method, uid, c)
					}
					return nil, nil
				})
			if ok[uid] {
				if err != nil || !reached {
					t.Errorf("%s uid %d: err %v reached %v, want allowed", method, uid, err, reached)
				}
			} else if status.Code(err) != codes.PermissionDenied || reached {
				t.Errorf("%s uid %d: err %v reached %v, want PermissionDenied", method, uid, err, reached)
			}
		}
	}
	// Exactly mirrors guest power.
	roles := MethodRoles()
	for snap, power := range map[string]string{
		propose: pb.ExecutorService_ProposePVEGuestPower_FullMethodName,
		commit:  pb.ExecutorService_CommitPVEGuestPower_FullMethodName,
	} {
		if !slices.Equal(roles[snap], roles[power]) {
			t.Errorf("%s roles %v, want %v (as %s)", snap, roles[snap], roles[power], power)
		}
	}
}

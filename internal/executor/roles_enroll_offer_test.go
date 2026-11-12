// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestMethodRolesEnrollOffers pins the role table of the one-step
// enrollment offer RPCs (ADR 0013 D1, D2; spec 03 v25-03-02): the server
// may create, fetch, show, download and revoke; the admin may list and
// revoke; no other role gets any of them.
func TestMethodRolesEnrollOffers(t *testing.T) {
	server, admin := peercred.RoleServer, peercred.RoleAdmin
	want := map[string][]peercred.Role{
		pb.ExecutorService_CreateEnrollOffer_FullMethodName:    {server},
		pb.ExecutorService_FetchEnrollScript_FullMethodName:    {server},
		pb.ExecutorService_ShowEnrollScript_FullMethodName:     {server},
		pb.ExecutorService_DownloadEnrollScript_FullMethodName: {server},
		pb.ExecutorService_RevokeEnrollOffer_FullMethodName:    {server, admin},
		pb.ExecutorService_ListEnrollOffers_FullMethodName:     {admin},
	}
	table := MethodRoles()
	for method, roles := range want {
		got := table[method]
		if len(got) != len(roles) {
			t.Errorf("%s roles = %v, want exactly %v", method, got, roles)
			continue
		}
		for _, r := range roles {
			if !slices.Contains(got, r) {
				t.Errorf("%s roles = %v, want exactly %v", method, got, roles)
			}
		}
	}

	const serverUID, adminUID, pveUID, netdevUID uint32 = 40001, 40002, 40003, 40004
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {server},
		adminUID:  {admin},
		pveUID:    {peercred.RolePVECollector},
		netdevUID: {peercred.RoleNetDevCollector},
	}, table)
	for method, roles := range want {
		for _, c := range []struct {
			uid  uint32
			role peercred.Role
		}{{serverUID, server}, {adminUID, admin}, {pveUID, peercred.RolePVECollector}, {netdevUID, peercred.RoleNetDevCollector}} {
			_, ok := policy.Allowed(c.uid, method)
			if ok != slices.Contains(roles, c.role) {
				t.Errorf("%s for role %s: allowed=%v, want %v", method, c.role, ok, !ok)
			}
		}
	}
}

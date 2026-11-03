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

// TestMethodRolesGuestProvisionThroughInterceptor pins ADR 0008 section 3
// (amendment 2026-11-03, variant B): through the real interceptor and role
// table, the server and the admin may propose and commit a guest
// provisioning; every other role (pve-collector, any other role, an
// unknown UID) is denied both RPCs before the handler runs.
func TestMethodRolesGuestProvisionThroughInterceptor(t *testing.T) {
	const (
		serverUID uint32 = 31001
		adminUID  uint32 = 31002
		collUID   uint32 = 31003
		discUID   uint32 = 31004
		otherUID  uint32 = 31999
	)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
		collUID:   {peercred.RolePVECollector},
		discUID:   {peercred.Role("discovery")},
	}, MethodRoles())
	for _, method := range []string{
		pb.ExecutorService_ProposePVEGuestProvision_FullMethodName,
		pb.ExecutorService_CommitPVEGuestProvision_FullMethodName,
	} {
		for _, uid := range []uint32{serverUID, adminUID, collUID, discUID, otherUID} {
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
			reached := false
			_, err := policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
				func(context.Context, any) (any, error) {
					reached = true
					return nil, nil
				})
			if uid == serverUID || uid == adminUID {
				if err != nil || !reached {
					t.Errorf("%s uid %d: err %v reached %v, want allowed", method, uid, err, reached)
				}
			} else if status.Code(err) != codes.PermissionDenied || reached {
				t.Errorf("%s uid %d: err %v reached %v, want PermissionDenied", method, uid, err, reached)
			}
		}
	}
	// The table entries are exactly {server, admin}: no further role.
	roles := MethodRoles()
	want := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin}
	for _, m := range []string{
		pb.ExecutorService_ProposePVEGuestProvision_FullMethodName,
		pb.ExecutorService_CommitPVEGuestProvision_FullMethodName,
	} {
		got := slices.Clone(roles[m])
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("%s roles %v, want %v", m, roles[m], want)
		}
	}
}

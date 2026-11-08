// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestServerGuestPowerCommitNeedsApprovedPermit pins decision WA-05
// variant (a) (2026-11-07) end to end through the real interceptor and
// role table: the server role reaches CommitPVEGuestPower, but the
// executor runs nothing until the permit is approved (the user's security
// key assertion, or the CLI); the risk floor of the proposal is the
// executor's, not the caller's. A role outside {server, admin} never
// reaches the handler.
func TestServerGuestPowerCommitNeedsApprovedPermit(t *testing.T) {
	const (
		serverUID uint32 = 32001
		collUID   uint32 = 32003
	)
	e, client, _, _, _ := newServicePowerEnv(t)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		collUID:   {peercred.RolePVECollector},
	}, MethodRoles())
	call := func(uid uint32, method string, h func(context.Context) (any, error)) (any, error) {
		ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
		return policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
			func(ctx context.Context, _ any) (any, error) { return h(ctx) })
	}
	target := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	commit := func(uid uint32, digest string) error {
		_, err := call(uid, pb.ExecutorService_CommitPVEGuestPower_FullMethodName, func(ctx context.Context) (any, error) {
			return e.svc.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: digest})
		})
		return err
	}

	out, err := call(serverUID, pb.ExecutorService_ProposePVEGuestPower_FullMethodName, func(ctx context.Context) (any, error) {
		return e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: target})
	})
	if err != nil {
		t.Fatalf("server propose: %v", err)
	}
	p := out.(*pb.ProposePVEGuestPowerResponse).GetPermit()
	// Shutdown of a guest at the executor's floor: HIGH, approved only
	// with a user-verified security key assertion.
	if p.GetRiskClass() != pb.RiskClass_RISK_CLASS_HIGH ||
		p.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		t.Fatalf("risk %v requirement %v, want the executor's HIGH floor with a user-verified security key",
			p.GetRiskClass(), p.GetApprovalRequirement())
	}

	// Pending permit: the server reaches the handler, the executor refuses.
	err = commit(serverUID, p.GetExecutionDigest())
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "no approved permit") {
		t.Fatalf("server commit of a pending permit: %v, want the executor's refusal", err)
	}
	if n := client.dispatchCount(); n != 0 {
		t.Fatalf("dispatched %d without approval", n)
	}

	// Another role is refused by the role table before the handler runs.
	err = commit(collUID, p.GetExecutionDigest())
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "may not call") {
		t.Fatalf("collector commit: %v, want the role table's refusal", err)
	}

	d, err := canonical.ParseDigest(p.GetExecutionDigest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveCLI(d, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := commit(collUID, p.GetExecutionDigest()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector commit of an approved permit: %v", err)
	}
	if n := client.dispatchCount(); n != 0 {
		t.Fatalf("dispatched %d for a refused role", n)
	}
	// Approved: the server's commit runs it, exactly once.
	if err := commit(serverUID, p.GetExecutionDigest()); err != nil {
		t.Fatalf("server commit of the approved permit: %v", err)
	}
	if n := client.dispatchCount(); n != 1 {
		t.Fatalf("dispatched %d, want 1", n)
	}
	if err := commit(serverUID, p.GetExecutionDigest()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("replayed server commit: %v, want refusal", err)
	}
	if n := client.dispatchCount(); n != 1 {
		t.Fatalf("dispatched %d after a replay, want 1", n)
	}
}

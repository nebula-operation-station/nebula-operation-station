// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// TestLazyExecutorServesGuestActions: the server's executor connection
// serves the typed guest power and snapshot controls (WA-05), and each
// call fails with errNotConnected without an executor.
func TestLazyExecutorServesGuestActions(t *testing.T) {
	var exec any = new(lazyExecutor)
	power, ok := exec.(ui.GuestPower)
	if !ok {
		t.Fatal("lazyExecutor does not serve the guest power controls")
	}
	snap, ok := exec.(ui.GuestSnapshot)
	if !ok {
		t.Fatal("lazyExecutor does not serve the guest snapshot controls")
	}
	ctx := context.Background()
	for name, call := range map[string]func() (any, error){
		"ProposePVEGuestPower":    func() (any, error) { return power.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{}) },
		"CommitPVEGuestPower":     func() (any, error) { return power.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{}) },
		"ProposePVEGuestSnapshot": func() (any, error) { return snap.ProposePVEGuestSnapshot(ctx, &pb.ProposePVEGuestSnapshotRequest{}) },
		"CommitPVEGuestSnapshot":  func() (any, error) { return snap.CommitPVEGuestSnapshot(ctx, &pb.CommitPVEGuestSnapshotRequest{}) },
	} {
		if _, err := call(); err != errNotConnected {
			t.Errorf("%s: %v, want errNotConnected", name, err)
		}
	}
}

// TestGuestActionsThroughRoleTable: the guest power and snapshot calls the
// UI makes reach the executor's handlers from the server role, through the
// server's lazyExecutor, executorclient and the real executor.MethodRoles
// (newProviderRig). The executor itself then refuses (no such remote, no
// approved permit); the role table never does. An admin-only call through
// the same rig is refused by the role table, so a regression to an
// admin-only commit fails here.
func TestGuestActionsThroughRoleTable(t *testing.T) {
	r := newProviderRig(t)
	lazy := new(lazyExecutor)
	lazy.c.Store(r.client)
	ctx := t.Context()
	digest := strings.Repeat("ab", 32)
	power := &pb.PVEGuestPowerTarget{RemoteId: "pve-a", Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	snap := &pb.PVEGuestSnapshotTarget{RemoteId: "pve-a", Kind: "qemu", Node: "pve1", Vmid: 101, Op: "create", Name: "before"}
	roleDenied := func(err error) bool {
		return status.Code(err) == codes.PermissionDenied && strings.Contains(status.Convert(err).Message(), "may not call")
	}
	for name, call := range map[string]func() error{
		"ProposePVEGuestPower": func() error {
			_, err := lazy.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: power})
			return err
		},
		"CommitPVEGuestPower": func() error {
			_, err := lazy.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: power, ExecutionDigest: digest})
			return err
		},
		"ProposePVEGuestSnapshot": func() error {
			_, err := lazy.ProposePVEGuestSnapshot(ctx, &pb.ProposePVEGuestSnapshotRequest{Target: snap})
			return err
		},
		"CommitPVEGuestSnapshot": func() error {
			_, err := lazy.CommitPVEGuestSnapshot(ctx, &pb.CommitPVEGuestSnapshotRequest{Target: snap, ExecutionDigest: digest})
			return err
		},
		"SubmitAssertion": func() error {
			_, err := lazy.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: digest, AssertionJson: []byte(`{}`)})
			return err
		},
	} {
		err := call()
		if err == nil {
			t.Errorf("%s: accepted without a remote or an approved permit", name)
			continue
		}
		if roleDenied(err) || status.Code(err) == codes.Unavailable {
			t.Errorf("%s: %v, want the executor's own refusal", name, err)
		}
	}
	// Control: the rig enforces the role table for the server role.
	if _, err := lazy.CommitPVERepin(ctx, &pb.CommitPVERepinRequest{}); !roleDenied(err) {
		t.Fatalf("admin-only CommitPVERepin: %v, want the role table's refusal", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// damageStoredCA puts the stored cluster CA of rm into the named state:
// "missing" (no vault entry), "mismatch" (another CA under the pin's id)
// or "corrupt" (bytes that are no certificate).
func damageStoredCA(t *testing.T, v *vault.Vault, rm executordb.PveRemote, how string) {
	t.Helper()
	id := pveCAVaultID(rm.RemoteID, rm.TrustPin)
	var err error
	switch how {
	case "missing":
		err = v.Delete(id)
	case "mismatch":
		_, err = v.Put(id, makeLeafOnlyCluster(t).ca.Raw, "test")
	case "corrupt":
		_, err = v.Put(id, []byte("not a certificate"), "test")
	default:
		t.Fatalf("unknown damage %q", how)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// requireRestoreHint fails unless err is a status whose message names the
// way out: a re-pin with --ca-file to the unchanged pin.
func requireRestoreHint(t *testing.T, err error) {
	t.Helper()
	msg := status.Convert(err).Message()
	for _, want := range []string{"nebula pve remote repin " + leafOnlyRemote, "--ca-file", "unchanged current pin"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not name the way out (missing %q)", msg, want)
		}
	}
}

// TestPveRepinToCurrentPinRestoresMissingOrUnusableStoredCA: a re-pin to
// the unchanged pin with a CA file whose fingerprint is that pin re-stores
// a missing or unusable stored CA after the normal approval; pin, trust
// generation, state and authority stay as they are.
func TestPveRepinToCurrentPinRestoresMissingOrUnusableStoredCA(t *testing.T) {
	for _, how := range []string{"missing", "mismatch", "corrupt"} {
		t.Run(how, func(t *testing.T) {
			e := newPveTestEnv(t)
			c := makeLeafOnlyCluster(t, labHosts...)
			e.probe.result = c.probe(labHosts...)
			rm, err := e.addWithCA(t, "nebulanetwork", pveEndpoints(labHosts...), fpHex(c.ca), c.caPEM)
			if err != nil {
				t.Fatal(err)
			}
			damageStoredCA(t, e.vault, rm, how)
			authorized := 0
			e.admin.AuthorizeRepin = func(_ context.Context, got executordb.PveRemote, in PveRepin) error {
				authorized++
				if got.TrustPin != rm.TrustPin || in.ConfirmedNewPin != rm.TrustPin {
					t.Fatalf("approval bound to %s/%s, want the current pin", got.TrustPin, in.ConfirmedNewPin)
				}
				return nil
			}
			revocations := len(e.revoke.reasons)

			// Without approval nothing is stored.
			authorize := e.admin.AuthorizeRepin
			e.admin.AuthorizeRepin = func(context.Context, executordb.PveRemote, PveRepin) error {
				return ErrPveApprovalRequired
			}
			if _, err := e.admin.Repin(context.Background(), PveRepin{RemoteID: "nebulanetwork", OldPin: rm.TrustPin, ConfirmedNewPin: rm.TrustPin, CAPEM: c.caPEM, By: "admin"}); !errors.Is(err, ErrPveApprovalRequired) {
				t.Fatalf("unapproved restore: %v", err)
			}
			if ca, _ := e.admin.StoredClusterCA(rm); ca != nil {
				t.Fatal("CA restored without approval")
			}
			e.admin.AuthorizeRepin = authorize

			got, err := e.admin.Repin(context.Background(), PveRepin{RemoteID: "nebulanetwork", OldPin: rm.TrustPin, ConfirmedNewPin: rm.TrustPin, CAPEM: c.caPEM, By: "admin"})
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
			if authorized != 1 {
				t.Fatalf("approval checked %d times, want 1", authorized)
			}
			if got.TrustPin != rm.TrustPin || got.TrustGeneration != rm.TrustGeneration || got.State != executordb.StateActive {
				t.Fatalf("remote after restore = %s gen %d %s; want unchanged", got.TrustPin, got.TrustGeneration, got.State)
			}
			stored, err := e.admin.StoredClusterCA(got)
			if err != nil || stored == nil || !bytes.Equal(stored.Raw, c.ca.Raw) {
				t.Fatalf("StoredClusterCA after restore = %v, %v; want the CA", stored, err)
			}
			if len(e.revoke.reasons) != revocations {
				t.Fatalf("restore revoked authority: %v", e.revoke.reasons[revocations:])
			}
		})
	}
}

// TestPveRepinToCurrentPinRefusedOtherwise: a re-pin to the unchanged pin
// is refused as before (ErrPvePinMismatch) unless it is a CA restore of an
// active cluster whose stored CA is missing or unusable and whose CA file
// is the pinned CA; nothing is approved or stored.
func TestPveRepinToCurrentPinRefusedOtherwise(t *testing.T) {
	for _, tc := range []struct {
		name    string
		damage  string // "" leaves the stored CA usable
		block   bool
		caPEM   func(c, other leafOnlyCluster) []byte
		wantErr error
	}{
		{"stored CA usable", "", false, func(c, _ leafOnlyCluster) []byte { return c.caPEM }, ErrPveCARestoreRefused},
		{"no CA file", "missing", false, func(leafOnlyCluster, leafOnlyCluster) []byte { return nil }, ErrPveCARestoreRefused},
		{"CA file of another CA", "missing", false, func(_, other leafOnlyCluster) []byte { return other.caPEM }, ErrPveLeafNotChained},
		{"remote blocked", "missing", true, func(c, _ leafOnlyCluster) []byte { return c.caPEM }, ErrPveCARestoreRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPveTestEnv(t)
			c := makeLeafOnlyCluster(t, labHosts...)
			other := makeLeafOnlyCluster(t)
			e.probe.result = c.probe(labHosts...)
			rm, err := e.addWithCA(t, "nebulanetwork", pveEndpoints(labHosts...), fpHex(c.ca), c.caPEM)
			if err != nil {
				t.Fatal(err)
			}
			if tc.damage != "" {
				damageStoredCA(t, e.vault, rm, tc.damage)
			}
			if tc.block {
				if rm, err = e.db.BlockRemote(rm.RemoteID, "trust failure", "test"); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := e.vault.List()
			e.admin.AuthorizeRepin = func(context.Context, executordb.PveRemote, PveRepin) error {
				t.Fatal("approval consulted for a refused restore")
				return nil
			}
			_, err = e.admin.Repin(context.Background(), PveRepin{RemoteID: "nebulanetwork", OldPin: rm.TrustPin, ConfirmedNewPin: rm.TrustPin, CAPEM: tc.caPEM(c, other), By: "admin"})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("restore = %v, want %v", err, tc.wantErr)
			}
			if errors.Is(err, ErrPveCARestoreRefused) && !errors.Is(err, ErrPvePinMismatch) {
				t.Fatalf("restore refusal %v does not wrap ErrPvePinMismatch", err)
			}
			got, _, _ := e.db.GetRemote("nebulanetwork")
			if got.TrustPin != rm.TrustPin || got.TrustGeneration != rm.TrustGeneration || got.State != rm.State {
				t.Fatalf("remote changed by a refused restore: %+v", got)
			}
			after, _ := e.vault.List()
			if len(after) != len(before) {
				t.Fatalf("vault changed by a refused restore: %v -> %v", before, after)
			}
			for i := range after {
				if after[i] != before[i] {
					t.Fatalf("vault changed by a refused restore: %v -> %v", before, after)
				}
			}
		})
	}
}

// TestPveLeafOnlyClusterWithoutStoredCAIsRefusedNotBlocked: without its
// stored CA a leaf-only cluster presents nothing to verify, so every
// connection is refused before a token is sent, but the remote is not
// blocked: it presented nothing different, and the way out (a CA restore
// by re-pin) needs it active.
func TestPveLeafOnlyClusterWithoutStoredCAIsRefusedNotBlocked(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
	rm := registerLeafOnlyCluster(t, e, c, pve.ep)
	damageStoredCA(t, e.svc.vault, rm, "missing")

	_, err := e.svc.pveReadTrust(context.Background(), rm)
	if !errors.Is(err, errPveStoredCA) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("pveReadTrust without stored CA = %v, want errPveStoredCA", err)
	}
	if _, _, _, _, err := e.svc.pveReaderConn(context.Background(), rm); !errors.Is(err, errPveStoredCA) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("pveReaderConn without stored CA = %v, want errPveStoredCA", err)
	}
	if _, _, _, err := e.svc.newPveMutationClient().conn(context.Background(), rm); !errors.Is(err, errPveStoredCA) || errors.Is(err, errPveReadTrust) {
		t.Fatalf("mutation conn without stored CA = %v, want errPveStoredCA", err)
	}
	e.approveNodesGrant("00000000-0000-4000-8000-0000000000e1", leafOnlyRemote)
	_, err = e.readNodesOf(leafOnlyRemote)
	if status.Code(err) != codes.Internal {
		t.Fatalf("ReadPVE without stored CA = %v, want Internal", err)
	}
	requireRestoreHint(t, err)
	e.requireActive(leafOnlyRemote)
	if n := pve.requests.Load(); n != 0 {
		t.Fatalf("%d authenticated requests without a stored CA", n)
	}
}

// TestPveStoredCARestoredByRepinRPC drives the way out the read error
// names: ProposePVERepin, approval and CommitPVERepin to the unchanged pin
// with the CA file restore a missing or unusable stored CA, and the next
// read after a restart succeeds with pin and generation unchanged.
func TestPveStoredCARestoredByRepinRPC(t *testing.T) {
	for _, how := range []string{"missing", "mismatch"} {
		t.Run(how, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindCluster)
			ctx := context.Background()
			c := makeLeafOnlyCluster(t, "127.0.0.1")
			pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
			rm := registerLeafOnlyCluster(t, e, c, pve.ep)
			damageStoredCA(t, e.svc.vault, rm, how)
			pin := rm.TrustPin

			e.approveNodesGrant("00000000-0000-4000-8000-0000000000d1", leafOnlyRemote)
			_, err := e.readNodesOf(leafOnlyRemote)
			if status.Code(err) != codes.Internal {
				t.Fatalf("ReadPVE with %s stored CA = %v, want Internal", how, err)
			}
			requireRestoreHint(t, err)
			e.requireActive(leafOnlyRemote)

			proposed, err := e.svc.ProposePVERepin(ctx, &pb.ProposePVERepinRequest{RemoteId: leafOnlyRemote, OldPin: pin, ConfirmedNewPin: pin, CaPem: c.caPEM})
			if err != nil {
				t.Fatalf("ProposePVERepin to the current pin: %v", err)
			}
			// Commit before approval stores nothing.
			if _, err := e.svc.CommitPVERepin(ctx, &pb.CommitPVERepinRequest{RemoteId: leafOnlyRemote, OldPin: pin, ConfirmedNewPin: pin,
				ExecutionDigest: proposed.GetPermit().ExecutionDigest, CaPem: c.caPEM}); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("unapproved CommitPVERepin = %v, want FailedPrecondition", err)
			}
			if ca, _ := e.svc.pveAdmin().StoredClusterCA(rm); ca != nil {
				t.Fatal("CA restored without approval")
			}
			d, err := canonical.ParseDigest(proposed.GetPermit().ExecutionDigest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.auth.ApproveCLI(d, 0, "personal-admin"); err != nil {
				t.Fatal(err)
			}
			restored, err := e.svc.CommitPVERepin(ctx, &pb.CommitPVERepinRequest{RemoteId: leafOnlyRemote, OldPin: pin, ConfirmedNewPin: pin,
				ExecutionDigest: proposed.GetPermit().ExecutionDigest, CaPem: c.caPEM})
			if err != nil {
				t.Fatalf("CommitPVERepin to the current pin: %v", err)
			}
			if restored.GetRemote().GetTrustPin() != pin || restored.GetRemote().GetTrustGeneration() != rm.TrustGeneration {
				t.Fatalf("remote after restore = %v; want pin and generation unchanged", restored.GetRemote())
			}
			// The approval is single-use.
			if _, err := e.svc.CommitPVERepin(ctx, &pb.CommitPVERepinRequest{RemoteId: leafOnlyRemote, OldPin: pin, ConfirmedNewPin: pin,
				ExecutionDigest: proposed.GetPermit().ExecutionDigest, CaPem: c.caPEM}); err == nil {
				t.Fatal("restore approval replayed")
			}

			dropPveCACache(e.svc)
			e.clock.Add(2 * time.Minute) // past the provider read interval
			e.approveNodesGrant("00000000-0000-4000-8000-0000000000d2", leafOnlyRemote)
			if _, err := e.readNodesOf(leafOnlyRemote); err != nil {
				t.Fatalf("ReadPVE after restore and restart: %v", err)
			}
			e.requireActive(leafOnlyRemote)
		})
	}
}

// TestPveRepinRPCToCurrentPinRefusedWhenStoredCAUsable: with a usable
// stored CA, a re-pin to the unchanged pin is refused at proposal with a
// message that says why, and no approval is created.
func TestPveRepinRPCToCurrentPinRefusedWhenStoredCAUsable(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
	rm := registerLeafOnlyCluster(t, e, c, pve.ep)
	_, err := e.svc.ProposePVERepin(context.Background(), &pb.ProposePVERepinRequest{RemoteId: leafOnlyRemote, OldPin: rm.TrustPin, ConfirmedNewPin: rm.TrustPin, CaPem: c.caPEM})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ProposePVERepin to the current pin with a usable CA = %v, want FailedPrecondition", err)
	}
	if msg := status.Convert(err).Message(); !strings.Contains(msg, "missing or unusable") {
		t.Fatalf("refusal %q does not say when a re-pin to the current pin is accepted", msg)
	}
}

// TestPveSeedFailureNamesTheWayOut: an add or re-pin whose stored CA
// cannot be loaded right after names the restore.
func TestPveSeedFailureNamesTheWayOut(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	rm := executordb.PveRemote{RemoteID: leafOnlyRemote, Kind: pvecontract.KindCluster, TrustPin: fpHex(c.ca)}
	damageStoredCA(t, e.svc.vault, rm, "corrupt")
	err := e.svc.seedPveClusterCA(e.svc.pveAdmin(), rm)
	if status.Code(err) != codes.Internal {
		t.Fatalf("seed with corrupt stored CA = %v, want Internal", err)
	}
	requireRestoreHint(t, err)
}

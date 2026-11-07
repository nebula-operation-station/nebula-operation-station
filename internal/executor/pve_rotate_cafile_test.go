// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// storedCADamages are the states of a stored cluster CA that is missing
// or unusable (damageStoredCA).
var storedCADamages = []string{"missing", "mismatch", "corrupt"}

// TestPveRotateWithMissingOrUnusableStoredCAIsNotATrustFailure: token
// rotation on a leaf-only cluster whose stored CA is missing, does not
// match the pin or is corrupt refuses before any token is sent, with
// errPveStoredCA, like read, mutation and repin. It is no trust failure:
// the remote stays active and no grant is revoked, so the documented way
// out (a re-pin to the unchanged pin, which needs an active remote) stays
// open.
func TestPveRotateWithMissingOrUnusableStoredCAIsNotATrustFailure(t *testing.T) {
	for _, how := range storedCADamages {
		t.Run(how, func(t *testing.T) {
			e := newPveTestEnv(t)
			c := makeLeafOnlyCluster(t, labHosts...)
			e.probe.result = c.probe(labHosts...)
			rm, err := e.addWithCA(t, "nebulanetwork", pveEndpoints(labHosts...), fpHex(c.ca), c.caPEM)
			if err != nil {
				t.Fatal(err)
			}
			damageStoredCA(t, e.vault, rm, how)
			calls, revokes := e.validate.calls, len(e.revoke.reasons)

			_, err = e.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: "nebulanetwork", Purpose: PvePurposeRead, Token: []byte("nosread@pve!tok2=okvalue"), By: "admin"})
			if !errors.Is(err, errPveStoredCA) {
				t.Fatalf("rotate with %s stored CA = %v, want errPveStoredCA", how, err)
			}
			// Not reported as a trust or CA-file failure.
			for _, wrong := range []error{ErrPvePinMismatch, ErrPveSuppliedCA, ErrPveClusterNoCA} {
				if errors.Is(err, wrong) {
					t.Fatalf("rotate with %s stored CA = %v; must not wrap %v", how, err, wrong)
				}
			}
			if e.validate.calls != calls {
				t.Fatal("token sent without a usable stored CA")
			}
			if len(e.revoke.reasons) != revokes {
				t.Fatalf("grants revoked: %v", e.revoke.reasons[revokes:])
			}
			got, _, _ := e.db.GetRemote("nebulanetwork")
			if got.State != executordb.StateActive || got.TrustPin != rm.TrustPin || got.TrustGeneration != rm.TrustGeneration {
				t.Fatalf("remote after refused rotation = %s pin %s gen %d; want unchanged and active", got.State, got.TrustPin, got.TrustGeneration)
			}
			if got.Credentials.ReadVersion != rm.Credentials.ReadVersion {
				t.Fatalf("read version = %d, want %d", got.Credentials.ReadVersion, rm.Credentials.ReadVersion)
			}
		})
	}
}

// TestPveRotateRPCWithMissingOrUnusableStoredCANamesTheWayOut: over the
// RPC, the refused rotation returns the same message as read (it names
// `repin <id> --ca-file`), leaves the remote active and unfenced, and
// keeps its grants: once the CA is restored, a grant approved before the
// rotation still reads.
func TestPveRotateRPCWithMissingOrUnusableStoredCANamesTheWayOut(t *testing.T) {
	for _, how := range storedCADamages {
		t.Run(how, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindCluster)
			c := makeLeafOnlyCluster(t, "127.0.0.1")
			pve := newSwitchableLeafPVE(t, c.tls["127.0.0.1"])
			rm := registerLeafOnlyCluster(t, e, c, pve.ep)
			e.approveNodesGrant("00000000-0000-4000-8000-0000000000f1", leafOnlyRemote)
			damageStoredCA(t, e.svc.vault, rm, how)

			_, err := e.svc.RotatePVEToken(context.Background(), &pb.RotatePVETokenRequest{RemoteId: leafOnlyRemote, Purpose: PvePurposeRead, Token: []byte("nosread@pve!rot2=new-token-value")})
			if status.Code(err) != codes.Internal {
				t.Fatalf("RotatePVEToken with %s stored CA = %v, want Internal", how, err)
			}
			requireRestoreHint(t, err)
			e.requireActive(leafOnlyRemote)
			if n := pve.requests.Load(); n != 0 {
				t.Fatalf("%d authenticated requests without a usable stored CA", n)
			}

			// Restore the CA: the grant approved before the rotation is
			// still valid.
			if _, err := (&PveAdmin{Vault: e.svc.vault}).storeClusterCA(leafOnlyRemote, rm.TrustPin, c.ca, "test"); err != nil {
				t.Fatal(err)
			}
			dropPveCACache(e.svc)
			e.clock.Add(2 * time.Minute)
			if _, err := e.readNodesOf(leafOnlyRemote); err != nil {
				t.Fatalf("ReadPVE with the grant approved before the refused rotation: %v", err)
			}
		})
	}
}

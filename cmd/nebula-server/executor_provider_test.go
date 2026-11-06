// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// providerRig is the real path of a provider lease on an install: a real
// executor Service on a Unix socket, guarded by executor.MethodRoles for a
// peer holding only the server role, reached through the server's own
// lazyExecutor and executorclient. No fake lister takes part, so a call the
// server role may not make fails here as it does in production.
type providerRig struct {
	svc    *executor.Service // in-process, for what the local admin does
	db     *executordb.DB
	client *executorclient.Client
	ops    *executions.Service
}

func newProviderRig(t *testing.T) *providerRig {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: "provider.test", Origins: []string{"https://provider.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	// Hardened mode: a read grant is approved by the local admin, which
	// needs no security key in this test.
	auth, err := permit.New(permit.Options{Mode: permit.ModeHardened, Verifier: verifier, Store: db, RiskPolicy: risk, Schedules: db})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "provider.test", Origins: []string{"https://provider.test"}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(auth, keyring.New(filepath.Join(dir, "keys")), db, reg, log)

	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}, executor.MethodRoles())
	sockDir, err := os.MkdirTemp("", "nos")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: sock, Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	srv := executor.NewGRPCServer(svc, policy, log)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop(); _ = db.Close() })

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := executorclient.New(ctx, executorclient.Options{SocketPath: sock, ExecutorUser: me.Username})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	lazy := new(lazyExecutor)
	lazy.c.Store(client)
	return &providerRig{svc: svc, db: db, client: client, ops: executions.New(t.Context(), lazy, nil, nil, log)}
}

// addRemote registers a remote with a valid pin at trust generation 1.
func (r *providerRig) addRemote(t *testing.T, id string, pinChar string, creds executordb.PveRemoteCredentials) {
	t.Helper()
	if _, err := r.db.AddRemote(pvecontract.Remote{RemoteID: id, Name: id, Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "pve.lab", Port: 8006}}, TrustPin: strings.Repeat(pinChar, 64), TrustGeneration: 1}, creds, "test"); err != nil {
		t.Fatal(err)
	}
}

// readCreds is a valid read credential of remote id at the given version.
func readCreds(id string, version int64) executordb.PveRemoteCredentials {
	return executordb.PveRemoteCredentials{ReadRef: executor.PveVaultID(id, executor.PvePurposeRead), ReadVersion: version}
}

// adminRemote is the registry entry as the admin listing shows it: what the
// server froze before ListPVERemotes replaced that listing.
func (r *providerRig) adminRemote(t *testing.T, id string) *pb.PVEAdminRemote {
	t.Helper()
	got, err := r.svc.ListPVEAdminRemotes(t.Context(), &pb.ListPVEAdminRemotesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rm := range got.GetRemotes() {
		if rm.GetRemoteId() == id {
			return rm
		}
	}
	t.Fatalf("remote %s is not registered", id)
	return nil
}

func (r *providerRig) pendingGrants(t *testing.T) int {
	t.Helper()
	got, err := r.svc.ListPendingReadGrants(t.Context(), &pb.ListPendingReadGrantsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return len(got.GetGrants())
}

// checkFrozen compares a proposed remote with the admin metadata.
func checkFrozen(t *testing.T, got executions.ReadGrantPreviewProvider, want *pb.PVEAdminRemote) {
	t.Helper()
	if got.RemoteID != want.GetRemoteId() || got.TrustPin != want.GetTrustPin() ||
		got.TrustGeneration != want.GetTrustGeneration() || got.CredentialVersion != want.GetReadVersion() {
		t.Fatalf("frozen remote %+v differs from the registry entry %v", got, want)
	}
}

// proposeRead proposes a provider read lease over remotes.
func (r *providerRig) proposeRead(ctx context.Context, remotes ...string) (executions.ReadGrantPreview, error) {
	return r.ops.ProposeProviderReadGrant(ctx, "alice", executions.ProviderReadGrantRequest{RemoteIDs: remotes, Days: executions.ReadGrantShortDays})
}

// TestProviderReadLeaseThroughRoleTable: a provider read lease reaches the
// executor from the server role and freezes the same binding data the admin
// listing reports. A server that calls an admin-only RPC fails here.
func TestProviderReadLeaseThroughRoleTable(t *testing.T) {
	r := newProviderRig(t)
	r.addRemote(t, "pve-a", "a", readCreds("pve-a", 7))
	r.addRemote(t, "pve-b", "b", readCreds("pve-b", 1))
	v, err := r.proposeRead(t.Context(), "pve-a", "pve-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Providers) != 2 {
		t.Fatalf("providers %+v, want 2", v.Providers)
	}
	checkFrozen(t, v.Providers[0], r.adminRemote(t, "pve-a"))
	checkFrozen(t, v.Providers[1], r.adminRemote(t, "pve-b"))
	if n := r.pendingGrants(t); n != 1 {
		t.Fatalf("%d pending grants, want the proposal", n)
	}
}

// providerInventory is an imported PVE inventory holding node pve1.
type providerInventory struct{}

func (providerInventory) HasRemote(context.Context, string) (bool, error) { return true, nil }

func (providerInventory) HasNode(_ context.Context, _, node string) (bool, error) {
	return node == "pve1", nil
}

func (providerInventory) ActiveGuests(context.Context, string, uint64, int) ([]executions.TelemetryGuest, error) {
	return nil, nil
}

// TestProviderTelemetryLeaseThroughRoleTable is the telemetry form of
// TestProviderReadLeaseThroughRoleTable.
func TestProviderTelemetryLeaseThroughRoleTable(t *testing.T) {
	r := newProviderRig(t)
	r.addRemote(t, "pve-a", "a", readCreds("pve-a", 7))
	v, err := r.ops.ProposeProviderTelemetryGrant(t.Context(), "alice", executions.ProviderTelemetryGrantRequest{
		RemoteID: "pve-a", Days: executions.ReadGrantShortDays,
		Targets: []executions.ProviderMetricsSelection{{Node: "pve1", Kind: permit.MetricsKindNode}},
	}, providerInventory{})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Providers) != 1 {
		t.Fatalf("providers %+v, want 1", v.Providers)
	}
	checkFrozen(t, v.Providers[0], r.adminRemote(t, "pve-a"))
}

// TestProviderLeaseRefusesRegistryStates: what ListPVERemotes really reports
// for an unusable remote is refused before anything is proposed, including
// a read credential whose reference ReadPVE would not accept.
func TestProviderLeaseRefusesRegistryStates(t *testing.T) {
	r := newProviderRig(t)
	r.addRemote(t, "pve-blocked", "a", readCreds("pve-blocked", 4))
	if _, err := r.db.BlockRemote("pve-blocked", "pin mismatch", "test"); err != nil {
		t.Fatal(err)
	}
	r.addRemote(t, "pve-removed", "b", readCreds("pve-removed", 4))
	if _, err := r.db.RemoveRemote("pve-removed", "test"); err != nil {
		t.Fatal(err)
	}
	r.addRemote(t, "pve-noread", "c", executordb.PveRemoteCredentials{})
	r.addRemote(t, "pve-foreign", "d", readCreds("pve-other", 4))
	for _, id := range []string{"pve-blocked", "pve-removed", "pve-noread", "pve-foreign", "pve-unknown"} {
		t.Run(id, func(t *testing.T) {
			_, err := r.proposeRead(t.Context(), id)
			var ie *executions.ReadGrantInputError
			if !errors.As(err, &ie) {
				t.Fatalf("err = %v, want an input error", err)
			}
			if n := r.pendingGrants(t); n != 0 {
				t.Fatalf("%d proposals reached the executor", n)
			}
		})
	}
}

// TestProviderBindingThroughRoleTable: the lease list compares a frozen
// remote with the registry over the server role, so it reports current
// until the read token is rotated, not unknown.
func TestProviderBindingThroughRoleTable(t *testing.T) {
	r := newProviderRig(t)
	r.addRemote(t, "pve-a", "a", readCreds("pve-a", 7))
	v, err := r.proposeRead(t.Context(), "pve-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ApproveReadGrantCLI(t.Context(), &pb.ApproveReadGrantCLIRequest{GrantDigest: v.Digest}); err != nil {
		t.Fatal(err)
	}
	binding := func() string {
		t.Helper()
		views, err := r.ops.ReadGrants(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(views) != 1 || len(views[0].Providers) != 1 {
			t.Fatalf("views %+v, want the one lease", views)
		}
		return views[0].Providers[0].Binding
	}
	if got := binding(); got != executions.ProviderBindingCurrent {
		t.Fatalf("binding %q, want %q", got, executions.ProviderBindingCurrent)
	}
	if _, err := r.db.SetRemoteCredentials("pve-a", readCreds("pve-a", 8), "test"); err != nil {
		t.Fatal(err)
	}
	if got := binding(); got != executions.ProviderBindingStale {
		t.Fatalf("binding after rotation %q, want %q", got, executions.ProviderBindingStale)
	}
}

// TestServerRoleCannotReadAdminRemotes proves the rig enforces the role
// table, and that the fix did not widen it: the admin listing, which names
// credential references, stays closed to the server.
func TestServerRoleCannotReadAdminRemotes(t *testing.T) {
	r := newProviderRig(t)
	if _, err := r.client.ListPVEAdminRemotes(t.Context(), &pb.ListPVEAdminRemotesRequest{}); !errors.Is(err, executorclient.ErrPermissionDenied) {
		t.Fatalf("server ListPVEAdminRemotes: err = %v, want ErrPermissionDenied", err)
	}
}

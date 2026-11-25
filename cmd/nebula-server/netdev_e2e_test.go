// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// The network device chain of ADR 0010 (A1-9, the required end-to-end test),
// over the real parts: an executor Service on Unix sockets with one peer
// role per socket, the collector's real Poller with the real executor client,
// a spool in a temporary directory, the server's importer and pages over
// loopback HTTP. No device is dialed and no network is used: the executor
// registry rows are written directly, and the device read itself is still
// Unimplemented (ND-14), so the chain ends at the spool.

// netdevE2ERig is the executor of the chain. The test runs as one OS user, so
// each socket's peer policy names that user with one role only; a call the
// role may not make is refused as it is in production.
type netdevE2ERig struct {
	db        *executordb.DB
	admin     *executorclient.Client
	server    *executorclient.Client
	collector *executorclient.Client
}

// newNetDevE2ERig starts an executor Service in hardened mode (a read lease is
// approved by the local admin CLI path, which needs no security key here) and
// one gRPC server per peer role on its own socket.
func newNetDevE2ERig(t *testing.T) *netdevE2ERig {
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
	t.Cleanup(func() { _ = db.Close() })
	const rpID = "netdev.test"
	origins := []string{"https://netdev.test"}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: origins, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Mode: permit.ModeHardened, Verifier: verifier, Store: db, RiskPolicy: risk, Leases: db, Schedules: db})
	if err != nil {
		t.Fatal(err)
	}
	// A new authority starts with reads paused. The local credential unlock
	// resumes them; this test has no keyring unlock, so it takes the resume
	// step itself (the same call the unlock makes).
	if err := auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: rpID, Origins: origins}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(auth, keyring.New(filepath.Join(dir, "keys")), db, reg, log)

	sockDir, err := os.MkdirTemp("", "nos")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	serve := func(name string, role peercred.Role) string {
		t.Helper()
		sock := filepath.Join(sockDir, name+".sock")
		lis, err := peercred.Listen(peercred.ListenOptions{Path: sock, Mode: 0o600})
		if err != nil {
			t.Fatal(err)
		}
		policy := peercred.NewPolicy(map[uint32][]peercred.Role{uid: {role}}, executor.MethodRoles())
		srv := executor.NewGRPCServer(svc, policy, log)
		go func() { _ = srv.Serve(lis) }()
		t.Cleanup(srv.Stop)
		return sock
	}
	adminSock := serve("admin", peercred.RoleAdmin)
	serverSock := serve("server", peercred.RoleServer)
	collectorSock := serve("collector", peercred.RoleNetDevCollector)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	r := &netdevE2ERig{db: db}
	opts := func(sock string) executorclient.Options {
		return executorclient.Options{SocketPath: sock, ExecutorUser: me.Username}
	}
	if r.admin, err = executorclient.New(ctx, opts(adminSock)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.admin.Close() })
	if r.server, err = executorclient.New(ctx, opts(serverSock)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.server.Close() })
	if r.collector, err = executorclient.NewNetDevCollector(ctx, opts(collectorSock)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.collector.Close() })
	return r
}

// addNetDevice writes a live CBS device with a read credential of version 1
// into the executor registry, as the admin's register and credential steps
// would leave it. The rows are written directly: nothing dials the device.
func (r *netdevE2ERig) addNetDevice(t *testing.T, id, label, endpoint, pinChar string) {
	t.Helper()
	ref := "netdev-" + id + "-rc"
	if _, err := r.db.InsertNetDevice(executordb.NetDevice{
		ID: id, Family: netdevcontract.FamilyCBS, Label: label, EndpointIP: endpoint, Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, PinValue: strings.Repeat(pinChar, 64),
		CredentialRef: ref, DigestKeyRef: "netdev-" + id + "-dk", FingerprintKeyRef: "netdev-" + id + "-fk",
	}); err != nil {
		t.Fatalf("register device %s: %v", id, err)
	}
	// The value is never opened on the read path: a read checks the version
	// only. The lengths are the sizes the vault's CHECK constraint accepts.
	if err := r.db.PutSecret(executordb.VaultSecret{ID: ref, Version: 1, WrappedDEK: make([]byte, 72), Sealed: make([]byte, 64), UpdatedAt: time.Now(), UpdatedBy: "test"}); err != nil {
		t.Fatalf("credential of device %s: %v", id, err)
	}
}

// buildLease builds the device read lease of id the way `nebula netdev lease`
// does: from the executor's own device row, for the given reads.
func (r *netdevE2ERig) buildLease(t *testing.T, id string, reads []string) executor.NetDevLease {
	t.Helper()
	ctx := t.Context()
	list, err := r.admin.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	var info *pb.NetDeviceInfo
	for _, d := range list.GetDevices() {
		if d.GetDeviceId() == id {
			info = d
		}
	}
	if info == nil {
		t.Fatalf("device %s is not in the executor's list", id)
	}
	lease, err := executor.NetDevLeaseFromInfo(info, executor.NetDevLeaseRequest{DeviceID: id, Reads: reads, Lifetime: 7 * 24 * time.Hour}, time.Now())
	if err != nil {
		t.Fatalf("lease for %s: %v", id, err)
	}
	return lease
}

// proposeAsAdmin proposes lease as the local admin and checks it is pending
// with exactly the typed document, as the CLI does before it asks for "yes".
func (r *netdevE2ERig) proposeAsAdmin(t *testing.T, lease executor.NetDevLease) {
	t.Helper()
	ctx := t.Context()
	got, err := r.admin.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: lease.JSON})
	if err != nil {
		t.Fatalf("admin propose: %v", err)
	}
	if got.GetGrantDigest() != lease.Digest {
		t.Fatalf("digest = %s, want %s", got.GetGrantDigest(), lease.Digest)
	}
	if !r.isPending(t, lease) {
		t.Fatal("the admin's lease is not pending")
	}
}

// isPending reports whether lease is in the executor's pending list with the
// byte-identical document.
func (r *netdevE2ERig) isPending(t *testing.T, lease executor.NetDevLease) bool {
	t.Helper()
	pending, err := r.admin.ListPendingReadGrants(t.Context(), &pb.ListPendingReadGrantsRequest{})
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	for _, g := range pending.GetGrants() {
		if g.GetGrantDigest() == lease.Digest {
			return bytes.Equal(g.GetCanonicalGrant(), lease.JSON)
		}
	}
	return false
}

// approveAsAdmin approves the pending lease on the executor CLI path, the
// step after the operator types "yes".
func (r *netdevE2ERig) approveAsAdmin(t *testing.T, lease executor.NetDevLease) {
	t.Helper()
	if _, err := r.admin.ApproveReadGrantCLI(t.Context(), &pb.ApproveReadGrantCLIRequest{GrantDigest: lease.Digest}); err != nil {
		t.Fatalf("admin approve: %v", err)
	}
}

// discardLog is the logger of the chain's parts, whose output the test does not
// read.
func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// runCollectorCycle runs one cycle of the collector's real Poller with the
// real executor client, spooling into root on the test clock, and waits for
// the device workers.
func runCollectorCycle(t *testing.T, r *netdevE2ERig, e *netdevTestEnv) netdevcollect.CycleReport {
	t.Helper()
	p := &netdevcollect.Poller{
		Client:   r.collector,
		Spool:    &netdevcollect.Spool{Dir: e.root, Now: e.clock},
		Now:      e.clock,
		Rand:     func() float64 { return 0.5 },
		Log:      discardLog(),
		Interval: time.Minute,
	}
	rep, err := p.Cycle(t.Context())
	if err != nil {
		t.Fatalf("collector cycle: %v", err)
	}
	p.Wait()
	return rep
}

// spoolNames lists the spool's file names.
func spoolNames(t *testing.T, root string) []string {
	t.Helper()
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	names := make([]string, 0, len(ents))
	for _, ent := range ents {
		names = append(names, ent.Name())
	}
	return names
}

// TestNetDevChainEndToEndToPage: an approved lease for one device, one
// collector cycle, one server import and the HTTP page. The active device
// shows with its escaped label and as reported by the collector; the blocked
// device does not show; the page is for admins only and sends a CSP header.
func TestNetDevChainEndToEndToPage(t *testing.T) {
	r := newNetDevE2ERig(t)
	r.addNetDevice(t, "sw1", `Core <i>&"sw"</i>`, "10.20.30.11", "a")
	r.addNetDevice(t, "sw2", "Hidden switch", "10.20.30.12", "b")
	if _, err := r.db.BlockNetDevice("sw2", "maintenance"); err != nil {
		t.Fatalf("block sw2: %v", err)
	}
	lease := r.buildLease(t, "sw1", []string{"cbs_version"})
	r.proposeAsAdmin(t, lease)
	r.approveAsAdmin(t, lease)

	e := newNetDevTestEnv(t)
	// The read is authorized by the lease and reaches the device step, which
	// is not implemented yet (ND-14): the answer is Unimplemented.
	_, err := r.collector.ReadNetDeviceByID(t.Context(), "sw1", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("read of a leased device = %v, want Unimplemented", err)
	}

	rep := runCollectorCycle(t, r, e)
	if rep.Devices != 2 || rep.MetadataWritten != 1 {
		t.Fatalf("cycle report = %+v, want two listed devices and one metadata record", rep)
	}
	// Only the metadata record of the active device is spooled: the read
	// ended Unimplemented and wrote nothing, and the blocked device has no record.
	names := spoolNames(t, e.root)
	if len(names) != rep.MetadataWritten {
		t.Fatalf("spool holds %d files, want the %d metadata record(s): %v", len(names), rep.MetadataWritten, names)
	}
	for _, n := range names {
		if !strings.Contains(n, "-"+netdevcollect.ReadDeviceMetadata+"-") {
			t.Fatalf("spool file %s is not a metadata record", n)
		}
	}

	imp, err := e.imp.imp.Run(t.Context())
	if err != nil {
		t.Fatalf("server import: %v", err)
	}
	if imp.MetadataWritten != 1 || imp.Kept != 0 {
		t.Fatalf("import report = %+v, want one metadata row written", imp)
	}

	h := newNetDevHTTP(t, e)
	list := h.get("/netdev", h.admin)
	if list.Code != http.StatusOK {
		t.Fatalf("GET /netdev as admin = %d, want 200", list.Code)
	}
	body := list.Body.String()
	if !strings.Contains(body, `Core &lt;i&gt;&amp;&#34;sw&#34;&lt;/i&gt;`) {
		t.Fatal("list does not show the active device with its escaped label")
	}
	if !strings.Contains(body, netdevReportedBadge) {
		t.Fatal("list does not mark the active device as reported by the collector")
	}
	if strings.Contains(body, "<i>&") || strings.Contains(body, "Hidden switch") {
		t.Fatal("list shows raw device text or the blocked device")
	}
	if csp := list.Header().Get("Content-Security-Policy"); csp == "" {
		t.Fatal("GET /netdev sends no Content-Security-Policy header")
	}

	detail := h.get("/netdev/sw1", h.admin)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), netdevReportedBadge) {
		t.Fatalf("GET /netdev/sw1 = %d, want 200 marked as reported by the collector", detail.Code)
	}
	for _, path := range []string{"/netdev", "/netdev/sw1"} {
		if rec := h.get(path, h.user); rec.Code != http.StatusForbidden {
			t.Errorf("GET %s as a non-admin = %d, want 403", path, rec.Code)
		}
	}
}

// TestNetDevLeaseRulesOnRealPath: the device lease rule on the real path. A
// read without an approved lease is refused before any device access; the
// server role may not propose a device lease, and its CommitReadGrant for the
// admin's pending digest is refused in hardened mode; after the admin approves,
// the leased read reaches the Unimplemented step and a read outside the lease
// is refused.
func TestNetDevLeaseRulesOnRealPath(t *testing.T) {
	r := newNetDevE2ERig(t)
	r.addNetDevice(t, "sw1", "Core switch", "10.20.30.11", "a")
	ctx := t.Context()

	_, err := r.collector.ReadNetDeviceByID(ctx, "sw1", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("read without a lease = %v, want PermissionDenied", err)
	}

	lease := r.buildLease(t, "sw1", []string{"cbs_version"})
	_, err = r.server.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: lease.JSON})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server proposal of a device lease = %v, want PermissionDenied", err)
	}
	if r.isPending(t, lease) {
		t.Fatal("a refused server proposal left a pending lease")
	}

	r.proposeAsAdmin(t, lease)
	if _, err := r.server.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: lease.Digest, AssertionJson: []byte(`{"id":"x"}`)}); err == nil {
		t.Fatal("server commit of the admin's device lease succeeded, want it refused")
	}
	if !r.isPending(t, lease) {
		t.Fatal("a refused server commit changed the pending lease")
	}

	r.approveAsAdmin(t, lease)
	if _, err := r.collector.ReadNetDeviceByID(ctx, "sw1", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); status.Code(err) != codes.Unimplemented {
		t.Fatalf("leased read = %v, want Unimplemented (device reads are ND-14)", err)
	}
	if _, err := r.collector.ReadNetDeviceByID(ctx, "sw1", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("read outside the lease = %v, want PermissionDenied", err)
	}
}

// TestNetDevHandPlacedLowerTrustGenerationKeepsRow: a spool record with a
// trust generation below the device's current one, placed by hand after the
// collector's own record, does not change the imported row.
func TestNetDevHandPlacedLowerTrustGenerationKeepsRow(t *testing.T) {
	r := newNetDevE2ERig(t)
	r.addNetDevice(t, "sw1", "Core switch", "10.20.30.11", "a")
	if _, err := r.db.BumpTrustGeneration("sw1", strings.Repeat("c", 64)); err != nil {
		t.Fatalf("bump trust generation: %v", err)
	}
	e := newNetDevTestEnv(t)
	if rep := runCollectorCycle(t, r, e); rep.MetadataWritten != 1 {
		t.Fatalf("cycle report = %+v, want one metadata record", rep)
	}
	if _, err := e.imp.imp.Run(t.Context()); err != nil {
		t.Fatalf("import: %v", err)
	}

	e.publish(t, "sw1", netdevcollect.ReadDeviceMetadata, 1,
		`{"device_id":"sw1","family":"cbs","label":"Evil switch","trust_generation":1,"blocked":false,"block_reason":""}`)
	if _, err := e.imp.imp.Run(t.Context()); err != nil {
		t.Fatalf("second import: %v", err)
	}
	d, err := netdevinventory.NewWithNow(e.db, e.clock).GetDevice(t.Context(), "sw1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.Label != "Core switch" || d.TrustGeneration != 2 {
		t.Fatalf("row = label %q generation %d, want the collector's row unchanged", d.Label, d.TrustGeneration)
	}
}

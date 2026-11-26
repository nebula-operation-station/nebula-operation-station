// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// The network device chain of ADR 0010 (A1-9, the required end-to-end test),
// over the real parts: an executor Service on Unix sockets with one peer
// role per socket, the collector's real Poller with the real executor client,
// a spool in a temporary directory, and the server started by runServer with
// its importer and its pages served over loopback HTTP. No device is dialed
// and no network is used: the executor registry rows are written directly,
// and the device read itself is still Unimplemented (ND-14), so the collector
// stops at the spool.

// netdevE2EOrigin is the public origin of the test server.
const netdevE2EOrigin = "https://netdev.example.test"

// netdevE2ECSP is the Content-Security-Policy every server page sends
// (internal/web/middleware, valueCSP). The test pins it exactly, so a weaker
// policy fails here too.
const netdevE2ECSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// netdevE2ERig is the executor of the chain. The test runs as one OS user, so
// each socket's peer policy names that user with one role only; a call the
// role may not make is refused as it is in production.
type netdevE2ERig struct {
	db         *executordb.DB
	verifier   *webauthnverify.Verifier
	admin      *executorclient.Client
	server     *executorclient.Client
	collector  *executorclient.Client
	serverSock string
}

// registerWebAuthnCredential makes id a credential the executor knows, so a web
// session of that credential is still valid (the server checks it with
// CheckCredential). The key is not used: the session tests never sign.
func (r *netdevE2ERig) registerWebAuthnCredential(t *testing.T, id []byte) {
	t.Helper()
	if err := r.verifier.Add(webauthnverify.Credential{ID: id, PublicKey: []byte{0x01}}); err != nil {
		t.Fatalf("register credential: %v", err)
	}
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
	r := &netdevE2ERig{db: db, verifier: verifier, serverSock: serverSock}
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

// runCollectorCycle runs one cycle of the collector's real Poller with the
// real executor client, spooling into root on the clock now, and waits for
// the device workers. It returns the cycle report and the debug log of the
// cycle: one line per read, spooled or failed with its read and error class.
func runCollectorCycle(t *testing.T, r *netdevE2ERig, root string, now func() time.Time) (netdevcollect.CycleReport, string) {
	t.Helper()
	var logs syncBuffer
	p := &netdevcollect.Poller{
		Client:   r.collector,
		Spool:    &netdevcollect.Spool{Dir: root, Now: now},
		Now:      now,
		Rand:     func() float64 { return 0.5 },
		Log:      slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Interval: time.Minute,
	}
	rep, err := p.Cycle(t.Context())
	if err != nil {
		t.Fatalf("collector cycle: %v", err)
	}
	p.Wait()
	return rep, logs.String()
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

// newNetDevE2ESpool creates the spool directory the collector writes to, in a
// temporary directory of the test.
func newNetDevE2ESpool(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "netdev")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create spool: %v", err)
	}
	return root
}

// setNetDevSpoolRoot points the importer that runServer starts at root until
// the test ends. It must be set before runServer starts.
func setNetDevSpoolRoot(t *testing.T, root string) {
	t.Helper()
	prev := netdevSpoolRoot
	netdevSpoolRoot = root
	t.Cleanup(func() { netdevSpoolRoot = prev })
}

// createWebSession creates a web session for user in dir's server.db, before the
// server starts, and returns its cookie token.
func createWebSession(t *testing.T, dir, credID, userName string) string {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	defer db.Close()
	token, _, err := auth.NewStore(db, nil).Create(t.Context(), credID, userName)
	if err != nil {
		t.Fatalf("session of %s: %v", userName, err)
	}
	return token
}

// netdevServer is one runServer started on a free loopback port.
type netdevServer struct {
	base string
	log  *syncBuffer
}

// netdevResponse is what the test reads from one loopback request.
type netdevResponse struct {
	code     int
	csp      string
	location string
	body     string
}

// startNetDevServer runs runServer on dir with the rig's server socket as the
// executor, and waits until it serves /login. Its cleanup stops it.
func startNetDevServer(t *testing.T, r *netdevE2ERig, dir string) *netdevServer {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	listen := freeListenAddr(t)
	path := writeConfig(t, dir, map[string]any{
		"public_origin":   netdevE2EOrigin,
		"data_dir":        dir,
		"listen":          listen,
		"executor_socket": r.serverSock,
		"executor_user":   me.Username,
	})
	s := &netdevServer{base: "http://" + listen, log: &syncBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runServer(ctx, []string{"-config", path}, s.log, vulnHooks{}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runServer: %v; log: %s", err, s.log.String())
			}
		case <-time.After(15 * time.Second):
			t.Error("runServer did not return after cancel")
		}
	})
	waitFor(t, "the server to serve /login", func() bool {
		resp, err := http.Get(s.base + "/login")
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return s
}

// get sends GET path over loopback HTTP with the web session token; an empty
// token sends no cookie. Redirects are not followed.
func (s *netdevServer) get(t *testing.T, path, token string) netdevResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.base+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return netdevResponse{code: resp.StatusCode, csp: resp.Header.Get("Content-Security-Policy"), location: resp.Header.Get("Location"), body: string(b)}
}

// TestNetDevChainEndToEndToPage: an approved lease for one device, one
// collector cycle into the spool, and the server started by runServer. The
// server's importer writes the active device's row from the spool; its pages
// answer over loopback HTTP: without a session they redirect to login, and a
// non-admin session is refused with the CSP header. The admin's view of the
// same database shows the device with its escaped label, the collector's badge
// and not the blocked device.
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

	spool := newNetDevE2ESpool(t)
	setNetDevSpoolRoot(t, spool)
	ctx := t.Context()

	// One cycle: two listed devices, one metadata record for the active device,
	// and the blocked device skipped. The collector reads every CBS read of the
	// active device; the executor answers the lease's read (ND-14: Unimplemented)
	// and refuses the others, which the cycle's log shows read by read.
	rep, logs := runCollectorCycle(t, r, spool, time.Now)
	if rep.Devices != 2 || rep.MetadataWritten != 1 || rep.Skipped != 1 {
		t.Fatalf("cycle report = %+v, want 2 devices, 1 metadata record, 1 skipped", rep)
	}
	// Every dispatched read logged one failure: none was spooled, the lease's
	// read reached the device step (the client reports the executor's
	// Unimplemented as "internal"), the four reads the lease does not cover
	// were refused, and the blocked device was never read.
	failed := strings.Count(logs, `msg="netdev read failed"`)
	if failed != rep.Dispatched || rep.Dispatched == 0 {
		t.Fatalf("dispatched %d reads, %d failures logged; want every dispatched read to fail\n%s", rep.Dispatched, failed, logs)
	}
	if n := strings.Count(logs, `msg="netdev read spooled"`); n != 0 {
		t.Fatalf("%d reads were spooled, want none (the device step is not implemented)\n%s", n, logs)
	}
	if !strings.Contains(logs, "device=sw1 read=cbs_version code=executor:internal") {
		t.Fatalf("the leased read did not reach the device step\n%s", logs)
	}
	if n := strings.Count(logs, "code=executor:permission_denied"); n != failed-1 {
		t.Fatalf("%d reads refused by the lease, want the %d reads it does not cover\n%s", n, failed-1, logs)
	}
	if strings.Contains(logs, "device=sw2") {
		t.Fatalf("the blocked device was read\n%s", logs)
	}
	// Only the metadata record of the active device is spooled: the read
	// ended Unimplemented and wrote nothing, and the blocked device has no record.
	names := spoolNames(t, spool)
	if len(names) != rep.MetadataWritten {
		t.Fatalf("spool holds %d files, want the %d metadata record(s): %v", len(names), rep.MetadataWritten, names)
	}
	for _, n := range names {
		if !strings.Contains(n, "-"+netdevcollect.ReadDeviceMetadata+"-") {
			t.Fatalf("spool file %s is not a metadata record", n)
		}
	}

	// The server: the importer runs from runServer, the pages are mounted
	// behind the session check, and a non-admin session is refused.
	dir := t.TempDir()
	bobCred := []byte("netdev-test-bob")
	r.registerWebAuthnCredential(t, bobCred)
	bob := createWebSession(t, dir, base64.RawURLEncoding.EncodeToString(bobCred), "bob")
	s := startNetDevServer(t, r, dir)

	for _, path := range []string{"/netdev", "/netdev/sw1", "/netdev/sw1/firewall"} {
		got := s.get(t, path, "")
		if got.code != http.StatusSeeOther || got.location != "/login" {
			t.Errorf("GET %s without a session = %d to %q, want 303 to /login", path, got.code, got.location)
		}
		if got.csp != netdevE2ECSP {
			t.Errorf("GET %s without a session: Content-Security-Policy = %q, want the server policy", path, got.csp)
		}
		got = s.get(t, path, bob)
		if got.code != http.StatusForbidden {
			t.Errorf("GET %s as a non-admin = %d, want 403", path, got.code)
		}
		if got.csp != netdevE2ECSP {
			t.Errorf("GET %s as a non-admin: Content-Security-Policy = %q, want the server policy", path, got.csp)
		}
	}

	// The importer that runServer started writes the active device's row.
	// The database is read through a second handle while the server runs.
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := netdevinventory.NewWithNow(db, time.Now)
	waitFor(t, "the server importer to write sw1", func() bool {
		d, err := store.GetDevice(ctx, "sw1")
		return err == nil && d.Origin == netdevinventory.OriginCollectorReported
	})
	if _, err := store.GetDevice(ctx, "sw2"); err == nil {
		t.Fatal("the blocked device sw2 has a row")
	}

	// The admin's pages are read from the same database, through the pages
	// mounted with the test's admin rule: the server's own admin rule needs a
	// privileged executor session this test does not hold.
	h := newNetDevHTTP(t, &netdevTestEnv{db: db, clock: time.Now})
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
	detail := h.get("/netdev/sw1", h.admin)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), netdevReportedBadge) {
		t.Fatalf("GET /netdev/sw1 = %d, want 200 marked as reported by the collector", detail.Code)
	}
}

// TestNetDevLeaseRulesOnRealPath: the device lease rule on the real path. A
// read without an approved lease is refused before any device access; the
// server role may not propose a device lease, and its CommitReadGrant for the
// admin's pending digest is refused with the CLI-approval code; after the admin
// approves, the leased read reaches the Unimplemented step and a read outside
// the lease is refused.
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
	// The server role may commit only with a user-verified assertion, and a
	// device lease only through the admin CLI. Hardened mode refuses the commit
	// first, with the CLI-approval code. A check that let the commit through
	// would fall to assertion verification, which refuses this assertion with
	// another code, so the code tells the two apart.
	_, err = r.server.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: lease.Digest, AssertionJson: []byte(`{"id":"x"}`)})
	if got := status.Convert(err); !strings.HasPrefix(got.Message(), string(permit.CodeCLIRequired)) {
		t.Fatalf("server commit of the admin's device lease = %v, want a refusal with %s", err, permit.CodeCLIRequired)
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
// collector's own record, does not change the imported row. The second import
// evaluates the record (it is not skipped) and the store refuses it. The
// record is then not kept or rejected: it stays in the spool with a
// store_failed error, because internal/netdevcollect's storeRejection does not
// map netdevinventory.ErrTrustGenerationRegressed. This test pins that outcome
// and is the record of the gap; moving the record to kept/ is a change in
// internal/netdevcollect, outside this branch.
func TestNetDevHandPlacedLowerTrustGenerationKeepsRow(t *testing.T) {
	r := newNetDevE2ERig(t)
	r.addNetDevice(t, "sw1", "Core switch", "10.20.30.11", "a")
	if _, err := r.db.BumpTrustGeneration("sw1", strings.Repeat("c", 64)); err != nil {
		t.Fatalf("bump trust generation: %v", err)
	}
	e := newNetDevTestEnv(t)
	if rep, _ := runCollectorCycle(t, r, e.root, e.clock); rep.MetadataWritten != 1 {
		t.Fatalf("cycle report = %+v, want one metadata record", rep)
	}
	if _, err := e.imp.imp.Run(t.Context()); err != nil {
		t.Fatalf("import: %v", err)
	}

	e.publish(t, "sw1", netdevcollect.ReadDeviceMetadata, 1,
		`{"device_id":"sw1","family":"cbs","label":"Evil switch","trust_generation":1,"blocked":false,"block_reason":""}`)
	rep, err := e.imp.imp.Run(t.Context())
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	// The record was evaluated (one file), wrote no row, and was neither kept
	// nor rejected: it stays for a retry (see the comment above).
	if rep.Files != 1 || rep.MetadataWritten != 0 || rep.Kept != 0 || rep.Retry != 1 {
		t.Fatalf("second import report = %+v, want the hand-placed record evaluated, retried and no row written", rep)
	}
	if len(rep.Errors) != 1 || !strings.HasSuffix(rep.Errors[0], ": store_failed") {
		t.Fatalf("second import errors = %v, want one store_failed for the hand-placed record", rep.Errors)
	}
	d, err := netdevinventory.NewWithNow(e.db, e.clock).GetDevice(t.Context(), "sw1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.Label != "Core switch" || d.TrustGeneration != 2 {
		t.Fatalf("row = label %q generation %d, want the collector's row unchanged", d.Label, d.TrustGeneration)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	leaseTestPassphrase = "lease-test-passphrase-9b1d-7e4a-03c5"
	leaseTestSwitch     = "core-sw"
	leaseTestFirewall   = "edge-fw"
)

var (
	leaseTestSwitchPin   = strings.Repeat("ab", 32)
	leaseTestFirewallPin = strings.Repeat("cd", 32)
	leaseTestVaultParams = vault.Params{Time: 1, MemoryKiB: 64, Threads: 1}
)

// leaseExecutor is a real executor service served on Unix sockets in
// temporary directories: one where the test's UID is the local admin and
// one where it holds only the server role.
type leaseExecutor struct {
	adminSocket, serverSocket string
	// admin is a client on the admin socket for setup and assertions.
	admin pb.ExecutorServiceClient
}

func leaseServe(t *testing.T, svc *executor.Service, log *slog.Logger, roles []peercred.Role) string {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "executor.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): roles}, executor.MethodRoles())
	srv := executor.NewGRPCServer(svc, policy, log)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop(); _ = lis.Close() })
	return socket
}

func leaseDialSocket(socket string) func() (pb.ExecutorServiceClient, func(), error) {
	return func() (pb.ExecutorServiceClient, func(), error) {
		conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, nil, err
		}
		return pb.NewExecutorServiceClient(conn), func() { _ = conn.Close() }, nil
	}
}

func leaseCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// newLeaseExecutor starts the executor, unlocks its vault and registers a
// CBS switch and a PAN-OS firewall, each with a stored read credential.
func newLeaseExecutor(t *testing.T) *leaseExecutor {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	keysDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: "lease.test", Origins: []string{"https://lease.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: verifier, Store: db, RiskPolicy: risk, Schedules: db, Leases: db})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "lease.test", Origins: []string{"https://lease.test"}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := executor.NewService(auth, keyring.New(keysDir), db, reg, log)
	svc.SetVaultParams(leaseTestVaultParams)

	e := &leaseExecutor{
		adminSocket:  leaseServe(t, svc, log, []peercred.Role{peercred.RoleAdmin}),
		serverSocket: leaseServe(t, svc, log, []peercred.Role{peercred.RoleServer}),
	}
	c, done, err := leaseDialSocket(e.adminSocket)()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(done)
	e.admin = c

	ctx := leaseCtx(t)
	if _, err := c.InitVault(ctx, &pb.InitVaultRequest{Passphrase: []byte(leaseTestPassphrase)}); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	if _, err := c.Unlock(ctx, &pb.UnlockRequest{Passphrase: []byte(leaseTestPassphrase), Scope: pb.UnlockScope_UNLOCK_SCOPE_VAULT}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	// RegisterNetDevice probes the device first; there is no device in a
	// test, so the registry step after the confirmed probe runs directly on
	// executor.db with the same vault (as test/security does).
	v := vault.New(db)
	v.SetMinParams(leaseTestVaultParams)
	if err := v.Unlock([]byte(leaseTestPassphrase)); err != nil {
		t.Fatalf("unlock registry vault: %v", err)
	}
	registry := &executor.NetDeviceRegistry{Store: db, Vault: v}
	for _, d := range []executor.NetDeviceRegistration{
		{DeviceID: leaseTestSwitch, Family: netdevcontract.FamilyCBS, Label: "core switch", Endpoint: "10.20.0.2", Port: 22,
			PinKind: netdevcontract.PinSSHHostKey, Pin: leaseTestSwitchPin, By: "admin"},
		{DeviceID: leaseTestFirewall, Family: netdevcontract.FamilyPANOS, Label: "edge firewall", Endpoint: "10.20.0.3", Port: 443,
			PinKind: netdevcontract.PinTLSLeaf, Pin: leaseTestFirewallPin, By: "admin"},
	} {
		if _, err := registry.RegisterNetDevice(ctx, d); err != nil {
			t.Fatalf("register %s: %v", d.DeviceID, err)
		}
		if _, err := c.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{
			DeviceId: d.DeviceID, Username: "nos-read", Secret: []byte("lease-test-read-secret"),
		}); err != nil {
			t.Fatalf("set credential %s: %v", d.DeviceID, err)
		}
	}
	return e
}

// leaseRun runs `nebula netdev lease` with args, the typed stdin and the
// given dial function, and returns the result output and the error.
func leaseRun(args []string, stdin string, tty bool, dial func() (pb.ExecutorServiceClient, func(), error)) (string, string, error) {
	var out, prompt bytes.Buffer
	env := netdevEnv{
		in:              bufio.NewReader(strings.NewReader(stdin)),
		stdinIsTerminal: tty,
		out:             &out,
		promptOut:       &prompt,
		now:             time.Now,
		dial:            dial,
	}
	err := netdevCmd(append([]string{"lease"}, args...), env)
	return out.String(), prompt.String(), err
}

func (e *leaseExecutor) pending(t *testing.T) []*pb.PendingReadGrant {
	t.Helper()
	r, err := e.admin.ListPendingReadGrants(leaseCtx(t), &pb.ListPendingReadGrantsRequest{})
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	return r.GetGrants()
}

func (e *leaseExecutor) grants(t *testing.T) []*pb.ReadGrant {
	t.Helper()
	r, err := e.admin.ListReadGrants(leaseCtx(t), &pb.ListReadGrantsRequest{})
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	return r.GetGrants()
}

func TestNetdevLeasePreviewShowsExactDeviceAndReadsWithoutApproval(t *testing.T) {
	e := newLeaseExecutor(t)
	out, prompt, err := leaseRun([]string{leaseTestSwitch, "--reads", "cbs_vlans,cbs_version"}, "no\n", true, leaseDialSocket(e.adminSocket))
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("err = %v, want not approved", err)
	}
	for _, want := range []string{
		"Approve this read grant? (as seen by the executor)",
		"network devices (1):",
		leaseTestSwitch + "  trust pin " + leaseTestSwitchPin + " generation 1  credential version 1  reads (2): cbs_version, cbs_vlans",
		"rate profile  netdevice",
		"canonical grant (complete):",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("preview lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{leaseTestFirewall, leaseTestFirewallPin, "panos_", "provider remotes", "registries ("} {
		if strings.Contains(out, unwanted) {
			t.Errorf("preview names %q, which the admin did not type:\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "hosts (0):") || !strings.Contains(out, "actions (0):") {
		t.Errorf("preview does not show an empty host and action list:\n%s", out)
	}
	if !strings.Contains(prompt, "Type 'yes'") {
		t.Errorf("no typed confirmation asked: %q", prompt)
	}
	if g := e.grants(t); len(g) != 0 {
		t.Fatalf("lease approved without a typed yes: %v", g)
	}
	// The proposal stays pending at the executor and is never approved here.
	if p := e.pending(t); len(p) != 1 {
		t.Fatalf("pending = %d, want the one unapproved proposal", len(p))
	}
}

func TestNetdevLeaseApprovedAfterTypedYesIsListedWithExpiry(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		life time.Duration
	}{
		{"default 7 days", nil, 7 * 24 * time.Hour},
		{"3 days", []string{"--days", "3"}, 3 * 24 * time.Hour},
		{"30 days", []string{"--days", "30"}, 30 * 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLeaseExecutor(t)
			args := append([]string{leaseTestFirewall, "--reads", "panos_zones"}, tc.args...)
			out, _, err := leaseRun(args, "yes\n", true, leaseDialSocket(e.adminSocket))
			if err != nil {
				t.Fatalf("lease: %v\n%s", err, out)
			}
			g := e.grants(t)
			if len(g) != 1 {
				t.Fatalf("grants = %d, want 1", len(g))
			}
			if got := time.Duration(g[0].GetExpiryUnix()-g[0].GetCreatedUnix()) * time.Second; got != tc.life {
				t.Fatalf("lifetime = %s, want %s", got, tc.life)
			}
			doc, err := decodeReadGrantDoc(g[0].GetCanonicalGrant())
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.NetDeviceTargets) != 1 || doc.NetDeviceTargets[0].DeviceID != leaseTestFirewall ||
				strings.Join(doc.NetDeviceTargets[0].Reads, ",") != "panos_zones" || doc.NetDeviceTargets[0].TrustPin != leaseTestFirewallPin ||
				len(doc.Targets)+len(doc.ProviderTargets)+len(doc.RegistryTargets)+len(doc.Actions) != 0 {
				t.Fatalf("stored lease is not exactly the typed device and reads: %+v", doc)
			}
			expiry := time.Unix(g[0].GetExpiryUnix(), 0).Format(time.RFC3339)
			for _, want := range []string{"approved: device read lease " + g[0].GetGrantId(), expiry, "nebula read-grant revoke " + g[0].GetGrantId()} {
				if !strings.Contains(out, want) {
					t.Errorf("result lacks %q:\n%s", want, out)
				}
			}
			if p := e.pending(t); len(p) != 0 {
				t.Fatalf("approved lease still pending: %d", len(p))
			}
		})
	}
}

func TestNetdevLeaseUnknownDeviceRefused(t *testing.T) {
	e := newLeaseExecutor(t)
	_, _, err := leaseRun([]string{"nope-sw", "--reads", "cbs_version"}, "yes\n", true, leaseDialSocket(e.adminSocket))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want device not found", err)
	}
	if len(e.pending(t)) != 0 || len(e.grants(t)) != 0 {
		t.Fatal("unknown device left a proposal or a lease")
	}
}

func TestNetdevLeaseReadOfOtherFamilyRefused(t *testing.T) {
	e := newLeaseExecutor(t)
	for _, reads := range []string{"panos_zones", "cbs_version,panos_zones", "cbs_bogus"} {
		_, _, err := leaseRun([]string{leaseTestSwitch, "--reads", reads}, "yes\n", true, leaseDialSocket(e.adminSocket))
		if err == nil {
			t.Fatalf("reads %q accepted for a CBS switch", reads)
		}
	}
	if len(e.pending(t)) != 0 || len(e.grants(t)) != 0 {
		t.Fatal("refused read set left a proposal or a lease")
	}
}

func TestNetdevLeaseNonAdminPeerRefused(t *testing.T) {
	e := newLeaseExecutor(t)
	_, _, err := leaseRun([]string{leaseTestSwitch, "--reads", "cbs_version"}, "yes\n", true, leaseDialSocket(e.serverSocket))
	if err == nil {
		t.Fatal("server-role peer proposed a device lease")
	}
	if c := grpcstatus.Code(errors.Unwrap(err)); c != codes.PermissionDenied && !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want permission denied", err)
	}
	if len(e.pending(t)) != 0 || len(e.grants(t)) != 0 {
		t.Fatal("non-admin peer left a proposal or a lease")
	}
}

func TestNetdevLeaseInputRefusedBeforeExecutor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		tty   bool
	}{
		{"no device", []string{"--reads", "cbs_version"}, "yes\n", true},
		{"flag before device", []string{"--reads", "cbs_version", leaseTestSwitch}, "yes\n", true},
		{"two devices", []string{leaseTestSwitch, leaseTestFirewall, "--reads", "cbs_version"}, "yes\n", true},
		{"no reads", []string{leaseTestSwitch}, "yes\n", true},
		{"empty reads", []string{leaseTestSwitch, "--reads", ""}, "yes\n", true},
		{"empty read element", []string{leaseTestSwitch, "--reads", "cbs_version,"}, "yes\n", true},
		{"duplicate read", []string{leaseTestSwitch, "--reads", "cbs_version,cbs_version"}, "yes\n", true},
		{"unknown read", []string{leaseTestSwitch, "--reads", "cbs_bogus"}, "yes\n", true},
		{"days 0", []string{leaseTestSwitch, "--reads", "cbs_version", "--days", "0"}, "yes\n", true},
		{"days 31", []string{leaseTestSwitch, "--reads", "cbs_version", "--days", "31"}, "yes\n", true},
		{"days negative", []string{leaseTestSwitch, "--reads", "cbs_version", "--days", "-1"}, "yes\n", true},
		{"piped yes", []string{leaseTestSwitch, "--reads", "cbs_version"}, "yes\n", false},
		{"unknown flag", []string{leaseTestSwitch, "--reads", "cbs_version", "--pin", "x"}, "yes\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialed := false
			dial := func() (pb.ExecutorServiceClient, func(), error) {
				dialed = true
				return nil, nil, errors.New("must not dial")
			}
			_, _, err := leaseRun(tc.args, tc.stdin, tc.tty, dial)
			if err == nil {
				t.Fatal("accepted")
			}
			if dialed {
				t.Fatalf("contacted the executor before refusing: %v", err)
			}
		})
	}
}

// leaseFake is an executor whose pending list returns a document other
// than the proposed one; the CLI must refuse to approve it.
type leaseFake struct {
	pb.ExecutorServiceClient
	dev      *pb.NetDeviceInfo
	pending  func(proposed []byte) *pb.PendingReadGrant
	proposed []byte
	approved bool
}

func (f *leaseFake) ListNetDevices(context.Context, *pb.ListNetDevicesRequest, ...grpc.CallOption) (*pb.ListNetDevicesResponse, error) {
	return &pb.ListNetDevicesResponse{Devices: []*pb.NetDeviceInfo{f.dev}}, nil
}

func (f *leaseFake) ProposeReadGrant(_ context.Context, in *pb.ProposeReadGrantRequest, _ ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	_, canon, digest, err := permit.ParseReadGrant(in.GetGrantJson(), time.Now())
	if err != nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "bad grant")
	}
	f.proposed = canon
	return &pb.ProposeReadGrantResponse{GrantDigest: digest, CanonicalGrant: canon}, nil
}

func (f *leaseFake) ListPendingReadGrants(context.Context, *pb.ListPendingReadGrantsRequest, ...grpc.CallOption) (*pb.ListPendingReadGrantsResponse, error) {
	return &pb.ListPendingReadGrantsResponse{Grants: []*pb.PendingReadGrant{f.pending(f.proposed)}}, nil
}

func (f *leaseFake) ApproveReadGrantCLI(context.Context, *pb.ApproveReadGrantCLIRequest, ...grpc.CallOption) (*pb.ApproveReadGrantCLIResponse, error) {
	f.approved = true
	return &pb.ApproveReadGrantCLIResponse{}, nil
}

func TestNetdevLeaseRefusesExecutorPreviewThatDiffersFromTypedLease(t *testing.T) {
	dev := &pb.NetDeviceInfo{DeviceId: leaseTestSwitch, Family: "cbs", TrustPin: leaseTestSwitchPin, TrustGeneration: 1, CredentialVersion: 1}
	for _, tc := range []struct {
		name    string
		pending func(proposed []byte) *pb.PendingReadGrant
	}{
		{"digest not pending", func([]byte) *pb.PendingReadGrant {
			return &pb.PendingReadGrant{GrantDigest: strings.Repeat("0", 64), CanonicalGrant: []byte("{}")}
		}},
		{"other document under the digest", func(proposed []byte) *pb.PendingReadGrant {
			_, _, digest, _ := permit.ParseReadGrant(proposed, time.Now())
			other := bytes.Replace(proposed, []byte(`"cbs_version"`), []byte(`"cbs_mac_table"`), 1)
			return &pb.PendingReadGrant{GrantDigest: digest, CanonicalGrant: other, ApprovalExpiryUnix: time.Now().Add(time.Hour).Unix()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &leaseFake{dev: dev, pending: tc.pending}
			out, _, err := leaseRun([]string{leaseTestSwitch, "--reads", "cbs_version"}, "yes\n", true,
				func() (pb.ExecutorServiceClient, func(), error) { return f, func() {}, nil })
			if err == nil {
				t.Fatal("approved a pending document other than the typed lease")
			}
			if f.approved {
				t.Fatal("ApproveReadGrantCLI called")
			}
			if strings.Contains(out, "Type 'yes'") {
				t.Fatalf("asked for approval: %s", out)
			}
		})
	}
}

func TestNetdevLeaseDayLimitsMatchExecutor(t *testing.T) {
	if d := time.Duration(netdevLeaseDefaultDays) * 24 * time.Hour; d != executor.NetDevLeaseDefaultLifetime {
		t.Fatalf("default %s, executor %s", d, executor.NetDevLeaseDefaultLifetime)
	}
	if d := time.Duration(netdevLeaseMaxDays) * 24 * time.Hour; d != executor.NetDevLeaseMaxLifetime {
		t.Fatalf("max %s, executor %s", d, executor.NetDevLeaseMaxLifetime)
	}
}

func TestNetdevLeaseUsageDescribesVerb(t *testing.T) {
	flat := strings.Join(strings.Fields(netdevUsage), " ")
	for _, want := range []string{
		"nebula netdev lease <device-id> --reads READ[,READ...] [--days N]",
		"nebula read-grant revoke",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("netdev help lacks %q", want)
		}
	}
	_, _, err := leaseRun(nil, "", true, func() (pb.ExecutorServiceClient, func(), error) {
		return nil, nil, errors.New("must not dial")
	})
	if err == nil || !strings.Contains(err.Error(), "usage: nebula netdev") {
		t.Fatalf("bare lease: %v", err)
	}
}

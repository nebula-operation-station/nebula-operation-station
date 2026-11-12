// SPDX-License-Identifier: AGPL-3.0-or-later

// Acceptance tests for network devices, phase 1 (ADR 0010, ND-21). They run
// the real executor service over a real Unix socket with the real
// method-role table and the real permit authority (with its read-lease
// store), and the real web UI pages over the real ingest validation:
//
//   - a compromised server cannot read a device credential or a raw config,
//     cannot widen or extend a device read lease and cannot add a dial
//     target;
//   - a compromised netdev-collector can do no more than the typed reads an
//     approved lease names, within its budget;
//   - hostile device output (host names, rule names, interface
//     descriptions with HTML or control characters) is refused at ingest or
//     rendered as inert text;
//   - the approved config baseline (ND-17 part 2) cannot be set by the
//     server.
//
// These tests are protected: a change that weakens or deletes one needs
// human review (see AGENTS.md).
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	// ndDevice is the registered CBS switch; ndEndpoint its approved
	// management address.
	ndDevice   = "core-sw"
	ndEndpoint = "10.20.0.2"
	// ndRogueDevice and ndRogueEndpoint are what an attacker would like
	// the executor to dial.
	ndRogueDevice   = "rogue-sw"
	ndRogueEndpoint = "10.66.0.9"
	// ndUser and ndSecret are the stored read credential. Neither may
	// appear in any reply, error or log line.
	ndUser   = "nos-read-user-7f3a"
	ndSecret = "nd21-switch-read-secret-5c1e9b"
	// ndAttackerSecret is a credential a compromised caller tries to plant.
	ndAttackerSecret = "nd21-attacker-planted-secret-0d4f"
)

// ndPin is the confirmed SSH host key pin of ndDevice.
var ndPin = strings.Repeat("ab", 32)

// ndVaultParams are cheap Argon2id parameters for tests.
var ndVaultParams = vault.Params{Time: 1, MemoryKiB: 64, Threads: 1}

// ndEnv is an executor with the real role table and a permit authority
// that holds device read leases, one registered CBS switch with a read
// credential, and a client whose UID holds only the roles under test.
// Local admin actions (vault init and unlock, credential entry, lease
// approval on the executor CLI) run in-process, as on the executor host.
type ndEnv struct {
	t      *testing.T
	db     *executordb.DB
	svc    *executor.Service
	client pb.ExecutorServiceClient
	conn   *grpc.ClientConn
	logs   *syncBuffer
	clock  *e21Clock
	seq    int
}

func newNDEnv(t *testing.T, roles ...peercred.Role) *ndEnv {
	t.Helper()
	dir := privateDir(t)
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(dir, "testkeys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEncryptedKey(t, keysDir, credRef)

	logs := &syncBuffer{}
	eventKey, _, err := events.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	chain := events.NewChain(db, eventKey)
	log := slog.New(events.NewHandler(slog.NewJSONHandler(logs, nil), chain))
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	clock := newE21Clock()
	authority, err := permit.New(permit.Options{
		Verifier: verifier, Store: db, RiskPolicy: risk, Schedules: db, Leases: db,
		Audit: executor.AuditLogger(log), Now: clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: rpID, Origins: []string{origin}, Audit: executor.RegistrationAuditLogger(log)}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(authority, keyring.New(keysDir), db, reg, log)
	svc.Now = clock.now
	svc.SetEventKey(chain.PublicKey())
	if _, _, err := db.RegisterEventKey(chain.PublicKey()); err != nil {
		t.Fatal(err)
	}
	svc.SetVaultParams(ndVaultParams)

	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): roles}, executor.MethodRoles())
	srv := executor.NewGRPCServer(svc, policy, log)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop(); _ = db.Close() })
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	e := &ndEnv{t: t, db: db, svc: svc, client: pb.NewExecutorServiceClient(conn), conn: conn, logs: logs, clock: clock}
	e.adminSetup()
	return e
}

func (e *ndEnv) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	e.t.Cleanup(cancel)
	return c
}

// adminSetup is the local admin on the executor host: vault init and
// unlock (which also resumes read dispatch), the device registration with
// the confirmed pin, and the read credential.
func (e *ndEnv) adminSetup() {
	e.t.Helper()
	ctx := e.ctx()
	if _, err := e.svc.InitVault(ctx, &pb.InitVaultRequest{Passphrase: []byte(passphrase)}); err != nil {
		e.t.Fatalf("init vault: %v", err)
	}
	if _, err := e.svc.Unlock(ctx, &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
		e.t.Fatalf("unlock: %v", err)
	}
	// RegisterNetDevice probes the endpoint first; tests have no device at
	// a private address, so the registry step after the confirmed probe
	// runs directly on executor.db with the same vault.
	v := vault.New(e.db)
	v.SetMinParams(ndVaultParams)
	if err := v.Unlock([]byte(passphrase)); err != nil {
		e.t.Fatalf("unlock registry vault: %v", err)
	}
	registry := &executor.NetDeviceRegistry{Store: e.db, Vault: v}
	if _, err := registry.RegisterNetDevice(ctx, executor.NetDeviceRegistration{
		DeviceID: ndDevice, Family: netdevcontract.FamilyCBS, Label: "core switch", Endpoint: ndEndpoint, Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, Pin: ndPin, By: "admin",
	}); err != nil {
		e.t.Fatalf("register device: %v", err)
	}
	if _, err := e.svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{
		DeviceId: ndDevice, Username: ndUser, Secret: []byte(ndSecret),
	}); err != nil {
		e.t.Fatalf("set credential: %v", err)
	}
}

// devices returns the executor registry as the admin sees it.
func (e *ndEnv) devices() []*pb.NetDeviceInfo {
	e.t.Helper()
	got, err := e.svc.ListNetDevices(e.ctx(), &pb.ListNetDevicesRequest{})
	if err != nil {
		e.t.Fatalf("list devices: %v", err)
	}
	return got.GetDevices()
}

// device returns the registry row of ndDevice.
func (e *ndEnv) device() *pb.NetDeviceInfo {
	e.t.Helper()
	for _, d := range e.devices() {
		if d.GetDeviceId() == ndDevice {
			return d
		}
	}
	e.t.Fatalf("device %s not registered", ndDevice)
	return nil
}

// requireRegistryUnchanged asserts that the registry still holds exactly
// the one device the admin registered, at its approved endpoint, pin,
// trust generation and credential version.
func (e *ndEnv) requireRegistryUnchanged(gen uint64, credVersion int64) {
	e.t.Helper()
	ds := e.devices()
	if len(ds) != 1 {
		e.t.Fatalf("registry has %d devices, want exactly the one the admin registered: %v", len(ds), ds)
	}
	d := ds[0]
	if d.GetDeviceId() != ndDevice || d.GetEndpointIp() != ndEndpoint || d.GetPort() != 22 || d.GetTrustPin() != ndPin ||
		d.GetTrustGeneration() != gen || d.GetCredentialVersion() != credVersion || d.GetBlocked() {
		e.t.Fatalf("registry row changed: %v", d)
	}
}

// target freezes the current registry row of ndDevice with reads.
func (e *ndEnv) target(reads ...string) permit.NetDeviceTarget {
	e.t.Helper()
	d := e.device()
	return permit.NetDeviceTarget{DeviceID: d.GetDeviceId(), TrustPin: d.GetTrustPin(), TrustGeneration: d.GetTrustGeneration(),
		CredentialVersion: d.GetCredentialVersion(), Reads: reads}
}

// leaseDoc returns a device read lease document in its exact form.
func (e *ndEnv) leaseDoc(lifetime time.Duration, budget, intervalS int64, targets ...permit.NetDeviceTarget) permit.ReadGrantDoc {
	e.seq++
	now := e.clock.now()
	return permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: fmt.Sprintf("4d210000-0000-4000-8000-%012d", e.seq), Issuer: "server",
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(lifetime).Unix(), Trigger: permit.TriggerScheduled,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: intervalS, RunBudget: budget,
		RateProfile: schedgrant.NetDeviceReadProfile, NetDeviceTargets: targets,
	}
}

func ndMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// approve proposes doc and approves it as the local admin on the
// executor CLI. It returns the grant id.
func (e *ndEnv) approve(doc permit.ReadGrantDoc) string {
	e.t.Helper()
	p, err := e.svc.ProposeReadGrant(e.ctx(), &pb.ProposeReadGrantRequest{GrantJson: ndMarshal(e.t, doc)})
	if err != nil {
		e.t.Fatalf("propose lease: %v", err)
	}
	e.approveDigest(p.GetGrantDigest())
	return doc.ID
}

func (e *ndEnv) approveDigest(digest string) {
	e.t.Helper()
	if _, err := e.svc.ApproveReadGrantCLI(e.ctx(), &pb.ApproveReadGrantCLIRequest{GrantDigest: digest}); err != nil {
		e.t.Fatalf("approve lease: %v", err)
	}
}

// read is one typed read as the executor serves it to the collector.
func (e *ndEnv) read(device string, r pb.NetDeviceRead) error {
	e.t.Helper()
	got, err := e.svc.ReadNetDevice(e.ctx(), &pb.ReadNetDeviceRequest{DeviceId: device, Read: r})
	if got != nil {
		e.t.Errorf("read %s %v: unexpected reply %v", device, r, got)
	}
	return err
}

// authorizedReads counts the executor's audit lines of authorized device
// reads: the authoritative record that a lease paid for a read.
func (e *ndEnv) authorizedReads() int {
	return strings.Count(e.logs.String(), `"kind":"netdev_read_authorized"`)
}

// wantAuthorized asserts that a read passed every authority check: the
// executor recorded the spend. Device I/O itself is not implemented yet
// (ND-14), so the reply is Unimplemented; later it may be Unavailable for
// the absent test device. Neither is a refusal by authority.
func (e *ndEnv) wantAuthorized(before int, err error) {
	e.t.Helper()
	if c := status.Code(err); c != codes.Unimplemented && c != codes.Unavailable {
		e.t.Fatalf("authorized read: want Unimplemented or Unavailable after the authority checks, got %v", err)
	}
	if got := e.authorizedReads(); got != before+1 {
		e.t.Fatalf("authorized read: %d netdev_read_authorized audit lines, want %d", got, before+1)
	}
}

// wantRefused asserts code c and that no read was authorized.
func (e *ndEnv) wantRefused(what string, before int, err error, c codes.Code) {
	e.t.Helper()
	if status.Code(err) != c {
		e.t.Errorf("%s: want %v, got %v", what, c, err)
	}
	if got := e.authorizedReads(); got != before {
		e.t.Errorf("%s: a read was authorized (%d audit lines, want %d)", what, got, before)
	}
}

// requireNoSecret asserts that neither the stored credential nor a
// planted one appears in the executor's log and event lines.
func (e *ndEnv) requireNoSecret() {
	e.t.Helper()
	logs := e.logs.String()
	for _, s := range []string{ndSecret, ndUser, ndAttackerSecret} {
		if strings.Contains(logs, s) {
			e.t.Fatalf("executor log contains credential material %q", s)
		}
	}
}

// requireNoSecretIn asserts that a reply or error text carries no
// credential material and no vault reference of a device.
func requireNoSecretIn(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range []string{ndSecret, ndUser, ndAttackerSecret, "netdev-"} {
		if strings.Contains(text, s) {
			t.Errorf("%s contains %q: %s", what, s, text)
		}
	}
}

// netdevMethods are every network device method of the executor service.
var netdevMethods = []string{
	pb.ExecutorService_ProbeNetDevice_FullMethodName,
	pb.ExecutorService_RegisterNetDevice_FullMethodName,
	pb.ExecutorService_SetNetDeviceCredential_FullMethodName,
	pb.ExecutorService_RotateNetDeviceCredential_FullMethodName,
	pb.ExecutorService_ProposeNetDeviceRepin_FullMethodName,
	pb.ExecutorService_CommitNetDeviceRepin_FullMethodName,
	pb.ExecutorService_BlockNetDevice_FullMethodName,
	pb.ExecutorService_UnblockNetDevice_FullMethodName,
	pb.ExecutorService_RemoveNetDevice_FullMethodName,
	pb.ExecutorService_ListNetDevices_FullMethodName,
	pb.ExecutorService_ReadNetDevice_FullMethodName,
}

// TestNetDevMethodListIsComplete keeps netdevMethods in step with the
// service: every executor method whose name mentions a network device is
// listed, so a new device method cannot escape the role tests below.
func TestNetDevMethodListIsComplete(t *testing.T) {
	listed := map[string]bool{}
	for _, m := range netdevMethods {
		listed[m] = true
	}
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		full := "/" + string(svc.FullName()) + "/" + string(m.Name())
		if strings.Contains(string(m.Name()), "NetDev") && !listed[full] {
			t.Errorf("network device method %s is not covered by the ND-21 role tests", full)
		}
	}
	for m := range listed {
		if _, ok := executor.MethodRoles()[m]; !ok {
			t.Errorf("%s has no MethodRoles entry", m)
		}
	}
}

// methodOutput returns the response descriptor of a full method name.
func methodOutput(t *testing.T, full string) protoreflect.MessageDescriptor {
	t.Helper()
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	name := full[strings.LastIndex(full, "/")+1:]
	m := svc.Methods().ByName(protoreflect.Name(name))
	if m == nil {
		t.Fatalf("method %s not in the service descriptor", full)
	}
	return m.Output()
}

// revealField matches response fields that would carry a credential or a
// raw (unredacted) device config.
var revealField = regexp.MustCompile(`(?i)(password|passphrase|api_key|private_key|secret_value|raw_config|running_config|startup_config|config_text|raw_text|raw_output)`)

func checkNoRevealFields(t *testing.T, method string, d protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[d.FullName()] {
		return
	}
	seen[d.FullName()] = true
	for i := 0; i < d.Fields().Len(); i++ {
		f := d.Fields().Get(i)
		if revealField.MatchString(string(f.Name())) {
			t.Errorf("%s: response field %s.%s could carry a credential or a raw config", method, d.FullName(), f.Name())
		}
		if f.Kind() == protoreflect.MessageKind {
			checkNoRevealFields(t, method, f.Message(), seen)
		}
	}
}

// rolesOf returns the methods MethodRoles grants to role.
func rolesOf(role peercred.Role) map[string]bool {
	out := map[string]bool{}
	for m, roles := range executor.MethodRoles() {
		for _, r := range roles {
			if r == role {
				out[m] = true
			}
		}
	}
	return out
}

// TestNetDevCompromisedServerCannotReachDevicesOrCredentials (ND-21 1):
// the server UID is denied every network device method over the real
// socket, whatever it sends: it cannot read the credential, plant one,
// probe or register an endpoint (a new dial target), re-pin, unblock or
// remove a device, list the registry or read a device. No response type
// the server can obtain has a field for a credential or a raw config, the
// registry is unchanged afterwards and no credential reaches the log.
func TestNetDevCompromisedServerCannotReachDevicesOrCredentials(t *testing.T) {
	e := newNDEnv(t, peercred.RoleServer)
	before := e.device()
	ctx := e.ctx()

	calls := map[string]func() error{
		pb.ExecutorService_ProbeNetDevice_FullMethodName: func() error {
			_, err := e.client.ProbeNetDevice(ctx, &pb.ProbeNetDeviceRequest{Family: "cbs", Endpoint: ndRogueEndpoint, Port: 22})
			return err
		},
		pb.ExecutorService_RegisterNetDevice_FullMethodName: func() error {
			_, err := e.client.RegisterNetDevice(ctx, &pb.RegisterNetDeviceRequest{DeviceId: ndRogueDevice, Family: "cbs", Label: "rogue",
				Endpoint: ndRogueEndpoint, Port: 22, PinKind: "ssh-host-key", ConfirmedPin: strings.Repeat("cd", 32), Confirm: "yes"})
			return err
		},
		pb.ExecutorService_SetNetDeviceCredential_FullMethodName: func() error {
			_, err := e.client.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: ndDevice, Username: "attacker", Secret: []byte(ndAttackerSecret)})
			return err
		},
		pb.ExecutorService_RotateNetDeviceCredential_FullMethodName: func() error {
			_, err := e.client.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{DeviceId: ndDevice, ExpectedCredentialVersion: 1,
				Username: "attacker", Secret: []byte(ndAttackerSecret)})
			return err
		},
		pb.ExecutorService_ProposeNetDeviceRepin_FullMethodName: func() error {
			_, err := e.client.ProposeNetDeviceRepin(ctx, &pb.ProposeNetDeviceRepinRequest{DeviceId: ndDevice, OldPin: ndPin, ConfirmedNewPin: strings.Repeat("cd", 32)})
			return err
		},
		pb.ExecutorService_CommitNetDeviceRepin_FullMethodName: func() error {
			_, err := e.client.CommitNetDeviceRepin(ctx, &pb.CommitNetDeviceRepinRequest{DeviceId: ndDevice, OldPin: ndPin,
				ConfirmedNewPin: strings.Repeat("cd", 32), ExecutionDigest: strings.Repeat("0", 64)})
			return err
		},
		pb.ExecutorService_BlockNetDevice_FullMethodName: func() error {
			_, err := e.client.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: ndDevice, Reason: "x"})
			return err
		},
		pb.ExecutorService_UnblockNetDevice_FullMethodName: func() error {
			_, err := e.client.UnblockNetDevice(ctx, &pb.UnblockNetDeviceRequest{DeviceId: ndDevice, Confirm: "yes"})
			return err
		},
		pb.ExecutorService_RemoveNetDevice_FullMethodName: func() error {
			_, err := e.client.RemoveNetDevice(ctx, &pb.RemoveNetDeviceRequest{DeviceId: ndDevice, Confirm: "yes"})
			return err
		},
		pb.ExecutorService_ListNetDevices_FullMethodName: func() error {
			_, err := e.client.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
			return err
		},
		pb.ExecutorService_ReadNetDevice_FullMethodName: func() error {
			_, err := e.client.ReadNetDevice(ctx, &pb.ReadNetDeviceRequest{DeviceId: ndDevice, Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION})
			return err
		},
	}
	for _, m := range netdevMethods {
		call, ok := calls[m]
		if !ok {
			t.Fatalf("no server attack call for %s", m)
		}
		err := call()
		wantCode(t, err, codes.PermissionDenied, "")
		requireNoSecretIn(t, m+" error", err.Error())
	}
	// The vault RPCs that hold the credential are admin-only as well.
	_, err := e.client.ListSecrets(ctx, &pb.ListSecretsRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = e.client.SetSecret(ctx, &pb.SetSecretRequest{Id: "netdev-core-sw-rc", Value: []byte(ndAttackerSecret)})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = e.client.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: "netdev-core-sw-rc"})
	wantCode(t, err, codes.PermissionDenied, "")

	// No response the server can obtain has a field for a credential or a
	// raw device config, and no method of the service reveals either.
	server := rolesOf(peercred.RoleServer)
	for _, m := range netdevMethods {
		if server[m] {
			t.Errorf("%s is granted to the server role", m)
		}
	}
	seen := map[protoreflect.FullName]bool{}
	for m := range server {
		checkNoRevealFields(t, m, methodOutput(t, m), seen)
	}
	reveal := regexp.MustCompile(`(?i)(get|read|open|reveal|export|dump|fetch).*(credential|config|secret)`)
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	for i := 0; i < svc.Methods().Len(); i++ {
		name := string(svc.Methods().Get(i).Name())
		if strings.Contains(name, "NetDev") && reveal.MatchString(name) {
			t.Errorf("method %s looks like it reveals a device credential or config", name)
		}
	}

	e.requireRegistryUnchanged(before.GetTrustGeneration(), before.GetCredentialVersion())
	e.requireNoSecret()
}

// TestNetDevCompromisedServerCannotWidenOrExtendLeases (ND-21 1): the
// server may propose device read leases, but a proposal is no authority:
// without the admin's approval nothing is read, a forged approval is
// refused, and the executor refuses at proposal every lease that would
// exceed the profile (lifetime, budget, interval), name a read outside the
// closed set or carry anything else, such as a dial endpoint, a command
// or an XPath. An approved lease grants exactly its reads within its
// interval until its expiry; a longer lease the server proposes does not
// extend it, and leases that name an unregistered device or a stale pin
// authorize nothing and add no dial target. Revocation, which the server
// may do, only narrows.
func TestNetDevCompromisedServerCannotWidenOrExtendLeases(t *testing.T) {
	e := newNDEnv(t, peercred.RoleServer)
	before := e.device()
	ctx := e.ctx()
	cbsVersion := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	n := e.authorizedReads()

	// A proposal alone authorizes nothing; a forged approval is refused.
	p, err := e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: ndMarshal(t,
		e.leaseDoc(permit.DefaultReadGrantLifetime, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion)))})
	if err != nil {
		t.Fatalf("server propose: %v", err)
	}
	e.wantRefused("read on a proposed, unapproved lease", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)
	_, err = e.client.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: p.GetGrantDigest(), AssertionJson: []byte(`{"id":"forged","type":"public-key"}`)})
	if err == nil {
		t.Fatal("server committed a device read lease with a forged assertion")
	}
	_, err = e.client.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: p.GetGrantDigest()})
	wantCode(t, err, codes.PermissionDenied, "")
	e.wantRefused("read after a forged approval", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)

	// Widening proposals are refused before any approval.
	valid := func() permit.ReadGrantDoc {
		return e.leaseDoc(permit.DefaultReadGrantLifetime, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion))
	}
	withMember := func(doc permit.ReadGrantDoc, inTarget bool, key string, value any) []byte {
		var m map[string]any
		if err := json.Unmarshal(ndMarshal(t, doc), &m); err != nil {
			t.Fatal(err)
		}
		if inTarget {
			m["netdevice_targets"].([]any)[0].(map[string]any)[key] = value
		} else {
			m[key] = value
		}
		return ndMarshal(t, m)
	}
	widen := []struct {
		name string
		raw  []byte
	}{
		{"lifetime beyond 30 days", func() []byte {
			d := valid()
			d.ExpiryUnix = d.CreatedUnix + int64((permit.ReadGrantMaxLifetime+time.Hour)/time.Second)
			return ndMarshal(t, d)
		}()},
		{"budget beyond the profile", func() []byte {
			d := valid()
			d.RunBudget = schedgrant.NetDeviceMaxRunBudget + 1
			return ndMarshal(t, d)
		}()},
		{"interval below the 15-minute floor", func() []byte { d := valid(); d.MinIntervalS = 60; return ndMarshal(t, d) }()},
		{"read outside the closed set", func() []byte {
			d := valid()
			d.NetDeviceTargets[0].Reads = []string{"cbs_running_config"}
			return ndMarshal(t, d)
		}()},
		{"reads of both families", func() []byte {
			d := valid()
			d.NetDeviceTargets[0].Reads = []string{schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadPANOSSecurityRules}
			return ndMarshal(t, d)
		}()},
		{"malformed trust pin", func() []byte { d := valid(); d.NetDeviceTargets[0].TrustPin = "any"; return ndMarshal(t, d) }()},
		{"SSH actions on a device lease", func() []byte {
			d := valid()
			d.Actions = []permit.ReadGrantAction{{ActionID: "facts.collect", ModuleVersion: "1.0.0", ArtifactSHA256: hexSum(script), ParametersHash: hexSum(params)}}
			return ndMarshal(t, d)
		}()},
		{"dial endpoint in the target", withMember(valid(), true, "endpoint", ndRogueEndpoint)},
		{"dial port in the target", withMember(valid(), true, "port", 2222)},
		{"command in the lease", withMember(valid(), false, "command", "show running-config")},
		{"xpath in the lease", withMember(valid(), false, "xpath", "/config")},
		{"credential reference in the target", withMember(valid(), true, "credential_ref", "netdev-core-sw-rc")},
	}
	for _, tc := range widen {
		_, err := e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: tc.raw})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument at proposal, got %v", tc.name, err)
		}
	}

	// The admin approves a narrow lease: one read, at least 15 minutes
	// apart, for one hour.
	e.approve(e.leaseDoc(time.Hour, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion)))
	n = e.authorizedReads()
	e.wantAuthorized(n, e.read(ndDevice, cbsVersion))
	n = e.authorizedReads()
	e.wantRefused("read not in the lease", n, e.read(ndDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE), codes.PermissionDenied)
	e.wantRefused("same read within the interval", n, e.read(ndDevice, cbsVersion), codes.ResourceExhausted)
	e.clock.add(16 * time.Minute)
	e.wantAuthorized(n, e.read(ndDevice, cbsVersion))
	n = e.authorizedReads()

	// The server proposes a 30-day lease with every CBS read; it stays a
	// proposal. When the approved lease expires, nothing is read.
	if _, err := e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: ndMarshal(t, e.leaseDoc(permit.ReadGrantMaxLifetime, 24, 900,
		e.target(schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs, schedgrant.NetDeviceReadCBSInterfaces,
			schedgrant.NetDeviceReadCBSMACTable, schedgrant.NetDeviceReadCBSLLDP)))}); err != nil {
		t.Fatalf("server propose of a longer lease: %v", err)
	}
	e.clock.add(time.Hour)
	e.wantRefused("read after the approved lease expired", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)
	e.wantRefused("read the unapproved longer lease would grant", n, e.read(ndDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE), codes.PermissionDenied)

	// A lease naming an unregistered device (even approved by a careless
	// admin) authorizes no read and adds no dial target; one with a
	// substituted pin is stale.
	rogue := e.target(schedgrant.NetDeviceReadCBSVersion)
	rogue.DeviceID = ndRogueDevice
	e.approve(e.leaseDoc(time.Hour, 24, 900, rogue))
	e.wantRefused("read of an unregistered device", n, e.read(ndRogueDevice, cbsVersion), codes.NotFound)
	stale := e.target(schedgrant.NetDeviceReadCBSVersion)
	stale.TrustPin = strings.Repeat("cd", 32)
	e.approve(e.leaseDoc(time.Hour, 24, 900, stale))
	e.wantRefused("read on a lease with a substituted pin", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)

	// Revocation by the server only narrows.
	id := e.approve(e.leaseDoc(time.Hour, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion)))
	if _, err := e.client.RevokeReadGrant(ctx, &pb.RevokeReadGrantRequest{GrantId: id}); err != nil {
		t.Fatalf("server revoke: %v", err)
	}
	e.wantRefused("read on a revoked lease", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)

	e.requireRegistryUnchanged(before.GetTrustGeneration(), before.GetCredentialVersion())
	e.requireNoSecret()
}

// TestNetDevCompromisedCollectorBoundary (ND-21 2): the netdev-collector
// UID may call ListNetDevices and ReadNetDevice and nothing else. The
// registry metadata it sees carries no credential, user name or vault
// reference; it reads only what an approved lease names, within the
// lease's interval, only for registered devices and typed reads; it
// cannot propose, approve or revoke leases, plant credentials or add
// devices; and a credential rotation or a block stops its reads.
func TestNetDevCompromisedCollectorBoundary(t *testing.T) {
	e := newNDEnv(t, peercred.RoleNetDevCollector)
	ctx := e.ctx()

	// Role table: exactly the two methods.
	allowed := map[string]bool{
		pb.ExecutorService_ListNetDevices_FullMethodName: true,
		pb.ExecutorService_ReadNetDevice_FullMethodName:  true,
	}
	if got := rolesOf(peercred.RoleNetDevCollector); len(got) != len(allowed) {
		t.Errorf("netdev-collector role grants %v, want exactly %v", got, allowed)
	}
	for method := range executor.MethodRoles() {
		err := e.conn.Invoke(ctx, method, &pb.GetStatusRequest{}, &pb.GetStatusResponse{})
		if allowed[method] {
			if status.Code(err) == codes.PermissionDenied {
				t.Errorf("%s: collector wants allowed, got PermissionDenied", method)
			}
			continue
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: collector wants PermissionDenied, got %v", method, err)
		}
	}

	// Registry metadata: no credential, user name or vault reference, and
	// no response field that could carry one or a raw config.
	list, err := e.client.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		t.Fatalf("collector ListNetDevices: %v", err)
	}
	if len(list.GetDevices()) != 1 || list.GetDevices()[0].GetEndpointIp() != ndEndpoint {
		t.Fatalf("collector ListNetDevices: %v", list)
	}
	wire, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	requireNoSecretIn(t, "ListNetDevices reply", string(wire))
	requireNoSecretIn(t, "ListNetDevices reply", protojson.Format(list))
	for m := range allowed {
		checkNoBytes(t, methodOutput(t, m), map[protoreflect.FullName]bool{})
		checkNoRevealFields(t, m, methodOutput(t, m), map[protoreflect.FullName]bool{})
	}

	// Lease management and device administration are refused, whatever
	// the collector sends.
	doc := e.leaseDoc(time.Hour, schedgrant.NetDeviceMaxRunBudget, 900, e.target(schedgrant.NetDeviceReadCBSVersion,
		schedgrant.NetDeviceReadCBSMACTable))
	_, err = e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: ndMarshal(t, doc)})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = e.client.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: strings.Repeat("0", 64)})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = e.client.ListReadGrants(ctx, &pb.ListReadGrantsRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = e.client.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: ndDevice, Secret: []byte(ndAttackerSecret)})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = e.client.RegisterNetDevice(ctx, &pb.RegisterNetDeviceRequest{DeviceId: ndRogueDevice, Family: "cbs", Endpoint: ndRogueEndpoint,
		Port: 22, PinKind: "ssh-host-key", ConfirmedPin: strings.Repeat("cd", 32), Confirm: "yes"})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = e.client.ProbeNetDevice(ctx, &pb.ProbeNetDeviceRequest{Family: "cbs", Endpoint: ndRogueEndpoint, Port: 22})
	wantCode(t, err, codes.PermissionDenied, "")

	read := func(device string, r pb.NetDeviceRead) error {
		t.Helper()
		got, err := e.client.ReadNetDevice(ctx, &pb.ReadNetDeviceRequest{DeviceId: device, Read: r})
		if got != nil {
			t.Errorf("collector read %s %v: unexpected reply %v", device, r, got)
		}
		if err != nil {
			requireNoSecretIn(t, "collector read error", err.Error())
		}
		return err
	}
	cbsVersion := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	n := e.authorizedReads()

	// Without a lease, nothing.
	e.wantRefused("read without a lease", n, read(ndDevice, cbsVersion), codes.PermissionDenied)

	// With an approved lease: exactly its read, at its interval.
	e.approve(e.leaseDoc(time.Hour, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion)))
	e.wantAuthorized(n, read(ndDevice, cbsVersion))
	n = e.authorizedReads()
	e.wantRefused("read not in the lease", n, read(ndDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE), codes.PermissionDenied)
	e.wantRefused("same read within the interval", n, read(ndDevice, cbsVersion), codes.ResourceExhausted)
	e.wantRefused("PAN-OS read on a switch", n, read(ndDevice, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES), codes.InvalidArgument)
	e.wantRefused("read outside the closed set", n, read(ndDevice, pb.NetDeviceRead(99)), codes.InvalidArgument)
	e.wantRefused("unspecified read", n, read(ndDevice, pb.NetDeviceRead_NET_DEVICE_READ_UNSPECIFIED), codes.InvalidArgument)
	for _, id := range []string{ndRogueEndpoint, "core-sw:22", "core-sw/../x", "CORE-SW", ""} {
		e.wantRefused("address or malformed id as device "+id, n, read(id, cbsVersion), codes.InvalidArgument)
	}
	e.wantRefused("unregistered device", n, read(ndRogueDevice, cbsVersion), codes.NotFound)

	// The admin rotates the credential: the lease is stale, the collector
	// reads nothing until a new lease is approved.
	e.clock.add(16 * time.Minute)
	if _, err := e.svc.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{DeviceId: ndDevice, ExpectedCredentialVersion: 1,
		Username: ndUser, Secret: []byte(ndSecret + "-2")}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	e.wantRefused("read after credential rotation", n, read(ndDevice, cbsVersion), codes.PermissionDenied)

	// A fresh lease, then the admin blocks the device: no read.
	e.approve(e.leaseDoc(time.Hour, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion)))
	if _, err := e.svc.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: ndDevice, Reason: "maintenance"}); err != nil {
		t.Fatalf("block: %v", err)
	}
	e.wantRefused("read of a blocked device", n, read(ndDevice, cbsVersion), codes.FailedPrecondition)

	// Still exactly one device, at the approved endpoint.
	if ds := e.devices(); len(ds) != 1 || ds[0].GetEndpointIp() != ndEndpoint || ds[0].GetPort() != 22 {
		t.Fatalf("registry changed: %v", ds)
	}
	e.requireNoSecret()
}

// TestNetDevDialAddressesArePrivateLiterals (ND-21 1, 2): the executor
// dials only the registry's stored private IP literal; no public,
// loopback, link-local, multicast or unspecified address passes the check
// that runs at every dial.
func TestNetDevDialAddressesArePrivateLiterals(t *testing.T) {
	e := newNDEnv(t, peercred.RoleServer)
	dev, ok, err := e.db.GetNetDevice(ndDevice)
	if err != nil || !ok {
		t.Fatalf("device: %v %v", ok, err)
	}
	ap, err := executor.DialAddr(dev)
	if err != nil || ap.String() != ndEndpoint+":22" {
		t.Fatalf("DialAddr = %v, %v; want %s:22", ap, err, ndEndpoint)
	}
	for _, s := range []string{"8.8.8.8", "203.0.113.9", "127.0.0.1", "::1", "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::"} {
		if err := executor.CheckDeviceAddr(mustAddr(t, s)); err == nil {
			t.Errorf("CheckDeviceAddr(%s): accepted, want refused", s)
		}
	}
	for _, s := range []string{"10.20.0.2", "192.168.1.1", "172.16.0.1", "fd00::1"} {
		if err := executor.CheckDeviceAddr(mustAddr(t, s)); err != nil {
			t.Errorf("CheckDeviceAddr(%s): %v, want accepted", s, err)
		}
	}
}

// TestNetDevBaselineNotSettableByServer (ND-21 4): the approved config
// baseline (ND-17 part 2) has no RPC; the server cannot obtain an
// approval for it through ProposeExecution (reserved action namespace);
// and even in-process the executor refuses a baseline whose raw_digest it
// did not compute itself, so a server-chosen digest can never become the
// baseline.
func TestNetDevBaselineNotSettableByServer(t *testing.T) {
	svcDesc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	for i := 0; i < svcDesc.Methods().Len(); i++ {
		if name := string(svcDesc.Methods().Get(i).Name()); strings.Contains(strings.ToLower(name), "baseline") {
			t.Errorf("method %s exposes the baseline; it must be admin-only with an executor-computed digest", name)
		}
	}
	for m := range executor.MethodRoles() {
		if strings.Contains(strings.ToLower(m), "baseline") {
			t.Errorf("MethodRoles grants %s", m)
		}
	}

	e := newNDEnv(t, peercred.RoleServer)
	ctx := e.ctx()
	ph, err := canonical.HashParameters([]byte(`{"device_id":"core-sw","version_id":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"nebula.netdev.baseline", "nebula.netdev.repin"} {
		_, err := e.client.ProposeExecution(ctx, &pb.ProposeExecutionRequest{
			Request: &pb.ExecutionRequest{
				ExecutionId: "00000000-0000-4000-8000-0000000d2104", ActionId: action, ModuleVersion: "1.0.0",
				ArtifactSha256: hexSum([]byte("x")), ParametersHash: ph, CredentialRefs: []string{credRef},
				RiskClass: pb.RiskClass_RISK_CLASS_MEDIUM, StagePlanHash: stageplan.SingleStageHash,
				ExpiryUnix:      e.clock.now().Add(time.Hour).Unix(),
				ResolvedTargets: []*pb.Target{{HostId: "dockerflux", HostKeyFingerprint: fpA}},
			},
			ParametersJson: []byte(`{"device_id":"core-sw","version_id":1}`),
		})
		wantCode(t, err, codes.InvalidArgument, "reserved")
	}

	digest := strings.Repeat("e", 64)
	if _, err := e.svc.ProposeNetDeviceBaseline(ctx, ndDevice, 1, digest); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("propose baseline with a digest the executor did not compute: want FailedPrecondition, got %v", err)
	}
	if _, err := e.svc.CommitNetDeviceBaseline(ctx, ndDevice, 1, digest, strings.Repeat("0", 64)); err == nil {
		t.Error("commit baseline without an approved permit: accepted")
	}
	if b, ok, err := e.svc.GetNetDeviceBaseline(ctx, ndDevice); err != nil || ok {
		t.Errorf("baseline after the attempts: %v, %v, %v; want none", b, ok, err)
	}
}

// --- hostile device output (ND-21 3) ---

// ndRLO is U+202E RIGHT-TO-LEFT OVERRIDE, built from its code point so
// that this source holds no bidi control.
var ndRLO = string(rune(0x202e))

// ndHostileMarkup are device texts with HTML that the contract allows as
// free text and the UI must render inert.
var ndHostileMarkup = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(2)>`,
	`' onmouseover='alert(3)`,
	`<iframe src="https://evil.example/">`,
	`javascript:alert(4)`,
}

// ndHostileControl are device texts with control or format characters:
// terminal escapes, NUL, line breaks, a bidi override.
var ndHostileControl = []string{
	"sw\x1b[2J\x1b[31mpwned",
	"sw\x00hidden",
	"sw\r\nSet-Cookie: x=1",
	"evil" + ndRLO + "gnp.exe",
	"bell\x07",
}

func ndPayload(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := protojson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ndIngest decodes a spooled payload strictly and writes it, as the
// server ingest does.
func ndIngest(ctx context.Context, s *netdevinventory.Store, device string, gen uint64, at time.Time, read pb.NetDeviceRead, payload []byte) (netdevinventory.Rows, error) {
	rows, err := netdevinventory.DecodePayload(read, payload)
	if err != nil {
		return nil, err
	}
	if _, err := s.ReplaceDataset(ctx, device, rows.Read(), gen, at, false, rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// ndUIStore serves the pages from the real inventory store (devices and
// dataset states) and the rows that passed the real ingest.
type ndUIStore struct {
	*netdevinventory.Store
	ids    []string
	facts  map[string]netdevcontract.Facts
	vlans  map[string][]netdevcontract.VLAN
	ports  map[string][]netdevcontract.Port
	lldp   map[string][]netdevcontract.LLDPNeighbor
	policy map[string]netdevcontract.FirewallPolicy
}

func (s *ndUIStore) ListDevices(ctx context.Context, limit int) ([]netdevinventory.Device, error) {
	var out []netdevinventory.Device
	for _, id := range s.ids {
		d, err := s.GetDevice(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func ndRowsOf[T any](m map[string]T, id string) (T, error) {
	v, ok := m[id]
	if !ok {
		return v, netdevinventory.ErrDatasetNotFound
	}
	return v, nil
}

func (s *ndUIStore) Facts(_ context.Context, id string) (netdevcontract.Facts, error) {
	return ndRowsOf(s.facts, id)
}
func (s *ndUIStore) VLANs(_ context.Context, id string) ([]netdevcontract.VLAN, error) {
	return ndRowsOf(s.vlans, id)
}
func (s *ndUIStore) Ports(_ context.Context, id string) ([]netdevcontract.Port, error) {
	return ndRowsOf(s.ports, id)
}
func (s *ndUIStore) MACEntries(context.Context, string, int, int) ([]netdevcontract.MACEntry, int, error) {
	return nil, 0, netdevinventory.ErrDatasetNotFound
}
func (s *ndUIStore) LLDPNeighbors(_ context.Context, id string) ([]netdevcontract.LLDPNeighbor, error) {
	return ndRowsOf(s.lldp, id)
}
func (s *ndUIStore) FirewallPolicy(_ context.Context, id string) (netdevcontract.FirewallPolicy, error) {
	return ndRowsOf(s.policy, id)
}

// ndAuthExec is the executor client of the web login; the pages under
// test are reached with an existing session and never log in.
type ndAuthExec struct{}

func ndNotNeeded() error { return status.Error(codes.Unimplemented, "not needed") }

func (ndAuthExec) BeginLogin(context.Context, *pb.BeginLoginRequest, ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) FinishLogin(context.Context, *pb.FinishLoginRequest, ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) BeginRegistration(context.Context, *pb.BeginRegistrationRequest, ...grpc.CallOption) (*pb.BeginRegistrationResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) FinishRegistration(context.Context, *pb.FinishRegistrationRequest, ...grpc.CallOption) (*pb.FinishRegistrationResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) BeginPrivilegedSession(context.Context, *pb.BeginPrivilegedSessionRequest, ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) CompletePrivilegedSession(context.Context, *pb.CompletePrivilegedSessionRequest, ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) Lock(context.Context, *pb.LockRequest, ...grpc.CallOption) (*pb.LockResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) CheckCredential(context.Context, *pb.CheckCredentialRequest, ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	return nil, ndNotNeeded()
}
func (ndAuthExec) RecoveryLogin(context.Context, *pb.RecoveryLoginRequest, ...grpc.CallOption) (*pb.RecoveryLoginResponse, error) {
	return nil, ndNotNeeded()
}

// ndCSP is the strict CSP of internal/web/middleware (ADR 0010 ND-19: it
// applies unchanged to the device pages).
const ndCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// ndEventAttr matches an inline event handler attribute.
var ndEventAttr = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)

// requireInert asserts that a page holds no hostile markup, no control or
// format character and no inline script, style or embedded content.
func requireInert(t *testing.T, path, body string) {
	t.Helper()
	for _, bad := range []string{"<script>alert", "<img", "<iframe", "' onmouseover='", `href="javascript:`, "<embed", "<object", "<frame"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s: page contains hostile markup %q", path, bad)
		}
	}
	for _, r := range body {
		if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f || r == 0x202e {
			t.Errorf("%s: page contains control or format character %U", path, r)
			break
		}
	}
	if strings.Contains(body, "<style") {
		t.Errorf("%s: page has an inline style element", path)
	}
	// Attributes are checked inside real tags only: escaped device text
	// holds no '<' and may spell "onerror=" harmlessly.
	for _, part := range strings.Split(body, "<")[1:] {
		tag, _, _ := strings.Cut(part, ">")
		if ndEventAttr.MatchString(tag) || strings.Contains(tag, " style=") {
			t.Errorf("%s: tag with inline style or event handler: <%s>", path, tag)
		}
	}
	for _, part := range strings.Split(body, "<script")[1:] {
		head, _, _ := strings.Cut(part, ">")
		if !strings.Contains(head, `src="/static/`) {
			t.Errorf("%s: inline script tag <script%s>", path, head)
		}
	}
}

// TestNetDevHostileDeviceOutputIsInertText (ND-21 3): device output with
// HTML in host names, VLAN names, interface descriptions, LLDP system
// names and firewall rule descriptions passes the strict ingest only as
// text and renders escaped; the same fields with terminal escapes, NUL,
// line breaks or a bidi override are refused at ingest; structured names
// (interface names, PAN-OS rule and zone names) refuse markup outright.
// Nothing hostile reaches the page as markup.
func TestNetDevHostileDeviceOutputIsInertText(t *testing.T) {
	ctx := context.Background()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	inv := netdevinventory.NewWithNow(db, func() time.Time { return now })
	sw := netdevcontract.Device{DeviceID: "sw-edge", Name: "edge switch", Family: netdevcontract.FamilyCBS,
		Endpoints: []netdevcontract.Endpoint{{Address: "10.20.0.3", Port: 22}}, PinKind: netdevcontract.PinSSHHostKey,
		TrustPin: strings.Repeat("a", 64), TrustGeneration: 1}
	fw := netdevcontract.Device{DeviceID: "fw-edge", Name: "edge firewall", Family: netdevcontract.FamilyPANOS,
		Endpoints: []netdevcontract.Endpoint{{Address: "10.20.0.1", Port: 443}}, PinKind: netdevcontract.PinTLSLeaf,
		TrustPin: strings.Repeat("b", 64), TrustGeneration: 1}
	for _, d := range []netdevcontract.Device{sw, fw} {
		if err := inv.UpsertDevice(ctx, d); err != nil {
			t.Fatalf("upsert %s: %v", d.DeviceID, err)
		}
	}
	// A device name with markup is a server-side label; a control
	// character in it is refused.
	bad := sw
	bad.Name = "sw\x1b[2J"
	if err := inv.UpsertDevice(ctx, bad); err == nil {
		t.Error("device name with a terminal escape: accepted")
	}

	up, access := pb.NetDevLinkState_NET_DEV_LINK_STATE_UP, pb.NetDevPortMode_NET_DEV_PORT_MODE_ACCESS
	cbsPayloads := func(s string) map[pb.NetDeviceRead][]byte {
		return map[pb.NetDeviceRead][]byte{
			pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION: ndPayload(t, &pb.NetDevCBSVersion{Model: s, Firmware: "1.0", Serial: "SN1"}),
			pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS:   ndPayload(t, &pb.NetDevVLANs{Vlans: []*pb.NetDevVLAN{{Id: 10, Name: s}}}),
			pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES: ndPayload(t, &pb.NetDevPorts{Ports: []*pb.NetDevPort{{Name: "gi1/0/1",
				AdminState: up, OperState: up, Mode: access, Description: s}}}),
			pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP: ndPayload(t, &pb.NetDevLLDPNeighbors{Neighbors: []*pb.NetDevLLDPNeighbor{{
				LocalPort: "gi1/0/1", ChassisId: "00:11:22:33:44:55", PortId: "Gi0/1", SystemName: s}}}),
		}
	}
	fwPayload := func(name, desc string) []byte {
		return ndPayload(t, &pb.NetDevSecurityRules{Rules: []*pb.NetDevSecurityRule{{Name: name, Uuid: "0e1d2c3b-4a59-4687-8a9b-0c1d2e3f4a5b",
			FromZones: []string{"any"}, ToZones: []string{"any"}, Source: []string{"any"}, Destination: []string{"any"},
			Application: []string{"any"}, Service: []string{"any"}, Action: pb.NetDevRuleAction_NET_DEV_RULE_ACTION_ALLOW, Description: desc}}})
	}

	// Control and format characters are refused at ingest, in every free
	// text field, and in structured names markup is refused as well.
	for _, s := range ndHostileControl {
		for read, payload := range cbsPayloads(s) {
			if _, err := ndIngest(ctx, inv, sw.DeviceID, 1, now, read, payload); err == nil {
				t.Errorf("%v with %q: accepted at ingest", read, s)
			}
		}
		if _, err := ndIngest(ctx, inv, fw.DeviceID, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES, fwPayload("allow-dns", s)); err == nil {
			t.Errorf("rule description with %q: accepted at ingest", s)
		}
	}
	for _, s := range append(append([]string{}, ndHostileMarkup...), ndHostileControl...) {
		if _, err := ndIngest(ctx, inv, sw.DeviceID, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES, ndPayload(t, &pb.NetDevPorts{
			Ports: []*pb.NetDevPort{{Name: s, AdminState: up, OperState: up, Mode: access}}})); err == nil {
			t.Errorf("interface name %q: accepted at ingest", s)
		}
		if _, err := ndIngest(ctx, inv, fw.DeviceID, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES, fwPayload(s, "")); err == nil {
			t.Errorf("rule name %q: accepted at ingest", s)
		}
	}

	// Markup in free text passes ingest as text; one page per payload.
	store := &ndUIStore{Store: inv, facts: map[string]netdevcontract.Facts{}, vlans: map[string][]netdevcontract.VLAN{},
		ports: map[string][]netdevcontract.Port{}, lldp: map[string][]netdevcontract.LLDPNeighbor{}, policy: map[string]netdevcontract.FirewallPolicy{}}
	for i, s := range ndHostileMarkup {
		id := fmt.Sprintf("sw-hostile-%d", i)
		d := sw
		d.DeviceID, d.Name, d.TrustPin = id, s, fmt.Sprintf("%064x", i+1)
		d.Endpoints = []netdevcontract.Endpoint{{Address: fmt.Sprintf("10.20.1.%d", i+1), Port: 22}}
		if err := inv.UpsertDevice(ctx, d); err != nil {
			t.Fatalf("upsert %s with label %q: %v", id, s, err)
		}
		store.ids = append(store.ids, id)
		for read, payload := range cbsPayloads(s) {
			rows, err := ndIngest(ctx, inv, id, 1, now, read, payload)
			if err != nil {
				t.Fatalf("%v with %q: refused at ingest: %v", read, s, err)
			}
			switch r := rows.(type) {
			case netdevinventory.FactsRows:
				store.facts[id] = r.Facts
			case netdevinventory.VLANRows:
				store.vlans[id] = r
			case netdevinventory.PortRows:
				store.ports[id] = r
			case netdevinventory.LLDPRows:
				store.lldp[id] = r
			}
		}
	}
	store.ids = append(store.ids, fw.DeviceID)
	rows, err := ndIngest(ctx, inv, fw.DeviceID, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES, fwPayload("allow-dns", ndHostileMarkup[0]))
	if err != nil {
		t.Fatalf("rule description with markup: refused at ingest: %v", err)
	}
	part, ok := rows.(netdevinventory.PolicyPartRows)
	if !ok {
		t.Fatalf("security rules decode to %T", rows)
	}
	store.policy[fw.DeviceID] = part.Policy

	// The real pages behind the real session and security middleware.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, err := ui.New(ui.Options{PublicOrigin: origin, Log: log, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	pages, err := u.NetDevPages(ui.NetDevOptions{Store: store, IsAdmin: func(_ context.Context, user string) (bool, error) { return user == "alice", nil }})
	if err != nil {
		t.Fatalf("NetDevPages: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", u.Handler())
	pages.Register(mux)
	sessions := auth.NewStore(db, time.Now)
	a, err := auth.New(auth.Options{Executor: ndAuthExec{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	srv := httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: origin}, a.Wrap(mux)))
	t.Cleanup(srv.Close)
	token, _, err := sessions.Create(ctx, "cred-alice", "alice")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	get := func(path string) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, res.StatusCode)
		}
		if got := res.Header.Get("Content-Security-Policy"); got != ndCSP {
			t.Errorf("GET %s: CSP = %q, want %q", path, got, ndCSP)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s: Content-Type %q", path, ct)
		}
		return string(body)
	}

	list := get("/netdev")
	requireInert(t, "/netdev", list)
	for i := range ndHostileMarkup {
		path := fmt.Sprintf("/netdev/sw-hostile-%d", i)
		body := get(path)
		requireInert(t, path, body)
		if i == 0 && !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
			t.Errorf("%s: the hostile text is not shown as escaped text", path)
		}
	}
	requireInert(t, "/netdev/fw-edge", get("/netdev/fw-edge"))
	if !bytes.Contains([]byte(list), []byte("&lt;script&gt;")) {
		t.Error("/netdev: the hostile label is not shown as escaped text")
	}
}

// mustAddr parses an IP literal.
func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

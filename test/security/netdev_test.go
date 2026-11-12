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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	requireNoNetDevReadIO(t)
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
// (ND-14), so the reply must be Unimplemented. Any other code means the
// read path changed; requireNoNetDevReadIO stops every ndEnv before that
// path could dial the registered address.
func (e *ndEnv) wantAuthorized(before int, err error) {
	e.t.Helper()
	if c := status.Code(err); c != codes.Unimplemented {
		e.t.Fatalf("authorized read: want Unimplemented after the authority checks (no device I/O in tests), got %v", err)
	}
	if got := e.authorizedReads(); got != before+1 {
		e.t.Fatalf("authorized read: %d netdev_read_authorized audit lines, want %d", got, before+1)
	}
}

// ndExecutorSrc is the executor package source, relative to this test.
const ndExecutorSrc = "../../internal/executor"

// ndIOImports are packages whose use on the read path means the executor
// can open a connection.
var ndIOImports = map[string]bool{
	"net": true, "net/http": true, "crypto/tls": true, "os/exec": true, "syscall": true,
	"golang.org/x/crypto/ssh": true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport": true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun":      true,
}

// ndReadPathImports are the packages the read path may use: those it uses
// before device I/O exists, none of which opens a connection. A package
// outside this list (a device client, a new transport) fails the guard
// until a reviewer has checked it and the tests inject a dialer.
var ndReadPathImports = map[string]bool{
	"context": true, "crypto/sha256": true, "encoding/binary": true, "encoding/hex": true, "encoding/json": true,
	"errors": true, "fmt": true, "io": true, "log/slog": true, "slices": true, "strings": true, "time": true,
	"google.golang.org/grpc/codes": true, "google.golang.org/grpc/status": true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical":      true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb":     true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract": true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit":         true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1": true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant":     true,
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault":          true,
}

// ndIOName matches identifiers on the read path that name a connection,
// a dialer or the device lifecycle that probes.
var ndIOName = regexp.MustCompile(`(?i)dial|transport|probe|netdevadmin|conn$|^conn|sshclient`)

// ndReadIOFindings walks the executor sources from ReadNetDevice through
// every package function or method it names (by name, so it
// over-approximates) and returns each use of an I/O package or a dial-like
// identifier, plus the visited function names.
func ndReadIOFindings(dir string) (findings, visited []string, err error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	type fn struct {
		decl    *ast.FuncDecl
		imports map[string]string
	}
	funcs := map[string][]fn{}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		imports := map[string]string{}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			alias := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			imports[alias] = p
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fn{fd, imports})
			}
		}
	}
	if len(funcs["ReadNetDevice"]) == 0 {
		return nil, nil, fmt.Errorf("ReadNetDevice not found in %s", dir)
	}
	seen := map[string]bool{"ReadNetDevice": true}
	queue := []string{"ReadNetDevice"}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		visited = append(visited, cur)
		for _, f := range funcs[cur] {
			ast.Inspect(f.decl.Body, func(n ast.Node) bool {
				var id *ast.Ident
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if pkg, ok := x.X.(*ast.Ident); ok {
						if p, ok := f.imports[pkg.Name]; ok && (ndIOImports[p] || !ndReadPathImports[p]) {
							findings = append(findings, fmt.Sprintf("%s: uses %s.%s (%s)", fset.Position(x.Pos()), pkg.Name, x.Sel.Name, p))
						}
					}
					id = x.Sel
				case *ast.Ident:
					id = x
				default:
					return true
				}
				if ndIOName.MatchString(id.Name) {
					findings = append(findings, fmt.Sprintf("%s: names %s", fset.Position(id.Pos()), id.Name))
				}
				if _, ok := funcs[id.Name]; ok && !seen[id.Name] {
					seen[id.Name] = true
					queue = append(queue, id.Name)
				}
				return true
			})
		}
	}
	return findings, visited, nil
}

// requireNoNetDevReadIO stops the test before any read when the
// executor's read path could open a connection. The registered device
// sits at a real private address (registration refuses loopback) and the
// executor has no dialer hook yet, so once ND-14 adds device I/O these
// tests must inject a loopback or failing dialer first; until then this
// guard keeps every read in this file off the network.
func requireNoNetDevReadIO(t *testing.T) {
	t.Helper()
	findings, visited, err := ndReadIOFindings(ndExecutorSrc)
	if err != nil {
		t.Fatalf("scan the executor read path: %v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("ReadNetDevice can reach device I/O; inject a loopback or test-failing dialer into ndEnv before reading %s at %s (functions on the path: %v):\n%s",
			ndDevice, ndEndpoint, visited, strings.Join(findings, "\n"))
	}
}

// TestNetDevReadIOGuardDetectsDial proves the guard is not vacuous: a
// read path that names a dialer or the net package is reported.
func TestNetDevReadIOGuardDetectsDial(t *testing.T) {
	for name, src := range map[string]string{
		"net package": `package x
import "net"
func (s *S) ReadNetDevice() { helper() }
func helper() { _, _ = net.Dial("tcp", "10.20.0.2:22") }`,
		"transport dialer": `package x
func (s *S) ReadNetDevice() { s.open() }
func (s *S) open() { s.transport.DialContext(nil, "tcp", "") }`,
		"aliased sshtransport": `package x
import st "github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
func (s *S) ReadNetDevice() { var c st.Config; _ = c }`,
		"unreviewed device client package": `package x
import "github.com/nebula-operation-station/nebula-operation-station/internal/netdevcbs"
func (s *S) ReadNetDevice() { s.run() }
func (s *S) run() { _ = netdevcbs.Collect(s.target) }`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		findings, _, err := ndReadIOFindings(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(findings) == 0 {
			t.Errorf("%s: guard found no I/O", name)
		}
	}
	// The walk follows the real read path into the lease check, and that
	// path is I/O-free today.
	_, visited, err := ndReadIOFindings(ndExecutorSrc)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("read path: %v", visited)
	if !slices.Contains(visited, "checkNetDeviceGrant") {
		t.Errorf("guard did not follow ReadNetDevice into checkNetDeviceGrant: %v", visited)
	}
	requireNoNetDevReadIO(t)
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

// ndSecretValues are the credential values no reply, error or log line
// may carry: the stored secret, its rotated successor, the user name and
// the secret a compromised caller tries to plant.
var ndSecretValues = []string{ndSecret, ndSecret + "-2", ndUser, ndAttackerSecret}

// ndSecretForms returns every form in which a credential value would
// appear in text: plain, and the encodings of its bytes that the JSON slog
// handler, encoding/json and protojson use for []byte (standard base64),
// plus the unpadded and URL-safe base64 variants and lower- and upper-case
// hex, so a secret that leaks as bytes is found as well.
func ndSecretForms() map[string]string {
	out := map[string]string{}
	for _, s := range ndSecretValues {
		b := []byte(s)
		out[s] = s
		for enc, form := range map[string]string{
			"base64":         base64.StdEncoding.EncodeToString(b),
			"raw base64":     base64.RawStdEncoding.EncodeToString(b),
			"base64url":      base64.URLEncoding.EncodeToString(b),
			"raw base64url":  base64.RawURLEncoding.EncodeToString(b),
			"hex":            hex.EncodeToString(b),
			"upper-case hex": strings.ToUpper(hex.EncodeToString(b)),
		} {
			out[form] = enc + " of " + s
		}
	}
	return out
}

// ndSecretLeaks returns a description of every credential form in text.
func ndSecretLeaks(text string) []string {
	var out []string
	for form, what := range ndSecretForms() {
		if strings.Contains(text, form) {
			out = append(out, what)
		}
	}
	slices.Sort(out)
	return out
}

// requireNoSecret asserts that neither the stored credential nor a
// planted one appears, plain or encoded, in the executor's log and event
// lines.
func (e *ndEnv) requireNoSecret() {
	e.t.Helper()
	if leaks := ndSecretLeaks(e.logs.String()); len(leaks) > 0 {
		e.t.Fatalf("executor log contains credential material: %v", leaks)
	}
}

// requireNoSecretIn asserts that a reply or error text carries no
// credential material, plain or encoded, and no vault reference of a
// device.
func requireNoSecretIn(t *testing.T, what, text string) {
	t.Helper()
	if leaks := ndSecretLeaks(text); len(leaks) > 0 {
		t.Errorf("%s contains credential material %v: %s", what, leaks, text)
	}
	if strings.Contains(text, "netdev-") {
		t.Errorf("%s contains a device vault reference: %s", what, text)
	}
}

// TestNetDevSecretCheckFindsEncodedLeaks proves that the secret checks
// are not limited to plain text: a credential that leaks as []byte through
// the JSON slog handler, protojson or encoding/json (base64), or as hex,
// is found, and clean text is not flagged.
func TestNetDevSecretCheckFindsEncodedLeaks(t *testing.T) {
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("leak", "secret", []byte(ndSecret))
	pj, err := protojson.Marshal(&pb.SetNetDeviceCredentialRequest{DeviceId: ndDevice, Secret: []byte(ndAttackerSecret)})
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"slog JSON of []byte":     logBuf.String(),
		"protojson bytes field":   string(pj),
		"encoding/json of []byte": string(ndMarshal(t, struct{ S []byte }{[]byte(ndSecret)})),
		"raw base64url":           "x=" + base64.RawURLEncoding.EncodeToString([]byte(ndAttackerSecret)) + "&",
		"raw base64":              base64.RawStdEncoding.EncodeToString([]byte(ndSecret + "-2")),
		"hex":                     "secret " + hex.EncodeToString([]byte(ndSecret)),
		"upper-case hex":          strings.ToUpper(hex.EncodeToString([]byte(ndAttackerSecret))),
	} {
		for _, s := range ndSecretValues {
			if strings.Contains(text, s) {
				t.Fatalf("%s: fixture holds the plain value %q, so it does not test an encoding: %s", name, s, text)
			}
		}
		if len(ndSecretLeaks(text)) == 0 {
			t.Errorf("%s: secret check missed the leak in %s", name, text)
		}
	}
	if len(ndSecretLeaks("user "+ndUser)) == 0 {
		t.Error("secret check missed the plain user name")
	}
	if leaks := ndSecretLeaks(`{"device_id":"core-sw","credential_version":1,"secret_count":0}`); len(leaks) != 0 {
		t.Errorf("clean metadata flagged: %v", leaks)
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

// revealScalarField matches the plain words secret, credential, username
// and config as a whole name or as its last "_"-separated part (secret,
// device_credential, config), but not metadata such as credential_version
// or config_digest. It applies to scalar fields: a message field of that
// name (such as the WebAuthn credential metadata list) is a container whose
// own fields are checked.
var revealScalarField = regexp.MustCompile(`(?i)(^|_)(secrets?|credentials?|username|configs?)$`)

// revealsByName reports whether field f's name marks it as a carrier of a
// credential or a raw config.
func revealsByName(f protoreflect.FieldDescriptor) bool {
	name := string(f.Name())
	return revealField.MatchString(name) || (f.Kind() != protoreflect.MessageKind && revealScalarField.MatchString(name))
}

// TestNetDevRevealFieldMatchesPlainNames pins revealField: plain names a
// new response field could use for a credential or a raw config match;
// the metadata fields the server legitimately sees do not.
func TestNetDevRevealFieldMatchesPlainNames(t *testing.T) {
	for _, name := range []string{"secret", "secrets", "credential", "credentials", "username", "config", "configs",
		"device_secret", "read_credential", "admin_username", "device_config", "password", "raw_config", "running_config"} {
		if !revealField.MatchString(name) && !revealScalarField.MatchString(name) {
			t.Errorf("reveal patterns do not match %q", name)
		}
	}
	for _, name := range []string{"credential_version", "credential_ref", "credential_id", "config_version", "config_digest",
		"user_name", "ssh_user", "configured", "secret_count"} {
		if revealField.MatchString(name) || revealScalarField.MatchString(name) {
			t.Errorf("reveal patterns match metadata field %q", name)
		}
	}
	// On a real descriptor: a scalar named like a credential is flagged,
	// the container list of WebAuthn credential metadata is not (its
	// fields are checked on their own).
	cred := (&pb.ListWebAuthnCredentialsResponse{}).ProtoReflect().Descriptor().Fields().ByName("credentials")
	if cred == nil || revealsByName(cred) {
		t.Errorf("container field %v flagged by name", cred)
	}
	user := (&pb.SetNetDeviceCredentialRequest{}).ProtoReflect().Descriptor().Fields().ByName("username")
	if user == nil || !revealsByName(user) {
		t.Errorf("scalar field %v not flagged by name", user)
	}
}

// serverBytesFields are the bytes fields of every response the server
// role may obtain, each with what it carries. None holds a device
// credential or a device config. A new bytes field in a server-visible
// response fails TestNetDevCompromisedServerCannotReachDevicesOrCredentials
// until it is reviewed and listed here.
var serverBytesFields = map[protoreflect.FullName]string{
	"nebula.executor.v1.BeginGateResponse.challenge":                          "WebAuthn challenge",
	"nebula.executor.v1.BeginGateResponse.request_options_json":               "WebAuthn options",
	"nebula.executor.v1.BeginLoginResponse.request_options_json":              "WebAuthn options",
	"nebula.executor.v1.BeginPrivilegedSessionResponse.challenge":             "WebAuthn challenge",
	"nebula.executor.v1.BeginPrivilegedSessionResponse.request_options_json":  "WebAuthn options",
	"nebula.executor.v1.BeginRegistrationResponse.authorization_options_json": "WebAuthn options",
	"nebula.executor.v1.BeginRegistrationResponse.creation_options_json":      "WebAuthn options",
	"nebula.executor.v1.BeginTrustArtifactResponse.challenge":                 "WebAuthn challenge",
	"nebula.executor.v1.BeginTrustArtifactResponse.request_options_json":      "WebAuthn options",
	"nebula.executor.v1.DownloadEnrollScriptResponse.script":                  "public enroll script",
	"nebula.executor.v1.Event.body":                                           "signed audit event",
	"nebula.executor.v1.Event.hash":                                           "event chain hash",
	"nebula.executor.v1.Event.prev_hash":                                      "event chain hash",
	"nebula.executor.v1.Event.signature":                                      "event signature",
	"nebula.executor.v1.EventKey.public_key":                                  "event public key",
	"nebula.executor.v1.FetchEnrollScriptResponse.script":                     "public enroll script",
	"nebula.executor.v1.ListEventsResponse.public_key":                        "event public key",
	"nebula.executor.v1.NetBirdOfferPermitInfo.canonical":                     "canonical permit document",
	"nebula.executor.v1.NetBirdOfferPermitInfo.challenge":                     "WebAuthn challenge",
	"nebula.executor.v1.PairedPermitInfo.canonical":                           "canonical permit document",
	"nebula.executor.v1.PairedPermitInfo.challenge":                           "WebAuthn challenge",
	"nebula.executor.v1.ProposeBatchResponse.canonical_batch":                 "canonical batch document",
	"nebula.executor.v1.ProposeBatchResponse.challenge":                       "WebAuthn challenge",
	"nebula.executor.v1.ProposeBatchResponse.request_options_json":            "WebAuthn options",
	"nebula.executor.v1.ProposeExecutionResponse.canonical_request":           "canonical request document",
	"nebula.executor.v1.ProposeExecutionResponse.challenge":                   "WebAuthn challenge",
	"nebula.executor.v1.ProposeExecutionResponse.request_options_json":        "WebAuthn options",
	"nebula.executor.v1.ProposeReadGrantResponse.canonical_grant":             "canonical lease document",
	"nebula.executor.v1.ProposeReadGrantResponse.challenge":                   "WebAuthn challenge",
	"nebula.executor.v1.ProposeReadGrantResponse.request_options_json":        "WebAuthn options",
	"nebula.executor.v1.ProposeScheduleGrantResponse.canonical_grant":         "canonical schedule document",
	"nebula.executor.v1.ProposeScheduleGrantResponse.challenge":               "WebAuthn challenge",
	"nebula.executor.v1.ProposeScheduleGrantResponse.request_options_json":    "WebAuthn options",
	"nebula.executor.v1.ReadGrant.canonical_grant":                            "canonical lease document",
	"nebula.executor.v1.RunAttachedResponse.log":                              "SSH run log (host actions only)",
	"nebula.executor.v1.RunAttachedResponse.result":                           "SSH run result (host actions only)",
	"nebula.executor.v1.RunBatchMemberResponse.log":                           "SSH run log (host actions only)",
	"nebula.executor.v1.RunBatchMemberResponse.result":                        "SSH run result (host actions only)",
	"nebula.executor.v1.RunStatus.log":                                        "SSH run log (host actions only)",
	"nebula.executor.v1.RunStatus.result":                                     "SSH run result (host actions only)",
	"nebula.executor.v1.ScheduleGrant.canonical_grant":                        "canonical schedule document",
	"nebula.executor.v1.ShowEnrollScriptResponse.script":                      "public enroll script",
}

// checkBytesListed fails for every bytes field reachable from d that is
// not in allowed: raw bytes are where a credential or a raw config would
// travel unnoticed by name checks.
// Every bytes field met is recorded in found.
func checkBytesListed(t *testing.T, method string, d protoreflect.MessageDescriptor, allowed map[protoreflect.FullName]string, seen, found map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[d.FullName()] {
		return
	}
	seen[d.FullName()] = true
	for i := 0; i < d.Fields().Len(); i++ {
		f := d.Fields().Get(i)
		switch f.Kind() {
		case protoreflect.BytesKind:
			found[f.FullName()] = true
			if _, ok := allowed[f.FullName()]; !ok {
				t.Errorf("%s: response field %s is an unreviewed bytes field", method, f.FullName())
			}
		case protoreflect.MessageKind:
			checkBytesListed(t, method, f.Message(), allowed, seen, found)
		}
	}
}

func checkNoRevealFields(t *testing.T, method string, d protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[d.FullName()] {
		return
	}
	seen[d.FullName()] = true
	for i := 0; i < d.Fields().Len(); i++ {
		f := d.Fields().Get(i)
		if revealsByName(f) {
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
	seenBytes, found := map[protoreflect.FullName]bool{}, map[protoreflect.FullName]bool{}
	for m := range server {
		checkNoRevealFields(t, m, methodOutput(t, m), seen)
		checkBytesListed(t, m, methodOutput(t, m), serverBytesFields, seenBytes, found)
	}
	// The allowlist holds no stale entry.
	for name := range serverBytesFields {
		if !found[name] {
			t.Errorf("serverBytesFields lists %s, which no server response contains", name)
		}
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

	// Edge cases of the lease bounds. Each is refused at proposal over the
	// socket, and the executor's own parser (permit.ParseReadGrant, whose
	// reason the RPC does not echo) refuses it for its own reason, so a
	// regression in that one check is caught even if another check would
	// still refuse a sloppier document.
	day := int64(24 * time.Hour / time.Second)
	maxLife := int64(permit.ReadGrantMaxLifetime / time.Second)
	distinctTargets := func(n int) []permit.NetDeviceTarget {
		out := make([]permit.NetDeviceTarget, n)
		for i := range out {
			out[i] = e.target(schedgrant.NetDeviceReadCBSVersion)
			out[i].DeviceID = fmt.Sprintf("sw-%02d", i)
		}
		return out
	}
	edges := []struct {
		name, reason string
		doc          func(*permit.ReadGrantDoc)
	}{
		// A server-chosen future creation time would move a 30-day window
		// past 30 days from now.
		{"created_unix one day ahead, 30 days from creation", "future", func(d *permit.ReadGrantDoc) {
			d.CreatedUnix += day
			d.ExpiryUnix = d.CreatedUnix + maxLife
		}},
		{"created_unix one minute ahead, 30 days from creation", "future", func(d *permit.ReadGrantDoc) {
			d.CreatedUnix += 60
			d.ExpiryUnix = d.CreatedUnix + maxLife
		}},
		{"created_unix one year ahead, one hour long", "future", func(d *permit.ReadGrantDoc) {
			d.CreatedUnix += 365 * day
			d.ExpiryUnix = d.CreatedUnix + 3600
		}},
		// Target merging: the same device twice, identical or with other
		// reads, must not add up to wider reads.
		{"same target twice", "listed twice", func(d *permit.ReadGrantDoc) {
			d.NetDeviceTargets = append(d.NetDeviceTargets, d.NetDeviceTargets[0])
		}},
		{"same device twice with other reads", "listed twice", func(d *permit.ReadGrantDoc) {
			d.NetDeviceTargets = append(d.NetDeviceTargets, e.target(schedgrant.NetDeviceReadCBSMACTable, schedgrant.NetDeviceReadCBSLLDP))
		}},
		{"same read twice in a target", "listed twice", func(d *permit.ReadGrantDoc) {
			d.NetDeviceTargets[0].Reads = []string{schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVersion}
		}},
		{"more than MaxNetDeviceTargets devices", "devices", func(d *permit.ReadGrantDoc) {
			d.NetDeviceTargets = distinctTargets(permit.MaxNetDeviceTargets + 1)
		}},
		{"no device", "devices", func(d *permit.ReadGrantDoc) { d.NetDeviceTargets = []permit.NetDeviceTarget{} }},
		// Lower bounds of the budget and the interval.
		{"zero run_budget", "run_budget", func(d *permit.ReadGrantDoc) { d.RunBudget = 0 }},
		{"negative run_budget", "run_budget", func(d *permit.ReadGrantDoc) { d.RunBudget = -1 }},
		{"most negative run_budget", "run_budget", func(d *permit.ReadGrantDoc) { d.RunBudget = -1 << 63 }},
		{"zero min_interval_s", "min_interval_s", func(d *permit.ReadGrantDoc) { d.MinIntervalS = 0 }},
		{"negative min_interval_s", "min_interval_s", func(d *permit.ReadGrantDoc) { d.MinIntervalS = -900 }},
		// Version and generation bounds of a target.
		{"zero credential_version", "credential_version", func(d *permit.ReadGrantDoc) { d.NetDeviceTargets[0].CredentialVersion = 0 }},
		{"negative credential_version", "credential_version", func(d *permit.ReadGrantDoc) { d.NetDeviceTargets[0].CredentialVersion = -1 }},
		{"zero trust_generation", "trust_generation", func(d *permit.ReadGrantDoc) { d.NetDeviceTargets[0].TrustGeneration = 0 }},
	}
	for _, tc := range edges {
		d := valid()
		tc.doc(&d)
		raw := ndMarshal(t, d)
		_, err := e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument at proposal, got %v", tc.name, err)
		}
		if _, _, _, err := permit.ParseReadGrant(raw, e.clock.now()); err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: parser: want a refusal naming %q, got %v", tc.name, tc.reason, err)
		}
	}
	// Controls: the bounds sit exactly where the edge cases put them. A
	// lease created now with the full 30 days, one with exactly
	// MaxNetDeviceTargets devices and one with the smallest budget are
	// valid proposals (they stay proposals; none is approved).
	for name, edit := range map[string]func(*permit.ReadGrantDoc){
		"created now, 30 days":        func(d *permit.ReadGrantDoc) { d.ExpiryUnix = d.CreatedUnix + maxLife },
		"MaxNetDeviceTargets devices": func(d *permit.ReadGrantDoc) { d.NetDeviceTargets = distinctTargets(permit.MaxNetDeviceTargets) },
		"run_budget 1":                func(d *permit.ReadGrantDoc) { d.RunBudget = 1 },
	} {
		d := valid()
		edit(&d)
		if _, err := e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: ndMarshal(t, d)}); err != nil {
			t.Errorf("control %s: refused at proposal: %v", name, err)
		}
	}
	e.wantRefused("read after the widening proposals", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)

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

// TestNetDevLeaseAheadOfRegistryAuthorizesNothing (ND-21 1): a lease
// whose credential_version or trust_generation is ahead of the registry
// binds an identity the device does not have. Even approved, alone or all
// together, such leases authorize no read, for any of their reads. A lease
// at the registry's current identity does read, so the refusals come from
// the lease binding, not from the device.
//
// Open (nd21g report): such a lease becomes live once an admin rotation
// brings the registry to the version it names, because the device
// lifecycle's revocation (NetDevAdmin.Revoke) revokes provider grants
// only, not device read leases. The assertion for that belongs here once
// the executor revokes device leases on rotation, block, re-pin and
// removal.
func TestNetDevLeaseAheadOfRegistryAuthorizesNothing(t *testing.T) {
	e := newNDEnv(t, peercred.RoleServer)
	cbsVersion := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	before := e.device()
	if before.GetCredentialVersion() != 1 || before.GetTrustGeneration() != 1 {
		t.Fatalf("fixture: device at credential version %d, trust generation %d; want 1, 1", before.GetCredentialVersion(), before.GetTrustGeneration())
	}
	n := e.authorizedReads()

	ahead := []struct {
		name string
		edit func(*permit.NetDeviceTarget)
	}{
		{"credential_version one ahead", func(t *permit.NetDeviceTarget) { t.CredentialVersion++ }},
		{"credential_version far ahead", func(t *permit.NetDeviceTarget) { t.CredentialVersion = 1<<53 - 1 }},
		{"trust_generation one ahead", func(t *permit.NetDeviceTarget) { t.TrustGeneration++ }},
		{"trust_generation far ahead", func(t *permit.NetDeviceTarget) { t.TrustGeneration = 1 << 48 }},
		{"both ahead", func(t *permit.NetDeviceTarget) { t.CredentialVersion++; t.TrustGeneration++ }},
	}
	for _, tc := range ahead {
		tgt := e.target(schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSMACTable)
		tc.edit(&tgt)
		e.approve(e.leaseDoc(2*time.Hour, 24, 900, tgt))
		e.wantRefused("read on a lease with "+tc.name, n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)
	}
	// All of them together still authorize nothing, for either read.
	e.wantRefused("read with every ahead lease approved", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)
	e.wantRefused("MAC table read with every ahead lease approved", n, e.read(ndDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE), codes.PermissionDenied)
	// The approvals changed nothing in the registry.
	e.requireRegistryUnchanged(before.GetTrustGeneration(), before.GetCredentialVersion())

	// Control: a lease at the registry's current identity reads.
	e.approve(e.leaseDoc(time.Hour, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion)))
	e.wantAuthorized(n, e.read(ndDevice, cbsVersion))
	e.requireNoSecret()
}

// approvedGrant returns the stored lease id as the server sees it.
func (e *ndEnv) approvedGrant(id string) *pb.ReadGrant {
	e.t.Helper()
	got, err := e.client.ListReadGrants(e.ctx(), &pb.ListReadGrantsRequest{})
	if err != nil {
		e.t.Fatalf("server ListReadGrants: %v", err)
	}
	for _, g := range got.GetGrants() {
		if g.GetGrantId() == id {
			return g
		}
	}
	e.t.Fatalf("lease %s not stored", id)
	return nil
}

// TestNetDevServerCannotReproposeApprovedLease (ND-21 1): the server
// re-proposes the id of an already approved device read lease with wider
// reads, with a later expiry, or both. Every such proposal is refused, so
// there is nothing for the admin to approve over the stored lease; the
// stored lease is byte-for-byte unchanged, its reads stay narrow and it
// still expires on time. The same wider document under a fresh id is
// accepted as a proposal, which shows that the refusal comes from the
// reused id ("grant exists"), not from the document's content.
func TestNetDevServerCannotReproposeApprovedLease(t *testing.T) {
	e := newNDEnv(t, peercred.RoleServer)
	ctx := e.ctx()
	cbsVersion := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION

	approved := e.leaseDoc(time.Hour, 24, 900, e.target(schedgrant.NetDeviceReadCBSVersion))
	id := e.approve(approved)
	stored := e.approvedGrant(id)

	allReads := func() []permit.NetDeviceTarget {
		return []permit.NetDeviceTarget{e.target(schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs,
			schedgrant.NetDeviceReadCBSInterfaces, schedgrant.NetDeviceReadCBSMACTable, schedgrant.NetDeviceReadCBSLLDP)}
	}
	maxExpiry := approved.CreatedUnix + int64(permit.ReadGrantMaxLifetime/time.Second)
	wider := approved
	wider.NetDeviceTargets = allReads()
	later := approved
	later.NetDeviceTargets = []permit.NetDeviceTarget{e.target(schedgrant.NetDeviceReadCBSVersion)}
	later.ExpiryUnix = maxExpiry
	both := approved
	both.NetDeviceTargets = allReads()
	both.ExpiryUnix = maxExpiry
	for _, tc := range []struct {
		name string
		doc  permit.ReadGrantDoc
	}{
		{"same id with wider reads", wider},
		{"same id with a later expiry", later},
		{"same id with wider reads and a later expiry", both},
	} {
		if tc.doc.ID != id {
			t.Fatalf("%s: id %s, want the approved %s", tc.name, tc.doc.ID, id)
		}
		_, err := e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: ndMarshal(t, tc.doc)})
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(status.Convert(err).Message(), "exists") {
			t.Errorf("%s: want InvalidArgument (grant exists), got %v", tc.name, err)
		}
	}
	pending, err := e.svc.ListPendingReadGrants(ctx, &pb.ListPendingReadGrantsRequest{})
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if n := len(pending.GetGrants()); n != 0 {
		t.Fatalf("%d pending leases after the re-proposals, want none to approve", n)
	}

	// Control: the same wide, long document under a fresh id is a valid
	// proposal (it stays one until the admin approves it).
	fresh := both
	fresh.ID = "4d210000-0000-4000-8000-0000000fffff"
	if _, err := e.client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: ndMarshal(t, fresh)}); err != nil {
		t.Fatalf("control: wide lease under a fresh id refused at proposal: %v", err)
	}

	after := e.approvedGrant(id)
	if !bytes.Equal(after.GetCanonicalGrant(), stored.GetCanonicalGrant()) || after.GetGrantDigest() != stored.GetGrantDigest() ||
		after.GetExpiryUnix() != approved.ExpiryUnix || after.GetRevokedUnix() != 0 {
		t.Fatalf("approved lease changed by the re-proposals:\nbefore %v\nafter  %v", stored, after)
	}

	n := e.authorizedReads()
	e.wantAuthorized(n, e.read(ndDevice, cbsVersion))
	n = e.authorizedReads()
	e.wantRefused("read the re-proposal would add", n, e.read(ndDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE), codes.PermissionDenied)
	e.clock.add(time.Hour)
	e.wantRefused("read after the approved expiry", n, e.read(ndDevice, cbsVersion), codes.PermissionDenied)
	e.requireNoSecret()
}

// TestNetDevLeaseRunBudgetIsEnforced (ND-21 2): a lease's RunBudget caps
// the reads per device in any rolling hour, even when every read respects
// the interval. With a budget of 2 and a 15-minute interval the collector
// gets two reads; the third, after the interval, is refused for the
// budget; only when the first read leaves the hour window is one more read
// authorized.
func TestNetDevLeaseRunBudgetIsEnforced(t *testing.T) {
	e := newNDEnv(t, peercred.RoleNetDevCollector)
	ctx := e.ctx()
	cbsVersion := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	read := func() error {
		t.Helper()
		got, err := e.client.ReadNetDevice(ctx, &pb.ReadNetDeviceRequest{DeviceId: ndDevice, Read: cbsVersion})
		if got != nil {
			t.Errorf("collector read: unexpected reply %v", got)
		}
		return err
	}

	e.approve(e.leaseDoc(2*time.Hour, 2, 900, e.target(schedgrant.NetDeviceReadCBSVersion)))
	n := e.authorizedReads()
	e.wantAuthorized(n, read()) // t = 0
	e.clock.add(16 * time.Minute)
	e.wantAuthorized(n+1, read()) // t = 16m
	n = e.authorizedReads()
	e.clock.add(16 * time.Minute)
	e.wantRefused("third read in the hour (interval elapsed, budget spent)", n, read(), codes.ResourceExhausted) // t = 32m
	e.clock.add(16 * time.Minute)
	e.wantRefused("read at 48m (budget still spent)", n, read(), codes.ResourceExhausted)
	e.clock.add(14 * time.Minute)
	e.wantAuthorized(n, read()) // t = 62m: the read at t = 0 left the window
	n = e.authorizedReads()
	e.clock.add(time.Minute)
	e.wantRefused("read at 63m (interval and budget)", n, read(), codes.ResourceExhausted)
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
	if got := rolesOf(peercred.RoleNetDevCollector); !maps.Equal(got, allowed) {
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
	// Mapped and zoned forms of otherwise private addresses are refused.
	for _, s := range []string{"::ffff:10.20.0.2", "::ffff:192.168.1.1", "fd00::1%eth0", "fe80::1%eth0"} {
		if err := executor.CheckDeviceAddr(mustAddr(t, s)); !errors.Is(err, executor.ErrNetDeviceAddress) {
			t.Errorf("CheckDeviceAddr(%s): %v, want ErrNetDeviceAddress", s, err)
		}
	}

	// DialAddr re-checks the stored row at every dial: a row that a
	// compromised writer or a bug left with another endpoint, a zero port
	// or a lifecycle state that forbids dialing yields no address at all.
	tomb := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		name string
		edit func(*executordb.NetDevice)
		want error
	}{
		{"public endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "203.0.113.9" }, executor.ErrNetDeviceAddress},
		{"public IPv6 endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "2001:db8::1" }, executor.ErrNetDeviceAddress},
		{"loopback endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "127.0.0.1" }, executor.ErrNetDeviceAddress},
		{"link-local endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "169.254.1.1" }, executor.ErrNetDeviceAddress},
		{"unspecified endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "0.0.0.0" }, executor.ErrNetDeviceAddress},
		{"IPv4-mapped endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "::ffff:10.20.0.2" }, executor.ErrNetDeviceAddress},
		{"zoned endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "fd00::1%eth0" }, executor.ErrNetDeviceAddress},
		{"non-canonical IPv6", func(d *executordb.NetDevice) { d.EndpointIP = "fd00:0:0::0001" }, executor.ErrNetDeviceAddress},
		{"upper-case IPv6", func(d *executordb.NetDevice) { d.EndpointIP = "FD00::1" }, executor.ErrNetDeviceAddress},
		{"leading zero IPv4", func(d *executordb.NetDevice) { d.EndpointIP = "10.20.0.02" }, executor.ErrNetDeviceAddress},
		{"padded endpoint", func(d *executordb.NetDevice) { d.EndpointIP = " 10.20.0.2" }, executor.ErrNetDeviceAddress},
		{"endpoint with port", func(d *executordb.NetDevice) { d.EndpointIP = "10.20.0.2:22" }, executor.ErrNetDeviceAddress},
		{"host name", func(d *executordb.NetDevice) { d.EndpointIP = "core-sw.lan" }, executor.ErrNetDeviceAddress},
		{"rogue private endpoint as a name", func(d *executordb.NetDevice) { d.EndpointIP = "10.66.0.9.nip.io" }, executor.ErrNetDeviceAddress},
		{"empty endpoint", func(d *executordb.NetDevice) { d.EndpointIP = "" }, executor.ErrNetDeviceAddress},
		{"port 0", func(d *executordb.NetDevice) { d.Port = 0 }, executor.ErrNetDeviceAddress},
		{"blocked", func(d *executordb.NetDevice) { d.Blocked, d.BlockReason = true, "maintenance" }, executor.ErrNetDeviceNotDialable},
		{"tombstoned", func(d *executordb.NetDevice) { d.TombstonedAt = &tomb }, executor.ErrNetDeviceNotDialable},
		{"blocked with a public endpoint", func(d *executordb.NetDevice) {
			d.Blocked, d.BlockReason, d.EndpointIP = true, "maintenance", "8.8.8.8"
		}, executor.ErrNetDeviceNotDialable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := dev
			tc.edit(&tampered)
			ap, err := executor.DialAddr(tampered)
			if !errors.Is(err, tc.want) {
				t.Errorf("DialAddr(%q port %d) = %v, %v; want %v", tampered.EndpointIP, tampered.Port, ap, err, tc.want)
			}
			if ap.IsValid() {
				t.Errorf("DialAddr returned an address %v with the refusal", ap)
			}
		})
	}
	// The untampered row still dials only the approved endpoint.
	if ap, err := executor.DialAddr(dev); err != nil || ap.String() != ndEndpoint+":22" {
		t.Fatalf("DialAddr after the table = %v, %v; want %s:22", ap, err, ndEndpoint)
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

	// The request is otherwise well-formed (registered, unblocked device;
	// positive version; 64 lowercase hex digest), so the only check left to
	// refuse it is that the executor did not compute the digest.
	digest := strings.Repeat("e", 64)
	_, err = e.svc.ProposeNetDeviceBaseline(ctx, ndDevice, 1, digest)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "not computed by the executor") {
		t.Errorf("propose baseline with a digest the executor did not compute: want FailedPrecondition (not computed by the executor), got %v", err)
	}
	_, err = e.svc.CommitNetDeviceBaseline(ctx, ndDevice, 1, digest, strings.Repeat("0", 64))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "not computed by the executor") {
		t.Errorf("commit baseline with a digest the executor did not compute: want FailedPrecondition (not computed by the executor), got %v", err)
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

// ndFormatRunes are the C1 controls and bidi format characters a device
// text may try to smuggle: U+0085 NEL, U+009B CSI (the one-byte terminal
// escape), U+200E/U+200F LRM/RLM, U+202A-U+202E embeddings and overrides,
// U+2066-U+2069 isolates. They are built from code points so that this
// source holds none of them.
var ndFormatRunes = []rune{0x0085, 0x009b, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069}

// ndIsControlOrFormat reports whether r must never reach a page: a C0
// control other than tab and line breaks, DEL, a C1 control, or one of
// ndFormatRunes.
func ndIsControlOrFormat(r rune) bool {
	if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || (r >= 0x7f && r <= 0x9f) {
		return true
	}
	for _, f := range ndFormatRunes {
		if r == f {
			return true
		}
	}
	return false
}

// ndHostileControl are device texts with control or format characters:
// terminal escapes (7-bit and the C1 CSI), NUL, line breaks (CR LF and
// NEL), bidi overrides, marks and isolates.
var ndHostileControl = func() []string {
	out := []string{
		"sw\x1b[2J\x1b[31mpwned",
		"sw\x00hidden",
		"sw\r\nSet-Cookie: x=1",
		"evil" + ndRLO + "gnp.exe",
		"bell\x07",
		"sw" + string(rune(0x009b)) + "2Jpwned",
		"sw" + string(rune(0x0085)) + "Set-Cookie: x=1",
		"admin" + string(rune(0x2067)) + "nimda" + string(rune(0x2069)),
	}
	for _, r := range ndFormatRunes {
		out = append(out, "sw"+string(r)+"x")
	}
	return out
}()

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
	macs   map[string][]netdevcontract.MACEntry
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
func (s *ndUIStore) MACEntries(_ context.Context, id string, offset, limit int) ([]netdevcontract.MACEntry, int, error) {
	all, err := ndRowsOf(s.macs, id)
	if err != nil {
		return nil, 0, err
	}
	offset = min(max(offset, 0), len(all))
	return all[offset:min(offset+max(limit, 0), len(all))], len(all), nil
}
func (s *ndUIStore) LLDPNeighbors(_ context.Context, id string) ([]netdevcontract.LLDPNeighbor, error) {
	return ndRowsOf(s.lldp, id)
}
func (s *ndUIStore) FirewallPolicy(_ context.Context, id string) (netdevcontract.FirewallPolicy, error) {
	return ndRowsOf(s.policy, id)
}

// HitCounts serves no hit counts: the firewall page under test shows the
// rules only.
func (s *ndUIStore) HitCounts(context.Context, string) ([]netdevcontract.HitCount, error) {
	return nil, netdevinventory.ErrDatasetNotFound
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
		if ndIsControlOrFormat(r) {
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
// (interface names, PAN-OS rule and zone names, MAC addresses and MAC
// table ports) refuse markup outright. PAN-OS rule list members refuse
// control characters in every list; a list that accepts markup as a member
// shows it escaped on the firewall view. Nothing hostile reaches the device
// list, detail or firewall page as markup.
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
	macDynamic := pb.NetDevMACType_NET_DEV_MAC_TYPE_DYNAMIC
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
		// The MAC table has no free text: a hostile MAC address or port
		// name is refused outright.
		for field, entry := range map[string]*pb.NetDevMACEntry{
			"mac":  {Vlan: 10, Mac: s, Port: "gi1/0/1", Type: macDynamic},
			"port": {Vlan: 10, Mac: "00:11:22:33:44:55", Port: s, Type: macDynamic},
		} {
			if _, err := ndIngest(ctx, inv, sw.DeviceID, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE,
				ndPayload(t, &pb.NetDevMACTable{Entries: []*pb.NetDevMACEntry{entry}})); err == nil {
				t.Errorf("MAC table %s %q: accepted at ingest", field, s)
			}
		}
	}

	// PAN-OS list members (zones, addresses, users, applications,
	// services, URL categories, tags): a control or format character is
	// refused at ingest in every list; markup is either refused or, if a
	// list accepts it as a name, rendered inert below.
	ruleLists := map[string]func(*pb.NetDevSecurityRule, string){
		"from_zones":  func(r *pb.NetDevSecurityRule, s string) { r.FromZones = []string{"trust", s} },
		"to_zones":    func(r *pb.NetDevSecurityRule, s string) { r.ToZones = []string{s} },
		"source":      func(r *pb.NetDevSecurityRule, s string) { r.Source = []string{"10.0.0.0/8", s} },
		"destination": func(r *pb.NetDevSecurityRule, s string) { r.Destination = []string{s} },
		"source_user": func(r *pb.NetDevSecurityRule, s string) { r.SourceUser = []string{s} },
		"application": func(r *pb.NetDevSecurityRule, s string) { r.Application = []string{"dns", s} },
		"service":     func(r *pb.NetDevSecurityRule, s string) { r.Service = []string{s} },
		"category":    func(r *pb.NetDevSecurityRule, s string) { r.Category = []string{s} },
		"tags":        func(r *pb.NetDevSecurityRule, s string) { r.Tags = []string{s} },
	}
	listPayload := func(field, s string) []byte {
		var rs pb.NetDevSecurityRules
		if err := protojson.Unmarshal(fwPayload("allow-dns", ""), &rs); err != nil {
			t.Fatal(err)
		}
		ruleLists[field](rs.Rules[0], s)
		return ndPayload(t, &rs)
	}
	for field := range ruleLists {
		for _, s := range ndHostileControl {
			if _, err := ndIngest(ctx, inv, fw.DeviceID, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES, listPayload(field, s)); err == nil {
				t.Errorf("rule %s member %q: accepted at ingest", field, s)
			}
		}
	}

	// Markup in free text passes ingest as text; one page per payload.
	store := &ndUIStore{Store: inv, facts: map[string]netdevcontract.Facts{}, vlans: map[string][]netdevcontract.VLAN{},
		ports: map[string][]netdevcontract.Port{}, lldp: map[string][]netdevcontract.LLDPNeighbor{}, macs: map[string][]netdevcontract.MACEntry{},
		policy: map[string]netdevcontract.FirewallPolicy{}}
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

	// A MAC table that passed ingest is shown on the switch page.
	macRows, err := ndIngest(ctx, inv, "sw-hostile-0", 1, now, pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE,
		ndPayload(t, &pb.NetDevMACTable{Entries: []*pb.NetDevMACEntry{{Vlan: 10, Mac: "00:11:22:33:44:55", Port: "gi1/0/1", Type: macDynamic}}}))
	if err != nil {
		t.Fatalf("valid MAC table refused at ingest: %v", err)
	}
	macs, ok := macRows.(netdevinventory.MACRows)
	if !ok {
		t.Fatalf("MAC table decodes to %T", macRows)
	}
	store.macs["sw-hostile-0"] = macs

	// Markup in PAN-OS list members: refused at ingest, or accepted and
	// then served on its own firewall page, which must be inert.
	// fw-probe takes the full ingest of each candidate; it is not served.
	probe := fw
	probe.DeviceID, probe.TrustPin = "fw-probe", strings.Repeat("c", 64)
	probe.Endpoints = []netdevcontract.Endpoint{{Address: "10.20.2.250", Port: 443}}
	if err := inv.UpsertDevice(ctx, probe); err != nil {
		t.Fatalf("upsert fw-probe: %v", err)
	}
	type hostileMember struct{ id, field, value string }
	var hostileFW []hostileMember
	for _, field := range slices.Sorted(maps.Keys(ruleLists)) {
		for _, s := range ndHostileMarkup {
			payload := listPayload(field, s)
			if _, err := ndIngest(ctx, inv, probe.DeviceID, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES, payload); err != nil {
				continue
			}
			id := fmt.Sprintf("fw-hostile-%d", len(hostileFW))
			d := fw
			d.DeviceID, d.TrustPin = id, fmt.Sprintf("%064x", 0x100+len(hostileFW))
			d.Endpoints = []netdevcontract.Endpoint{{Address: fmt.Sprintf("10.20.2.%d", len(hostileFW)+1), Port: 443}}
			if err := inv.UpsertDevice(ctx, d); err != nil {
				t.Fatalf("upsert %s: %v", id, err)
			}
			rows, err := ndIngest(ctx, inv, id, 1, now, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES, payload)
			if err != nil {
				t.Fatalf("rule %s member %q: accepted on fw-probe, refused on %s: %v", field, s, id, err)
			}
			store.policy[id] = rows.(netdevinventory.PolicyPartRows).Policy
			store.ids = append(store.ids, id)
			hostileFW = append(hostileFW, hostileMember{id, field, s})
			t.Logf("rule %s accepts %q as a list member; %s renders it", field, s, id)
		}
	}

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
	fwPage, err := u.NetDevFirewallPage(ui.NetDevFirewallOptions{Store: store, IsAdmin: func(_ context.Context, user string) (bool, error) { return user == "alice", nil }})
	if err != nil {
		t.Fatalf("NetDevFirewallPage: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", u.Handler())
	pages.Register(mux)
	fwPage.Register(mux)
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
		if i == 0 && !strings.Contains(body, "00:11:22:33:44:55") {
			t.Errorf("%s: the MAC table is not shown", path)
		}
	}
	requireInert(t, "/netdev/fw-edge", get("/netdev/fw-edge"))
	// The firewall view shows the rules: the rule description with markup
	// is there as escaped text.
	fwBody := get("/netdev/fw-edge/firewall")
	requireInert(t, "/netdev/fw-edge/firewall", fwBody)
	if !strings.Contains(fwBody, "allow-dns") || !strings.Contains(fwBody, html.EscapeString(ndHostileMarkup[0])) {
		t.Error("/netdev/fw-edge/firewall: the rule or its hostile description is not shown as escaped text")
	}
	for _, h := range hostileFW {
		path := "/netdev/" + h.id + "/firewall"
		body := get(path)
		requireInert(t, path, body)
		if !strings.Contains(body, html.EscapeString(h.value)) {
			t.Errorf("/netdev/%s: rule %s member %q is not shown as escaped text", h.id, h.field, h.value)
		}
	}
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// TestPveMutationsWiresProductionProvisioner: with a data directory the
// executor's one engine carries the production provisioner as TaskIDs
// (provisioning steps are identified and reconciled after a restart), on
// the same engine, with the pinned reader, the state files in the data
// directory and the automation key from the keyring.
func TestPveMutationsWiresProductionProvisioner(t *testing.T) {
	e := newReconcileEnv(t)
	dir := t.TempDir()
	e.svc.SetBackupDirs(dir, filepath.Join(dir, "keys"))
	m := e.svc.pveMutations()
	p := e.svc.pveProvisioner()
	if p == nil || m.TaskIDs != PveJobTaskIDs(p) || p.Mutations != m || p.Images == nil || p.Images.Mutations != m {
		t.Fatalf("provisioner %#v not wired on the engine", p)
	}
	// Every provisioner and image dependency is set: the only refusal left
	// is the engine's own locked vault.
	if err := p.Images.checkDeps(); err != nil {
		t.Fatalf("production image deps: %v", err)
	}
	if err := p.checkDeps(); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("production provisioner deps: %v, want only the locked vault", err)
	}
	if _, ok := p.Reader.(pveProvisionReaderAPI); !ok {
		t.Fatalf("reader = %T, want the pinned pveProvisionReaderAPI", p.Reader)
	}
	if vs, ok := p.VMIDs.(*FilePveVMIDStore); !ok || vs.Path != filepath.Join(dir, pveVMIDsFile) {
		t.Fatalf("vmid store = %#v", p.VMIDs)
	}
	if ts, ok := p.Images.Templates.(*FilePveTemplateStore); !ok || ts.Path != filepath.Join(dir, pveTemplatesFile) {
		t.Fatalf("template store = %#v", p.Images.Templates)
	}
	if p.Images.Catalog == nil || p.Images.Catalog.State == nil {
		t.Fatal("image catalog has no rollback state store")
	}
	// Only the designated automation credential resolves: the keyring's
	// host credential "cred" is refused without a keyring lookup, and the
	// designated one is not loaded here.
	if key, err := p.AutomationKeys("cred"); !errors.Is(err, ErrPveAutomationCredential) || key != "" {
		t.Fatalf("host credential as automation key = %q, %v", key, err)
	}
	if _, err := p.AutomationKeys("no-such-ref"); !errors.Is(err, ErrPveAutomationCredential) {
		t.Fatalf("unknown credential ref: %v", err)
	}
	if _, err := p.AutomationKeys(PveAutomationCredentialRef); !errors.Is(err, keyring.ErrUnknownRef) {
		t.Fatalf("designated ref not in the keyring: %v", err)
	}
	// Provisioning steps get task types and IDs from the production client.
	c := m.Client.(*pveMutationClient)
	if tt, ok := c.TaskType(pveStepGuestClone); !ok || tt != "qmclone" {
		t.Fatalf("clone task type = %q %v", tt, ok)
	}
	if e.svc.pveProvisioner() != p {
		t.Fatal("provisioner is not single")
	}
}

// TestPveProvisionReaderReadsOverThePinnedChannel: the production reader
// lists the cluster guests and reads one storage with the read token over
// the remote's pinned TLS channel.
func TestPveProvisionReaderReadsOverThePinnedChannel(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.pve.mu.Lock()
	e.pve.bodies["/api2/json/nodes/pve1/storage/local/status"] = `{"data":{"type":"dir","content":"images,import","active":1,"shared":0,"used":100,"total":1000}}`
	e.pve.mu.Unlock()
	r := pveProvisionReaderAPI{agent: pveGuestAgentAPI{s: e.svc}}
	ctx := context.Background()
	inv, err := r.ClusterInventory(ctx, e.remote(), tokenOf(pveReadToken))
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	vmids := map[int]bool{}
	for _, g := range inv.Guests {
		vmids[g.VMID] = true
	}
	if len(inv.Nodes) != 1 || inv.Nodes[0].Name != "pve1" || !vmids[100] || !vmids[200] || inv.Partial || inv.Truncated {
		t.Fatalf("inventory %+v", inv)
	}
	st, err := r.NodeStorage(ctx, e.remote(), "pve1", "local", tokenOf(pveReadToken))
	if err != nil || st.ID != "local" {
		t.Fatalf("storage %+v %v", st, err)
	}
	if n := e.pve.badAuth.Load(); n != 0 {
		t.Fatalf("%d requests without the read token", n)
	}
	// Without a credential nothing is sent.
	before := e.pve.requests.Load()
	if _, err := r.ClusterInventory(ctx, e.remote(), nil); err == nil {
		t.Fatal("inventory without a read token")
	}
	if e.pve.requests.Load() != before {
		t.Fatal("a request was sent without a credential")
	}
}

// TestPveProvisionReaderTrustChangeBlocksRemote: a remote presenting
// another certificate gets no read token and is blocked, as on the read
// path.
func TestPveProvisionReaderTrustChangeBlocksRemote(t *testing.T) {
	for _, read := range []string{"inventory", "storage"} {
		t.Run(read, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindStandalone)
			r := pveProvisionReaderAPI{agent: pveGuestAgentAPI{s: e.svc}}
			impostor := makeTestChain(t)
			e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
			e.pve.srv.CloseClientConnections()
			var err error
			if read == "inventory" {
				_, err = r.ClusterInventory(context.Background(), e.remote(), tokenOf(pveReadToken))
			} else {
				_, err = r.NodeStorage(context.Background(), e.remote(), "pve1", "local", tokenOf(pveReadToken))
			}
			if err == nil {
				t.Fatal("read from an impostor succeeded")
			}
			if e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
				t.Fatal("a request reached the impostor")
			}
			if rm := e.remote(); rm.State != executordb.StateBlocked {
				t.Fatalf("remote state = %s, want blocked", rm.State)
			}
		})
	}
}

// TestServiceGuestProvisionUnavailableWithoutDataDir: without a data
// directory there is no provisioner and both RPCs fail closed.
func TestServiceGuestProvisionUnavailableWithoutDataDir(t *testing.T) {
	e := newReconcileEnv(t)
	if e.svc.pveMutations().TaskIDs != nil {
		t.Fatal("TaskIDs set without a provisioner")
	}
	spec := testProvisionSpec(bindingOf(PveTemplateRecord{PveTemplateKey: PveTemplateKey{RemoteID: mutRemote, Node: "pve1", Storage: "local-lvm", ImageID: imgUbuntuID}, VMID: 9000}), PveAutomationCredentialRef)
	_, err := e.svc.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{Spec: spec})
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "not available") {
		t.Fatalf("propose: %v", err)
	}
	_, err = e.svc.CommitPVEGuestProvision(context.Background(), &pb.CommitPVEGuestProvisionRequest{Spec: spec,
		ExecutionId: "00000000-0000-4000-c000-000000000001", ExecutionDigest: strings.Repeat("ab", 32)})
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "not available") {
		t.Fatalf("commit: %v", err)
	}
}

// TestServiceGuestProvisionReachesTheProvisioner: on the production wiring
// the propose RPC goes on to the provisioner's checks against the remote
// (here: a read-only remote without action credential) and contacts no
// PVE endpoint.
func TestServiceGuestProvisionReachesTheProvisioner(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	dir := t.TempDir()
	e.svc.SetBackupDirs(dir, filepath.Join(dir, "keys"))
	e.svc.keys = testAutomationKeyring(t)
	tpl := PveTemplateBinding{PveTemplateKey: PveTemplateKey{RemoteID: pveReadRemote, Node: "pve1", Storage: "local-lvm", ImageID: imgUbuntuID},
		VMID: 9000, Generation: 1, SourceSHA256: imgUbuntuSHA}
	spec := testProvisionSpec(tpl, PveAutomationCredentialRef)
	spec.RemoteId = pveReadRemote
	_, err := e.svc.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{Spec: spec})
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "no action credential") {
		t.Fatalf("propose: %v", err)
	}
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("a read-only remote was contacted %d times", n)
	}
}

// TestServiceGuestProvisionRejectsMalformedSpecs: an untrusted spec that
// is missing parts, exceeds a limit or carries a malformed address is
// refused before anything is read or reserved.
func TestServiceGuestProvisionRejectsMalformedSpecs(t *testing.T) {
	e := newReconcileEnv(t)
	dir := t.TempDir()
	e.svc.SetBackupDirs(dir, filepath.Join(dir, "keys"))
	tpl := PveTemplateBinding{PveTemplateKey: PveTemplateKey{RemoteID: mutRemote, Node: "pve1", Storage: "local-lvm", ImageID: imgUbuntuID}, VMID: 9000}
	for name, mutate := range map[string]func(*pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec{
		"nil spec":      func(*pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { return nil },
		"no template":   func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Template = nil; return s },
		"no nic":        func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Nic = nil; return s },
		"too many keys": func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.SshKeys = make([]string, 64); return s },
		"too many dns": func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec {
			s.Nameservers = []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}
			return s
		},
		"bad nameserver": func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec {
			s.Nameservers = []string{"not-an-ip"}
			return s
		},
		"long nameserver": func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec {
			s.Nameservers = []string{strings.Repeat("1", 100)}
			return s
		},
		"huge disk":        func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.DiskGib = 1 << 63; return s },
		"huge cores":       func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Cores = 1 << 31; return s },
		"bad vlan":         func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Nic.Vlan = 5000; return s },
		"bad ipam prefix":  func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Ipam.Prefix = "10.0.0.0/99"; return s },
		"bad ipam address": func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Ipam.Address = "x"; return s },
		"bad ipam gateway": func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Ipam.Gateway = "x"; return s },
		"bad ipam vlan":    func(s *pb.PVEGuestProvisionSpec) *pb.PVEGuestProvisionSpec { s.Ipam.Vlan = 5000; return s },
	} {
		t.Run(name, func(t *testing.T) {
			spec := mutate(testProvisionSpec(tpl, PveAutomationCredentialRef))
			_, err := e.svc.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{Spec: spec})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("propose: %v, want InvalidArgument", err)
			}
		})
	}
	_, err := e.svc.CommitPVEGuestProvision(context.Background(), &pb.CommitPVEGuestProvisionRequest{Spec: testProvisionSpec(tpl, PveAutomationCredentialRef),
		ExecutionId: "00000000-0000-4000-c000-000000000001", ExecutionDigest: "not-a-digest"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("commit with malformed digest: %v", err)
	}
}

// testProvisionSpec mirrors provisionEnv.request as an RPC spec.
func testProvisionSpec(tpl PveTemplateBinding, autoRef string) *pb.PVEGuestProvisionSpec {
	return &pb.PVEGuestProvisionSpec{
		RemoteId: mutRemote, Node: "pve1", Storage: "local-lvm",
		Template: &pb.PVETemplateRef{RemoteId: tpl.RemoteID, Node: tpl.Node, Storage: tpl.Storage, ImageId: tpl.ImageID,
			Vmid: tpl.VMID, Generation: tpl.Generation, SourceSha256: tpl.SourceSHA256},
		Name: "web1.lab.test", Cores: 2, MemoryMib: 4096, DiskGib: 32,
		Nic: &pb.PVEProvisionNIC{Bridge: "vmbr0", Vlan: 10},
		Ipam: &pb.PVEIPAMBinding{NetworkId: "lan", Pool: "servers", Prefix: "192.168.10.0/24", Gateway: "192.168.10.1", Vlan: 10,
			Address: "192.168.10.12", ReservedBy: "admin", ReservedAtUnix: 1_800_000_000},
		CiUser: "nos", Nameservers: []string{"192.168.10.1"}, SearchDomains: []string{"lab.test"}, Start: true,
		AutomationCredentialRef: autoRef,
	}
}

// provisionRPCEnv is a Service whose one engine and provisioner run over
// the provisioning test doubles (prepared template, fake client and
// reader), so the RPCs, the permit flow and the engine wiring are tested
// end to end; the production client and reader are tested on their own.
//
// The keyring holds the designated NOS automation credential
// (PveAutomationCredentialRef, unless noAutomationKey) and an unrelated
// host credential "cred" with another key. The authority verifies
// assertions of one virtual authenticator credential; sign answers a
// challenge with user presence only (presence) or with user verification.
type provisionRPCEnv struct {
	*provisionEnv
	svc     *Service
	keys    *keyring.Keyring
	autoKey string
	hostKey string
	sign    func(challenge []byte, verified bool) []byte
}

// provisionRPCOptions configure newProvisionRPCEnvWith.
type provisionRPCOptions struct {
	// risk is the authority's risk policy under GuestProvisionRiskFloor
	// (default fixedRisk: MEDIUM).
	risk permit.RiskPolicy
	// noAutomationKey leaves the designated credential out of the keyring.
	noAutomationKey bool
}

// sharedAutomationKey is a second credential key, distinct from the
// shared host credential key (testCredentialKey), generated once.
var sharedAutomationKey struct {
	once sync.Once
	pem  []byte
	pub  ssh.PublicKey
	err  error
}

// testAutomationKey returns the encrypted OpenSSH PEM and public key of
// the designated automation credential of the RPC tests.
func testAutomationKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	k := &sharedAutomationKey
	k.once.Do(func() {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			k.err = err
			return
		}
		block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "automation", []byte(testPassphrase))
		if err != nil {
			k.err = err
			return
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			k.err = err
			return
		}
		k.pem, k.pub = pem.EncodeToMemory(block), pub
	})
	if k.err != nil {
		t.Fatal(k.err)
	}
	return append([]byte(nil), k.pem...), k.pub
}

// testAutomationKeyring returns an unlocked keyring holding only the
// designated automation credential.
func testAutomationKeyring(t *testing.T) *keyring.Keyring {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := testAutomationKey(t)
	if err := os.WriteFile(filepath.Join(dir, PveAutomationCredentialRef+".key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	kr := keyring.New(dir)
	if _, err := kr.Unlock([]byte(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	return kr
}

func newProvisionRPCEnv(t *testing.T) *provisionRPCEnv {
	t.Helper()
	return newProvisionRPCEnvWith(t, provisionRPCOptions{})
}

func newProvisionRPCEnvWith(t *testing.T, o provisionRPCOptions) *provisionRPCEnv {
	t.Helper()
	if o.risk == nil {
		o.risk = fixedRisk{}
	}
	e := newProvisionEnv(t, o.risk)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hostPEM, hostPub := testCredentialKey(t)
	if err := os.WriteFile(filepath.Join(keysDir, "cred.key"), hostPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	autoPEM, autoPub := testAutomationKey(t)
	if !o.noAutomationKey {
		if err := os.WriteFile(filepath.Join(keysDir, PveAutomationCredentialRef+".key"), autoPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kr := keyring.New(keysDir)
	if _, err := kr.Unlock([]byte(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}, Counters: e.pe.db},
		[]webauthnverify.Credential{{ID: cred.ID, PublicKey: cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	// The Service's authority verifies the virtual authenticator; the
	// provisioning engine of the env uses the same one.
	auth, err := permit.New(permit.Options{Verifier: v, Store: e.pe.db,
		RiskPolicy: GuestProvisionRiskFloor{Next: o.risk, Linked: noLinkedHosts, Remote: PveRegistryRemoteOf(e.pe.db)}})
	if err != nil {
		t.Fatal(err)
	}
	e.auth, e.m.Auth = auth, auth
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}}, v, e.pe.db)
	if err != nil {
		t.Fatal(err)
	}
	present := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserNotVerified: true})
	present.AddCredential(cred)
	verifying := virtualwebauthn.NewAuthenticator()
	verifying.AddCredential(cred)
	rp := virtualwebauthn.RelyingParty{Name: "Mut", ID: "mut.test", Origin: "https://mut.test"}
	sign := func(challenge []byte, verified bool) []byte {
		dev := present
		if verified {
			dev = verifying
		}
		return []byte(virtualwebauthn.CreateAssertionResponse(rp, dev, cred,
			virtualwebauthn.AssertionOptions{Challenge: challenge, RelyingPartyID: "mut.test"}))
	}
	svc := NewService(e.auth, kr, e.pe.db, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.vault = e.pe.vault
	svc.SetBackupDirs(dir, keysDir)
	m := svc.pveMutations()
	p := svc.pveProvisioner()
	if p == nil {
		t.Fatal("no provisioner")
	}
	// Test doubles for the remote side only; the engine, provisioner,
	// VMID store and authority are the Service's own.
	m.Client, m.PollInterval, m.MaxWait = e.pc, time.Millisecond, 2*time.Second
	imgs := *e.imgs
	imgs.Mutations = m
	p.Images, p.Reader = &imgs, e.reader
	return &provisionRPCEnv{provisionEnv: e, svc: svc, keys: kr, sign: sign,
		autoKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(autoPub))),
		hostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostPub)))}
}

// TestServiceGuestProvisionRunsOnlyWithTheApprovedPermit: the server
// proposes over the RPC (template bound, VMID reserved, risk at least
// MEDIUM); a commit before approval is refused as unapproved and sends
// nothing; after the normal approval the commit runs clone, config, resize
// and start on the Service's one engine with the designated automation key
// (never the host credential); a commit with another spec is refused by the
// permit and a second commit is refused as already used, both sending
// nothing.
func TestServiceGuestProvisionRunsOnlyWithTheApprovedPermit(t *testing.T) {
	e := newProvisionRPCEnv(t)
	ctx := context.Background()
	spec := testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)
	prop, err := e.svc.ProposePVEGuestProvision(ctx, &pb.ProposePVEGuestProvisionRequest{Spec: spec})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if prop.GetVmid() < pvecontract.MinVMID || prop.GetExecutionId() == "" || prop.GetPermit() == nil {
		t.Fatalf("proposal %+v", prop)
	}
	if prop.GetPermit().GetRiskClass() == pb.RiskClass_RISK_CLASS_LOW || prop.GetPermit().GetState() != pb.PermitState_PERMIT_STATE_PENDING {
		t.Fatalf("permit risk %v state %v", prop.GetPermit().GetRiskClass(), prop.GetPermit().GetState())
	}
	d, err := canonical.ParseDigest(prop.GetPermit().GetExecutionDigest())
	if err != nil {
		t.Fatal(err)
	}
	committed := testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)
	committed.Vmid = prop.GetVmid()
	commit := &pb.CommitPVEGuestProvisionRequest{Spec: committed, ExecutionId: prop.GetExecutionId(), ExecutionDigest: d.String()}

	// Not approved yet: refused as not covered by an approved permit,
	// nothing is sent.
	_, err = e.svc.CommitPVEGuestProvision(ctx, commit)
	if st := status.Convert(err); st.Code() != codes.PermissionDenied || !strings.Contains(st.Message(), "no approved permit") {
		t.Fatalf("commit before approval: %v, want PermissionDenied (no approved permit)", err)
	}
	if n := len(e.pc.provisionSteps()); n != 0 {
		t.Fatalf("%d steps sent before approval", n)
	}

	if _, err := e.auth.ApproveCLI(d, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	// Another spec than the approved one is refused by the permit and
	// sends nothing; the approved permit stays usable.
	other := testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)
	other.Vmid, other.Cores = prop.GetVmid(), 4
	_, err = e.svc.CommitPVEGuestProvision(ctx, &pb.CommitPVEGuestProvisionRequest{Spec: other, ExecutionId: commit.ExecutionId, ExecutionDigest: commit.ExecutionDigest})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("commit with a changed spec: %v, want PermissionDenied", err)
	}
	if n := len(e.pc.provisionSteps()); n != 0 {
		t.Fatalf("%d steps sent for a changed spec", n)
	}

	res, err := e.svc.CommitPVEGuestProvision(ctx, commit)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	want := []string{pveStepGuestClone, pveStepGuestConfig, pveStepGuestResize, pveStepGuestStart}
	if got := e.pc.methods(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("steps %v, want %v", got, want)
	}
	if res.GetVmid() != prop.GetVmid() || res.GetExecutionId() != prop.GetExecutionId() || len(res.GetSteps()) != 4 || res.GetGuestKept() {
		t.Fatalf("result %+v", res)
	}
	for _, st := range res.GetSteps() {
		if st.GetState() != string(executordb.PveJobSucceeded) || st.GetUpid() == "" {
			t.Fatalf("step %+v", st)
		}
	}
	cfg := string(e.pc.provisionSteps()[1].Args)
	if !strings.Contains(cfg, strings.Fields(e.autoKey)[1]) {
		t.Fatalf("config step does not carry the designated automation key: %s", cfg)
	}
	if strings.Contains(cfg, strings.Fields(e.hostKey)[1]) {
		t.Fatal("config step carries the host credential's key")
	}

	// Single use: a replay is refused as already used and sends nothing.
	_, err = e.svc.CommitPVEGuestProvision(ctx, commit)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("second commit: %v, want PermissionDenied", err)
	}
	if n := len(e.pc.provisionSteps()); n != 4 {
		t.Fatalf("%d steps after replay, want 4", n)
	}
}

// TestServiceGuestProvisionNeedsTheDesignatedAutomationKey: the production
// provisioner has no fixed automation key and installs only the designated
// NOS automation credential. A spec without a credential ref is a spec
// error; a ref naming any other keyring credential (an unrelated host
// credential the keyring does hold, or an unknown name) is refused as not
// designated; a locked keyring and a keyring without the designated
// credential get their own errors. Nothing is reserved or sent in any case.
func TestServiceGuestProvisionNeedsTheDesignatedAutomationKey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ref      string
		opts     provisionRPCOptions
		lock     bool
		wantCode codes.Code
		wantMsg  string
	}{
		{name: "no ref", ref: "", wantCode: codes.InvalidArgument, wantMsg: "invalid"},
		{name: "host credential", ref: "cred", wantCode: codes.PermissionDenied, wantMsg: "designated"},
		{name: "unknown ref", ref: "no-such-ref", wantCode: codes.PermissionDenied, wantMsg: "designated"},
		{name: "keyring locked", ref: PveAutomationCredentialRef, lock: true, wantCode: codes.FailedPrecondition, wantMsg: "keyring locked"},
		{name: "not in keyring", ref: PveAutomationCredentialRef, opts: provisionRPCOptions{noAutomationKey: true}, wantCode: codes.NotFound, wantMsg: "not in the keyring"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newProvisionRPCEnvWith(t, tc.opts)
			if tc.lock {
				e.keys.Lock()
			}
			spec := testProvisionSpec(bindingOf(e.tpl), tc.ref)
			_, err := e.svc.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{Spec: spec})
			if st := status.Convert(err); st.Code() != tc.wantCode || !strings.Contains(st.Message(), tc.wantMsg) {
				t.Fatalf("ref %q: %v, want %v %q", tc.ref, err, tc.wantCode, tc.wantMsg)
			}
			if strings.Contains(status.Convert(err).Message(), strings.Fields(e.hostKey)[1]) {
				t.Fatal("error carries key material")
			}
			store := e.svc.pveProvisioner().VMIDs.(*FilePveVMIDStore)
			if r, err := store.Reservations(mutRemote, time.Now()); err != nil || len(r) != 0 {
				t.Fatalf("reservations %v %v", r, err)
			}
			if n := len(e.pc.provisionSteps()); n != 0 {
				t.Fatalf("%d steps sent", n)
			}
			if p := e.auth.Pending(); len(p) != 0 {
				t.Fatalf("%d permits registered", len(p))
			}
		})
	}
}

// TestServiceGuestProvisionCommitRefusesAnUndesignatedKey: a commit whose
// spec names a host credential is refused before anything is sent, even
// with a digest of an approved proposal; a locked keyring at commit time
// is reported as such.
func TestServiceGuestProvisionCommitRefusesAnUndesignatedKey(t *testing.T) {
	e := newProvisionRPCEnv(t)
	ctx := context.Background()
	prop, d := e.proposeApproved(t, ctx)
	for _, tc := range []struct {
		name     string
		ref      string
		lock     bool
		wantCode codes.Code
	}{
		{name: "host credential", ref: "cred", wantCode: codes.PermissionDenied},
		{name: "keyring locked", ref: PveAutomationCredentialRef, lock: true, wantCode: codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.lock {
				e.keys.Lock()
			}
			spec := testProvisionSpec(bindingOf(e.tpl), tc.ref)
			spec.Vmid = prop.GetVmid()
			_, err := e.svc.CommitPVEGuestProvision(ctx, &pb.CommitPVEGuestProvisionRequest{Spec: spec, ExecutionId: prop.GetExecutionId(), ExecutionDigest: d.String()})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("commit: %v, want %v", err, tc.wantCode)
			}
			if n := len(e.pc.provisionSteps()); n != 0 {
				t.Fatalf("%d steps sent", n)
			}
		})
	}
}

// TestServiceGuestProvisionResponseFailureReleasesTheVMID: when the
// registered permit cannot be turned into a response, the proposal fails,
// the VMID reservation is released like after an authority refusal, and
// the dropped pending permit cannot run even if it is approved later.
func TestServiceGuestProvisionResponseFailureReleasesTheVMID(t *testing.T) {
	e := newProvisionRPCEnv(t)
	ctx := context.Background()
	var dropped permit.Permit
	failing := func(p permit.Permit) (*pb.ProposeExecutionResponse, error) {
		dropped = p
		return nil, status.Error(codes.Internal, "request options")
	}
	const vmid = 4242
	spec := testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)
	spec.Vmid = vmid
	_, err := e.svc.proposePVEGuestProvision(ctx, &pb.ProposePVEGuestProvisionRequest{Spec: spec}, failing)
	if status.Code(err) != codes.Internal {
		t.Fatalf("propose: %v, want the response error", err)
	}
	if dropped.Digest == (canonical.Digest{}) {
		t.Fatal("no permit was registered")
	}
	store := e.svc.pveProvisioner().VMIDs.(*FilePveVMIDStore)
	if r, err := store.Reservations(mutRemote, time.Now()); err != nil || len(r) != 0 {
		t.Fatalf("reservations after a failed response: %v %v", r, err)
	}

	// The dropped permit, approved anyway, cannot run: its VMID is no
	// longer reserved for its execution.
	if _, err := e.auth.ApproveCLI(dropped.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.CommitPVEGuestProvision(ctx, &pb.CommitPVEGuestProvisionRequest{Spec: spec,
		ExecutionId: dropped.Request.ExecutionID, ExecutionDigest: dropped.Digest.String()})
	if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "not reserved") {
		t.Fatalf("commit of the dropped permit: %v, want FailedPrecondition (vmid not reserved)", err)
	}
	if n := len(e.pc.provisionSteps()); n != 0 {
		t.Fatalf("%d steps sent", n)
	}

	// The VMID is free for the next proposal.
	prop, err := e.svc.ProposePVEGuestProvision(ctx, &pb.ProposePVEGuestProvisionRequest{Spec: spec})
	if err != nil || prop.GetVmid() != vmid {
		t.Fatalf("next proposal: %+v %v, want vmid %d", prop, err, vmid)
	}
}

// TestServiceGuestProvisionRepliesBeforeTheCallerDeadline: a clone task
// that outlasts the caller's deadline does not swallow the run: the commit
// stops waiting shortly before the deadline and returns the execution and
// the step states (clone still running, UPID recorded) while the caller
// still listens, so the run page can follow the execution.
func TestServiceGuestProvisionRepliesBeforeTheCallerDeadline(t *testing.T) {
	e := newProvisionRPCEnv(t)
	prop, d := e.proposeApproved(t, context.Background())
	e.svc.pveMutations().MaxWait = time.Hour
	e.pc.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{Running: true}, nil }
	committed := testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)
	committed.Vmid = prop.GetVmid()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := e.svc.CommitPVEGuestProvision(ctx, &pb.CommitPVEGuestProvisionRequest{Spec: committed,
		ExecutionId: prop.GetExecutionId(), ExecutionDigest: d.String()})
	if ctx.Err() != nil {
		t.Fatalf("commit returned after the caller deadline: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("commit: %v, want the step states", err)
	}
	if res.GetExecutionId() != prop.GetExecutionId() || len(res.GetSteps()) != 1 || !res.GetGuestKept() {
		t.Fatalf("result %+v", res)
	}
	if st := res.GetSteps()[0]; st.GetState() != string(executordb.PveJobRunning) || st.GetUpid() == "" {
		t.Fatalf("clone step %+v, want running with its UPID", st)
	}
}

// TestPveProvisionRunContextEndsBeforeTheDeadline: the run context ends
// the reply margin before the caller's deadline, at most half the
// remaining time, and has no deadline when the caller has none.
func TestPveProvisionRunContextEndsBeforeTheDeadline(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name   string
		remain time.Duration
		want   time.Duration
	}{
		{name: "long", remain: time.Hour, want: time.Hour - pveProvisionReplyMargin},
		{name: "short", remain: 10 * time.Second, want: 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithDeadline(context.Background(), now.Add(tc.remain))
			defer cancel()
			ctx, cancelRun := pveProvisionRunContext(parent, now)
			defer cancelRun()
			dl, ok := ctx.Deadline()
			if !ok || !dl.Equal(now.Add(tc.want)) {
				t.Fatalf("deadline %v (%v), want %v", dl.Sub(now), ok, tc.want)
			}
		})
	}
	ctx, cancel := pveProvisionRunContext(context.Background(), now)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("deadline without a caller deadline")
	}
}

// TestPveGuestProvisionRunBoundCoversEveryStep: the commit bound a client
// sizes its deadline by covers the task wait of every step of a full
// provisioning (clone, config, resize, start) plus slack for the reads.
func TestPveGuestProvisionRunBoundCoversEveryStep(t *testing.T) {
	e := newProvisionRPCEnv(t)
	prop, d := e.proposeApproved(t, context.Background())
	committed := testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)
	committed.Vmid = prop.GetVmid()
	res, err := e.svc.CommitPVEGuestProvision(context.Background(), &pb.CommitPVEGuestProvisionRequest{Spec: committed,
		ExecutionId: prop.GetExecutionId(), ExecutionDigest: d.String()})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.GetSteps()); n > pveGuestProvisionMaxSteps {
		t.Fatalf("%d steps, more than pveGuestProvisionMaxSteps %d", n, pveGuestProvisionMaxSteps)
	}
	if PveGuestProvisionRunBound < time.Duration(pveGuestProvisionMaxSteps)*pveTaskMaxWait+pveProvisionReplyMargin {
		t.Fatalf("run bound %v does not cover %d task waits of %v", PveGuestProvisionRunBound, pveGuestProvisionMaxSteps, pveTaskMaxWait)
	}
}

// highRisk is a risk policy that records every target as HIGH.
type highRisk struct{}

func (highRisk) MinimumRisk(canonical.Request, []canonical.Target) (canonical.Risk, string, error) {
	return canonical.RiskHigh, "test", nil
}

// commitAfterWebAuthn plays the server of variant B (ADR 0008 section 3):
// it relays the user's assertion over the given challenge to the executor
// (SubmitAssertion) and then commits the proposed provisioning.
func (e *provisionRPCEnv) commitAfterWebAuthn(t *testing.T, prop *pb.ProposePVEGuestProvisionResponse, verified bool) (*pb.SubmitAssertionResponse, error, *pb.CommitPVEGuestProvisionResponse, error) {
	t.Helper()
	ctx := context.Background()
	if active, _ := e.auth.Session(); !active {
		e.openSession(t)
	}
	digest := prop.GetPermit().GetExecutionDigest()
	approved, approveErr := e.svc.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: digest,
		AssertionJson: e.sign(prop.GetPermit().GetChallenge(), verified)})
	committed := testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)
	committed.Vmid = prop.GetVmid()
	res, err := e.svc.CommitPVEGuestProvision(ctx, &pb.CommitPVEGuestProvisionRequest{Spec: committed,
		ExecutionId: prop.GetExecutionId(), ExecutionDigest: digest})
	return approved, approveErr, res, err
}

// openSession opens the privileged browser session browser approvals need
// (a user-verified assertion over the session challenge).
func (e *provisionRPCEnv) openSession(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	b, err := e.svc.BeginPrivilegedSession(ctx, &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CompletePrivilegedSession(ctx, &pb.CompletePrivilegedSessionRequest{AssertionJson: e.sign(b.GetChallenge(), true)}); err != nil {
		t.Fatalf("privileged session: %v", err)
	}
}

// TestServiceGuestProvisionRunsAfterWebAuthnPresenceApproval: end to end
// over the RPCs, variant B. The executor proposes at MEDIUM and asks for a
// WebAuthn approval with user presence (challenge and request options in
// the response); within the privileged browser session the server relays
// the user's presence-only assertion and then starts the run, which
// provisions the guest with the designated automation key.
func TestServiceGuestProvisionRunsAfterWebAuthnPresenceApproval(t *testing.T) {
	e := newProvisionRPCEnv(t)
	prop, err := e.svc.ProposePVEGuestProvision(context.Background(),
		&pb.ProposePVEGuestProvisionRequest{Spec: testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	pm := prop.GetPermit()
	if pm.GetRiskClass() != pb.RiskClass_RISK_CLASS_MEDIUM || pm.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE ||
		len(pm.GetChallenge()) == 0 || len(pm.GetRequestOptionsJson()) == 0 {
		t.Fatalf("permit risk %v requirement %v challenge %d options %d", pm.GetRiskClass(), pm.GetApprovalRequirement(), len(pm.GetChallenge()), len(pm.GetRequestOptionsJson()))
	}
	approved, approveErr, res, err := e.commitAfterWebAuthn(t, prop, false)
	if approveErr != nil || approved.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		t.Fatalf("presence approval: %+v %v", approved, approveErr)
	}
	if err != nil {
		t.Fatalf("commit after approval: %v", err)
	}
	want := []string{pveStepGuestClone, pveStepGuestConfig, pveStepGuestResize, pveStepGuestStart}
	if got := e.pc.methods(); strings.Join(got, ",") != strings.Join(want, ",") || len(res.GetSteps()) != len(want) {
		t.Fatalf("steps %v (result %d), want %v", got, len(res.GetSteps()), want)
	}
	if cfg := string(e.pc.provisionSteps()[1].Args); !strings.Contains(cfg, strings.Fields(e.autoKey)[1]) {
		t.Fatal("config step does not carry the designated automation key")
	}
}

// TestServiceGuestProvisionRaisedRiskNeedsUserVerification: when the
// authority's risk policy raises the provisioning above MEDIUM, the permit
// requires WebAuthn user verification. A presence-only assertion is
// refused, the permit stays pending and the server's commit is refused as
// unapproved without sending anything; a user-verified assertion approves
// it and the run goes through.
func TestServiceGuestProvisionRaisedRiskNeedsUserVerification(t *testing.T) {
	e := newProvisionRPCEnvWith(t, provisionRPCOptions{risk: highRisk{}})
	prop, err := e.svc.ProposePVEGuestProvision(context.Background(),
		&pb.ProposePVEGuestProvisionRequest{Spec: testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	pm := prop.GetPermit()
	if pm.GetRiskClass() != pb.RiskClass_RISK_CLASS_HIGH || pm.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		t.Fatalf("permit risk %v requirement %v, want HIGH with user verification", pm.GetRiskClass(), pm.GetApprovalRequirement())
	}

	_, approveErr, _, err := e.commitAfterWebAuthn(t, prop, false)
	if status.Code(approveErr) != codes.PermissionDenied {
		t.Fatalf("presence-only approval of a HIGH permit: %v, want PermissionDenied", approveErr)
	}
	d, perr := canonical.ParseDigest(pm.GetExecutionDigest())
	if perr != nil {
		t.Fatal(perr)
	}
	if st, ok := e.auth.PermitState(d); !ok || st != permit.StatePending {
		t.Fatalf("permit state %v %v after a refused approval, want pending", st, ok)
	}
	if st := status.Convert(err); st.Code() != codes.PermissionDenied || !strings.Contains(st.Message(), "no approved permit") {
		t.Fatalf("commit after a refused approval: %v, want PermissionDenied (no approved permit)", err)
	}
	if n := len(e.pc.provisionSteps()); n != 0 {
		t.Fatalf("%d steps sent without user verification", n)
	}

	approved, approveErr, res, err := e.commitAfterWebAuthn(t, prop, true)
	if approveErr != nil || approved.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		t.Fatalf("verified approval: %+v %v", approved, approveErr)
	}
	if err != nil || len(res.GetSteps()) != 4 {
		t.Fatalf("commit after verified approval: %+v %v", res, err)
	}
}

// proposeApproved proposes the designated-key spec over the RPC and
// approves it with the CLI.
func (e *provisionRPCEnv) proposeApproved(t *testing.T, ctx context.Context) (*pb.ProposePVEGuestProvisionResponse, canonical.Digest) {
	t.Helper()
	prop, err := e.svc.ProposePVEGuestProvision(ctx, &pb.ProposePVEGuestProvisionRequest{Spec: testProvisionSpec(bindingOf(e.tpl), PveAutomationCredentialRef)})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	d, err := canonical.ParseDigest(prop.GetPermit().GetExecutionDigest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(d, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	return prop, d
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
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
	key, err := p.AutomationKeys("cred")
	if err != nil || key != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.userPub))) {
		t.Fatalf("automation key = %q, %v", key, err)
	}
	if _, err := p.AutomationKeys("no-such-ref"); err == nil {
		t.Fatal("unknown credential ref resolved")
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
	spec := testProvisionSpec(bindingOf(PveTemplateRecord{PveTemplateKey: PveTemplateKey{RemoteID: mutRemote, Node: "pve1", Storage: "local-lvm", ImageID: imgUbuntuID}, VMID: 9000}), "cred")
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
	tpl := PveTemplateBinding{PveTemplateKey: PveTemplateKey{RemoteID: pveReadRemote, Node: "pve1", Storage: "local-lvm", ImageID: imgUbuntuID},
		VMID: 9000, Generation: 1, SourceSHA256: imgUbuntuSHA}
	spec := testProvisionSpec(tpl, "cred")
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
			spec := mutate(testProvisionSpec(tpl, "cred"))
			_, err := e.svc.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{Spec: spec})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("propose: %v, want InvalidArgument", err)
			}
		})
	}
	_, err := e.svc.CommitPVEGuestProvision(context.Background(), &pb.CommitPVEGuestProvisionRequest{Spec: testProvisionSpec(tpl, "cred"),
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
type provisionRPCEnv struct {
	*provisionEnv
	svc     *Service
	autoKey string
}

func newProvisionRPCEnv(t *testing.T) *provisionRPCEnv {
	t.Helper()
	e := newProvisionEnv(t, fixedRisk{})
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPEM, pub := testCredentialKey(t)
	if err := os.WriteFile(filepath.Join(keysDir, "cred.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	kr := keyring.New(keysDir)
	if _, err := kr.Unlock([]byte(testPassphrase)); err != nil {
		t.Fatal(err)
	}
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}, Counters: e.pe.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}}, v, e.pe.db)
	if err != nil {
		t.Fatal(err)
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
	return &provisionRPCEnv{provisionEnv: e, svc: svc, autoKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))}
}

// TestServiceGuestProvisionRunsOnlyWithTheApprovedPermit: the server
// proposes over the RPC (template bound, VMID reserved, risk at least
// MEDIUM); a commit before approval sends nothing; after the normal
// approval the commit runs clone, config, resize and start on the
// Service's one engine with the keyring's automation key; a second commit
// and a commit with another spec are refused and send nothing.
func TestServiceGuestProvisionRunsOnlyWithTheApprovedPermit(t *testing.T) {
	e := newProvisionRPCEnv(t)
	ctx := context.Background()
	spec := testProvisionSpec(bindingOf(e.tpl), "cred")
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
	committed := testProvisionSpec(bindingOf(e.tpl), "cred")
	committed.Vmid = prop.GetVmid()
	commit := &pb.CommitPVEGuestProvisionRequest{Spec: committed, ExecutionId: prop.GetExecutionId(), ExecutionDigest: d.String()}

	// Not approved yet: nothing is sent.
	if _, err := e.svc.CommitPVEGuestProvision(ctx, commit); err == nil {
		t.Fatal("commit before approval succeeded")
	}
	if n := len(e.pc.provisionSteps()); n != 0 {
		t.Fatalf("%d steps sent before approval", n)
	}

	if _, err := e.auth.ApproveCLI(d, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	// Another spec than the approved one is refused and sends nothing.
	other := testProvisionSpec(bindingOf(e.tpl), "cred")
	other.Vmid, other.Cores = prop.GetVmid(), 4
	if _, err := e.svc.CommitPVEGuestProvision(ctx, &pb.CommitPVEGuestProvisionRequest{Spec: other, ExecutionId: commit.ExecutionId, ExecutionDigest: commit.ExecutionDigest}); err == nil {
		t.Fatal("commit with a changed spec succeeded")
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
		t.Fatalf("config step does not carry the keyring automation key: %s", cfg)
	}

	// Single use: a replay sends nothing.
	if _, err := e.svc.CommitPVEGuestProvision(ctx, commit); err == nil {
		t.Fatal("second commit succeeded")
	}
	if n := len(e.pc.provisionSteps()); n != 4 {
		t.Fatalf("%d steps after replay, want 4", n)
	}
}

// TestServiceGuestProvisionNeedsAKeyringAutomationKey: the production
// provisioner has no fixed automation key; a spec without a credential
// ref, or with one the keyring does not hold, is refused and nothing is
// reserved or sent.
func TestServiceGuestProvisionNeedsAKeyringAutomationKey(t *testing.T) {
	e := newProvisionRPCEnv(t)
	for _, ref := range []string{"", "no-such-ref"} {
		spec := testProvisionSpec(bindingOf(e.tpl), ref)
		_, err := e.svc.ProposePVEGuestProvision(context.Background(), &pb.ProposePVEGuestProvisionRequest{Spec: spec})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("ref %q: %v, want InvalidArgument", ref, err)
		}
	}
	store := e.svc.pveProvisioner().VMIDs.(*FilePveVMIDStore)
	if r, err := store.Reservations(mutRemote, time.Now()); err != nil || len(r) != 0 {
		t.Fatalf("reservations %v %v", r, err)
	}
	if n := len(e.pc.provisionSteps()); n != 0 {
		t.Fatalf("%d steps sent", n)
	}
}

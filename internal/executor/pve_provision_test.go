// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const provPassword = "Corr3ct-Horse-Battery"

var provArtifact = []byte("pve.guest.provision 1.0.0\nProvision one guest from a prepared template.\n")

func testAuthorizedKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if comment != "" {
		line += " " + comment
	}
	return line
}

// provisionClient extends the image client with the provisioning step
// allowlist; UPIDs name the source (clone) or the new guest.
type provisionClient struct {
	*imageClient
	pmu    sync.Mutex
	psteps []PveMutationStep
	// onStep may replace the UPID of the n-th provisioning step (1-based).
	onStep func(n int, step PveMutationStep, upid string) (string, error)
	// onRecent runs before every task listing.
	onRecent func()
	// onTaskType runs before every provisioning task type lookup.
	onTaskType func()
}

func (c *provisionClient) RecentTasks(ctx context.Context, rm executordb.PveRemote, node string, since time.Time, tok pveapi.TokenSupplier) ([]string, error) {
	c.pmu.Lock()
	on := c.onRecent
	c.pmu.Unlock()
	if on != nil {
		on()
	}
	return c.imageClient.RecentTasks(ctx, rm, node, since, tok)
}

func (c *provisionClient) TaskType(method string) (string, bool) {
	c.pmu.Lock()
	on := c.onTaskType
	c.pmu.Unlock()
	if on != nil {
		if _, ok := ProvisionStepTaskType(method); ok {
			on()
		}
	}
	if tt, ok := ProvisionStepTaskType(method); ok {
		return tt, true
	}
	return ImageStepTaskType(method)
}

func (c *provisionClient) TaskID(step PveMutationStep) (string, bool) {
	return ProvisionStepTaskID(step)
}

func stepVMIDs(step PveMutationStep) (src, dst string) {
	var a map[string]any
	_ = json.Unmarshal(step.Args, &a)
	f := func(k string) string {
		if v, ok := a[k].(float64); ok {
			return fmt.Sprint(int64(v))
		}
		return ""
	}
	if step.Method == pveStepGuestClone {
		return f("source_vmid"), f("new_vmid")
	}
	return f("vmid"), f("vmid")
}

func (c *provisionClient) Dispatch(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, tok pveapi.TokenSupplier) (string, error) {
	tt, ok := ProvisionStepTaskType(step.Method)
	if !ok {
		return c.imageClient.Dispatch(ctx, rm, node, step, tok)
	}
	_, _ = c.fakeMutClient.Dispatch(ctx, rm, node, step, tok)
	c.pmu.Lock()
	c.psteps = append(c.psteps, step)
	n := len(c.psteps)
	on := c.onStep
	c.pmu.Unlock()
	id, _ := stepVMIDs(step)
	upid := testTaskUPID(node, time.Now(), tt, id, mutActionUser, 500+n)
	if on != nil {
		return on(n, step, upid)
	}
	return upid, nil
}

func (c *provisionClient) provisionSteps() []PveMutationStep {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	return append([]PveMutationStep(nil), c.psteps...)
}

func (c *provisionClient) methods() []string {
	var out []string
	for _, s := range c.provisionSteps() {
		out = append(out, s.Method)
	}
	return out
}

// fakeProvisionReader serves a cluster guest list and one storage.
type fakeProvisionReader struct {
	mu      sync.Mutex
	inv     pveapi.ClusterInventory
	storage pveapi.Storage
	headers []string
}

func (r *fakeProvisionReader) ClusterInventory(ctx context.Context, _ executordb.PveRemote, tok pveapi.TokenSupplier) (pveapi.ClusterInventory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.headers = append(r.headers, header(ctx, tok))
	inv := r.inv
	inv.Guests = append([]pveapi.Guest(nil), r.inv.Guests...)
	return inv, nil
}

func (r *fakeProvisionReader) NodeStorage(ctx context.Context, _ executordb.PveRemote, _, storage string, tok pveapi.TokenSupplier) (pveapi.Storage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.headers = append(r.headers, header(ctx, tok))
	if storage != r.storage.ID {
		return pveapi.Storage{}, errors.New("no such storage")
	}
	return r.storage, nil
}

func (r *fakeProvisionReader) addGuest(node string, vmid int, mem uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inv.Guests = append(r.inv.Guests, pveapi.Guest{Node: node, VMID: vmid, MaxMemory: int64(mem)})
}

type provisionEnv struct {
	*imagesEnv
	pc       *provisionClient
	reader   *fakeProvisionReader
	vmids    *FilePveVMIDStore
	prov     *PveProvisioner
	tpl      PveTemplateRecord
	autoKey  string
	extraKey string
}

// newProvisionEnv prepares template 9000 on pve1 and wires a provisioner
// whose authority enforces GuestProvisionRiskFloor over next (fixedRisk:
// every criticality counts as recorded MEDIUM).
func newProvisionEnv(t *testing.T, next permit.RiskPolicy) *provisionEnv {
	t.Helper()
	ie := newImagesEnv(t)
	pc := &provisionClient{imageClient: ie.client}
	ie.m.Client = pc
	tpl := ie.prepare(prepareReq(imgUbuntuID, 9000))
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}, Counters: ie.pe.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: v, Store: ie.pe.db, RiskPolicy: GuestProvisionRiskFloor{Next: next, Linked: noLinkedHosts}})
	if err != nil {
		t.Fatal(err)
	}
	ie.auth, ie.m.Auth = auth, auth
	reader := &fakeProvisionReader{
		inv: pveapi.ClusterInventory{
			Nodes:  []pveapi.Node{{Name: "pve1", MaxMemory: 64 * gib}, {Name: "pve2", MaxMemory: 64 * gib}},
			Guests: []pveapi.Guest{{Node: "pve1", VMID: 9000, MaxMemory: int64(gib)}, {Node: "pve2", VMID: 100, MaxMemory: int64(4 * gib)}},
		},
		storage: pveapi.Storage{ID: "local-lvm", Active: true, CapacityKnown: true, TotalBytes: 500 * gib, UsedBytes: 100 * gib},
	}
	vmids := &FilePveVMIDStore{Path: filepath.Join(t.TempDir(), "pve-vmids.json")}
	e := &provisionEnv{imagesEnv: ie, pc: pc, reader: reader, vmids: vmids, tpl: tpl,
		autoKey: testAuthorizedKey(t, "nos-automation"), extraKey: testAuthorizedKey(t, "alice@laptop")}
	e.prov = &PveProvisioner{Mutations: ie.m, Images: ie.imgs, Reader: reader, VMIDs: vmids, Passwords: ie.pe.vault,
		AutomationKey: e.autoKey, Artifact: provArtifact, ModuleVersion: "1.0.0"}
	ie.m.TaskIDs = e.prov
	return e
}

// restartProvisioner simulates an executor restart: a new engine (no
// in-memory state) wired to the same provisioner, stores and client.
func (e *provisionEnv) restartProvisioner() {
	e.t.Helper()
	e.restart()
	e.m.Client = e.pc
	e.m.TaskIDs = e.prov
	e.prov.Mutations = e.m
}

func (e *provisionEnv) request() PveProvisionRequest {
	return PveProvisionRequest{
		RemoteID: mutRemote, Node: "pve1", Storage: "local-lvm", Template: bindingOf(e.tpl),
		Name: "web1.lab.test", Cores: 2, MemoryMiB: 4096, DiskGiB: 32,
		NIC: PveProvisionNIC{Bridge: "vmbr0", VLAN: 10},
		IPAM: &PveIPAMBinding{NetworkID: "lan", Pool: "servers", Prefix: netip.MustParsePrefix("192.168.10.0/24"),
			Gateway: netip.MustParseAddr("192.168.10.1"), VLAN: 10, Address: netip.MustParseAddr("192.168.10.12"),
			ReservedBy: "admin", ReservedAtUnix: 1_800_000_000},
		CIUser: "nos", SSHKeys: []string{e.extraKey}, Nameservers: []netip.Addr{netip.MustParseAddr("192.168.10.1")},
		SearchDomains: []string{"lab.test"}, Start: true,
	}
}

var provExecSeq int

func nextProvExec() string {
	provExecSeq++
	return fmt.Sprintf("00000000-0000-4000-c000-%012d", provExecSeq)
}

// propose builds and registers a proposal of req; it returns the pending
// permit and the reserved VMID.
func (e *provisionEnv) propose(req PveProvisionRequest) (permit.Permit, PveProvisionProposal) {
	e.t.Helper()
	pp, err := e.prov.ProposalRequest(context.Background(), req, nextProvExec(), canonical.RiskLow, strings.Repeat("c", 64), time.Now().Add(time.Hour))
	if err != nil {
		e.t.Fatal(err)
	}
	res, err := e.auth.ProposeAtLeastMinimum(pp.Request, pp.Parameters)
	if err != nil {
		e.t.Fatal(err)
	}
	return res.Permit, pp
}

// approve proposes and approves req and returns it ready for Provision.
func (e *provisionEnv) approve(req PveProvisionRequest) PveProvisionRequest {
	e.t.Helper()
	p, pp := e.propose(req)
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest, req.ExecutionID, req.VMID = p.Digest, p.Request.ExecutionID, pp.VMID
	return req
}

func (e *provisionEnv) setPassword() {
	e.t.Helper()
	if _, err := e.prov.SetGuestPassword("web1", []byte(provPassword), "admin"); err != nil {
		e.t.Fatal(err)
	}
}

// noPassword fails if the guest password appears anywhere the server or a
// log reader could see it.
func (e *provisionEnv) noPassword(err error, executionID string, params []byte) {
	e.t.Helper()
	e.noSecrets(err, executionID)
	if err != nil && strings.Contains(err.Error(), provPassword) {
		e.t.Fatalf("error carries the password: %v", err)
	}
	if strings.Contains(e.logs.String(), provPassword) {
		e.t.Fatal("log carries the password")
	}
	if strings.Contains(string(params), provPassword) {
		e.t.Fatal("parameters carry the password")
	}
	steps, _ := e.pe.db.PveJobSteps(executionID)
	if strings.Contains(fmt.Sprintf("%+v", steps), provPassword) {
		e.t.Fatal("job record carries the password")
	}
}

func TestProvisionProposalBindsExactConfiguration(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	e.setPassword()
	req := e.request()
	req.PasswordID = "web1"
	p, pp := e.propose(req)
	if pp.VMID != 101 {
		t.Fatalf("vmid %d, want 101 (100 and 9000 are live)", pp.VMID)
	}
	if p.Request.RiskClass != canonical.RiskMedium || p.Request.ActionID != PveGuestProvisionAction {
		t.Fatalf("request %+v", p.Request)
	}
	var doc struct {
		Parameters pveProvisionPlan `json:"parameters"`
	}
	if err := json.Unmarshal(p.Parameters, &doc); err != nil {
		t.Fatal(err)
	}
	plan := doc.Parameters
	tp := plan.Template
	if tp.RemoteID != mutRemote || tp.Node != "pve1" || tp.VMID != 9000 || tp.Generation != e.tpl.Generation || tp.SourceSHA256 != imgUbuntuSHA ||
		tp.ConfigDigest != e.tpl.ConfigDigest || tp.ImageID != imgUbuntuID {
		t.Fatalf("template binding %+v", tp)
	}
	g := plan.Guest
	if g.VMID != 101 || g.Name != "web1.lab.test" || g.Storage != "local-lvm" || g.Cores != 2 || g.MemoryMiB != 4096 || g.Disk != "scsi0" ||
		g.DiskGiB != 32 || g.Net0 != (pveProvisionNet0{Model: "virtio", Bridge: "vmbr0", Tag: 10}) {
		t.Fatalf("guest %+v", g)
	}
	n := plan.Network
	if n.Mode != "ipam" || n.NetworkID != "lan" || n.Pool != "servers" || n.Prefix != "192.168.10.0/24" || n.Address != "192.168.10.12" ||
		n.Gateway != "192.168.10.1" || n.VLAN != 10 || n.ReservedBy != "admin" || n.ReservedAtUnix != 1_800_000_000 {
		t.Fatalf("network %+v", n)
	}
	ci := plan.CloudInit
	auto, _ := canonicalAuthorizedKey(e.autoKey)
	extra, _ := canonicalAuthorizedKey(e.extraKey)
	if ci.CIUser != "nos" || len(ci.SSHKeys) != 2 || ci.SSHKeys[0] != auto || ci.SSHKeys[1] != extra ||
		ci.IPConfig0 != (pveProvisionIP{Address: "192.168.10.12/24", Gateway: "192.168.10.1"}) ||
		strings.Join(ci.Nameservers, ",") != "192.168.10.1" || strings.Join(ci.SearchDomains, ",") != "lab.test" {
		t.Fatalf("cloud-init %+v", ci)
	}
	if ci.Password == nil || ci.Password.Ref != "pve-guestpw-web1" || ci.Password.Version != 1 {
		t.Fatalf("password binding %+v", ci.Password)
	}
	if !plan.Start || plan.Capacity != (PveProvisionCapacity{}) || !validHexDigest(plan.ConfigDigest) {
		t.Fatalf("plan %+v", plan)
	}
	var methods []string
	for _, s := range plan.Steps {
		methods = append(methods, s.Method)
	}
	if strings.Join(methods, ",") != "pve.guest.clone,pve.guest.config,pve.guest.resize,pve.guest.start" {
		t.Fatalf("steps %v", methods)
	}
	// The binding is a node target with the executor's own registry identity.
	if !strings.Contains(string(p.Parameters), `"kind":"node"`) || !strings.Contains(string(p.Parameters), `"node":"pve1"`) {
		t.Fatalf("binding target: %s", p.Parameters)
	}
	// The VMID is reserved for this execution.
	h, ok, err := e.vmids.VMIDHolder(mutRemote, 101, time.Now())
	if err != nil || !ok || h.ExecutionID != p.Request.ExecutionID {
		t.Fatalf("holder %+v %v %v", h, ok, err)
	}
	for _, hd := range e.reader.headers {
		if hd != "PVEAPIToken="+mutReadToken {
			t.Fatalf("reads used %q", hd)
		}
	}
	e.noPassword(nil, p.Request.ExecutionID, p.Parameters)

	// Any changed field gives other parameters (another permit).
	other := e.request()
	other.PasswordID = "web1"
	other.IPAM.Address = netip.MustParseAddr("192.168.10.13")
	p2, _ := e.propose(other)
	if p2.Request.ParametersHash == p.Request.ParametersHash {
		t.Fatal("another address gives the same parameters")
	}
}

func TestProvisionDHCPWithoutPasswordAndNoStart(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	req := e.request()
	req.IPAM, req.NIC.VLAN, req.Start, req.SSHKeys = nil, 0, false, nil
	req.NIC.MAC = "BC:24:11:00:00:01"
	res, err := e.prov.Provision(context.Background(), e.approve(req))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(e.pc.methods(), ",") != "pve.guest.clone,pve.guest.config,pve.guest.resize" {
		t.Fatalf("steps %v", e.pc.methods())
	}
	var a pveConfigArgs
	if err := json.Unmarshal(e.pc.provisionSteps()[1].Args, &a); err != nil {
		t.Fatal(err)
	}
	auto, _ := canonicalAuthorizedKey(e.autoKey)
	if !a.IPConfig0.DHCP || a.PasswordRef != "" || len(a.SSHKeys) != 1 || a.SSHKeys[0] != auto || a.Net0.MAC != "bc:24:11:00:00:01" || !a.Agent {
		t.Fatalf("config args %+v", a)
	}
	if res.GuestKept || res.GuestConfigDigest == "" {
		t.Fatalf("result %+v", res)
	}
}

// guestServer is a loopback PVE that answers each provisioning write with
// a well-formed UPID and records the forms.
type guestServer struct {
	mu    sync.Mutex
	paths []string
	forms []url.Values
}

func (s *guestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	s.mu.Lock()
	s.paths = append(s.paths, r.Method+" "+r.URL.Path)
	s.forms = append(s.forms, form)
	n := len(s.paths)
	s.mu.Unlock()
	parts := strings.Split(r.URL.Path, "/")
	vmid := parts[len(parts)-2]
	if vmid == "status" {
		vmid = parts[len(parts)-3]
	}
	typ := map[string]string{"clone": "qmclone", "config": "qmconfig", "resize": "resize", "start": "qmstart"}[parts[len(parts)-1]]
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"data":"%s"}`, testTaskUPID("pve1", time.Now(), typ, vmid, mutActionUser, n))
}

func (s *guestServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.paths)
}

func newGuestWriter(t *testing.T, s *guestServer) *pveapi.Writer {
	t.Helper()
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	w, err := pveapi.NewWriter(ts.URL, ts.Client(), func(context.Context) (string, error) { return "PVEAPIToken=" + mutActionToken, nil }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestProvisionRunsCloneConfigResizeStartAsTypedCalls(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	e.setPassword()
	req := e.request()
	req.PasswordID = "web1"
	req = e.approve(req)
	res, err := e.prov.Provision(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(e.pc.methods(), ",") != "pve.guest.clone,pve.guest.config,pve.guest.resize,pve.guest.start" {
		t.Fatalf("steps %v", e.pc.methods())
	}
	if len(res.Steps) != 4 || res.VMID != 101 || res.GuestKept || res.GuestConfigDigest == "" {
		t.Fatalf("result %+v", res)
	}
	for _, s := range res.Steps {
		if s.State != executordb.PveJobSucceeded || s.UPID == "" || s.Node != "pve1" || s.Action != PveGuestProvisionAction {
			t.Fatalf("step %+v", s)
		}
	}
	for _, d := range e.client.fakeMutClient.dispatches {
		if d.header != "PVEAPIToken="+mutActionToken {
			t.Fatalf("dispatch used %q", d.header)
		}
	}
	// The reservation ends once the guest exists.
	if _, ok, _ := e.vmids.VMIDHolder(mutRemote, 101, time.Now()); ok {
		t.Fatal("reservation kept after success")
	}

	// The approved steps become exactly these PVE calls.
	gs := &guestServer{}
	w := newGuestWriter(t, gs)
	for _, s := range e.pc.provisionSteps() {
		if _, err := DispatchProvisionStep(context.Background(), w, e.pe.vault, "pve1", s); err != nil {
			t.Fatalf("%s: %v", s.Method, err)
		}
	}
	wantPaths := []string{"POST /api2/json/nodes/pve1/qemu/9000/clone", "POST /api2/json/nodes/pve1/qemu/101/config",
		"PUT /api2/json/nodes/pve1/qemu/101/resize", "POST /api2/json/nodes/pve1/qemu/101/status/start"}
	if strings.Join(gs.paths, "|") != strings.Join(wantPaths, "|") {
		t.Fatalf("paths %v", gs.paths)
	}
	clone, cfg, resize := gs.forms[0], gs.forms[1], gs.forms[2]
	if clone.Get("newid") != "101" || clone.Get("full") != "1" || clone.Get("name") != "web1.lab.test" || clone.Get("storage") != "local-lvm" {
		t.Fatalf("clone %v", clone)
	}
	auto, _ := canonicalAuthorizedKey(e.autoKey)
	extra, _ := canonicalAuthorizedKey(e.extraKey)
	keys, _ := url.QueryUnescape(cfg.Get("sshkeys"))
	if cfg.Get("ipconfig0") != "ip=192.168.10.12/24,gw=192.168.10.1" || cfg.Get("ciuser") != "nos" || cfg.Get("nameserver") != "192.168.10.1" ||
		cfg.Get("searchdomain") != "lab.test" || cfg.Get("net0") != "virtio,bridge=vmbr0,tag=10" || cfg.Get("cores") != "2" ||
		cfg.Get("memory") != "4096" || cfg.Get("agent") != "enabled=1" || cfg.Get("name") != "web1.lab.test" ||
		keys != auto+"\n"+extra || cfg.Get("cipassword") != provPassword {
		t.Fatalf("config %v (keys %q)", cfg, keys)
	}
	for k := range cfg {
		switch k {
		case "name", "cores", "memory", "agent", "net0", "ipconfig0", "ciuser", "sshkeys", "cipassword", "nameserver", "searchdomain":
		default:
			t.Fatalf("config sent %s", k)
		}
	}
	if resize.Get("disk") != "scsi0" || resize.Get("size") != "32G" {
		t.Fatalf("resize %v", resize)
	}
	e.noPassword(nil, res.ExecutionID, nil)
}

func TestProvisionPasswordStaysOnTheExecutor(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	for _, bad := range []string{"short", "has\nnewline-in-it", strings.Repeat("x", 257)} {
		if _, err := e.prov.SetGuestPassword("web1", []byte(bad), "admin"); !errors.Is(err, ErrPveGuestPassword) {
			t.Fatalf("password %q: %v", bad, err)
		}
	}
	if _, err := e.prov.SetGuestPassword("Bad ID", []byte(provPassword), "admin"); !errors.Is(err, ErrPveProvisionInvalid) {
		t.Fatalf("bad id: %v", err)
	}
	// A missing password refuses the proposal.
	req := e.request()
	req.PasswordID = "web1"
	if _, err := e.prov.ProposalRequest(context.Background(), req, nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveGuestPassword) {
		t.Fatalf("missing password: %v", err)
	}
	e.setPassword()
	approved := e.approve(req)
	// Re-entering the password after approval changes the bound version: the
	// permit no longer covers the run and nothing is sent.
	if _, err := e.prov.SetGuestPassword("web1", []byte("An0ther-Secret-Value"), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.prov.Provision(context.Background(), approved); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("changed password version: %v", err)
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched with another password version")
	}
	if strings.Contains(e.logs.String(), "An0ther-Secret-Value") {
		t.Fatal("log carries the password")
	}
	e.noPassword(nil, approved.ExecutionID, nil)
	if err := e.prov.DeleteGuestPassword("web1", "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionConfigStepOpensOnlyGuestPasswords(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	e.setPassword()
	gs := &guestServer{}
	w := newGuestWriter(t, gs)
	base := pveConfigArgs{VMID: 101, Cores: 1, CIUser: "nos", IPConfig0: pveProvisionIP{DHCP: true},
		Net0: pveProvisionNet0{Model: "virtio", Bridge: "vmbr0"}, SSHKeys: []string{e.autoKey}}
	cases := map[string]func(*pveConfigArgs){
		"action token":   func(a *pveConfigArgs) { a.PasswordRef, a.PasswordVersion = PveVaultID(mutRemote, PvePurposeAction), 1 },
		"read token":     func(a *pveConfigArgs) { a.PasswordRef, a.PasswordVersion = PveVaultID(mutRemote, PvePurposeRead), 1 },
		"wrong version":  func(a *pveConfigArgs) { a.PasswordRef, a.PasswordVersion = "pve-guestpw-web1", 2 },
		"no version":     func(a *pveConfigArgs) { a.PasswordRef, a.PasswordVersion = "pve-guestpw-web1", 0 },
		"version only":   func(a *pveConfigArgs) { a.PasswordVersion = 1 },
		"missing entry":  func(a *pveConfigArgs) { a.PasswordRef, a.PasswordVersion = "pve-guestpw-nope", 1 },
		"malformed name": func(a *pveConfigArgs) { a.PasswordRef, a.PasswordVersion = "pve-guestpw-../x", 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := base
			mutate(&a)
			st, err := stepOf(pveStepGuestConfig, a)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DispatchProvisionStep(context.Background(), w, e.pe.vault, "pve1", st)
			if !errors.Is(err, ErrPveRejected) || !errors.Is(err, ErrPveGuestPassword) {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), "actionsecret") || strings.Contains(err.Error(), provPassword) {
				t.Fatalf("error leaks a secret: %v", err)
			}
		})
	}
	if gs.count() != 0 {
		t.Fatalf("%d requests sent", gs.count())
	}
	// Unknown fields and other methods are refused unsent.
	for _, st := range []PveMutationStep{
		{Method: pveStepGuestStart, Args: json.RawMessage(`{"vmid":101,"extra":1}`)},
		{Method: pveStepGuestClone, Args: json.RawMessage(`{"source_vmid":9000,"new_vmid":101} {}`)},
		{Method: "pve.guest.delete", Args: json.RawMessage(`{"vmid":101}`)},
		{Method: pveStepGuestResize, Args: json.RawMessage(`{"vmid":101,"disk":"scsi0","size_gib":` + strings.Repeat("9", 20) + `}`)},
	} {
		if _, err := DispatchProvisionStep(context.Background(), w, e.pe.vault, "pve1", st); !errors.Is(err, ErrPveRejected) {
			t.Fatalf("%s: %v", st.Args, err)
		}
	}
	if gs.count() != 0 {
		t.Fatalf("%d requests sent", gs.count())
	}
	if _, ok := ProvisionStepTaskType("pve.guest.delete"); ok {
		t.Fatal("delete is allowlisted")
	}
}

func TestProvisionVMIDReservedAgainstLiveGuests(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	_, a := e.propose(e.request())
	_, b := e.propose(e.request())
	if a.VMID != 101 || b.VMID != 102 {
		t.Fatalf("vmids %d %d", a.VMID, b.VMID)
	}
	// An explicit VMID that a guest on another node uses is refused.
	req := e.request()
	req.VMID = 100
	if _, err := e.prov.ProposalRequest(context.Background(), req, nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("live vmid: %v", err)
	}
	req.VMID = 9000
	if _, err := e.prov.ProposalRequest(context.Background(), req, nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveProvisionInvalid) {
		t.Fatalf("template vmid: %v", err)
	}

	// A guest that appears with the VMID after approval stops the run.
	approved := e.approve(e.request())
	e.reader.addGuest("pve2", int(approved.VMID), gib)
	if _, err := e.prov.Provision(context.Background(), approved); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("vmid became live: %v", err)
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched onto a live vmid")
	}

	// Another execution cannot run on a VMID reserved for someone else.
	approved = e.approve(e.request())
	stolen := approved
	stolen.ExecutionID = nextProvExec()
	if _, err := e.prov.Provision(context.Background(), stolen); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("foreign execution: %v", err)
	}
	// An incomplete guest list cannot prove a VMID free.
	e.reader.mu.Lock()
	e.reader.inv.Partial = true
	e.reader.mu.Unlock()
	if _, err := e.prov.Provision(context.Background(), approved); !errors.Is(err, ErrPveInventoryIncomplete) {
		t.Fatalf("partial inventory: %v", err)
	}
	if _, err := e.prov.ProposalRequest(context.Background(), e.request(), nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveInventoryIncomplete) {
		t.Fatalf("partial inventory proposal: %v", err)
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched")
	}
}

func TestPveMutationRefusesPermitOfAnotherExecution(t *testing.T) {
	e := newPveMutEnv(t, true)
	req := e.approve(mutRequest("guest.start"))
	req.ExecutionID = "00000000-0000-4000-a000-000000000000"
	if _, err := e.m.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("other execution: %v", err)
	}
	if e.client.dispatchCount() != 0 {
		t.Fatal("dispatched")
	}
}

func TestProvisionCapacityNeverRaisesRiskAndIsRecheckedBeforeRun(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	// Fits: MEDIUM, no warning.
	if p, pp := e.propose(e.request()); p.Request.RiskClass != canonical.RiskMedium || pp.Capacity != (PveProvisionCapacity{}) {
		t.Fatalf("fits: %s %+v", p.Request.RiskClass, pp.Capacity)
	}
	// A disk larger than the free storage is a warning, still MEDIUM (ADR
	// 0008 decision 2: no automatic raise).
	big := e.request()
	big.DiskGiB = 401
	if p, pp := e.propose(big); p.Request.RiskClass != canonical.RiskMedium || !pp.Capacity.StorageOvercommit {
		t.Fatalf("storage over-commit: %s %+v", p.Request.RiskClass, pp.Capacity)
	}
	// RAM beyond the node is a warning, still MEDIUM.
	ram := e.request()
	ram.MemoryMiB = 64 << 10
	p, pp := e.propose(ram)
	if p.Request.RiskClass != canonical.RiskMedium || !pp.Capacity.MemoryOvercommit {
		t.Fatalf("ram over-commit: %s %+v", p.Request.RiskClass, pp.Capacity)
	}
	if !strings.Contains(string(p.Parameters), `"memory_overcommit":true`) {
		t.Fatalf("warning not in the frozen plan: %s", p.Parameters)
	}
	// PCI passthrough is refused, not raised.
	pci := e.request()
	pci.PCIPassthrough = true
	if _, err := e.prov.ProposalRequest(context.Background(), pci, nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveProvisionUnsupported) {
		t.Fatalf("pci: %v", err)
	}
	// A server proposal below MEDIUM is refused.
	pp, err := e.prov.ProposalRequest(context.Background(), e.request(), nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	low := pp.Request
	low.RiskClass = canonical.RiskLow
	if _, err := e.auth.Propose(low, pp.Parameters); err == nil {
		t.Fatal("LOW proposal accepted")
	}

	// A capacity warning that changes after approval refuses the run before
	// dispatch: the reviewer approved another plan.
	approved := e.approve(e.request())
	e.reader.addGuest("pve1", 300, 62*gib)
	if _, err := e.prov.Provision(context.Background(), approved); !errors.Is(err, ErrPveMutationDenied) || !errors.Is(err, ErrPvePermitFinal) {
		t.Fatalf("capacity changed: %v, want a final denial", err)
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched after the capacity changed")
	}
	// Nothing was sent, so the VMID is free again.
	if _, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now()); ok {
		t.Fatal("reservation kept although nothing was sent")
	}
}

func TestProvisionUnknownCriticalityIsHigh(t *testing.T) {
	src := critSource{artifact: canonical.RiskMedium, hosts: map[canonical.Target]canonical.Risk{}}
	pol, err := riskpolicy.New(src)
	if err != nil {
		t.Fatal(err)
	}
	e := newProvisionEnv(t, pol)
	p, _ := e.propose(e.request())
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("unknown criticality: %s", p.Request.RiskClass)
	}
	rm, _, _ := e.pe.db.GetRemote(mutRemote)
	remote, err := PveRemoteRiskTarget(rm.TrustPin)
	if err != nil {
		t.Fatal(err)
	}
	node := p.Request.ResolvedTargets[0]
	src.hosts[node], src.hosts[remote] = canonical.RiskLow, canonical.RiskLow
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskMedium {
		t.Fatalf("recorded low criticality: %s", p.Request.RiskClass)
	}
	src.hosts[remote] = canonical.RiskHigh
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("high remote: %s", p.Request.RiskClass)
	}
	src.hosts[remote], src.hosts[node] = canonical.RiskLow, canonical.RiskHigh
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("high node: %s", p.Request.RiskClass)
	}
}

func TestProvisionFailedStepKeepsGuest(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.client.fakeMutClient.mu.Lock()
	e.client.fakeMutClient.status = func(upid string) (PveTaskStatus, error) {
		if strings.Contains(upid, ":qmconfig:") {
			return PveTaskStatus{ExitStatus: "unable to apply config"}, nil
		}
		return PveTaskStatus{ExitStatus: "OK"}, nil
	}
	e.client.fakeMutClient.mu.Unlock()
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveStepFailed) {
		t.Fatalf("err = %v", err)
	}
	if !res.GuestKept || len(res.Steps) != 2 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[1].State != executordb.PveJobFailed {
		t.Fatalf("result %+v", res)
	}
	if strings.Join(e.pc.methods(), ",") != "pve.guest.clone,pve.guest.config" {
		t.Fatalf("dispatched %v", e.pc.methods())
	}
	for _, d := range e.client.fakeMutClient.dispatches {
		if strings.Contains(d.method, "delete") || strings.Contains(d.method, "destroy") {
			t.Fatalf("failed guest deleted: %+v", d)
		}
	}
	if !strings.Contains(e.logs.String(), "pve_guest_provision_failed") || !strings.Contains(e.logs.String(), "guest_kept=true") {
		t.Fatalf("no audit of the kept guest: %s", e.logs.String())
	}
	// The permit was consumed: the run cannot be repeated blindly.
	if _, err := e.prov.Provision(context.Background(), approved); err == nil {
		t.Fatal("failed provisioning ran again")
	}
	if len(e.pc.provisionSteps()) != 2 {
		t.Fatal("redispatched")
	}
}

func TestProvisionLostResponseNeverAdoptsAnotherGuestsTask(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.pc.onStep = func(n int, step PveMutationStep, upid string) (string, error) {
		if n == 2 {
			// The config response is lost; the node lists only a qmconfig
			// task of another guest by the same action token.
			foreign := testTaskUPID("pve1", time.Now(), "qmconfig", "105", mutActionUser, 900)
			e.client.fakeMutClient.mu.Lock()
			e.client.fakeMutClient.recent = []string{foreign}
			e.client.fakeMutClient.mu.Unlock()
			return "", errors.New("connection reset")
		}
		return upid, nil
	}
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveDispatchUncertain) || !res.GuestKept {
		t.Fatalf("err = %v result %+v", err, res)
	}
	if res.Steps[1].UPID != "" || res.Steps[1].State != executordb.PveJobReconciling {
		t.Fatalf("foreign task adopted: %+v", res.Steps[1])
	}
	if len(e.pc.provisionSteps()) != 2 {
		t.Fatalf("dispatched %v", e.pc.methods())
	}
	if id, ok := ProvisionStepTaskID(e.pc.provisionSteps()[0]); !ok || id != "9000" {
		t.Fatalf("clone task id %q", id)
	}
	if id, ok := ProvisionStepTaskID(e.pc.provisionSteps()[1]); !ok || id != "101" {
		t.Fatalf("config task id %q", id)
	}
	if _, ok := ProvisionStepTaskID(PveMutationStep{Method: "pve.guest.delete", Args: json.RawMessage(`{"vmid":101}`)}); ok {
		t.Fatal("task id for a foreign method")
	}
}

func TestProvisionLostResponseIsReconciledNotRedispatched(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	var cloneUPID string
	e.pc.onStep = func(n int, step PveMutationStep, upid string) (string, error) {
		if n == 1 {
			// The clone reached PVE but the response was lost.
			cloneUPID = upid
			e.client.fakeMutClient.mu.Lock()
			e.client.fakeMutClient.recent = []string{upid}
			e.client.fakeMutClient.mu.Unlock()
			return "", errors.New("connection reset")
		}
		return upid, nil
	}
	res, err := e.prov.Provision(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(e.pc.methods(), ",") != "pve.guest.clone,pve.guest.config,pve.guest.resize,pve.guest.start" {
		t.Fatalf("dispatched %v (the clone must be sent exactly once)", e.pc.methods())
	}
	if res.Steps[0].UPID != cloneUPID || res.Steps[0].State != executordb.PveJobSucceeded {
		t.Fatalf("clone step %+v", res.Steps[0])
	}
}

func TestProvisionUnidentifiedStepStaysOpenAndKeepsGuest(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.pc.onStep = func(n int, step PveMutationStep, upid string) (string, error) {
		if n == 2 {
			return "", errors.New("timeout") // config sent, no UPID, no task listed
		}
		return upid, nil
	}
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveDispatchUncertain) || !res.GuestKept {
		t.Fatalf("err = %v result %+v", err, res)
	}
	if res.Steps[1].State != executordb.PveJobReconciling {
		t.Fatalf("config step %+v", res.Steps[1])
	}
	// Reconciliation after a restart observes, never dispatches.
	e.restartProvisioner()
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(res.ExecutionID)
	if len(steps) != 2 || steps[1].State != executordb.PveJobUnknown {
		t.Fatalf("steps after reconcile %+v", steps)
	}
	if len(e.pc.provisionSteps()) != 2 {
		t.Fatalf("reconcile dispatched: %v", e.pc.methods())
	}
}

func TestProvisionTemplateChangedRefusesRun(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.client.setTemplateDigest(strings.Repeat("0f", 32))
	if _, err := e.prov.Provision(context.Background(), approved); !errors.Is(err, ErrPveTemplateChanged) {
		t.Fatalf("changed template: %v", err)
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched from a changed template")
	}
}

func TestProvisionRejectsInvalidRequests(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	cases := map[string]func(*PveProvisionRequest){
		"name uppercase":     func(r *PveProvisionRequest) { r.Name = "Web1" },
		"name with space":    func(r *PveProvisionRequest) { r.Name = "web 1" },
		"no cores":           func(r *PveProvisionRequest) { r.Cores = 0 },
		"too much memory":    func(r *PveProvisionRequest) { r.MemoryMiB = pveapi.MaxMemoryMiB + 1 },
		"no disk":            func(r *PveProvisionRequest) { r.DiskGiB = 0 },
		"bad disk slot":      func(r *PveProvisionRequest) { r.Disk = "nvme0" },
		"bad storage":        func(r *PveProvisionRequest) { r.Storage = "../x" },
		"bad bridge":         func(r *PveProvisionRequest) { r.NIC.Bridge = "vmbr0,firewall=1" },
		"bad model":          func(r *PveProvisionRequest) { r.NIC.Model = "rtl8139" },
		"multicast mac":      func(r *PveProvisionRequest) { r.NIC.MAC = "01:00:5e:00:00:01" },
		"vlan mismatch":      func(r *PveProvisionRequest) { r.NIC.VLAN = 20 },
		"address outside":    func(r *PveProvisionRequest) { r.IPAM.Address = netip.MustParseAddr("192.168.11.5") },
		"broadcast address":  func(r *PveProvisionRequest) { r.IPAM.Address = netip.MustParseAddr("192.168.10.255") },
		"network address":    func(r *PveProvisionRequest) { r.IPAM.Address = netip.MustParseAddr("192.168.10.0") },
		"gateway is address": func(r *PveProvisionRequest) { r.IPAM.Gateway = r.IPAM.Address },
		"gateway outside":    func(r *PveProvisionRequest) { r.IPAM.Gateway = netip.MustParseAddr("10.0.0.1") },
		"unmasked prefix":    func(r *PveProvisionRequest) { r.IPAM.Prefix = netip.MustParsePrefix("192.168.10.7/24") },
		"ipv6 reservation": func(r *PveProvisionRequest) {
			r.IPAM.Prefix, r.IPAM.Address = netip.MustParsePrefix("fd00::/64"), netip.MustParseAddr("fd00::5")
		},
		"no reservation user":  func(r *PveProvisionRequest) { r.IPAM.ReservedBy = "" },
		"bad network id":       func(r *PveProvisionRequest) { r.IPAM.NetworkID = "LAN!" },
		"bad ciuser":           func(r *PveProvisionRequest) { r.CIUser = "root;rm" },
		"key with options":     func(r *PveProvisionRequest) { r.SSHKeys = []string{`command="/bin/sh" ` + e.extraKey} },
		"garbage key":          func(r *PveProvisionRequest) { r.SSHKeys = []string{"ssh-ed25519 AAAA"} },
		"too many keys":        func(r *PveProvisionRequest) { r.SSHKeys = make([]string, pveapi.MaxSSHKeys) },
		"bad searchdomain":     func(r *PveProvisionRequest) { r.SearchDomains = []string{"-bad.example"} },
		"too many nameservers": func(r *PveProvisionRequest) { r.Nameservers = make([]netip.Addr, 4) },
		"bad password id":      func(r *PveProvisionRequest) { r.PasswordID = "../x" },
		"template elsewhere":   func(r *PveProvisionRequest) { r.Node = "pve2" },
		"vmid below range":     func(r *PveProvisionRequest) { r.VMID = 50 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := e.request()
			ipam := *req.IPAM
			req.IPAM = &ipam
			mutate(&req)
			_, err := e.prov.ProposalRequest(context.Background(), req, nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour))
			if !errors.Is(err, ErrPveProvisionInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	req := e.request()
	req.PCIPassthrough = true
	if _, err := e.prov.ProposalRequest(context.Background(), req, nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveProvisionUnsupported) {
		t.Fatalf("pci passthrough: %v", err)
	}
	// Nothing was reserved by any refused request.
	if _, ok, _ := e.vmids.VMIDHolder(mutRemote, 101, time.Now()); ok {
		t.Fatal("a refused request reserved a vmid")
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched")
	}
	// A provisioner without a valid automation key refuses to work.
	bad := &PveProvisioner{Mutations: e.prov.Mutations, Images: e.prov.Images, Reader: e.prov.Reader, VMIDs: e.prov.VMIDs,
		Passwords: e.prov.Passwords, AutomationKey: "not a key", Artifact: e.prov.Artifact, ModuleVersion: e.prov.ModuleVersion}
	if _, err := bad.ProposalRequest(context.Background(), e.request(), nextProvExec(), canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("no automation key accepted")
	}
}

// loseStep makes the response of step lost (1-based) of the next
// provisioning run get lost; the node then lists listed(upid).
func (e *provisionEnv) loseStep(lost int, listed func(upid string) []string) {
	base := len(e.pc.provisionSteps())
	e.pc.onStep = func(n int, step PveMutationStep, upid string) (string, error) {
		if n-base == lost {
			e.client.fakeMutClient.mu.Lock()
			e.client.fakeMutClient.recent = listed(upid)
			e.client.fakeMutClient.mu.Unlock()
			return "", errors.New("connection reset")
		}
		return upid, nil
	}
}

func (e *provisionEnv) listTasks(upids ...string) {
	e.client.fakeMutClient.mu.Lock()
	e.client.fakeMutClient.recent = upids
	e.client.fakeMutClient.mu.Unlock()
}

func TestProvisionRestartReconcileNeverAdoptsAnotherGuestsTask(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.loseStep(2, func(string) []string { return nil })
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveDispatchUncertain) || !res.GuestKept || res.Steps[1].State != executordb.PveJobReconciling {
		t.Fatalf("err = %v result %+v", err, res)
	}
	// The step is open, so the reservation stays: it is what narrows the
	// step after the restart.
	if h, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now()); !ok || !h.Started || h.TemplateVMID != 9000 {
		t.Fatalf("reservation %+v %v", h, ok)
	}

	// After the restart the node lists only a qmconfig task of another
	// guest (105), started by the same action token inside the window.
	e.restartProvisioner()
	foreign := testTaskUPID("pve1", time.Now(), "qmconfig", "105", mutActionUser, 900)
	e.listTasks(foreign)
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(res.ExecutionID)
	if steps[1].UPID != "" || steps[1].State != executordb.PveJobReconciling {
		t.Fatalf("foreign task adopted at restart: %+v", steps[1])
	}
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ = e.pe.db.PveJobSteps(res.ExecutionID)
	if steps[1].UPID != "" || steps[1].State != executordb.PveJobUnknown {
		t.Fatalf("foreign task adopted at restart: %+v", steps[1])
	}
	if len(e.pc.provisionSteps()) != 2 {
		t.Fatalf("reconcile dispatched: %v", e.pc.methods())
	}
}

func TestProvisionRestartReconcileAdoptsOnlyTheGuestsOwnTask(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.loseStep(2, func(string) []string { return nil })
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("err = %v", err)
	}
	e.restartProvisioner()
	foreign := testTaskUPID("pve1", time.Now(), "qmconfig", "105", mutActionUser, 900)
	own := testTaskUPID("pve1", time.Now(), "qmconfig", fmt.Sprint(approved.VMID), mutActionUser, 901)
	e.listTasks(foreign, own)
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(res.ExecutionID)
	if steps[1].UPID != own || steps[1].State != executordb.PveJobSucceeded {
		t.Fatalf("own task not identified: %+v", steps[1])
	}
	// The job settled (no step open, clone succeeded): the reservation is
	// released once the guest is in the live list.
	e.reader.addGuest("pve1", int(approved.VMID), 4*gib)
	if n, err := e.prov.ReleaseSettledVMIDs(context.Background(), mutRemote); err != nil || n != 1 {
		t.Fatalf("released %d %v", n, err)
	}
}

func TestProvisionRestartWithoutTaskIDSourceFailsClosed(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.loseStep(2, func(string) []string { return nil })
	res, _ := e.prov.Provision(context.Background(), approved)
	// An engine without the provisioner's task ID source cannot narrow the
	// node-level step, so even a task with the right ID is not adopted.
	e.restart()
	e.m.Client = e.pc
	e.listTasks(testTaskUPID("pve1", time.Now(), "qmconfig", fmt.Sprint(approved.VMID), mutActionUser, 901))
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(res.ExecutionID)
	if steps[1].UPID != "" || steps[1].State != executordb.PveJobUnknown {
		t.Fatalf("unnarrowed step identified: %+v", steps[1])
	}
	// A provisioner on an engine without it refuses to run at all.
	e.prov.Mutations = e.m
	if _, err := e.prov.Provision(context.Background(), e.request()); err == nil || errors.Is(err, ErrPveProvisionInvalid) {
		t.Fatalf("unwired provisioner: %v", err)
	}
}

func TestProvisionLostCloneIsAmbiguousWhileAnotherCloneOfTheTemplateIsUnknown(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	a := e.approve(e.request())
	b := e.approve(e.request())
	// A's clone response is lost and its task is not listed in time: A's
	// clone ends unknown and A keeps its reservation.
	var cloneA string
	e.loseStep(1, func(upid string) []string { cloneA = upid; return nil })
	ra, err := e.prov.Provision(context.Background(), a)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("a: %v", err)
	}
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if steps, _ := e.pe.db.PveJobSteps(ra.ExecutionID); steps[0].State != executordb.PveJobUnknown {
		t.Fatalf("a clone %+v", steps[0])
	}
	if h, ok, _ := e.vmids.VMIDHolder(mutRemote, a.VMID, time.Now()); !ok || h.ExecutionID != a.ExecutionID {
		t.Fatal("unknown clone released its reservation")
	}
	// B clones the same template; its response is lost and the node lists
	// only A's clone task (same template ID, same token). B must not adopt it.
	e.m.Now = nil
	e.loseStep(1, func(string) []string { return []string{cloneA} })
	rb, err := e.prov.Provision(context.Background(), b)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("b: %v", err)
	}
	if rb.Steps[0].UPID == cloneA {
		t.Fatal("b adopted a's clone task")
	}
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(rb.ExecutionID)
	if steps[0].UPID != "" || steps[0].State != executordb.PveJobUnknown {
		t.Fatalf("b clone %+v", steps[0])
	}
}

func TestProvisionFailedCloneReleasesAndUnknownCloneKeepsReservation(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.client.fakeMutClient.mu.Lock()
	e.client.fakeMutClient.status = func(upid string) (PveTaskStatus, error) {
		return PveTaskStatus{ExitStatus: "clone failed: storage error"}, nil
	}
	e.client.fakeMutClient.mu.Unlock()
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveStepFailed) || res.GuestKept || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobFailed {
		t.Fatalf("err = %v result %+v", err, res)
	}
	if _, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now()); ok {
		t.Fatal("definitively failed clone leaks its reservation")
	}

	// An unknown clone stays reserved until its guest is seen.
	e.client.fakeMutClient.mu.Lock()
	e.client.fakeMutClient.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{ExitStatus: "OK"}, nil }
	e.client.fakeMutClient.mu.Unlock()
	approved = e.approve(e.request())
	e.loseStep(1, func(string) []string { return nil })
	res, err = e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveDispatchUncertain) || !res.GuestKept {
		t.Fatalf("err = %v result %+v", err, res)
	}
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, err := e.prov.ReleaseSettledVMIDs(context.Background(), mutRemote); err != nil || n != 0 {
		t.Fatalf("unknown clone released: %d %v", n, err)
	}
	if _, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now()); !ok {
		t.Fatal("unknown clone lost its reservation")
	}
	e.reader.addGuest("pve1", int(approved.VMID), 4*gib)
	if n, err := e.prov.ReleaseSettledVMIDs(context.Background(), mutRemote); err != nil || n != 1 {
		t.Fatalf("seen guest not released: %d %v", n, err)
	}
}

func TestProvisionJobStoreFailureKeepsReservation(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.pc.onStep = func(n int, step PveMutationStep, upid string) (string, error) {
		// The clone reached PVE; then the job store becomes unreadable.
		_ = e.pe.db.Close()
		return upid, nil
	}
	res, err := e.prov.Provision(context.Background(), approved)
	if err == nil || !res.GuestKept {
		t.Fatalf("err = %v result %+v", err, res)
	}
	if h, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now()); !ok || h.ExecutionID != approved.ExecutionID {
		t.Fatal("reservation freed although the steps could not be read")
	}
}

func TestProvisionReleasedUnknownCloneNeverLetsAnotherCloneAdoptItsTask(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	a := e.approve(e.request())
	b := e.approve(e.request())
	// A's clone ends unknown; its unrecorded task appears in the list later.
	var cloneA string
	e.loseStep(1, func(upid string) []string { cloneA = upid; return nil })
	if _, err := e.prov.Provision(context.Background(), a); !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("a: %v", err)
	}
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A's guest appears, so A's reservation becomes releasable by itself.
	e.reader.addGuest("pve1", int(a.VMID), 4*gib)
	// B's clone response is lost while A's task is listed: B stays
	// reconciling inside its window.
	e.m.Now = nil
	e.loseStep(1, func(string) []string { return []string{cloneA} })
	rb, err := e.prov.Provision(context.Background(), b)
	if !errors.Is(err, ErrPveDispatchUncertain) || rb.Steps[0].State != executordb.PveJobReconciling || rb.Steps[0].UPID != "" {
		t.Fatalf("b: %v %+v", err, rb.Steps)
	}
	// While B is still identifying, A's reservation (the ambiguity marker)
	// is not released, even after A's own window passed.
	e.passMatchWindow()
	if n, err := e.prov.ReleaseSettledVMIDs(context.Background(), mutRemote); err != nil || n != 0 {
		t.Fatalf("released %d %v while b reconciles", n, err)
	}
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, _ := e.pe.db.PveJobSteps(rb.ExecutionID)
	if steps[0].UPID == cloneA || steps[0].State != executordb.PveJobUnknown {
		t.Fatalf("b adopted a's clone task: %+v", steps[0])
	}
	// With B settled, A's reservation goes (B's stays: its guest is unseen).
	if n, err := e.prov.ReleaseSettledVMIDs(context.Background(), mutRemote); err != nil || n != 1 {
		t.Fatalf("released %d %v", n, err)
	}
	if _, ok, _ := e.vmids.VMIDHolder(mutRemote, b.VMID, time.Now()); !ok {
		t.Fatal("b's unknown clone lost its reservation")
	}
}

func TestProvisionUnknownCloneIsNotReleasedInsideItsTaskWindow(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	a := e.approve(e.request())
	e.loseStep(1, func(string) []string { return nil })
	if _, err := e.prov.Provision(context.Background(), a); !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("a: %v", err)
	}
	// Mark the clone unknown at once (ambiguous candidates), still inside
	// the window of a clone step started now.
	e.listTasks(testTaskUPID("pve1", time.Now(), "qmclone", "9000", mutActionUser, 950),
		testTaskUPID("pve1", time.Now(), "qmclone", "9000", mutActionUser, 951))
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.reader.addGuest("pve1", int(a.VMID), 4*gib)
	if n, err := e.prov.ReleaseSettledVMIDs(context.Background(), mutRemote); err != nil || n != 0 {
		t.Fatalf("released inside the task window: %d %v", n, err)
	}
}

func TestProvisionTransientFailureBeforeDispatchKeepsReservationForRetry(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	e.client.fakeMutClient.mu.Lock()
	e.client.fakeMutClient.liveNode = "pve9"
	e.client.fakeMutClient.mu.Unlock()
	if _, err := e.prov.Provision(context.Background(), approved); err == nil || errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("transient target read: %v", err)
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched")
	}
	h, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now())
	if !ok || h.ExecutionID != approved.ExecutionID || h.Started {
		t.Fatalf("reservation after a transient failure: %+v %v", h, ok)
	}
	// It expires with the proposal again, and the approved run can retry.
	if _, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now().Add(2*time.Hour)); ok {
		t.Fatal("unstarted reservation does not expire")
	}
	e.client.fakeMutClient.mu.Lock()
	e.client.fakeMutClient.liveNode = "pve1"
	e.client.fakeMutClient.mu.Unlock()
	if _, err := e.prov.Provision(context.Background(), approved); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestProvisionNarrowingIsRecheckedAfterTheListing(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	// A clone task of template 9000 by the same token, not A's.
	other := testTaskUPID("pve1", time.Now(), "qmclone", "9000", mutActionUser, 960)
	e.loseStep(1, func(string) []string { return []string{other} })
	// Between A's narrowing check and the listing, another provisioning of
	// the same template starts (its clone task is unrecorded).
	var once sync.Once
	e.pc.pmu.Lock()
	e.pc.onRecent = func() {
		once.Do(func() {
			c := nextProvExec()
			if _, err := e.vmids.ReserveVMID(mutRemote, c, 150, nil, time.Now().Add(time.Hour), time.Now()); err != nil {
				t.Error(err)
			}
			if err := e.vmids.StartVMID(mutRemote, 150, c, 9000); err != nil {
				t.Error(err)
			}
		})
	}
	e.pc.pmu.Unlock()
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("err = %v", err)
	}
	if res.Steps[0].UPID == other || res.Steps[0].UPID != "" {
		t.Fatalf("task adopted although the narrowing changed: %+v", res.Steps[0])
	}
	if !strings.Contains(e.logs.String(), "pve_mutation_narrowing_changed") {
		t.Fatal("no audit of the changed narrowing")
	}
}

func TestProvisionConcurrentRunOfTheSameExecutionKeepsTheReservation(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	approved := e.approve(e.request())
	// The first run blocks after consuming the permit, before its clone
	// intent is recorded.
	blocked, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.pc.pmu.Lock()
	e.pc.onTaskType = func() { once.Do(func() { close(blocked); <-release }) }
	e.pc.pmu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := e.prov.Provision(context.Background(), approved)
		done <- err
	}()
	<-blocked
	res, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveMutationDenied) || !errors.Is(err, ErrPveMutationAlreadyRun) || len(res.Steps) != 0 {
		t.Fatalf("second run: %v %+v", err, res)
	}
	h, ok, _ := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now().Add(2*time.Hour))
	if !ok || !h.Started || h.ExecutionID != approved.ExecutionID {
		t.Fatalf("second run touched the first run's reservation: %+v %v", h, ok)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first run: %v", err)
	}
	if strings.Join(e.pc.methods(), ",") != "pve.guest.clone,pve.guest.config,pve.guest.resize,pve.guest.start" {
		t.Fatalf("dispatched %v", e.pc.methods())
	}
}

// noLinkedHosts is a linked-host source for nodes that are not enrolled hosts.
func noLinkedHosts(canonical.Request, canonical.Target) ([]canonical.Target, error) { return nil, nil }

// switchRisk is a risk policy whose answer a test can change after approval.
type switchRisk struct{ r *canonical.Risk }

func (s switchRisk) MinimumRisk(canonical.Request, []canonical.Target) (canonical.Risk, string, error) {
	return *s.r, "test", nil
}

// TestProvisionTransientDenialKeepsVMID pins the review finding of PR #162
// round 6: a denial that can change again (here the risk rose above the
// approval after a criticality change) sends nothing and keeps the VMID
// reserved for the approved execution, so a retry is not refused with
// ErrPveVMIDTaken and no other proposal can take the VMID meanwhile.
func TestProvisionTransientDenialKeepsVMID(t *testing.T) {
	risk := canonical.RiskMedium
	e := newProvisionEnv(t, switchRisk{r: &risk})
	approved := e.approve(e.request())
	risk = canonical.RiskHigh
	_, err := e.prov.Provision(context.Background(), approved)
	if !errors.Is(err, ErrPveMutationDenied) || errors.Is(err, ErrPvePermitFinal) {
		t.Fatalf("risk above approval: %v, want a non-final denial", err)
	}
	if len(e.pc.provisionSteps()) != 0 {
		t.Fatal("dispatched above the approved risk")
	}
	h, ok, err := e.vmids.VMIDHolder(mutRemote, approved.VMID, time.Now())
	if err != nil || !ok || h.ExecutionID != approved.ExecutionID {
		t.Fatalf("reservation after a transient denial: holder %+v ok %v err %v, want kept for %s", h, ok, err, approved.ExecutionID)
	}
}

func TestPermitDenialFinal(t *testing.T) {
	for _, c := range []permit.Code{permit.CodeNotFound, permit.CodeExpired, permit.CodeWrongState, permit.CodeParametersMismatch, permit.CodeRolloutAborted} {
		if !permitDenialFinal(c) {
			t.Errorf("%s not final", c)
		}
	}
	for _, c := range []permit.Code{permit.CodeStorage, permit.CodeRiskAboveApproval, permit.CodeStageNotOpen, permit.CodeSessionRequired, permit.CodeLimit, permit.CodeHostAlreadyRun, permit.Code("future_code")} {
		if permitDenialFinal(c) {
			t.Errorf("%s final, want transient", c)
		}
	}
}

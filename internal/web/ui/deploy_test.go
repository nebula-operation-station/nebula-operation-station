// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modules"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Deployments (ADR 0008 section 6, PV-08): the Deploy navigation entry,
// the chart's "Deploy here", the wizard with its IPAM suggestion, the
// review with the executor's risk, the run states, the enrollment with
// fingerprint review through pveinventory.GuestJoinFlow, and the staged
// bootstrap/runbook plan with one batch approval.

const (
	dpRemote   = "pve-lab"
	dpNode     = "p1"
	dpTemplate = 9000
	dpVMID     = 123
	dpExec     = "exec-prov-1"
)

var (
	dpPin         = strings.Repeat("c1", 32)
	dpImageSHA    = strings.Repeat("ab", 32)
	dpFingerprint = "SHA256:" + strings.Repeat("Q", 43)
)

// fakeProvision is the executor's provisioning side.
type fakeProvision struct {
	mu          sync.Mutex
	proposed    []*pb.PVEGuestProvisionSpec
	commits     []*pb.CommitPVEGuestProvisionRequest
	assertions  []string
	risk        canonical.Risk
	requirement pb.ApprovalRequirement
	proposeErr  error
	commitErr   error
	failStep    bool
	// mutate changes the bound canonical request (a misbehaving executor).
	mutate func(*canonical.Request)
}

func (f *fakeProvision) ProposePVEGuestProvision(_ context.Context, in *pb.ProposePVEGuestProvisionRequest, _ ...grpc.CallOption) (*pb.ProposePVEGuestProvisionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proposed = append(f.proposed, in.GetSpec())
	if f.proposeErr != nil {
		return nil, f.proposeErr
	}
	target, err := permit.ProviderMutationTarget{RemoteID: in.GetSpec().GetRemoteId(), TrustPin: dpPin, Kind: "node", Node: in.GetSpec().GetNode()}.RiskTarget()
	if err != nil {
		return nil, err
	}
	rq := canonical.Request{RequestVersion: 1, ExecutionID: dpExec, ActionID: "pve.guest.provision", ModuleVersion: "1.0.0",
		ArtifactSHA256: strings.Repeat("a1", 32), ParametersHash: strings.Repeat("0d", 32), CredentialRefs: []string{"pve-lab-action"},
		RiskClass: f.risk, StagePlanHash: strings.Repeat("5e", 32), ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		ResolvedTargets: []canonical.Target{target}}
	if f.mutate != nil {
		f.mutate(&rq)
	}
	c, err := canonical.Encode(rq)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	return &pb.ProposePVEGuestProvisionResponse{ExecutionId: dpExec, Vmid: dpVMID, CapacityWarnings: []string{"memory over-commit on p1"},
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: hex.EncodeToString(sum[:]), CanonicalRequest: c,
			ApprovalRequirement: f.requirement, RiskClass: riskPB(string(f.risk)),
			ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix(), RequestOptionsJson: []byte(`{"challenge":"Y2hhbA"}`)}}, nil
}

func riskPB(r string) pb.RiskClass {
	return pb.RiskClass(pb.RiskClass_value["RISK_CLASS_"+r])
}

func (f *fakeProvision) SubmitAssertion(_ context.Context, in *pb.SubmitAssertionRequest, _ ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assertions = append(f.assertions, in.GetExecutionDigest())
	return &pb.SubmitAssertionResponse{}, nil
}

func (f *fakeProvision) CommitPVEGuestProvision(_ context.Context, in *pb.CommitPVEGuestProvisionRequest, _ ...grpc.CallOption) (*pb.CommitPVEGuestProvisionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits = append(f.commits, in)
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	out := &pb.CommitPVEGuestProvisionResponse{ExecutionId: dpExec, Vmid: in.GetSpec().GetVmid(), GuestConfigDigest: strings.Repeat("9", 64)}
	for i, typ := range []string{"qmclone", "qmconfig", "qmresize", "qmstart"} {
		st := "succeeded"
		if f.failStep && i == 2 {
			st, out.GuestKept = "failed", true
		}
		out.Steps = append(out.Steps, &pb.PVEGuestPowerStep{State: st, TaskType: typ, Upid: "UPID:p1:0000" + typ + ":"})
		if st == "failed" {
			break
		}
	}
	return out, nil
}

func (f *fakeProvision) commitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.commits)
}

// fakeJoinExec is the executor's guest join side (server role): it reads
// a host key and binds it; the commit pins exactly the approved binding.
type fakeJoinExec struct {
	mu       sync.Mutex
	proposed []*pb.ProposeGuestJoinRequest
	commits  []*pb.CommitGuestJoinRequest
	pinned   bool
	// boundHost overrides the host the canonical request binds.
	boundHost string
}

func (f *fakeJoinExec) ProposeGuestJoin(_ context.Context, in *pb.ProposeGuestJoinRequest, _ ...grpc.CallOption) (*pb.ProposeGuestJoinResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proposed = append(f.proposed, in)
	h := in.GetHost()
	bound := h.GetHostId()
	if f.boundHost != "" {
		bound = f.boundHost
	}
	rq := canonical.Request{RequestVersion: 1, ExecutionID: "exec-join-1", ActionID: "core.enroll", ModuleVersion: "1.0.0",
		ArtifactSHA256: strings.Repeat("e1", 32), ParametersHash: strings.Repeat("0e", 32), CredentialRefs: []string{h.GetCredentialRef()},
		RiskClass: canonical.RiskMedium, StagePlanHash: strings.Repeat("5f", 32), ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		ResolvedTargets: []canonical.Target{{HostID: bound, HostKeyFingerprint: dpFingerprint}}}
	c, err := canonical.Encode(rq)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	return &pb.ProposeGuestJoinResponse{JoinMethod: pveinventory.JoinMethodReview, AgentDetail: "the guest agent is not used",
		Host: &pb.EnrollHost{HostId: h.GetHostId(), Endpoint: h.GetEndpoint() + ":22", SshUser: h.GetSshUser(),
			CredentialRef: h.GetCredentialRef(), Fingerprint: dpFingerprint, KeyType: "ssh-ed25519"},
		Guest: in.GetGuest(),
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: hex.EncodeToString(sum[:]), CanonicalRequest: c,
			RiskClass: pb.RiskClass_RISK_CLASS_MEDIUM, ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE,
			RequestOptionsJson: []byte(`{"challenge":"am9pbg"}`), ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix()},
	}, nil
}

func (f *fakeJoinExec) CommitGuestJoin(_ context.Context, in *pb.CommitGuestJoinRequest, _ ...grpc.CallOption) (*pb.CommitGuestJoinResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits = append(f.commits, in)
	return &pb.CommitGuestJoinResponse{
		Result:          &pb.EnrollResult{HostId: in.GetHost().GetHostId(), Pinned: f.pinned, Fingerprint: in.GetHost().GetFingerprint()},
		ExecutionDigest: in.GetExecutionDigest(), Guest: in.GetGuest(), Host: in.GetHost(), JoinMethod: in.GetJoinMethod(),
	}, nil
}

// fakeDeployBatches records the staged plan.
type fakeDeployBatches struct {
	mu       sync.Mutex
	requests []executions.BatchRequest
	counts   executions.BatchCounts
}

func (f *fakeDeployBatches) ProposeBatch(_ context.Context, _ string, req executions.BatchRequest) (executions.BatchCreated, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	return executions.BatchCreated{ID: "batch-1", State: "pending"}, nil
}

func (f *fakeDeployBatches) Batch(context.Context, string) (executions.BatchView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return executions.BatchView{ID: "batch-1", Summary: "running", Counts: f.counts}, nil
}

// dpModules serves the real first-party bootstrap modules from the tree.
type dpModules struct{ versions []modules.Version }

func (m dpModules) Import(context.Context, string, []byte) (modules.Version, error) {
	return modules.Version{}, errors.New("not supported")
}
func (m dpModules) Verify(context.Context, string, string) (modules.Version, error) {
	return modules.Version{}, errors.New("not supported")
}
func (m dpModules) Latest(context.Context) ([]modules.Version, error) { return m.versions, nil }
func (m dpModules) Versions(context.Context, string) ([]modules.Version, error) {
	return m.versions, nil
}
func (m dpModules) Get(context.Context, string, string) (modules.Version, error) {
	return modules.Version{}, modules.ErrNotFound
}

func loadBootstrapModule(t *testing.T, name string) modules.Version {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "modules", "bootstrap", name)
	raw, err := os.ReadFile(filepath.Join(dir, "module.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock modulelock.Lock
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	v := modules.Version{Lock: lock, Scripts: map[string][]byte{}, State: modules.StateVerified}
	for _, a := range lock.Actions {
		b, err := os.ReadFile(filepath.Join(dir, a.Script))
		if err != nil {
			t.Fatal(err)
		}
		v.Scripts[a.Script] = b
	}
	return v
}

// dpRunbooks serves one runbook, harden at version 3.
type dpRunbooks struct{}

func (dpRunbooks) Save(context.Context, string, runbooks.Draft) (runbooks.Version, error) {
	return runbooks.Version{}, errors.New("not supported")
}
func (dpRunbooks) Latest(ctx context.Context) ([]runbooks.Version, error) {
	v, err := dpRunbooks{}.Get(ctx, "harden", 3)
	return []runbooks.Version{v}, err
}
func (dpRunbooks) Versions(ctx context.Context, slug string) ([]runbooks.Version, error) {
	return dpRunbooks{}.Latest(ctx)
}
func (dpRunbooks) Get(_ context.Context, slug string, version int) (runbooks.Version, error) {
	if slug != "harden" || version != 3 {
		return runbooks.Version{}, runbooks.ErrNotFound
	}
	return runbooks.Version{Draft: runbooks.Draft{Slug: "harden", Title: "Harden SSH", Risk: "MEDIUM", TimeoutS: 60},
		Version: 3, Artifact: []byte("#!/bin/sh\ntrue\n")}, nil
}

// dpEnv is a deployment server with the real PVE inventory, IPAM, deploy
// profile and inventory stores and fake executor sides.
type dpEnv struct {
	h       http.Handler
	db      *sql.DB
	pve     *pveinventory.Store
	ipam    *ipam.Store
	prov    *fakeProvision
	join    *fakeJoinExec
	batches *fakeDeployBatches
	state   string
	gen     uint64
}

func newDPEnv(t *testing.T) *dpEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &dpEnv{db: db, pve: pveinventory.New(db), state: "active",
		prov: &fakeProvision{risk: canonical.RiskHigh, requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED},
		join: &fakeJoinExec{pinned: true}, batches: &fakeDeployBatches{}}
	ctx := context.Background()
	if err := e.pve.UpsertRemote(ctx, pvecontract.Remote{RemoteID: dpRemote, Name: "PVE lab", Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "192.168.0.10", Port: 8006}}, TrustPin: dpPin, TrustGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	e.observe(t) // the template only
	e.ipam = ipam.New(db, func(context.Context) (map[netip.Addr][]string, error) { return nil, nil })
	if err := e.ipam.SaveNetwork(ctx, ipam.Network{ID: "lan", Name: "LAN", Prefix: netip.MustParsePrefix("192.168.10.0/24"),
		Gateway: netip.MustParseAddr("192.168.10.1"),
		Pools:   []ipam.Pool{{Name: "servers", First: netip.MustParseAddr("192.168.10.50"), Last: netip.MustParseAddr("192.168.10.59")}}}); err != nil {
		t.Fatal(err)
	}
	profiles := deployprofile.New(db)
	if _, err := profiles.Save(ctx, "alice", deployprofile.Profile{Slug: "web_s", Title: "Web S", Image: "debian-13",
		Size: deployprofile.Size{Preset: "S"}, StorageClass: "local-lvm",
		Network:   deployprofile.Network{Bridge: "vmbr0", IPAMPool: "servers"},
		DNS:       deployprofile.DNS{Nameservers: []string{"192.168.10.1"}, SearchDomain: "lab.example"},
		Bootstrap: []deployprofile.BootstrapModule{{Name: "timezone", Params: map[string]string{"zone": "/Europe/Berlin"}}, {Name: "qemu-guest-agent"}},
		Runbooks:  []deployprofile.RunbookRef{{Slug: "harden", Version: 3}}, VaultRefs: []deployprofile.VaultRef{}}); err != nil {
		t.Fatal(err)
	}
	e.h = newTestHandler(t, ui.Options{
		PublicOrigin: gpOrigin,
		Hosts:        func(context.Context) ([]inventory.Host, error) { return nil, nil },
		PVE:          e.pve,
		PVEChart:     func(ctx context.Context) (pveinventory.Tree, error) { return e.pve.ChartTree(ctx, time.Now()) },
		PVERemotes: func(context.Context) ([]ui.PVERemoteMeta, error) {
			return []ui.PVERemoteMeta{{RemoteID: dpRemote, Name: "PVE lab", Kind: "standalone", State: e.state, TrustPin: dpPin,
				Endpoints: []ui.PVEEndpoint{{Host: "192.168.0.10", Port: 8006}}}}, nil
		},
		Network:        e.ipam,
		DeployProfiles: profiles,
		Modules: dpModules{versions: []modules.Version{loadBootstrapModule(t, "qemu-guest-agent"),
			loadBootstrapModule(t, "timezone"), loadBootstrapModule(t, "user")}},
		Runbooks:      dpRunbooks{},
		Deploy:        e.prov,
		DeployJoin:    &pveinventory.GuestJoinFlow{Store: e.pve, Executor: e.join},
		DeployIPAM:    e.ipam,
		DeployBatches: e.batches,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler()
	return e
}

func dpGuest(vmid uint64, name string, status pvecontract.GuestStatus) pvecontract.GuestObservation {
	return pvecontract.GuestObservation{VMID: vmid, Kind: pvecontract.GuestQEMU, Node: dpNode, Name: name, Status: status, Generation: 1,
		Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
		Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("not read"),
		Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
		Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
		Backups:    pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("not read")}
}

// observe ingests one complete PVE collection: the node, the template and
// the given guests.
func (e *dpEnv) observe(t *testing.T, guests ...pvecontract.GuestObservation) {
	t.Helper()
	e.gen++
	all := append([]pvecontract.GuestObservation{dpGuest(dpTemplate, "debian-13-tpl", pvecontract.GuestStopped)}, guests...)
	obs := pvecontract.Observation{RemoteID: dpRemote, ObservedAt: time.Now(), Source: "test-collector", CollectionGeneration: e.gen, Complete: true,
		Nodes: pvecontract.AvailableDataset([]pvecontract.NodeObservation{{Node: dpNode, Status: pvecontract.NodeOnline, CPUCount: 8,
			RAMTotalBytes: 32 << 30, Details: pvecontract.UnavailableDataset[pvecontract.NodeDetails]("not read")}}),
		Guests:   pvecontract.AvailableDataset(all),
		Storages: pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("not read"),
		Cluster:  pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("not read"),
		Tasks:    pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("not read")}
	if _, err := e.pve.IngestObservation(context.Background(), obs); err != nil {
		t.Fatalf("ingest: %v", err)
	}
}

func (e *dpEnv) do(t *testing.T, method, path, contentType, body string) (int, string, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header().Get("Location")
}

func dpForm() url.Values {
	return url.Values{
		"remote": {dpRemote}, "node": {dpNode}, "storage": {"local-lvm"}, "profile": {"web_s"}, "profile_version": {"1"},
		"image": {"debian-13"}, "template_vmid": {"9000"}, "template_sha256": {dpImageSHA}, "size": {"S"},
		"name": {"web1"}, "environment": {"QA"}, "bridge": {"vmbr0"}, "ip_mode": {"ipam"}, "network": {"lan"},
		"pool": {"servers"}, "address": {"192.168.10.50"}, "nameservers": {"192.168.10.1"}, "search_domain": {"lab.example"},
		"ci_user": {"nebula"}, "password": {"none"},
		"bootstrap": {"user", "timezone", "qemu-guest-agent"}, "runbook": {"harden@3"},
	}
}

// propose posts the wizard and returns the run page path.
func (e *dpEnv) propose(t *testing.T, f url.Values) string {
	t.Helper()
	code, body, loc := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, f.Encode())
	if code != http.StatusSeeOther || !regexp.MustCompile(`^/deployments/[0-9a-f]{32}$`).MatchString(loc) {
		t.Fatalf("propose = %d %q -> %q", code, body, loc)
	}
	return loc
}

// waitState polls the run page until it shows state.
func (e *dpEnv) waitState(t *testing.T, path, state string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, body, _ := e.do(t, http.MethodGet, path, "", "")
		if strings.Contains(body, `id="deploy-state">`+state+`<`) {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("run never reached %q: %s", state, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func approveJSON(id string) string {
	return `{"id":"` + id + `","assertion":{"id":"x"}}`
}

func TestDeployNavEntryHasThreePages(t *testing.T) {
	e := newDPEnv(t)
	_, body, _ := e.do(t, http.MethodGet, "/deploy", "", "")
	for _, want := range []string{`href="/deployments"`, "<span>Deploy</span>", `href="/deployments/new">New deployment`, `href="/deployments">Deployment runs`, `href="/deploy">Profiles`} {
		if !strings.Contains(body, want) {
			t.Errorf("deploy pages lack %q", want)
		}
	}
	if code, _, _ := e.do(t, http.MethodGet, "/deployments", "", ""); code != http.StatusOK {
		t.Errorf("runs page = %d", code)
	}
	// Without provisioning the entry stays the profile list only.
	h := newTestHandler(t, ui.Options{PublicOrigin: gpOrigin, PVE: e.pve}).Handler()
	if body := getBody(t, h, "/deploy"); strings.Contains(body, "/deployments") {
		t.Error("deployment pages offered without provisioning")
	}
	if code := statusOf(t, h, "/deployments/new"); code != http.StatusNotFound {
		t.Errorf("wizard without provisioning = %d, want 404", code)
	}
}

func TestChartNodeOffersDeployHereOnActiveRemotesOnly(t *testing.T) {
	e := newDPEnv(t)
	_, body, _ := e.do(t, http.MethodGet, "/inventory/chart", "", "")
	want := `href="/deployments/new?node=p1&amp;remote=pve-lab">Deploy here`
	if !strings.Contains(body, want) {
		t.Fatalf("chart node lacks %s", want)
	}
	e.state = "blocked"
	if _, body, _ := e.do(t, http.MethodGet, "/inventory/chart", "", ""); strings.Contains(body, "Deploy here") {
		t.Error("a blocked remote offers Deploy here")
	}
}

func TestDeployWizardPreselectsTargetAndSuggestsFreeAddress(t *testing.T) {
	e := newDPEnv(t)
	ctx := context.Background()
	if _, err := e.ipam.Reserve(ctx, "bob", "lan", "servers", netip.MustParseAddr("192.168.10.50"), "taken"); err != nil {
		t.Fatal(err)
	}
	_, body, _ := e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1&profile=web_s", "", "")
	for _, want := range []string{
		`<input type="hidden" name="remote" value="pve-lab">`, `<input type="hidden" name="node" value="p1">`,
		`<input type="hidden" name="profile_version" value="1">`,
		// The profile's pool selects its network; .50 is reserved, so .51
		// is the suggested free address.
		`name="address" value="192.168.10.51"`, `<option value="9000">9000 debian-13-tpl</option>`,
		`value="qemu-guest-agent" checked`, `value="harden@3" checked`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("wizard lacks %s", want)
		}
	}
	// A blocked remote is not offered and its node is not preselected.
	e.state = "blocked"
	_, body, _ = e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1", "", "")
	if strings.Contains(body, `name="remote" value="pve-lab"`) || strings.Contains(body, "deploy-form") {
		t.Error("the wizard offers a blocked remote")
	}
}

func TestDeployReviewShowsFrozenPlanAndExecutorRisk(t *testing.T) {
	e := newDPEnv(t)
	run := e.propose(t, dpForm())
	_, body, _ := e.do(t, http.MethodGet, run, "", "")
	for _, want := range []string{
		`id="deploy-risk">HIGH<`, `id="deploy-state">proposed<`, "memory over-commit on p1",
		`<td class="mono">qemu-guest-agent.install</td><td class="mono">1.0.0</td>`,
		`<td class="mono">timezone.install</td>`, `zone=/Europe/Berlin`,
		`<td class="mono">runbook.harden</td><td class="mono">3.0.0</td>`,
		"user.install 1.0.0</span>: needs the secret slot(s) ssh_public_key",
		`data-commit="/deployments/approve"`, "192.168.10.50 in 192.168.10.0/24",
	} {
		if !strings.Contains(html.UnescapeString(body), html.UnescapeString(want)) {
			t.Errorf("review lacks %s", want)
		}
	}
	// The plan keeps the documented order (ADR 0008 section 5): modules,
	// then runbooks, whatever order the form sent.
	if i, j := strings.Index(body, "timezone.install"), strings.Index(body, "qemu-guest-agent.install"); i < 0 || j < i {
		t.Error("bootstrap modules are not in the documented order")
	}
	spec := e.prov.proposed[0]
	if spec.GetIpam().GetAddress() != "192.168.10.50" || spec.GetIpam().GetGateway() != "192.168.10.1" ||
		spec.GetTemplate().GetVmid() != dpTemplate || spec.GetTemplate().GetGeneration() != 1 || spec.GetTemplate().GetSourceSha256() != dpImageSHA ||
		spec.GetCores() != 1 || spec.GetMemoryMib() != 1024 || spec.GetDiskGib() != 16 || !spec.GetStart() || spec.GetVmid() != 0 ||
		spec.GetAutomationCredentialRef() != "nebula-default" {
		t.Errorf("proposed spec %v", spec)
	}
	// The address is held by the IPAM reservation.
	if _, err := e.ipam.Reserve(context.Background(), "bob", "lan", "servers", netip.MustParseAddr("192.168.10.50"), "x"); !errors.Is(err, ipam.ErrAddressTaken) {
		t.Errorf("the proposed address is not reserved: %v", err)
	}
}

func TestDeployBindingMismatchWithholdsApproval(t *testing.T) {
	cases := map[string]func(*canonical.Request){
		"other action": func(rq *canonical.Request) { rq.ActionID = "pve.guest.power" },
		"other node": func(rq *canonical.Request) {
			tg, _ := permit.ProviderMutationTarget{RemoteID: dpRemote, TrustPin: dpPin, Kind: "node", Node: "p2"}.RiskTarget()
			rq.ResolvedTargets = []canonical.Target{tg}
		},
		"lower risk":      func(rq *canonical.Request) { rq.RiskClass = canonical.RiskMedium },
		"other execution": func(rq *canonical.Request) { rq.ExecutionID = "exec-other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDPEnv(t)
			e.prov.mutate = mutate
			run := e.propose(t, dpForm())
			_, body, _ := e.do(t, http.MethodGet, run, "", "")
			if !strings.Contains(body, "approval withheld") || strings.Contains(body, "schedule-approve") {
				t.Fatal("a mismatching binding is offered for approval")
			}
			id := strings.TrimPrefix(run, "/deployments/")
			if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusNotFound {
				t.Errorf("approve of a mismatch = %d", code)
			}
			if len(e.prov.assertions) != 0 {
				t.Error("the assertion reached the executor")
			}
		})
	}
}

func TestDeployProposeRejectsBadInputWithoutReservingOrProposing(t *testing.T) {
	cases := map[string]func(url.Values){
		"uppercase name":            func(f url.Values) { f.Set("name", "Web1") },
		"dotted name":               func(f url.Values) { f.Set("name", "web1.lab") },
		"short sha":                 func(f url.Values) { f.Set("template_sha256", "abc") },
		"unknown module":            func(f url.Values) { f.Add("bootstrap", "rootkit") },
		"runbook twice":             func(f url.Values) { f.Add("runbook", "harden@3") },
		"no such runbook":           func(f url.Values) { f.Set("runbook", "harden@4") },
		"bad address":               func(f url.Values) { f.Set("address", "192.168.10.500") },
		"ipv6 address":              func(f url.Values) { f.Set("address", "fd00::5") },
		"template not qemu on node": func(f url.Values) { f.Set("template_vmid", "9999") },
		"bad nameserver":            func(f url.Values) { f.Set("nameservers", "dns.example") },
		"password without id":       func(f url.Values) { f.Set("password", "executor") },
		"custom size range":         func(f url.Values) { f.Set("size", "custom"); f.Set("vcpu", "99") },
		"save as with profile":      func(f url.Values) { f.Set("save_as", "copy") },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDPEnv(t)
			f := dpForm()
			mod(f)
			if code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, f.Encode()); code != http.StatusBadRequest {
				t.Fatalf("propose = %d %q, want 400", code, body)
			}
			if len(e.prov.proposed) != 0 {
				t.Error("an invalid deployment reached the executor")
			}
			if _, err := e.ipam.Reserve(context.Background(), "bob", "lan", "servers", netip.MustParseAddr("192.168.10.50"), "x"); err != nil {
				t.Errorf("the address was reserved by a refused proposal: %v", err)
			}
		})
	}
}

func TestDeployProposeRefusalReleasesTheAddress(t *testing.T) {
	e := newDPEnv(t)
	e.prov.proposeErr = status.Error(codes.FailedPrecondition, "pve guest provision: the template is not prepared or changed; prepare it again")
	code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode())
	if code != http.StatusConflict || !strings.Contains(body, "template is not prepared") {
		t.Fatalf("propose = %d %q", code, body)
	}
	if _, err := e.ipam.Reserve(context.Background(), "bob", "lan", "servers", netip.MustParseAddr("192.168.10.50"), "x"); err != nil {
		t.Errorf("the reservation of a refused proposal is kept: %v", err)
	}
}

func TestDeployTakenAddressIsRefused(t *testing.T) {
	e := newDPEnv(t)
	if _, err := e.ipam.Reserve(context.Background(), "bob", "lan", "servers", netip.MustParseAddr("192.168.10.50"), "x"); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode()); code != http.StatusConflict || !strings.Contains(body, "no longer free") {
		t.Fatalf("propose = %d %q", code, body)
	}
	if len(e.prov.proposed) != 0 {
		t.Error("proposed with a taken address")
	}
}

func TestDeployFailedProvisioningKeepsGuestAndStops(t *testing.T) {
	e := newDPEnv(t)
	e.prov.failStep = true
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	body := e.waitState(t, run, "failed")
	for _, want := range []string{"Creating (failed)", "left in PVE for inspection", "UPID:p1:0000qmresize:", "qmresize"} {
		if !strings.Contains(body, want) {
			t.Errorf("failed run lacks %q", want)
		}
	}
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusNotFound {
		t.Errorf("enrollment of a failed run = %d", code)
	}
}

func TestDeployCLIApprovalRunsOnlyWhenApproved(t *testing.T) {
	e := newDPEnv(t)
	e.prov.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
	e.prov.commitErr = status.Error(codes.PermissionDenied, "pve guest provision: no approved permit covers this provisioning")
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	_, body, _ := e.do(t, http.MethodGet, run, "", "")
	if !strings.Contains(body, "nebula approve ") || strings.Contains(body, "schedule-approve") {
		t.Fatal("hardened mode must show the CLI command, not the key button")
	}
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusNotFound {
		t.Errorf("key approval of a CLI proposal = %d", code)
	}
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/run", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther {
		t.Fatalf("run = %d", code)
	}
	body = e.waitState(t, run, "proposed")
	if !strings.Contains(body, "no approved permit") {
		t.Errorf("refused run lacks the reason: %s", body)
	}
}

// TestDeployEndToEndEnrollsProvisionedGuestWithPinnedKey is the PV-06
// wiring: provisioned guest, propose the join, review and approve the
// fingerprint, commit; the inventory host and its guest link exist with
// the pinned key, and the staged plan is proposed as one batch.
func TestDeployEndToEndEnrollsProvisionedGuestWithPinnedKey(t *testing.T) {
	e := newDPEnv(t)
	ctx := context.Background()
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	body := e.waitState(t, run, "booting")
	if !strings.Contains(body, "UPID:p1:0000qmstart:") || !strings.Contains(body, `href="https://192.168.0.10:8006/#v1:0:=qemu%2F123:4:::::::"`) {
		t.Errorf("booting page lacks the PVE tasks and links")
	}
	if c := e.prov.commits[0]; c.GetSpec().GetVmid() != dpVMID || c.GetExecutionId() != dpExec || c.GetExecutionDigest() != e.prov.assertions[0] {
		t.Errorf("commit %v", c)
	}
	// Before the PVE collection has seen the new guest nothing is proposed.
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusBadRequest || !strings.Contains(body, "not in the PVE inventory yet") {
		t.Fatalf("early join = %d %q", code, body)
	}
	e.observe(t, dpGuest(dpVMID, "web1", pvecontract.GuestRunning))
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther {
		t.Fatalf("join = %d %q", code, body)
	}
	jp := e.join.proposed[0]
	if jp.GetHost().GetHostId() != "web1" || jp.GetHost().GetEndpoint() != "192.168.10.50" || jp.GetHost().GetCredentialRef() != "nebula-default" ||
		jp.GetGuest().GetVmid() != dpVMID || jp.GetGuest().GetGeneration() != 1 || jp.GetGuest().GetNode() != dpNode {
		t.Fatalf("join proposal %v", jp)
	}
	_, body, _ = e.do(t, http.MethodGet, run, "", "")
	for _, want := range []string{`id="deploy-state">enrolling<`, `id="deploy-fingerprint">` + dpFingerprint, "compare the fingerprint", `data-commit="/deployments/join/approve"`} {
		if !strings.Contains(body, want) {
			t.Errorf("enrolling page lacks %s", want)
		}
	}
	// Nothing exists before approval.
	if _, err := e.pve.GetLink(ctx, dpRemote, dpVMID, 1); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Fatalf("link before approval: %v", err)
	}
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/join/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("join approve = %d %q", code, body)
	}
	if len(e.prov.assertions) != 2 || e.join.commits[0].GetExecutionDigest() != e.prov.assertions[1] {
		t.Fatalf("join commit not bound to the approved digest")
	}
	link, err := e.pve.GetLink(ctx, dpRemote, dpVMID, 1)
	if err != nil || link.HostID != "web1" {
		t.Fatalf("link = %+v, %v", link, err)
	}
	host, err := inventory.New(e.db).Get(ctx, "web1")
	if err != nil || host.CredentialRef != "nebula-default" || len(host.Endpoints) != 1 || host.Endpoints[0].Address != "192.168.10.50" ||
		host.Environment != inventory.EnvQA || host.Criticality != inventory.CriticalityHigh {
		t.Fatalf("host = %+v, %v", host, err)
	}
	_, body, _ = e.do(t, http.MethodGet, run, "", "")
	if !strings.Contains(body, `id="deploy-state">bootstrapping<`) || !strings.Contains(body, `id="deploy-pinned">`+dpFingerprint) {
		t.Fatalf("bootstrapping page: %s", body)
	}
	// The staged plan: one batch, one member per stage, modules then
	// runbooks at their frozen versions; the secret-slot module is not in it.
	if code, body, loc := e.do(t, http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther || loc != "/batches/batch-1" {
		t.Fatalf("plan = %d %q -> %q", code, body, loc)
	}
	req := e.batches.requests[0]
	var got []string
	for _, st := range req.Stages {
		if len(st.Members) != 1 || st.Gate != "automatic" || st.FailureThreshold != 0 || st.UnreachableThreshold != 0 || st.Members[0].HostID != "web1" {
			t.Fatalf("stage %+v", st)
		}
		got = append(got, st.Members[0].ActionID+"@"+st.Members[0].Version)
	}
	if want := "timezone.install@1.0.0 qemu-guest-agent.install@1.0.0 runbook.harden@3.0.0"; strings.Join(got, " ") != want {
		// timezone precedes qemu-guest-agent in the documented order.
		t.Fatalf("staged plan %v, want %s", got, want)
	}
	if p := req.Stages[0].Members[0].Params; p["zone"] != "/Europe/Berlin" {
		t.Errorf("module parameters from the profile version: %v", p)
	}
	// A second proposal of the same plan is refused.
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusNotFound {
		t.Errorf("second plan proposal = %d", code)
	}
	// The batch outcome finishes the run.
	e.batches.mu.Lock()
	e.batches.counts = executions.BatchCounts{Total: 3, Success: 3}
	e.batches.mu.Unlock()
	body = e.waitState(t, run, "done")
	if !strings.Contains(body, "3 of 3 succeeded") {
		t.Errorf("done page lacks the batch outcome")
	}
}

func TestDeployJoinRefusedWhenNotPinnedOrBoundElsewhere(t *testing.T) {
	t.Run("not pinned", func(t *testing.T) {
		e := newDPEnv(t)
		e.join.pinned = false
		id, run := e.toEnrolling(t)
		if code, body, _ := e.do(t, http.MethodPost, "/deployments/join/approve", "application/json", approveJSON(id)); code != http.StatusConflict || !strings.Contains(body, "did not pin") {
			t.Fatalf("approve = %d %q", code, body)
		}
		if _, err := inventory.New(e.db).Get(context.Background(), "web1"); !errors.Is(err, inventory.ErrHostNotFound) {
			t.Errorf("a host was created without a pin: %v", err)
		}
		e.waitState(t, run, "enrolling")
	})
	t.Run("bound another host", func(t *testing.T) {
		e := newDPEnv(t)
		e.join.boundHost = "web9"
		id, run := e.toEnrolling(t)
		_, body, _ := e.do(t, http.MethodGet, run, "", "")
		if !strings.Contains(body, "another host") || strings.Contains(body, "/deployments/join/approve") {
			t.Fatal("a join bound to another host is offered for approval")
		}
		if code, _, _ := e.do(t, http.MethodPost, "/deployments/join/approve", "application/json", approveJSON(id)); code != http.StatusNotFound {
			t.Errorf("approve = %d", code)
		}
		if len(e.join.commits) != 0 {
			t.Error("committed a mismatching join")
		}
	})
}

// toEnrolling runs a deployment up to the fingerprint review.
func (e *dpEnv) toEnrolling(t *testing.T) (string, string) {
	t.Helper()
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatal("approve")
	}
	e.waitState(t, run, "booting")
	e.observe(t, dpGuest(dpVMID, "web1", pvecontract.GuestRunning))
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther {
		t.Fatalf("join = %d %q", code, body)
	}
	return id, run
}

func TestDeployRunsAreVisibleToTheirProposerOnly(t *testing.T) {
	e := newDPEnv(t)
	sessions := auth.NewStore(e.db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: sessions, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: gpOrigin}, a.Wrap(e.h)))
	t.Cleanup(srv.Close)
	login := func(user string) *http.Cookie {
		token, _, err := sessions.Create(context.Background(), "cred-"+user, user)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: token}
	}
	do := func(c *http.Cookie, method, path, ct, body string) (int, string) {
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(c)
		req.Header.Set("Origin", gpOrigin)
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, res.Header.Get("Location") + string(b)
	}
	alice, bob := login("alice"), login("bob")
	code, loc := do(alice, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode())
	if code != http.StatusSeeOther {
		t.Fatalf("alice propose = %d %q", code, loc)
	}
	run := strings.TrimSpace(loc[:len("/deployments/")+32])
	id := strings.TrimPrefix(run, "/deployments/")
	if code, body := do(alice, http.MethodGet, run, "", ""); code != http.StatusOK || !strings.Contains(body, "schedule-approve") {
		t.Fatalf("alice's own run = %d", code)
	}
	if _, body := do(bob, http.MethodGet, "/deployments", "", ""); strings.Contains(body, id) {
		t.Error("bob's run list shows alice's run")
	}
	for _, c := range []struct{ method, path, ct, body string }{
		{http.MethodGet, run, "", ""},
		{http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)},
		{http.MethodPost, "/deployments/run", gpFormCT, url.Values{"id": {id}}.Encode()},
		{http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}}.Encode()},
		{http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode()},
	} {
		if code, _ := do(bob, c.method, c.path, c.ct, c.body); code != http.StatusNotFound {
			t.Errorf("%s %s by bob = %d", c.method, c.path, code)
		}
	}
	if len(e.prov.assertions) != 0 || e.prov.commitCount() != 0 {
		t.Error("bob's request reached the executor")
	}
}

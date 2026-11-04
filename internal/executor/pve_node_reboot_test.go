// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const rebootOldUptime = 10 * 24 * 3600

// rebootClient is a fake PVE client with the node reboot surface. It
// embeds the power fake for the node target state and dispatches through
// the real DispatchNodeRebootStep with a recording writer.
type rebootClient struct {
	*powerClient
	rmu       sync.Mutex
	facts     PveNodeRebootFacts
	factReads int
	// beforeSend, if set, may change the facts after the engine's last
	// check and before the dispatcher's recheck.
	beforeSend func(c *rebootClient)
	// lost makes the writer report a lost answer after recording the send.
	lost bool
	sent []string
	// back reports the node returned (fresh boot) once a reboot was sent.
	back      bool
	onSent    func()
	bootReads int
	// evacuated makes every read show HA's evacuation done: each guest
	// HA manages has left pve1 and runs started on pve2.
	evacuated bool
	// onRead, if set, runs (with rmu held) before each fact read.
	onRead func(c *rebootClient)
}

func (c *rebootClient) snapshot() PveNodeRebootFacts {
	f := c.facts
	f.Nodes = append([]pveapi.Node(nil), c.facts.Nodes...)
	f.Cluster.Members = append([]pveapi.ClusterMember(nil), c.facts.Cluster.Members...)
	f.Guests = append([]pveapi.Guest(nil), c.facts.Guests...)
	f.HA.Resources = append([]pveapi.HAResource(nil), c.facts.HA.Resources...)
	if c.facts.Votes.Votes != nil {
		f.Votes.Votes = map[string]int{}
		for k, v := range c.facts.Votes.Votes {
			f.Votes.Votes[k] = v
		}
	}
	if c.facts.HA.Maintenance != nil {
		f.HA.Maintenance = map[string]bool{}
		for k, v := range c.facts.HA.Maintenance {
			f.HA.Maintenance[k] = v
		}
	}
	if c.facts.Placement != nil {
		f.Placement = map[PveRebootGuestRef]PveRebootPlacement{}
		for k, v := range c.facts.Placement {
			f.Placement[k] = v
		}
	}
	if c.evacuated {
		for i, r := range f.HA.Resources {
			if r.Node != "pve1" {
				continue
			}
			f.HA.Resources[i].Node, f.HA.Resources[i].State = "pve2", "started"
			f.Guests = slices.DeleteFunc(f.Guests, func(g pveapi.Guest) bool { return g.VMID == r.VMID })
		}
	}
	return f
}

func (c *rebootClient) NodeRebootFacts(_ context.Context, _ executordb.PveRemote, _ string, _ pveapi.TokenSupplier) (PveNodeRebootFacts, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.factReads++
	if c.onRead != nil {
		c.onRead(c)
	}
	return c.snapshot(), nil
}

// TargetState reports the requested node online (any node of the fake).
func (c *rebootClient) TargetState(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (PveTargetState, error) {
	live, err := c.powerClient.TargetState(ctx, rm, kind, node, vmid, read)
	live.Node = node
	return live, err
}

func (c *rebootClient) NodeBoot(_ context.Context, _ executordb.PveRemote, node string, _ pveapi.TokenSupplier) (PveNodeBoot, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.bootReads++
	up := uint64(rebootOldUptime)
	if c.back && len(c.sent) > 0 {
		up = 60
	}
	return PveNodeBoot{Online: true, UptimeSeconds: up, Cluster: c.snapshot().Cluster}, nil
}

func (c *rebootClient) DispatchNodeReboot(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, _, _ pveapi.TokenSupplier) error {
	if c.beforeSend != nil {
		c.rmu.Lock()
		c.beforeSend(c)
		c.rmu.Unlock()
	}
	return DispatchNodeRebootStep(ctx, &rebootWriter{c: c}, &rebootReader{c: c}, rm.Kind, node, step)
}

func (c *rebootClient) sentNodes() []string {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return append([]string(nil), c.sent...)
}

type rebootWriter struct{ c *rebootClient }

func (w *rebootWriter) RebootNode(_ context.Context, node string) error {
	w.c.rmu.Lock()
	w.c.sent = append(w.c.sent, node)
	lost, on := w.c.lost, w.c.onSent
	w.c.rmu.Unlock()
	if on != nil {
		on()
	}
	if lost {
		return errors.New("connection reset")
	}
	return nil
}

type rebootReader struct{ c *rebootClient }

func (r *rebootReader) NodeRebootFacts(context.Context, string) (PveNodeRebootFacts, error) {
	r.c.rmu.Lock()
	defer r.c.rmu.Unlock()
	r.c.factReads++
	if r.c.onRead != nil {
		r.c.onRead(r.c)
	}
	return r.c.snapshot(), nil
}

type rebootEnv struct {
	t      *testing.T
	kind   pvecontract.Kind
	pe     *pveTestEnv
	rm     executordb.PveRemote
	crit   critSource
	auth   *permit.Authority
	client *rebootClient
	m      *PveMutations
	r      *PveNodeReboot
	logs   *bytes.Buffer
	// offset is added to the engine clock (nanoseconds).
	offset atomic.Int64
}

// clusterRebootFacts: a quorate three-node cluster lab, every node up for
// ten days with one vote each and 64 GiB of which 8 GiB are used, no
// QDevice, HA shutdown_policy=migrate, pve1 in HA maintenance mode. On
// pve1: QEMU 101 running (not HA), QEMU 201 running (HA, started, movable),
// LXC 301 stopped; each guest has 4 GiB.
func clusterRebootFacts() PveNodeRebootFacts {
	const gib = 1 << 30
	node := func(name string) pveapi.Node {
		return pveapi.Node{Name: name, Status: "online", UptimeSeconds: rebootOldUptime, MaxMemory: 64 * gib, Memory: 8 * gib}
	}
	return PveNodeRebootFacts{
		Nodes: []pveapi.Node{node("pve1"), node("pve2"), node("pve3")},
		Cluster: pveapi.ClusterStatus{Available: true, Name: "lab", Quorum: true, NodesOnline: 3, NodesTotal: 3,
			Members: []pveapi.ClusterMember{{Name: "pve1", Online: true}, {Name: "pve2", Online: true}, {Name: "pve3", Online: true}}},
		Votes:   pveapi.NodeVotes{Available: true, Votes: map[string]int{"pve1": 1, "pve2": 1, "pve3": 1}},
		QDevice: PveQDevice{Known: true},
		HA: pveapi.HAStatus{Available: true, Maintenance: map[string]bool{"pve1": true, "pve2": false, "pve3": false},
			Resources: []pveapi.HAResource{{VMID: 201, Type: "vm", Managed: true, DesiredState: "started", State: "started", Node: "pve1"}}},
		HAShutdownPolicy: pveHAPolicyMigrate,
		Guests: []pveapi.Guest{
			{Node: "pve1", Kind: pveapi.KindQemu, VMID: 101, Status: "running", MaxMemory: 4 * gib},
			{Node: "pve1", Kind: pveapi.KindQemu, VMID: 201, Status: "running", MaxMemory: 4 * gib},
			{Node: "pve1", Kind: pveapi.KindLxc, VMID: 301, Status: "stopped", MaxMemory: 4 * gib},
		},
		Placement: map[PveRebootGuestRef]PveRebootPlacement{{Kind: permit.ProviderKindQemu, VMID: 201}: {Known: true}},
	}
}

func standaloneRebootFacts() PveNodeRebootFacts {
	return PveNodeRebootFacts{
		Nodes:   []pveapi.Node{{Name: "pve1", Status: "online", UptimeSeconds: rebootOldUptime}},
		Cluster: pveapi.ClusterStatus{Reason: "standalone host: no cluster configured"},
		Guests:  []pveapi.Guest{{Node: "pve1", Kind: pveapi.KindQemu, VMID: 101, Status: "running"}},
	}
}

func newRebootEnv(t *testing.T, kind pvecontract.Kind, withAction bool) *rebootEnv {
	t.Helper()
	return newRebootEnvAt(t, kind, withAction, executordb.SiteOnsite)
}

// newRebootEnvAt is newRebootEnv with the remote's site marker set to
// site (SiteUnset leaves it unset).
func newRebootEnvAt(t *testing.T, kind pvecontract.Kind, withAction bool, site string) *rebootEnv {
	t.Helper()
	pe := newPveTestEnv(t)
	chain := makeTestChain(t)
	pe.probe.result = probeResultFrom(chain, "pve1.example.test")
	pin, facts := fpHex(chain.ca), clusterRebootFacts()
	if kind == pvecontract.KindStandalone {
		pin, facts = fpHex(chain.leaf), standaloneRebootFacts()
	}
	if _, err := pe.add(t, mutRemote, kind, pveEndpoints("pve1.example.test"), pin, []byte(mutReadToken)); err != nil {
		t.Fatal(err)
	}
	if site != executordb.SiteUnset {
		if _, err := pe.admin.SetSite(context.Background(), PveSetSite{RemoteID: mutRemote, Site: site, By: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	if withAction {
		if _, err := pe.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: mutRemote, Purpose: PvePurposeAction, Token: []byte(mutActionToken), By: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	rm, _, err := pe.db.GetRemote(mutRemote)
	if err != nil {
		t.Fatal(err)
	}
	e := &rebootEnv{t: t, kind: kind, pe: pe, rm: rm, logs: &bytes.Buffer{},
		crit:   critSource{artifact: canonical.RiskMedium, hosts: map[canonical.Target]canonical.Risk{}},
		client: &rebootClient{powerClient: &powerClient{liveNode: "pve1", digest: strings.Repeat("cd", 32)}, facts: facts}}
	// The engine clock jumps ahead once a reboot is sent, so the fake's
	// fresh uptime places the boot after the step's intent.
	e.client.onSent = func() { e.offset.Store(int64(10 * time.Minute)) }
	e.restart()
	return e
}

// restart replaces the authority and engine as an executor restart does.
func (e *rebootEnv) restart() {
	e.t.Helper()
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "power.test", Origins: []string{"https://power.test"}, Counters: e.pe.db}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	policy, err := riskpolicy.New(e.crit)
	if err != nil {
		e.t.Fatal(err)
	}
	e.auth, err = permit.New(permit.Options{Verifier: v, Store: e.pe.db, RiskPolicy: policy})
	if err != nil {
		e.t.Fatal(err)
	}
	e.m = &PveMutations{DB: e.pe.db, Auth: e.auth, Vault: e.pe.vault, Client: e.client, PollInterval: time.Millisecond,
		MaxWait: 2 * time.Second, RebootPollInterval: time.Millisecond, RebootMaxWait: time.Hour,
		Now: func() time.Time { return time.Now().Add(time.Duration(e.offset.Load())) },
		Log: slog.New(slog.NewTextHandler(e.logs, nil))}
	e.pe.admin.Mutations = e.m
	e.r = &PveNodeReboot{Mutations: e.m, Criticality: e.crit}
}

func rebootReq() PveNodeRebootRequest {
	return PveNodeRebootRequest{RemoteID: mutRemote, Node: "pve1", AcceptedDowntime: []PveRebootGuestRef{{Kind: permit.ProviderKindQemu, VMID: 101}}}
}

// req is the default request of the env: on the cluster, QEMU 101 is
// accepted downtime and QEMU 201 is evacuated by HA.
func (e *rebootEnv) req() PveNodeRebootRequest {
	r := rebootReq()
	if e.kind == pvecontract.KindCluster {
		r.HAEvacuate = []PveRebootGuestRef{{Kind: permit.ProviderKindQemu, VMID: 201}}
	}
	return r
}

var rebootExecSeq int

func nextRebootExec() string {
	rebootExecSeq++
	return fmt.Sprintf("00000000-0000-4000-e000-%012d", rebootExecSeq)
}

func (e *rebootEnv) propose(req PveNodeRebootRequest) (permit.Permit, error) {
	return e.r.Propose(context.Background(), req, nextRebootExec(), time.Now().Add(time.Hour))
}

// approve proposes req and approves it via the CLI with the typed target
// count the permit needs.
func (e *rebootEnv) approve(req PveNodeRebootRequest) (PveNodeRebootRequest, permit.Permit) {
	e.t.Helper()
	p, err := e.propose(req)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, p.TargetCount(), "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest = p.Digest
	// HA moves the guests listed for evacuation off the node.
	if len(req.HAEvacuate) > 0 {
		e.client.rmu.Lock()
		e.client.evacuated = true
		e.client.rmu.Unlock()
	}
	return req, p
}

func rebootParams(t *testing.T, p permit.Permit) pveRebootParams {
	t.Helper()
	var doc struct {
		Parameters pveRebootParams `json:"parameters"`
	}
	if err := json.Unmarshal(p.Parameters, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Parameters
}

func TestNodeRebootStandaloneIsHighAndWaitsForReturn(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindStandalone, true)
	e.client.back = true
	p, err := e.propose(e.req())
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskHigh || p.Requirement != permit.RequireAssertionVerified {
		t.Fatalf("risk %s requirement %s, want HIGH with user verification", p.Request.RiskClass, p.Requirement)
	}
	rp := rebootParams(t, p)
	if rp.Bound.Clustered || len(rp.Bound.Guests) != 1 || !rp.Bound.Guests[0].AcceptedDowntime || rp.Risk != canonical.RiskHigh {
		t.Fatalf("bound %+v", rp)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	req := e.req()
	req.Digest = p.Digest
	res, err := e.r.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[0].TaskType != pveNodeRebootTaskType ||
		res.Steps[0].Kind != permit.ProviderKindNode || res.Steps[0].Node != "pve1" {
		t.Fatalf("steps %+v", res.Steps)
	}
	if sent := e.client.sentNodes(); len(sent) != 1 || sent[0] != "pve1" {
		t.Fatalf("sent %v", sent)
	}
}

func TestNodeRebootClusterIsCriticalAndNeedsTargetCount(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	e.client.back = true
	p, err := e.propose(e.req())
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskCritical || p.Requirement != permit.RequireAssertionVerifiedTypedCount {
		t.Fatalf("risk %s requirement %s, want CRITICAL with typed target count", p.Request.RiskClass, p.Requirement)
	}
	rp := rebootParams(t, p)
	b := rp.Bound
	if !b.Clustered || b.Cluster != "lab" || b.TotalVotes != 3 || b.RemainingVotes != 2 || len(b.Members) != 3 ||
		b.HAShutdownPolicy != pveHAPolicyMigrate || !b.Maintenance || len(b.Guests) != 3 {
		t.Fatalf("bound %+v", b)
	}
	want := []PveRebootGuest{
		{Kind: "lxc", VMID: 301, Status: "stopped"},
		{Kind: "qemu", VMID: 101, Status: "running", AcceptedDowntime: true},
		{Kind: "qemu", VMID: 201, Status: "running", HAEvacuates: true},
	}
	for i := range want {
		if b.Guests[i] != want[i] {
			t.Fatalf("guest %d = %+v, want %+v", i, b.Guests[i], want[i])
		}
	}
	// The node and both running guests are the targets: the stopped guest
	// is not impacted. Each target is listed with its object and effect.
	if p.TargetCount() != 3 || len(rp.Targets) != 3 {
		t.Fatalf("targets %d %+v, want node + 2 guests", p.TargetCount(), rp.Targets)
	}
	effects := map[string]string{}
	for _, tg := range rp.Targets {
		if !slices.ContainsFunc(p.Request.ResolvedTargets, func(c canonical.Target) bool {
			return c.HostID == tg.HostID && c.HostKeyFingerprint == tg.Fingerprint
		}) {
			t.Fatalf("listed target %+v not bound in the permit", tg)
		}
		effects[fmt.Sprintf("%s/%d", tg.Kind, tg.VMID)] = tg.Effect
	}
	if effects["node/0"] != pveRebootEffectReboot || effects["qemu/101"] != pveRebootEffectDowntime || effects["qemu/201"] != pveRebootEffectEvacuation {
		t.Fatalf("effects %v", effects)
	}
	// CRITICAL: a wrong typed target count is refused; 1 (only the node)
	// is wrong. (A third failure would discard the permit.)
	for _, n := range []int{1, 2} {
		if _, err := e.auth.ApproveCLI(p.Digest, n, "admin"); permit.CodeOf(err) != permit.CodeTypedCountMismatch {
			t.Fatalf("typed %d: got %v, want typed count mismatch", n, err)
		}
	}
	req := e.req()
	req.Digest = p.Digest
	e.client.evacuated = true
	if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) || len(e.client.sentNodes()) != 0 {
		t.Fatalf("unapproved run: %v, sent %v", err, e.client.sentNodes())
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 3, "admin"); err != nil {
		t.Fatal(err)
	}
	res, err := e.r.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded {
		t.Fatalf("steps %+v", res.Steps)
	}
	if e.client.factReads < 5 {
		t.Fatalf("facts read %d times, want proposal, evacuation, run, intent and dispatch rechecks", e.client.factReads)
	}
}

// TestNodeRebootLXCEvacuationIsDowntime: HA moves a container by restart
// migration, so an LXC guest listed for HA evacuation is listed with
// effect downtime (and how HA moves it); a QEMU guest HA live-migrates.
func TestNodeRebootLXCEvacuationIsDowntime(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	b := pveRebootBound{Guests: []PveRebootGuest{
		{Kind: "lxc", VMID: 301, Status: "running", HAEvacuates: true},
		{Kind: "lxc", VMID: 302, Status: "running", AcceptedDowntime: true},
		{Kind: "qemu", VMID: 201, Status: "running", HAEvacuates: true},
	}}
	ts, ls, err := rebootTargets(e.rm, "pve1", b)
	if err != nil || len(ts) != 4 || len(ls) != 4 {
		t.Fatalf("targets %+v %v", ls, err)
	}
	want := map[string]PveRebootTarget{
		"node/0":   {Effect: pveRebootEffectReboot},
		"lxc/301":  {Effect: pveRebootEffectDowntime, HAMove: pveRebootHAMoveRestart},
		"lxc/302":  {Effect: pveRebootEffectDowntime},
		"qemu/201": {Effect: pveRebootEffectEvacuation},
	}
	for _, l := range ls {
		w := want[fmt.Sprintf("%s/%d", l.Kind, l.VMID)]
		if l.Effect != w.Effect || l.HAMove != w.HAMove {
			t.Fatalf("target %+v, want effect %q ha_move %q", l, w.Effect, w.HAMove)
		}
	}
	raw, err := json.Marshal(ls[1])
	if err != nil || !strings.Contains(string(raw), `"effect":"downtime"`) || !strings.Contains(string(raw), `"ha_move":"restart_migration"`) {
		t.Fatalf("listed target %s %v", raw, err)
	}
}

func TestNodeRebootTypedCountCoversEveryImpactedGuest(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	e.client.facts.HA.Maintenance["pve1"] = false
	e.client.facts.Guests = append(e.client.facts.Guests,
		pveapi.Guest{Node: "pve1", Kind: pveapi.KindLxc, VMID: 302, Status: "running"},
		pveapi.Guest{Node: "pve1", Kind: pveapi.KindQemu, VMID: 102, Status: "paused"})
	req := rebootReq()
	req.AcceptedDowntime = append(req.AcceptedDowntime, PveRebootGuestRef{Kind: "qemu", VMID: 201},
		PveRebootGuestRef{Kind: "lxc", VMID: 302}, PveRebootGuestRef{Kind: "qemu", VMID: 102})
	p, err := e.propose(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.TargetCount() != 5 {
		t.Fatalf("target count %d, want the node and 4 guests", p.TargetCount())
	}
	for _, n := range []int{1, 4} {
		if _, err := e.auth.ApproveCLI(p.Digest, n, "admin"); permit.CodeOf(err) != permit.CodeTypedCountMismatch {
			t.Fatalf("typed %d: got %v", n, err)
		}
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 5, "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRebootCriticalityRaisesStandalone(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindStandalone, true)
	nt, err := (permit.ProviderMutationTarget{RemoteID: e.rm.RemoteID, TrustPin: e.rm.TrustPin, Kind: permit.ProviderKindNode, Node: "pve1"}).RiskTarget()
	if err != nil {
		t.Fatal(err)
	}
	e.crit.hosts[nt] = canonical.RiskCritical
	p, err := e.propose(e.req())
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskCritical {
		t.Fatalf("risk %s, want CRITICAL from the node record", p.Request.RiskClass)
	}
}

func TestNodeRebootQuorumLossRefused(t *testing.T) {
	cases := map[string]func(f *PveNodeRebootFacts){
		"two-node cluster": func(f *PveNodeRebootFacts) {
			f.Nodes = f.Nodes[:2]
			f.Cluster.Members, f.Cluster.NodesOnline, f.Cluster.NodesTotal = f.Cluster.Members[:2], 2, 2
			f.Votes.Votes = map[string]int{"pve1": 1, "pve2": 1}
		},
		"node holds half the votes": func(f *PveNodeRebootFacts) { f.Votes.Votes = map[string]int{"pve1": 2, "pve2": 1, "pve3": 1} },
		"cluster without quorum":    func(f *PveNodeRebootFacts) { f.Cluster.Quorum = false },
		"votes unreadable":          func(f *PveNodeRebootFacts) { f.Votes = pveapi.NodeVotes{Reason: "forbidden"} },
		"votes miss a member":       func(f *PveNodeRebootFacts) { delete(f.Votes.Votes, "pve3") },
		"votes name a stranger":     func(f *PveNodeRebootFacts) { delete(f.Votes.Votes, "pve3"); f.Votes.Votes["pve9"] = 1 },
		"qdevice configured":        func(f *PveNodeRebootFacts) { f.QDevice.Configured = true },
		"qdevice state unknown":     func(f *PveNodeRebootFacts) { f.QDevice = PveQDevice{} },
		"member count disagrees":    func(f *PveNodeRebootFacts) { f.Cluster.NodesTotal = 4 },
		"zero votes everywhere":     func(f *PveNodeRebootFacts) { f.Votes.Votes = map[string]int{"pve1": 0, "pve2": 0, "pve3": 0} },
		"negative vote":             func(f *PveNodeRebootFacts) { f.Votes.Votes["pve2"] = -1 },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newRebootEnv(t, pvecontract.KindCluster, true)
			mod(&e.client.facts)
			if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootQuorum) {
				t.Fatalf("got %v, want quorum refusal", err)
			}
		})
	}
	// Quorum lost between approval and run: nothing is sent.
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	req, _ := e.approve(e.req())
	e.client.facts.Votes.Votes["pve1"] = 3
	if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootQuorum) || len(e.client.sentNodes()) != 0 {
		t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
	}
}

func TestNodeRebootSecondConcurrentNodeRefused(t *testing.T) {
	cases := map[string]func(f *PveNodeRebootFacts){
		"other member offline": func(f *PveNodeRebootFacts) {
			f.Cluster.Members[1].Online, f.Cluster.NodesOnline = false, 2
			f.Nodes[1].Status = "offline"
		},
		"other node just rebooted":  func(f *PveNodeRebootFacts) { f.Nodes[2].UptimeSeconds = 90 },
		"other node uptime unknown": func(f *PveNodeRebootFacts) { f.Nodes[2].UptimeSeconds = 0 },
		"other node listed offline": func(f *PveNodeRebootFacts) { f.Nodes[1].Status = "offline" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newRebootEnv(t, pvecontract.KindCluster, true)
			mod(&e.client.facts)
			if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootBusy) {
				t.Fatalf("got %v, want busy refusal", err)
			}
		})
	}

	t.Run("open reboot step of another node", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		if err := e.pe.db.CreatePveJobIntent(executordb.PveJob{ExecutionID: "00000000-0000-4000-e000-999999999999", Step: 1,
			Digest: strings.Repeat("a", 64), Action: PveNodeRebootAction, RemoteID: mutRemote, TrustGeneration: e.rm.TrustGeneration,
			Kind: permit.ProviderKindNode, Node: "pve2", RequestDigest: strings.Repeat("b", 64), TaskType: pveNodeRebootTaskType, TaskUser: mutActionUser}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootBusy) {
			t.Fatalf("propose: got %v", err)
		}
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootBusy) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("run: got %v, sent %v", err, e.client.sentNodes())
		}
	})

	t.Run("reboot running in the engine", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		release, ok := e.m.lockNodeReboot(mutRemote)
		if !ok {
			t.Fatal("lock")
		}
		if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootBusy) {
			t.Fatalf("propose: got %v", err)
		}
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootBusy) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("run: got %v, sent %v", err, e.client.sentNodes())
		}
		release()
		e.client.back = true
		if _, err := e.r.Run(context.Background(), req); err != nil {
			t.Fatalf("after release: %v", err)
		}
	})

	t.Run("two runs at once send one reboot", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.facts.Guests = nil
		r1, _ := e.approve(PveNodeRebootRequest{RemoteID: mutRemote, Node: "pve1"})
		r2, _ := e.approve(PveNodeRebootRequest{RemoteID: mutRemote, Node: "pve2"})
		started := make(chan struct{})
		e.client.onSent = func() { close(started) }
		done := make(chan error, 1)
		go func() {
			_, err := e.r.Run(context.Background(), r1)
			done <- err
		}()
		<-started
		if _, err := e.r.Run(context.Background(), r2); !errors.Is(err, ErrPveRebootBusy) {
			t.Fatalf("second node: got %v, want busy", err)
		}
		e.client.rmu.Lock()
		e.client.back = true
		e.client.rmu.Unlock()
		e.offset.Store(int64(10 * time.Minute))
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if sent := e.client.sentNodes(); len(sent) != 1 || sent[0] != "pve1" {
			t.Fatalf("sent %v", sent)
		}
	})
}

func TestNodeRebootUnlistedRunningGuestRefused(t *testing.T) {
	q201 := PveRebootGuestRef{Kind: permit.ProviderKindQemu, VMID: 201}
	cases := []struct {
		name string
		mod  func(f *PveNodeRebootFacts, r *PveNodeRebootRequest)
		want error
	}{
		{"running guest not listed", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) { r.AcceptedDowntime = nil }, ErrPveRebootGuests},
		{"ha guest not listed", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) { r.HAEvacuate = nil }, ErrPveRebootGuests},
		{"paused guest counts as running", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.Guests = append(f.Guests, pveapi.Guest{Node: "pve1", Kind: pveapi.KindQemu, VMID: 401, Status: "paused"})
		}, ErrPveRebootGuests},
		{"accepted guest is stopped", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) {
			r.AcceptedDowntime = append(r.AcceptedDowntime, PveRebootGuestRef{Kind: permit.ProviderKindLXC, VMID: 301})
		}, ErrPveRebootGuests},
		{"accepted guest not on the node", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) {
			r.AcceptedDowntime = append(r.AcceptedDowntime, PveRebootGuestRef{Kind: permit.ProviderKindQemu, VMID: 999})
		}, ErrPveRebootGuests},
		{"evacuated guest not on the node", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) {
			r.HAEvacuate = append(r.HAEvacuate, PveRebootGuestRef{Kind: permit.ProviderKindQemu, VMID: 999})
		}, ErrPveRebootGuests},
		{"accepted with the wrong kind", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) {
			r.AcceptedDowntime = []PveRebootGuestRef{{Kind: permit.ProviderKindLXC, VMID: 101}}
		}, ErrPveRebootGuests},
		{"guest of another node in the list", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.Guests[0].Node = "pve2" }, ErrPveRebootState},
		{"duplicate vmid", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.Guests = append(f.Guests, pveapi.Guest{Node: "pve1", Kind: pveapi.KindLxc, VMID: 101, Status: "stopped"})
		}, ErrPveRebootState},
		{"ha state unknown", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.HA = pveapi.HAStatus{Reason: "forbidden"} }, ErrPveRebootState},
		{"ha policy unknown", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.HAShutdownPolicy = "" }, ErrPveRebootState},

		// A guest listed for HA evacuation must be provably movable.
		{"migrate policy without maintenance mode", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.HA.Maintenance["pve1"] = false
		}, ErrPveRebootNotEvacuable},
		{"maintenance state of the node unknown", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			delete(f.HA.Maintenance, "pve1")
		}, ErrPveRebootNotEvacuable},
		{"ha resource not started", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.HA.Resources[0].DesiredState = "ignored" }, ErrPveRebootNotEvacuable},
		{"not ha managed", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.HA.Resources = nil }, ErrPveRebootNotEvacuable},
		{"ha resource of the other kind", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.HA.Resources[0].Type = "ct" }, ErrPveRebootNotEvacuable},
		{"placement unknown", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.Placement = nil }, ErrPveRebootNotEvacuable},
		{"placement not modelled", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.Placement[q201] = PveRebootPlacement{} }, ErrPveRebootNotEvacuable},
		{"local resources", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.Placement[q201] = PveRebootPlacement{Known: true, LocalResources: true}
		}, ErrPveRebootNotEvacuable},
		{"ha group allows no other node", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.Placement[q201] = PveRebootPlacement{Known: true, Restricted: true, AllowedNodes: []string{"pve1"}}
		}, ErrPveRebootNotEvacuable},
		{"allowed node has no room", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.Placement[q201] = PveRebootPlacement{Known: true, Restricted: true, AllowedNodes: []string{"pve1", "pve2"}}
			f.Nodes[1].Memory = f.Nodes[1].MaxMemory - 1<<20
		}, ErrPveRebootNotEvacuable},
		{"guest memory unknown", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.Guests[1].MaxMemory = 0 }, ErrPveRebootNotEvacuable},
		{"other nodes' memory unknown", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.Nodes[1].MaxMemory, f.Nodes[2].MaxMemory = 0, 0
		}, ErrPveRebootNotEvacuable},
		{"guest is paused", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.Guests[1].Status = "paused" }, ErrPveRebootNotEvacuable},
		{"guest is stopped", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.Guests[1].Status = "stopped" }, ErrPveRebootNotEvacuable},
		{"listed twice", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) {
			r.AcceptedDowntime = append(r.AcceptedDowntime, q201)
		}, ErrPveRebootRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRebootEnv(t, pvecontract.KindCluster, true)
			req := e.req()
			tc.mod(&e.client.facts, &req)
			if _, err := e.propose(req); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("not movable guest accepted as downtime", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.facts.HA.Maintenance["pve1"] = false
		req := e.req()
		req.HAEvacuate, req.AcceptedDowntime = nil, append(req.AcceptedDowntime, q201)
		p, err := e.propose(req)
		if err != nil {
			t.Fatal(err)
		}
		if g := rebootParams(t, p).Bound.Guests[2]; g.HAEvacuates || !g.AcceptedDowntime {
			t.Fatalf("ha guest %+v", g)
		}
	})

	t.Run("evacuating guests must fit together", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		const gib = 1 << 30
		f := &e.client.facts
		f.Guests[0].MaxMemory = 40 * gib
		f.HA.Resources = append(f.HA.Resources, pveapi.HAResource{VMID: 101, Type: "vm", Managed: true, DesiredState: "started", State: "started", Node: "pve1"})
		f.Placement[PveRebootGuestRef{Kind: "qemu", VMID: 101}] = PveRebootPlacement{Known: true, Restricted: true, AllowedNodes: []string{"pve2"}}
		f.Placement[q201] = PveRebootPlacement{Known: true, Restricted: true, AllowedNodes: []string{"pve2"}}
		f.Nodes[1].Memory = 64*gib - 42*gib // 42 GiB free on pve2: 40 + 4 do not fit
		req := e.req()
		req.AcceptedDowntime, req.HAEvacuate = nil, []PveRebootGuestRef{{Kind: "qemu", VMID: 101}, q201}
		if _, err := e.propose(req); !errors.Is(err, ErrPveRebootNotEvacuable) {
			t.Fatalf("got %v", err)
		}
		f.Placement[q201] = PveRebootPlacement{Known: true}
		if _, err := e.propose(req); err != nil {
			t.Fatalf("201 may go to pve3: %v", err)
		}
	})

	t.Run("new running guest after approval blocks the dispatch", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		e.client.beforeSend = func(c *rebootClient) {
			c.facts.Guests = append(c.facts.Guests, pveapi.Guest{Node: "pve1", Kind: pveapi.KindLxc, VMID: 302, Status: "running"})
		}
		res, err := e.r.Run(context.Background(), req)
		if !errors.Is(err, ErrPveStepFailed) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
		if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobFailed {
			t.Fatalf("steps %+v", res.Steps)
		}
	})

	t.Run("guest status change after approval blocks the run", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		e.client.facts.Guests[2].Status = "running"
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootGuests) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})
}

func TestNodeRebootWaitsForHAEvacuation(t *testing.T) {
	t.Run("sent only after the guest moved", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.back = true
		req, _ := e.approve(e.req())
		e.client.evacuated = false
		reads := 0
		e.client.onRead = func(c *rebootClient) {
			reads++
			if reads == 3 { // HA finishes moving 201 while the Run waits
				c.evacuated = true
			}
		}
		e.client.beforeSend = func(c *rebootClient) {
			if !c.evacuated {
				t.Error("dispatch before the evacuation finished")
			}
		}
		if _, err := e.r.Run(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if sent := e.client.sentNodes(); len(sent) != 1 || reads < 4 {
			t.Fatalf("sent %v after %d reads", sent, reads)
		}
	})

	t.Run("evacuation not finished in time", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		e.client.evacuated = false
		e.m.RebootEvacuationWait = 20 * time.Millisecond
		res, err := e.r.Run(context.Background(), req)
		if !errors.Is(err, ErrPveRebootEvacuation) || len(e.client.sentNodes()) != 0 || len(res.Steps) != 0 {
			t.Fatalf("got %v, sent %v, steps %+v", err, e.client.sentNodes(), res.Steps)
		}
		// Nothing was authorized: the permit still runs once HA is done.
		e.client.evacuated, e.client.back = true, true
		if _, err := e.r.Run(context.Background(), req); err != nil {
			t.Fatalf("after evacuation: %v", err)
		}
	})

	t.Run("moved guest not started elsewhere", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		e.m.RebootEvacuationWait, e.m.RebootMaxWait = 20*time.Millisecond, time.Millisecond
		// 201 left pve1, but HA reports it in error on pve2.
		e.client.evacuated = false
		e.client.facts.Guests = slices.DeleteFunc(e.client.facts.Guests, func(g pveapi.Guest) bool { return g.VMID == 201 })
		e.client.facts.HA.Resources[0].Node, e.client.facts.HA.Resources[0].State = "pve2", "error"
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootEvacuation) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})

	t.Run("quorum lost after the evacuation", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		e.client.facts.Votes.Votes["pve1"] = 3
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootQuorum) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})

	t.Run("maintenance mode ended after approval", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		e.client.facts.HA.Maintenance["pve1"] = false
		if _, err := e.r.Run(context.Background(), req); err == nil || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})

	t.Run("guest back on the node at dispatch", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(e.req())
		e.client.beforeSend = func(c *rebootClient) { c.evacuated = false }
		res, err := e.r.Run(context.Background(), req)
		if !errors.Is(err, ErrPveStepFailed) || len(e.client.sentNodes()) != 0 || res.Steps[0].State != executordb.PveJobFailed {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})
}

func TestNodeRebootReadOnlyRemoteRefused(t *testing.T) {
	for _, kind := range []pvecontract.Kind{pvecontract.KindStandalone, pvecontract.KindCluster} {
		t.Run(string(kind), func(t *testing.T) {
			e := newRebootEnv(t, kind, false)
			if _, err := e.propose(e.req()); !errors.Is(err, ErrPveReadOnly) {
				t.Fatalf("propose: got %v, want read-only", err)
			}
			req := e.req()
			req.Digest = canonical.Digest{1}
			if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveReadOnly) {
				t.Fatalf("run: got %v, want read-only", err)
			}
			if e.client.factReads != 0 || e.client.reads != 0 || len(e.client.sentNodes()) != 0 {
				t.Fatal("a read-only remote was read or written")
			}
		})
	}
}

func TestNodeRebootOffsiteOrUnsetSiteRefused(t *testing.T) {
	for _, kind := range []pvecontract.Kind{pvecontract.KindStandalone, pvecontract.KindCluster} {
		for site, want := range map[string]error{executordb.SiteOffsite: ErrPveRebootOffsite, executordb.SiteUnset: ErrPveRebootSite} {
			t.Run(string(kind)+"/"+site, func(t *testing.T) {
				// The remote has an action credential: still refused.
				e := newRebootEnvAt(t, kind, true, site)
				if _, err := e.propose(e.req()); !errors.Is(err, want) {
					t.Fatalf("propose: got %v, want %v", err, want)
				}
				req := e.req()
				req.Digest = canonical.Digest{1}
				if _, err := e.r.Run(context.Background(), req); !errors.Is(err, want) {
					t.Fatalf("run: got %v, want %v", err, want)
				}
				if e.client.factReads != 0 || len(e.client.sentNodes()) != 0 {
					t.Fatal("an offsite or unmarked remote was read or written")
				}
			})
		}
	}

	t.Run("marked offsite after approval", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		req, _ := e.approve(e.req())
		if _, err := e.pe.db.SetRemoteSite(mutRemote, executordb.SiteOffsite, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootOffsite) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})

	t.Run("marked offsite right before the send", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		req, _ := e.approve(e.req())
		var once sync.Once
		e.client.onRead = func(*rebootClient) {
			// After the engine's last liveCheck read: the dispatcher's own
			// site check refuses.
			if e.client.factReads >= 3 {
				once.Do(func() {
					if _, err := e.pe.db.SetRemoteSite(mutRemote, executordb.SiteOffsite, "admin"); err != nil {
						t.Error(err)
					}
				})
			}
		}
		_, err := e.r.Run(context.Background(), req)
		if err == nil || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})
}

func TestNodeRebootRequestRefusedWithoutIO(t *testing.T) {
	cases := map[string]func(r *PveNodeRebootRequest){
		"empty node":         func(r *PveNodeRebootRequest) { r.Node = "" },
		"malformed node":     func(r *PveNodeRebootRequest) { r.Node = "pve1/../x" },
		"node kind accepted": func(r *PveNodeRebootRequest) { r.AcceptedDowntime = []PveRebootGuestRef{{Kind: "node", VMID: 101}} },
		"bad vmid":           func(r *PveNodeRebootRequest) { r.AcceptedDowntime = []PveRebootGuestRef{{Kind: "qemu", VMID: 7}} },
		"duplicate accepted": func(r *PveNodeRebootRequest) { r.AcceptedDowntime = append(r.AcceptedDowntime, r.AcceptedDowntime[0]) },
		"too many accepted": func(r *PveNodeRebootRequest) {
			for i := 0; i <= maxPveRebootAccepted; i++ {
				r.AcceptedDowntime = append(r.AcceptedDowntime, PveRebootGuestRef{Kind: "lxc", VMID: uint64(1000 + i)})
			}
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newRebootEnv(t, pvecontract.KindCluster, true)
			req := e.req()
			mod(&req)
			if _, err := e.propose(req); !errors.Is(err, ErrPveRebootRequest) {
				t.Fatalf("got %v", err)
			}
			if e.client.factReads != 0 || e.client.reads != 0 {
				t.Fatal("read the remote for a malformed request")
			}
		})
	}
}

func TestNodeRebootNodeAndClusterStateRefused(t *testing.T) {
	t.Run("node offline", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.facts.Nodes[0].Status = "offline"
		if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cluster remote without cluster status", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.facts.Cluster = pveapi.ClusterStatus{Reason: "standalone host: no cluster configured"}
		if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("standalone remote listing several nodes", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		e.client.facts.Nodes = append(e.client.facts.Nodes, pveapi.Node{Name: "pve2", Status: "online", UptimeSeconds: rebootOldUptime})
		if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("standalone remote that joined a cluster", func(t *testing.T) {
		// The reboot lock is per remote: the cluster must be registered as
		// a cluster remote, not reached through a standalone one.
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		e.client.facts = clusterRebootFacts()
		if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("too many guests", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		for i := 0; i < maxPveRebootGuests; i++ {
			e.client.facts.Guests = append(e.client.facts.Guests, pveapi.Guest{Node: "pve1", Kind: pveapi.KindLxc, VMID: 1000 + i, Status: "stopped"})
		}
		if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestNodeRebootNotBackIsUnknown(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	req, _ := e.approve(e.req())
	e.m.RebootMaxWait = time.Millisecond
	e.client.onSent = nil
	res, err := e.r.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("got %v, want uncertain", err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobUnknown || res.Steps[0].UPID != "" {
		t.Fatalf("steps %+v", res.Steps)
	}
	if sent := e.client.sentNodes(); len(sent) != 1 {
		t.Fatalf("sent %v", sent)
	}
}

func TestNodeRebootBackWithoutQuorumIsNotSuccess(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	req, _ := e.approve(e.req())
	e.client.back = true
	e.client.onSent = func() {
		e.offset.Store(int64(10 * time.Minute))
		e.client.facts.Cluster.Quorum = false // the writer runs without rmu held
	}
	e.m.RebootMaxWait = 5 * time.Minute // passes under the jumped clock
	res, err := e.r.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) || res.Steps[0].State != executordb.PveJobUnknown {
		t.Fatalf("got %v, steps %+v", err, res.Steps)
	}
}

func TestNodeRebootLostAnswerObservedNeverResent(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	req, _ := e.approve(e.req())
	e.client.lost, e.client.back = true, true
	res, err := e.r.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Steps[0].State != executordb.PveJobSucceeded || !strings.Contains(res.Steps[0].UPID, ":"+pveNodeRebootTaskType+":") {
		t.Fatalf("steps %+v", res.Steps)
	}
	if _, err := e.r.Run(context.Background(), req); err == nil {
		t.Fatal("second run of the same permit succeeded")
	}
	if sent := e.client.sentNodes(); len(sent) != 1 {
		t.Fatalf("sent %v", sent)
	}
}

func TestNodeRebootReconcileAfterRestart(t *testing.T) {
	open := func(e *rebootEnv, exec string) {
		e.t.Helper()
		if err := e.pe.db.CreatePveJobIntent(executordb.PveJob{ExecutionID: exec, Step: 1, Digest: strings.Repeat("a", 64), Action: PveNodeRebootAction,
			RemoteID: mutRemote, TrustGeneration: e.rm.TrustGeneration, Kind: permit.ProviderKindNode, Node: "pve1",
			RequestDigest: strings.Repeat("b", 64), TaskType: pveNodeRebootTaskType, TaskUser: mutActionUser}); err != nil {
			e.t.Fatal(err)
		}
	}
	t.Run("node back", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		exec := nextRebootExec()
		open(e, exec)
		if err := e.m.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if j, _, _ := e.pe.db.PveJob(exec, 1); j.State != executordb.PveJobReconciling {
			t.Fatalf("still up: state %s", j.State)
		}
		// The node returned with a fresh boot after the intent.
		e.client.sent, e.client.back = []string{"pve1"}, true
		e.offset.Store(int64(10 * time.Minute))
		if err := e.m.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if j, _, _ := e.pe.db.PveJob(exec, 1); j.State != executordb.PveJobSucceeded {
			t.Fatalf("state %s", j.State)
		}
	})
	t.Run("node not back in time", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		exec := nextRebootExec()
		open(e, exec)
		e.m.RebootMaxWait = time.Minute
		e.offset.Store(int64(2 * time.Minute))
		if err := e.m.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if j, _, _ := e.pe.db.PveJob(exec, 1); j.State != executordb.PveJobUnknown {
			t.Fatalf("state %s", j.State)
		}
	})
}

func TestDispatchNodeRebootStepRefusesMalformedSteps(t *testing.T) {
	c := &rebootClient{facts: clusterRebootFacts(), evacuated: true}
	good := pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: []PveRebootGuestRef{{Kind: "qemu", VMID: 101}},
		Evacuate: []PveRebootGuestRef{{Kind: "qemu", VMID: 201}}}
	b, err := bindNodeReboot("pve1", good.Accepted, good.Evacuate, pvecontract.KindCluster, clusterRebootFacts(), rebootPropose)
	if err != nil {
		t.Fatal(err)
	}
	if good.BoundSHA256, err = pveRebootBoundHash(b); err != nil {
		t.Fatal(err)
	}
	step := func(a any) PveMutationStep {
		raw, _ := json.Marshal(a)
		return PveMutationStep{Method: pveNodeRebootMethod, Args: raw}
	}
	cases := map[string]struct {
		node string
		step PveMutationStep
	}{
		"other method":          {"pve1", PveMutationStep{Method: "guest.qemu.start", Args: step(good).Args}},
		"node mismatch":         {"pve2", step(good)},
		"unknown field":         {"pve1", PveMutationStep{Method: pveNodeRebootMethod, Args: json.RawMessage(`{"node":"pve1","force":true}`)}},
		"wrong hash":            {"pve1", step(pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: good.Accepted, BoundSHA256: strings.Repeat("0", 64)})},
		"unsorted list":         {"pve1", step(pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: []PveRebootGuestRef{{"qemu", 201}, {"qemu", 101}}, BoundSHA256: good.BoundSHA256})},
		"clustered flag":        {"pve1", step(pveRebootStepArgs{Node: "pve1", Accepted: good.Accepted, Evacuate: good.Evacuate, BoundSHA256: good.BoundSHA256})},
		"evacuation not listed": {"pve1", step(pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: good.Accepted, BoundSHA256: good.BoundSHA256})},
		"guest listed twice": {"pve1", step(pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: good.Accepted,
			Evacuate: append(slices.Clone(good.Evacuate), good.Accepted...), BoundSHA256: good.BoundSHA256})},
		"oversized args": {"pve1", PveMutationStep{Method: pveNodeRebootMethod, Args: json.RawMessage(`{"node":"` + strings.Repeat("a", maxPveRebootStepArgs) + `"}`)}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := DispatchNodeRebootStep(context.Background(), &rebootWriter{c: c}, &rebootReader{c: c}, pvecontract.KindCluster, tc.node, tc.step)
			if !errors.Is(err, ErrPveRejected) || len(c.sentNodes()) != 0 {
				t.Fatalf("got %v, sent %v", err, c.sentNodes())
			}
		})
	}
	// The guest listed for evacuation is still on the node: not sent.
	c.evacuated = false
	if err := DispatchNodeRebootStep(context.Background(), &rebootWriter{c: c}, &rebootReader{c: c}, pvecontract.KindCluster, "pve1", step(good)); !errors.Is(err, ErrPveRejected) {
		t.Fatalf("not evacuated: %v", err)
	}
	c.evacuated = true
	if err := DispatchNodeRebootStep(context.Background(), &rebootWriter{c: c}, &rebootReader{c: c}, pvecontract.KindCluster, "pve1", step(good)); err != nil {
		t.Fatalf("good step: %v", err)
	}
	if sent := c.sentNodes(); len(sent) != 1 || sent[0] != "pve1" {
		t.Fatalf("sent %v", sent)
	}
}

func TestDecodeHAOption(t *testing.T) {
	// A named key keeps the literal's alignment identical under the gofmt
	// of Go 1.26 (lint job) and Go 1.27 (test job).
	const dupPolicy = `{"shutdown_policy":"migrate,shutdown_policy=freeze"}`
	for in, want := range map[string]string{
		`"shutdown_policy=migrate"`:              pveHAPolicyMigrate,
		`{"shutdown_policy":"migrate"}`:          pveHAPolicyMigrate,
		`{"shutdown_policy":"freeze","other":1}`: "freeze",
		`{}`:                                     pveHAPolicyConditional,
		`{"shutdown_policy":"bogus"}`:            "",
		`{"shutdown_policy":1}`:                  "",
		`{"shutdown_policy":"migrate,x=y"}`:      "",
		`null`:                                   "",
		`["shutdown_policy=migrate"]`:            "",
		`"` + strings.Repeat("a", 300) + `"`:     "",
		dupPolicy:                                "",
	} {
		got, err := decodeHAOption(json.RawMessage(in))
		if want == "" {
			if err == nil {
				t.Errorf("%s: got %q, want error", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v, want %q", in, got, err, want)
		}
	}
}

func TestParseHAShutdownPolicy(t *testing.T) {
	for in, want := range map[string]string{
		"shutdown_policy=migrate":          pveHAPolicyMigrate,
		"shutdown_policy=freeze":           "freeze",
		"other=1,shutdown_policy=failover": "failover",
		"shutdown_policy=migrate,other=x":  pveHAPolicyMigrate,
		"other=x":                          pveHAPolicyConditional,
		"":                                 "",
		"shutdown_policy=bogus":            "",
		"shutdown_policy=migrate,shutdown_policy=freeze": "",
		"migrate": "",
	} {
		got, err := parseHAShutdownPolicy(in)
		if want == "" {
			if err == nil {
				t.Errorf("%q: got %q, want error", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v, want %q", in, got, err, want)
		}
	}
}

func TestNodeRebootUnknownStepBlocksUntilNodeSeenBack(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	exec := nextRebootExec()
	if err := e.pe.db.CreatePveJobIntent(executordb.PveJob{ExecutionID: exec, Step: 1, Digest: strings.Repeat("a", 64), Action: PveNodeRebootAction,
		RemoteID: mutRemote, TrustGeneration: e.rm.TrustGeneration, Kind: permit.ProviderKindNode, Node: "pve2",
		RequestDigest: strings.Repeat("b", 64), TaskType: pveNodeRebootTaskType, TaskUser: mutActionUser}); err != nil {
		t.Fatal(err)
	}
	if err := e.pe.db.MarkPveJobReconciling(exec, 1); err != nil {
		t.Fatal(err)
	}
	if err := e.pe.db.FinishPveJob(exec, 1, executordb.PveJobUnknown, ""); err != nil {
		t.Fatal(err)
	}
	// pve2 still shows its old boot: its reboot may still happen.
	if _, err := e.propose(e.req()); !errors.Is(err, ErrPveRebootBusy) {
		t.Fatalf("old boot: got %v, want busy", err)
	}
	// pve2 was seen back with a boot after the step's intent (and settled).
	e.offset.Store(int64(time.Hour))
	e.client.facts.Nodes[1].UptimeSeconds = 30 * 60
	if _, err := e.propose(e.req()); err != nil {
		t.Fatalf("node back: %v", err)
	}
	// An unknown step older than the hold no longer blocks.
	e.client.facts.Nodes[1].UptimeSeconds = rebootOldUptime
	e.offset.Store(int64(pveRebootUnknownHold + time.Hour))
	if _, err := e.propose(e.req()); err != nil {
		t.Fatalf("after the hold: %v", err)
	}
}

// pveRebootFakeAPI serves the PVE API reads of the production fact and
// boot readers for a three-node cluster; bodies maps an API path (below
// /api2/json) to its JSON body, a missing path answers 404.
func pveRebootFakeAPI(t *testing.T, bodies map[string]string) (*httptest.Server, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, ok := bodies[strings.TrimPrefix(r.URL.Path, "/api2/json")]
		if r.Method != http.MethodGet || !ok {
			http.NotFound(w, r)
			return
		}
		if body == "500" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &mu
}

func pveRebootAPIBodies() map[string]string {
	return map[string]string{
		"/nodes": `{"data":[{"node":"pve1","status":"online","type":"node","maxcpu":8,"maxmem":68719476736,"mem":8589934592,"uptime":864000},` +
			`{"node":"pve2","status":"online","type":"node","maxcpu":8,"maxmem":68719476736,"mem":8589934592,"uptime":864000},` +
			`{"node":"pve3","status":"online","type":"node","maxcpu":8,"maxmem":68719476736,"mem":8589934592,"uptime":864000}]}`,
		"/cluster/status": `{"data":[{"type":"cluster","id":"cluster","name":"lab","nodes":3,"quorate":1,"version":3},` +
			`{"type":"node","id":"node/pve1","name":"pve1","online":1,"nodeid":1},{"type":"node","id":"node/pve2","name":"pve2","online":1,"nodeid":2},` +
			`{"type":"node","id":"node/pve3","name":"pve3","online":1,"nodeid":3}]}`,
		"/cluster/config/nodes": `{"data":[{"node":"pve1","quorum_votes":"1"},{"node":"pve2","quorum_votes":"1"},{"node":"pve3","quorum_votes":"1"}]}`,
		"/cluster/ha/resources": `{"data":[{"sid":"vm:201","type":"vm","state":"started","group":"g1"}]}`,
		"/cluster/ha/status/current": `{"data":[{"id":"quorum","type":"quorum","status":"OK"},` +
			`{"id":"lrm:pve1","type":"lrm","node":"pve1","status":"pve1 (maintenance mode, Sat Nov  1 10:00:00 2026)"},` +
			`{"id":"lrm:pve2","type":"lrm","node":"pve2","status":"pve2 (active, Sat Nov  1 10:00:00 2026)"},` +
			`{"id":"lrm:pve3","type":"lrm","node":"pve3","status":"pve3 (active, Sat Nov  1 10:00:00 2026)"},` +
			`{"id":"service:vm:201","type":"service","sid":"vm:201","state":"started","node":"pve1"}]}`,
		"/cluster/config/qdevice": `{"data":{}}`,
		"/cluster/options":        `{"data":{"ha":"shutdown_policy=migrate","keyboard":"de"}}`,
		"/nodes/pve1/qemu": `{"data":[{"vmid":101,"name":"web","status":"running","maxmem":4294967296},` +
			`{"vmid":201,"name":"db","status":"running","maxmem":4294967296}]}`,
		"/nodes/pve1/lxc":             `{"data":[{"vmid":301,"name":"dns","status":"stopped"}]}`,
		"/nodes/pve1/storage":         `{"data":[{"storage":"ceph","type":"rbd","content":"images","active":1,"shared":1},{"storage":"local","type":"dir","content":"iso,images","active":1,"shared":0}]}`,
		"/nodes/pve1/qemu/201/config": `{"data":{"scsi0":"ceph:vm-201-disk-0,size=32G","ide2":"none,media=cdrom","memory":4096,"digest":"x"}}`,
		"/cluster/ha/groups":          `{"data":[{"group":"g1","nodes":"pve1:2,pve2","restricted":1,"type":"group"}]}`,
	}
}

// TestPveNodeRebootFactsProductionReader: the production fact reader
// against a fake PVE HTTP API (PVE 8 layout: HA groups, no /cluster/ha/rules).
func TestPveNodeRebootFactsProductionReader(t *testing.T) {
	read := func(context.Context) (string, error) { return "PVEAPIToken=r@pve!r=x", nil }
	q201 := PveRebootGuestRef{Kind: "qemu", VMID: 201}
	facts := func(t *testing.T, mod func(b map[string]string)) PveNodeRebootFacts {
		t.Helper()
		b := pveRebootAPIBodies()
		if mod != nil {
			mod(b)
		}
		srv, _ := pveRebootFakeAPI(t, b)
		f, err := pveNodeRebootFacts(context.Background(), srv.Client(), srv.URL, read, "pve1")
		if err != nil {
			t.Fatalf("facts: %v", err)
		}
		return f
	}

	f := facts(t, nil)
	if !f.Cluster.Available || !f.Cluster.Quorum || len(f.Nodes) != 3 || f.Votes.Votes["pve2"] != 1 || !f.QDevice.Known || f.QDevice.Configured ||
		f.HAShutdownPolicy != pveHAPolicyMigrate || !f.HA.Maintenance["pve1"] || len(f.Guests) != 3 {
		t.Fatalf("facts %+v", f)
	}
	if p := f.Placement[q201]; !p.Known || p.LocalResources || !p.Restricted || !slices.Equal(p.AllowedNodes, []string{"pve1", "pve2"}) || len(f.Placement) != 1 {
		t.Fatalf("placement %+v", f.Placement)
	}
	// The bound facts of the default cluster reboot come out of it.
	b, err := bindNodeReboot("pve1", []PveRebootGuestRef{{Kind: "qemu", VMID: 101}}, []PveRebootGuestRef{q201}, pvecontract.KindCluster, f, rebootPropose)
	if err != nil || len(b.Guests) != 3 || !b.Guests[2].HAEvacuates {
		t.Fatalf("bind %+v %v", b, err)
	}

	for name, tc := range map[string]struct {
		mod   func(b map[string]string)
		check func(f PveNodeRebootFacts) bool
	}{
		"qdevice configured": {func(b map[string]string) { b["/cluster/config/qdevice"] = `{"data":{"Model":"Net","Node ID":"1"}}` },
			func(f PveNodeRebootFacts) bool { return f.QDevice.Known && f.QDevice.Configured }},
		"qdevice unreadable": {func(b map[string]string) { b["/cluster/config/qdevice"] = "500" },
			func(f PveNodeRebootFacts) bool { return !f.QDevice.Known }},
		"qdevice null": {func(b map[string]string) { b["/cluster/config/qdevice"] = `{"data":null}` },
			func(f PveNodeRebootFacts) bool { return !f.QDevice.Known }},
		"ha option absent": {func(b map[string]string) { b["/cluster/options"] = `{"data":{"keyboard":"de"}}` },
			func(f PveNodeRebootFacts) bool { return f.HAShutdownPolicy == pveHAPolicyConditional }},
		"passthrough device": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","hostpci0":"0000:01:00.0"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].Known && f.Placement[q201].LocalResources }},
		"usb device": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","usb0":"host=1234:5678"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].LocalResources }},
		"serial host device": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","serial0":"/dev/ttyS0"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].Known && f.Placement[q201].LocalResources }},
		"serial socket is movable": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","serial0":"socket"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].Known && !f.Placement[q201].LocalResources }},
		"parallel device": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","parallel0":"/dev/parport0"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].Known && f.Placement[q201].LocalResources }},
		"serial not a string": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","serial0":7}}`
		}, func(f PveNodeRebootFacts) bool { return !f.Placement[q201].Known }},
		"local disk": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","scsi1":"local:201/vm-201-disk-1.qcow2"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].LocalResources }},
		"local unused volume": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","unused0":"local:201/vm-201-disk-2.qcow2"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].LocalResources }},
		"local cd image": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"ceph:vm-201-disk-0","ide2":"local:iso/debian.iso,media=cdrom"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].LocalResources }},
		"passthrough disk": {func(b map[string]string) {
			b["/nodes/pve1/qemu/201/config"] = `{"data":{"scsi0":"/dev/disk/by-id/ata-x"}}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].LocalResources }},
		"config unreadable": {func(b map[string]string) { b["/nodes/pve1/qemu/201/config"] = "500" },
			func(f PveNodeRebootFacts) bool { return !f.Placement[q201].Known }},
		"storages unreadable": {func(b map[string]string) { b["/nodes/pve1/storage"] = "500" },
			func(f PveNodeRebootFacts) bool { return !f.Placement[q201].Known }},
		"group missing": {func(b map[string]string) { b["/cluster/ha/groups"] = `{"data":[]}` },
			func(f PveNodeRebootFacts) bool { return !f.Placement[q201].Known }},
		"group unrestricted": {func(b map[string]string) {
			b["/cluster/ha/groups"] = `{"data":[{"group":"g1","nodes":"pve1","restricted":0}]}`
		}, func(f PveNodeRebootFacts) bool { return f.Placement[q201].Known && !f.Placement[q201].Restricted }},
		"group malformed": {func(b map[string]string) {
			b["/cluster/ha/groups"] = `{"data":[{"group":"g1","nodes":"pve 1","restricted":1}]}`
		},
			func(f PveNodeRebootFacts) bool { return !f.Placement[q201].Known }},
		"pve9 strict node-affinity rule": {func(b map[string]string) {
			b["/cluster/ha/resources"] = `{"data":[{"sid":"vm:201","type":"vm","state":"started"}]}`
			b["/cluster/ha/rules"] = `{"data":[{"rule":"r1","type":"node-affinity","resources":"vm:201,vm:202","nodes":"pve3:1","strict":1},` +
				`{"rule":"r2","type":"resource-affinity","resources":"vm:201","affinity":"negative","disable":1}]}`
		}, func(f PveNodeRebootFacts) bool {
			p := f.Placement[q201]
			return p.Known && p.Restricted && slices.Equal(p.AllowedNodes, []string{"pve3"})
		}},
		"pve9 resource-affinity rule": {func(b map[string]string) {
			b["/cluster/ha/rules"] = `{"data":[{"rule":"r2","type":"resource-affinity","resources":"vm:201,vm:101","affinity":"positive"}]}`
		}, func(f PveNodeRebootFacts) bool { return !f.Placement[q201].Known }},
		"rules unreadable": {func(b map[string]string) { b["/cluster/ha/rules"] = "500" },
			func(f PveNodeRebootFacts) bool { return !f.Placement[q201].Known }},
		"group and rule intersect": {func(b map[string]string) {
			b["/cluster/ha/rules"] = `{"data":[{"rule":"r1","type":"node-affinity","resources":"vm:201","nodes":"pve2,pve3","strict":1}]}`
		}, func(f PveNodeRebootFacts) bool { return slices.Equal(f.Placement[q201].AllowedNodes, []string{"pve2"}) }},
		"votes unreadable": {func(b map[string]string) { b["/cluster/config/nodes"] = "500" },
			func(f PveNodeRebootFacts) bool { return !f.Votes.Available }},
		"ha guest not started": {func(b map[string]string) {
			b["/cluster/ha/resources"] = `{"data":[{"sid":"vm:201","type":"vm","state":"stopped"}]}`
		}, func(f PveNodeRebootFacts) bool { return len(f.Placement) == 0 }},
	} {
		t.Run(name, func(t *testing.T) {
			if f := facts(t, tc.mod); !tc.check(f) {
				t.Fatalf("facts %+v placement %+v", f, f.Placement)
			}
		})
	}

	for name, mod := range map[string]func(b map[string]string){
		"nodes unreadable":   func(b map[string]string) { b["/nodes"] = "500" },
		"options unreadable": func(b map[string]string) { b["/cluster/options"] = "500" },
		"guests unreadable":  func(b map[string]string) { b["/nodes/pve1/lxc"] = "500" },
		"ha option invalid":  func(b map[string]string) { b["/cluster/options"] = `{"data":{"ha":"shutdown_policy=bogus"}}` },
	} {
		t.Run(name, func(t *testing.T) {
			b := pveRebootAPIBodies()
			mod(b)
			srv, _ := pveRebootFakeAPI(t, b)
			if _, err := pveNodeRebootFacts(context.Background(), srv.Client(), srv.URL, read, "pve1"); err == nil {
				t.Fatal("facts read")
			}
		})
	}

	// A remote that stalls the guest config reads cannot hold one facts
	// read beyond its overall deadline (each request alone could take
	// pveMutationRequestTimeout): the read fails closed.
	t.Run("slow config reads hit the facts deadline", func(t *testing.T) {
		b := pveRebootAPIBodies()
		fast, _ := pveRebootFakeAPI(t, b)
		var slowReads atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/config") && strings.Contains(r.URL.Path, "/qemu/") {
				slowReads.Add(1)
				select {
				case <-r.Context().Done():
				case <-time.After(10 * time.Second):
				}
				return
			}
			fast.Config.Handler.ServeHTTP(w, r)
		}))
		t.Cleanup(srv.Close)
		start := time.Now()
		_, err := pveNodeRebootFactsWithin(context.Background(), 200*time.Millisecond, srv.Client(), srv.URL, read, "pve1")
		if !errors.Is(err, errPveMutationRead) {
			t.Fatalf("facts read past its deadline: %v", err)
		}
		if d := time.Since(start); d > 5*time.Second || slowReads.Load() != 1 {
			t.Fatalf("facts read took %v with %d slow reads, want the deadline to stop it", d, slowReads.Load())
		}
		if pveRebootFactsDeadline <= 0 || pveRebootFactsDeadline >= maxPveRebootGuests*pveMutationRequestTimeout {
			t.Fatalf("facts deadline %v does not bound the per-guest reads", pveRebootFactsDeadline)
		}
	})

	t.Run("node boot", func(t *testing.T) {
		b := pveRebootAPIBodies()
		srv, mu := pveRebootFakeAPI(t, b)
		nb, err := pveNodeBoot(context.Background(), srv.Client(), srv.URL, read, "pve2")
		if err != nil || !nb.Online || nb.UptimeSeconds != 864000 || !nb.Cluster.Quorum || len(nb.Cluster.Members) != 3 {
			t.Fatalf("boot %+v %v", nb, err)
		}
		mu.Lock()
		b["/nodes"] = `{"data":[{"node":"pve1","status":"online","maxcpu":8,"maxmem":1,"mem":0,"uptime":5},{"node":"pve2","status":"offline"}]}`
		mu.Unlock()
		if nb, err := pveNodeBoot(context.Background(), srv.Client(), srv.URL, read, "pve2"); err != nil || nb.Online {
			t.Fatalf("offline node: %+v %v", nb, err)
		}
		mu.Lock()
		b["/cluster/status"] = "500"
		mu.Unlock()
		// An unreadable cluster status is unavailable, never quorate.
		if nb, err := pveNodeBoot(context.Background(), srv.Client(), srv.URL, read, "pve2"); err != nil || nb.Cluster.Available || nb.Cluster.Quorum {
			t.Fatalf("cluster status unreadable: %+v %v", nb, err)
		}
	})
}

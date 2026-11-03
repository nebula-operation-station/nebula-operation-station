// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	return f
}

func (c *rebootClient) NodeRebootFacts(_ context.Context, _ executordb.PveRemote, _ string, _ pveapi.TokenSupplier) (PveNodeRebootFacts, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.factReads++
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
	return r.c.snapshot(), nil
}

type rebootEnv struct {
	t      *testing.T
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
// ten days with one vote each, no QDevice, HA shutdown_policy=migrate. On
// pve1: QEMU 101 running (not HA), QEMU 201 running (HA, started), LXC 301
// stopped.
func clusterRebootFacts() PveNodeRebootFacts {
	return PveNodeRebootFacts{
		Nodes: []pveapi.Node{{Name: "pve1", Status: "online", UptimeSeconds: rebootOldUptime},
			{Name: "pve2", Status: "online", UptimeSeconds: rebootOldUptime}, {Name: "pve3", Status: "online", UptimeSeconds: rebootOldUptime}},
		Cluster: pveapi.ClusterStatus{Available: true, Name: "lab", Quorum: true, NodesOnline: 3, NodesTotal: 3,
			Members: []pveapi.ClusterMember{{Name: "pve1", Online: true}, {Name: "pve2", Online: true}, {Name: "pve3", Online: true}}},
		Votes:            pveapi.NodeVotes{Available: true, Votes: map[string]int{"pve1": 1, "pve2": 1, "pve3": 1}},
		QDevice:          PveQDevice{Known: true},
		HA:               pveapi.HAStatus{Available: true, Resources: []pveapi.HAResource{{VMID: 201, Type: "vm", Managed: true, DesiredState: "started", Node: "pve1"}}},
		HAShutdownPolicy: pveHAPolicyMigrate,
		Guests: []pveapi.Guest{
			{Node: "pve1", Kind: pveapi.KindQemu, VMID: 101, Status: "running"},
			{Node: "pve1", Kind: pveapi.KindQemu, VMID: 201, Status: "running"},
			{Node: "pve1", Kind: pveapi.KindLxc, VMID: 301, Status: "stopped"},
		},
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
	if withAction {
		if _, err := pe.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: mutRemote, Purpose: PvePurposeAction, Token: []byte(mutActionToken), By: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	rm, _, err := pe.db.GetRemote(mutRemote)
	if err != nil {
		t.Fatal(err)
	}
	e := &rebootEnv{t: t, pe: pe, rm: rm, logs: &bytes.Buffer{},
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
	p, err := e.propose(rebootReq())
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
	req := rebootReq()
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
	p, err := e.propose(rebootReq())
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskCritical || p.Requirement != permit.RequireAssertionVerifiedTypedCount {
		t.Fatalf("risk %s requirement %s, want CRITICAL with typed target count", p.Request.RiskClass, p.Requirement)
	}
	rp := rebootParams(t, p)
	b := rp.Bound
	if !b.Clustered || b.Cluster != "lab" || b.TotalVotes != 3 || b.RemainingVotes != 2 || len(b.Members) != 3 ||
		b.HAShutdownPolicy != pveHAPolicyMigrate || len(b.Guests) != 3 {
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
	// CRITICAL: a wrong or missing typed target count is refused.
	for _, n := range []int{0, 2} {
		if _, err := e.auth.ApproveCLI(p.Digest, n, "admin"); permit.CodeOf(err) != permit.CodeTypedCountMismatch {
			t.Fatalf("typed %d: got %v, want typed count mismatch", n, err)
		}
	}
	req := rebootReq()
	req.Digest = p.Digest
	if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) || len(e.client.sentNodes()) != 0 {
		t.Fatalf("unapproved run: %v, sent %v", err, e.client.sentNodes())
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 1, "admin"); err != nil {
		t.Fatal(err)
	}
	res, err := e.r.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded {
		t.Fatalf("steps %+v", res.Steps)
	}
	if e.client.factReads < 4 {
		t.Fatalf("facts read %d times, want proposal, run, intent and dispatch rechecks", e.client.factReads)
	}
}

func TestNodeRebootCriticalityRaisesStandalone(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindStandalone, true)
	nt, err := (permit.ProviderMutationTarget{RemoteID: e.rm.RemoteID, TrustPin: e.rm.TrustPin, Kind: permit.ProviderKindNode, Node: "pve1"}).RiskTarget()
	if err != nil {
		t.Fatal(err)
	}
	e.crit.hosts[nt] = canonical.RiskCritical
	p, err := e.propose(rebootReq())
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
			if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootQuorum) {
				t.Fatalf("got %v, want quorum refusal", err)
			}
		})
	}
	// Quorum lost between approval and run: nothing is sent.
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	req, _ := e.approve(rebootReq())
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
			if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootBusy) {
				t.Fatalf("got %v, want busy refusal", err)
			}
		})
	}

	t.Run("open reboot step of another node", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(rebootReq())
		if err := e.pe.db.CreatePveJobIntent(executordb.PveJob{ExecutionID: "00000000-0000-4000-e000-999999999999", Step: 1,
			Digest: strings.Repeat("a", 64), Action: PveNodeRebootAction, RemoteID: mutRemote, TrustGeneration: e.rm.TrustGeneration,
			Kind: permit.ProviderKindNode, Node: "pve2", RequestDigest: strings.Repeat("b", 64), TaskType: pveNodeRebootTaskType, TaskUser: mutActionUser}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootBusy) {
			t.Fatalf("propose: got %v", err)
		}
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootBusy) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("run: got %v, sent %v", err, e.client.sentNodes())
		}
	})

	t.Run("reboot running in the engine", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(rebootReq())
		release, ok := e.m.lockNodeReboot(mutRemote)
		if !ok {
			t.Fatal("lock")
		}
		if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootBusy) {
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
	cases := []struct {
		name string
		mod  func(f *PveNodeRebootFacts, r *PveNodeRebootRequest)
		want error
	}{
		{"running guest not listed", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) { r.AcceptedDowntime = nil }, ErrPveRebootGuests},
		{"ha guest frozen under conditional policy", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.HAShutdownPolicy = pveHAPolicyConditional
		}, ErrPveRebootGuests},
		{"ha resource not started", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) { f.HA.Resources[0].DesiredState = "ignored" }, ErrPveRebootGuests},
		{"paused guest counts as running", func(f *PveNodeRebootFacts, _ *PveNodeRebootRequest) {
			f.Guests = append(f.Guests, pveapi.Guest{Node: "pve1", Kind: pveapi.KindQemu, VMID: 401, Status: "paused"})
		}, ErrPveRebootGuests},
		{"accepted guest is stopped", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) {
			r.AcceptedDowntime = append(r.AcceptedDowntime, PveRebootGuestRef{Kind: permit.ProviderKindLXC, VMID: 301})
		}, ErrPveRebootGuests},
		{"accepted guest not on the node", func(_ *PveNodeRebootFacts, r *PveNodeRebootRequest) {
			r.AcceptedDowntime = append(r.AcceptedDowntime, PveRebootGuestRef{Kind: permit.ProviderKindQemu, VMID: 999})
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRebootEnv(t, pvecontract.KindCluster, true)
			req := rebootReq()
			tc.mod(&e.client.facts, &req)
			if _, err := e.propose(req); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("ha guest accepted under conditional policy", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.facts.HAShutdownPolicy = pveHAPolicyConditional
		req := rebootReq()
		req.AcceptedDowntime = append(req.AcceptedDowntime, PveRebootGuestRef{Kind: permit.ProviderKindQemu, VMID: 201})
		p, err := e.propose(req)
		if err != nil {
			t.Fatal(err)
		}
		if g := rebootParams(t, p).Bound.Guests[2]; g.HAEvacuates || !g.AcceptedDowntime {
			t.Fatalf("ha guest %+v", g)
		}
	})

	t.Run("ha maintenance mode evacuates", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.facts.HAShutdownPolicy = pveHAPolicyConditional
		e.client.facts.HA.Maintenance = map[string]bool{"pve1": true}
		p, err := e.propose(rebootReq())
		if err != nil {
			t.Fatal(err)
		}
		if b := rebootParams(t, p).Bound; !b.Maintenance || !b.Guests[2].HAEvacuates {
			t.Fatalf("bound %+v", b)
		}
	})

	t.Run("new running guest after approval blocks the dispatch", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		req, _ := e.approve(rebootReq())
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
		req, _ := e.approve(rebootReq())
		e.client.facts.Guests[2].Status = "running"
		if _, err := e.r.Run(context.Background(), req); !errors.Is(err, ErrPveRebootGuests) || len(e.client.sentNodes()) != 0 {
			t.Fatalf("got %v, sent %v", err, e.client.sentNodes())
		}
	})
}

func TestNodeRebootReadOnlyRemoteRefused(t *testing.T) {
	for _, kind := range []pvecontract.Kind{pvecontract.KindStandalone, pvecontract.KindCluster} {
		t.Run(string(kind), func(t *testing.T) {
			e := newRebootEnv(t, kind, false)
			if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveReadOnly) {
				t.Fatalf("propose: got %v, want read-only", err)
			}
			req := rebootReq()
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
			req := rebootReq()
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
		if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cluster remote without cluster status", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindCluster, true)
		e.client.facts.Cluster = pveapi.ClusterStatus{Reason: "standalone host: no cluster configured"}
		if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("standalone remote listing several nodes", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		e.client.facts.Nodes = append(e.client.facts.Nodes, pveapi.Node{Name: "pve2", Status: "online", UptimeSeconds: rebootOldUptime})
		if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("standalone remote that joined a cluster is critical", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		e.client.facts = clusterRebootFacts()
		p, err := e.propose(rebootReq())
		if err != nil {
			t.Fatal(err)
		}
		if p.Request.RiskClass != canonical.RiskCritical {
			t.Fatalf("risk %s", p.Request.RiskClass)
		}
	})
	t.Run("too many guests", func(t *testing.T) {
		e := newRebootEnv(t, pvecontract.KindStandalone, true)
		for i := 0; i < maxPveRebootGuests; i++ {
			e.client.facts.Guests = append(e.client.facts.Guests, pveapi.Guest{Node: "pve1", Kind: pveapi.KindLxc, VMID: 1000 + i, Status: "stopped"})
		}
		if _, err := e.propose(rebootReq()); !errors.Is(err, ErrPveRebootState) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestNodeRebootNotBackIsUnknown(t *testing.T) {
	e := newRebootEnv(t, pvecontract.KindCluster, true)
	req, _ := e.approve(rebootReq())
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
	req, _ := e.approve(rebootReq())
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
	req, _ := e.approve(rebootReq())
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
	c := &rebootClient{facts: clusterRebootFacts()}
	good := pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: []PveRebootGuestRef{{Kind: "qemu", VMID: 101}}}
	b, err := bindNodeReboot("pve1", good.Accepted, pvecontract.KindCluster, c.facts)
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
		"other method":   {"pve1", PveMutationStep{Method: "guest.qemu.start", Args: step(good).Args}},
		"node mismatch":  {"pve2", step(good)},
		"unknown field":  {"pve1", PveMutationStep{Method: pveNodeRebootMethod, Args: json.RawMessage(`{"node":"pve1","force":true}`)}},
		"wrong hash":     {"pve1", step(pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: good.Accepted, BoundSHA256: strings.Repeat("0", 64)})},
		"unsorted list":  {"pve1", step(pveRebootStepArgs{Node: "pve1", Clustered: true, Accepted: []PveRebootGuestRef{{"qemu", 201}, {"qemu", 101}}, BoundSHA256: good.BoundSHA256})},
		"clustered flag": {"pve1", step(pveRebootStepArgs{Node: "pve1", Accepted: good.Accepted, BoundSHA256: good.BoundSHA256})},
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
	if err := DispatchNodeRebootStep(context.Background(), &rebootWriter{c: c}, &rebootReader{c: c}, pvecontract.KindCluster, "pve1", step(good)); err != nil {
		t.Fatalf("good step: %v", err)
	}
	if sent := c.sentNodes(); len(sent) != 1 || sent[0] != "pve1" {
		t.Fatalf("sent %v", sent)
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

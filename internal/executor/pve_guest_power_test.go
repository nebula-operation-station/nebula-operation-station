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
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// powerClient is a fake PVE client for guest power actions. It reports
// the guest's kind and power status and creates tasks of the task type
// the step method names.
type powerClient struct {
	mu       sync.Mutex
	liveNode string
	liveKind string
	digest   string
	gen      string
	statusFn func(read int) string
	// qmp is the QMP status of a QEMU guest; empty: the same as the
	// power status.
	qmp        string
	reads      int
	dispatched []PveMutationStep
	onDispatch func(step PveMutationStep) (string, error)
	recent     []string
	taskStatus func(upid string) (PveTaskStatus, error)
}

func (c *powerClient) TaskType(method string) (string, bool) { return GuestPowerStepTaskType(method) }

func (c *powerClient) TaskID(step PveMutationStep) (string, bool) { return GuestPowerStepTaskID(step) }

func (c *powerClient) Dispatch(_ context.Context, _ executordb.PveRemote, node string, step PveMutationStep, _ pveapi.TokenSupplier) (string, error) {
	c.mu.Lock()
	c.dispatched = append(c.dispatched, step)
	n := len(c.dispatched)
	on := c.onDispatch
	c.mu.Unlock()
	if on != nil {
		return on(step)
	}
	tt, _ := GuestPowerStepTaskType(step.Method)
	id, _ := GuestPowerStepTaskID(step)
	return testTaskUPID(node, time.Now(), tt, id, mutActionUser, n), nil
}

func (c *powerClient) TaskStatus(_ context.Context, _ executordb.PveRemote, _, upid string, _ pveapi.TokenSupplier) (PveTaskStatus, error) {
	c.mu.Lock()
	st := c.taskStatus
	c.mu.Unlock()
	if st != nil {
		return st(upid)
	}
	return PveTaskStatus{ExitStatus: "OK"}, nil
}

func (c *powerClient) RecentTasks(context.Context, executordb.PveRemote, string, time.Time, pveapi.TokenSupplier) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recent, nil
}

func (c *powerClient) TargetState(_ context.Context, _ executordb.PveRemote, _, _ string, _ uint64, _ pveapi.TokenSupplier) (PveTargetState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	st := "running"
	if c.statusFn != nil {
		st = c.statusFn(c.reads)
	}
	live := PveTargetState{Node: c.liveNode, Kind: c.liveKind, Status: st, ConfigDigest: c.digest, Generation: c.gen}
	if c.liveKind == permit.ProviderKindQemu {
		live.QMPStatus = st
		if c.qmp != "" {
			live.QMPStatus = c.qmp
		}
	}
	return live, nil
}

func (c *powerClient) dispatchCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.dispatched)
}

type powerEnv struct {
	t      *testing.T
	pe     *pveTestEnv
	crit   critSource
	linked map[string][]canonical.Target
	auth   *permit.Authority
	client *powerClient
	g      *PveGuestPower
	logs   *bytes.Buffer
}

func newPowerEnv(t *testing.T, kind string) *powerEnv {
	t.Helper()
	pe := newPveTestEnv(t)
	chain := makeTestChain(t)
	pe.probe.result = probeResultFrom(chain, "pve1.example.test")
	if _, err := pe.add(t, mutRemote, pvecontract.KindCluster, pveEndpoints("pve1.example.test"), fpHex(chain.ca), []byte(mutReadToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := pe.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: mutRemote, Purpose: PvePurposeAction, Token: []byte(mutActionToken), By: "admin"}); err != nil {
		t.Fatal(err)
	}
	e := &powerEnv{t: t, pe: pe, logs: &bytes.Buffer{}, linked: map[string][]canonical.Target{},
		crit:   critSource{artifact: canonical.RiskMedium, hosts: map[canonical.Target]canonical.Risk{}},
		client: &powerClient{liveNode: "pve1", liveKind: kind, digest: strings.Repeat("cd", 32), gen: strings.Repeat("9f", 20)}}
	// Every target of the default guest is recorded MEDIUM.
	e.record(kind, 101, canonical.RiskMedium, canonical.RiskMedium, canonical.RiskMedium)
	e.restart()
	return e
}

// restart replaces the authority and the engines as an executor restart
// does: permits and in-memory bindings are gone, the database and vault
// stay.
func (e *powerEnv) restart() {
	e.t.Helper()
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "power.test", Origins: []string{"https://power.test"}, Counters: e.pe.db}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	next, err := riskpolicy.New(e.crit)
	if err != nil {
		e.t.Fatal(err)
	}
	bindings := &PveGuestPowerBindings{}
	floor := GuestPowerRiskFloor{Next: next, Criticality: e.crit, Bindings: bindings,
		Linked: func(_ canonical.Request, t canonical.Target) ([]canonical.Target, error) {
			return e.linked[t.HostID], nil
		}}
	e.auth, err = permit.New(permit.Options{Verifier: v, Store: e.pe.db, RiskPolicy: floor})
	if err != nil {
		e.t.Fatal(err)
	}
	m := &PveMutations{DB: e.pe.db, Auth: e.auth, Vault: e.pe.vault, Client: e.client, PollInterval: time.Millisecond,
		MaxWait: 2 * time.Second, Log: slog.New(slog.NewTextHandler(e.logs, nil))}
	e.pe.admin.Mutations = m
	e.g = &PveGuestPower{Mutations: m, Bindings: bindings}
}

// targets returns the guest, node and remote risk targets of a guest.
func (e *powerEnv) targets(kind string, vmid uint64) (guest, node, remote canonical.Target) {
	e.t.Helper()
	rm, _, err := e.pe.db.GetRemote(mutRemote)
	if err != nil {
		e.t.Fatal(err)
	}
	g, n, r, err := PveGuestRiskTargets(permit.ProviderMutationTarget{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, Kind: kind, Node: "pve1", VMID: vmid})
	if err != nil {
		e.t.Fatal(err)
	}
	return g, n, r
}

func (e *powerEnv) record(kind string, vmid uint64, guest, node, remote canonical.Risk) {
	g, n, r := e.targets(kind, vmid)
	for t, c := range map[canonical.Target]canonical.Risk{g: guest, n: node, r: remote} {
		if c == "" {
			delete(e.crit.hosts, t)
		} else {
			e.crit.hosts[t] = c
		}
	}
}

func powerReq(kind, verb string) PveGuestPowerRequest {
	return PveGuestPowerRequest{RemoteID: mutRemote, Kind: kind, Node: "pve1", VMID: 101, Verb: verb}
}

var powerExecSeq int

func (e *powerEnv) propose(req PveGuestPowerRequest) (permit.Permit, error) {
	powerExecSeq++
	id := fmt.Sprintf("00000000-0000-4000-b000-%012d", powerExecSeq)
	return e.g.Propose(context.Background(), req, id, time.Now().Add(time.Hour))
}

func (e *powerEnv) approve(req PveGuestPowerRequest) PveGuestPowerRequest {
	e.t.Helper()
	p, err := e.propose(req)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest = p.Digest
	return req
}

func TestGuestPowerRiskPerVerbAndCriticality(t *testing.T) {
	M, H, C := canonical.RiskMedium, canonical.RiskHigh, canonical.RiskCritical
	cases := []struct {
		name                string
		kind, verb          string
		guest, node, remote canonical.Risk
		linkNode, linkGuest canonical.Risk
		want                canonical.Risk
	}{
		{"shutdown base", "qemu", "shutdown", M, M, M, "", "", M},
		{"reboot base", "lxc", "reboot", M, M, M, "", "", M},
		{"stop base", "lxc", "stop", M, M, M, "", "", H},
		{"reset base", "qemu", "reset", M, M, M, "", "", H},
		{"low records do not lower", "qemu", "shutdown", canonical.RiskLow, canonical.RiskLow, canonical.RiskLow, "", "", M},
		{"guest critical", "qemu", "shutdown", C, M, M, "", "", C},
		{"node high", "qemu", "reboot", M, H, M, "", "", H},
		{"remote critical", "qemu", "stop", M, M, C, "", "", C},
		{"unknown guest", "qemu", "shutdown", "", M, M, "", "", H},
		{"unknown node", "qemu", "shutdown", M, "", M, "", "", H},
		{"unknown remote", "qemu", "shutdown", M, M, "", "", "", H},
		{"linked node host critical", "qemu", "shutdown", M, M, M, C, "", C},
		{"linked guest host high", "lxc", "shutdown", M, M, M, "", H, H},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newPowerEnv(t, c.kind)
			e.record(c.kind, 101, c.guest, c.node, c.remote)
			g, n, _ := e.targets(c.kind, 101)
			if c.linkNode != "" {
				h := canonical.Target{HostID: "host-node", HostKeyFingerprint: "SHA256:node"}
				e.linked[n.HostID] = []canonical.Target{h}
				e.crit.hosts[h] = c.linkNode
			}
			if c.linkGuest != "" {
				h := canonical.Target{HostID: "host-guest", HostKeyFingerprint: "SHA256:guest"}
				e.linked[g.HostID] = []canonical.Target{h}
				e.crit.hosts[h] = c.linkGuest
			}
			p, err := e.propose(powerReq(c.kind, c.verb))
			if err != nil {
				t.Fatal(err)
			}
			if p.Request.RiskClass != c.want {
				t.Fatalf("risk %s, want %s", p.Request.RiskClass, c.want)
			}
		})
	}
}

func TestGuestPowerRiskFloorFailsClosed(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	req := powerReq("qemu", "shutdown")
	mreq, err := req.mutation()
	if err != nil {
		t.Fatal(err)
	}
	rq, params, err := e.g.Mutations.ProposalRequest(context.Background(), mreq, "00000000-0000-4000-b000-999999999999", canonical.RiskMedium, pveGuestPowerStagePlan, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	next, _ := riskpolicy.New(e.crit)
	linked := func(canonical.Request, canonical.Target) ([]canonical.Target, error) { return nil, nil }
	full := GuestPowerRiskFloor{Next: next, Criticality: e.crit, Linked: linked, Bindings: e.g.Bindings}
	// Without a binding for the exact parameters the guest is unknown.
	if r, _, err := full.MinimumRisk(rq, rq.ResolvedTargets); err != nil || r != canonical.RiskHigh {
		t.Fatalf("unbound request: %s %v", r, err)
	}
	for name, f := range map[string]GuestPowerRiskFloor{
		"no next": {Criticality: e.crit, Linked: linked, Bindings: e.g.Bindings},
		"no crit": {Next: next, Linked: linked, Bindings: e.g.Bindings},
		"no link": {Next: next, Criticality: e.crit, Bindings: e.g.Bindings},
		"no bind": {Next: next, Criticality: e.crit, Linked: linked},
	} {
		if r, _, err := f.MinimumRisk(rq, rq.ResolvedTargets); err != nil || r != canonical.RiskHigh {
			t.Fatalf("%s: %s %v", name, r, err)
		}
	}
	failing := full
	failing.Linked = func(canonical.Request, canonical.Target) ([]canonical.Target, error) { return nil, errors.New("store") }
	bound, err := boundTarget(params)
	if err != nil {
		t.Fatal(err)
	}
	release, err := e.g.hold(bound, "shutdown", rq.ParametersHash)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if r, _, err := full.MinimumRisk(rq, rq.ResolvedTargets); err != nil || r != canonical.RiskMedium {
		t.Fatalf("bound request: %s %v", r, err)
	}
	if _, _, err := failing.MinimumRisk(rq, rq.ResolvedTargets); err == nil {
		t.Fatal("linked-host error did not fail")
	}
	// A request whose artifact is not the verb's artifact is HIGH.
	other := rq
	other.ArtifactSHA256 = sha256Hex(pveGuestPowerArtifact("stop"))
	if r, _, err := full.MinimumRisk(other, rq.ResolvedTargets); err != nil || r != canonical.RiskHigh {
		t.Fatalf("artifact mismatch: %s %v", r, err)
	}
	// Targets other than the bound guest are HIGH.
	if r, _, err := full.MinimumRisk(rq, []canonical.Target{{HostID: "x", HostKeyFingerprint: "SHA256:x"}}); err != nil || r != canonical.RiskHigh {
		t.Fatalf("foreign target: %s %v", r, err)
	}
}

func TestGuestPowerLXCResetIsRefused(t *testing.T) {
	e := newPowerEnv(t, "lxc")
	if _, err := e.propose(powerReq("lxc", "reset")); !errors.Is(err, ErrPveGuestPowerVerb) {
		t.Fatalf("lxc reset proposal: %v", err)
	}
	if _, err := e.g.Run(context.Background(), powerReq("lxc", "reset")); !errors.Is(err, ErrPveGuestPowerVerb) {
		t.Fatalf("lxc reset run: %v", err)
	}
	if e.client.reads != 0 || e.client.dispatchCount() != 0 {
		t.Fatalf("lxc reset read %d times, dispatched %d", e.client.reads, e.client.dispatchCount())
	}
	if _, ok := GuestPowerStepTaskType("guest.lxc.reset"); ok {
		t.Fatal("lxc reset has a task type")
	}
	w := &fakePowerWriter{}
	if _, err := DispatchGuestPowerStep(context.Background(), w, "pve1", PveMutationStep{Method: "guest.lxc.reset", Args: json.RawMessage(`{"vmid":101}`)}); !errors.Is(err, ErrPveRejected) {
		t.Fatalf("lxc reset dispatch: %v", err)
	}
	if len(w.calls) != 0 {
		t.Fatalf("writer called: %v", w.calls)
	}
	for _, verb := range []string{"", "start", "Shutdown", "shutdown;stop"} {
		if _, err := e.propose(powerReq("qemu", verb)); !errors.Is(err, ErrPveGuestPowerVerb) {
			t.Fatalf("verb %q: %v", verb, err)
		}
	}
	// Stop and reset take no timeout; a timeout outside the bounds is refused.
	for _, r := range []PveGuestPowerRequest{
		{RemoteID: mutRemote, Kind: "qemu", Node: "pve1", VMID: 101, Verb: "stop", TimeoutSec: 10},
		{RemoteID: mutRemote, Kind: "qemu", Node: "pve1", VMID: 101, Verb: "shutdown", TimeoutSec: pveapi.MaxPowerTimeoutSec + 1},
		{RemoteID: mutRemote, Kind: "qemu", Node: "pve1", VMID: 101, Verb: "shutdown", TimeoutSec: -1},
	} {
		if _, err := e.propose(r); !errors.Is(err, ErrPveGuestPowerVerb) {
			t.Fatalf("%+v: %v", r, err)
		}
	}
}

func TestGuestPowerStateMismatchRefusedBeforeSend(t *testing.T) {
	for _, verb := range []string{"shutdown", "reboot", "stop", "reset"} {
		t.Run(verb, func(t *testing.T) {
			e := newPowerEnv(t, "qemu")
			req := e.approve(powerReq("qemu", verb))
			// The guest stopped after approval: nothing is sent and the
			// permit is not used.
			e.client.statusFn = func(int) string { return "stopped" }
			if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveGuestState) {
				t.Fatalf("stopped guest: %v", err)
			}
			if e.client.dispatchCount() != 0 {
				t.Fatal("dispatched to a stopped guest")
			}
			// The guest changed state between authorization and dispatch:
			// refused before the intent is recorded.
			reads := e.client.reads
			e.client.statusFn = func(n int) string {
				if n > reads+2 {
					return "stopped"
				}
				return "running"
			}
			res, err := e.g.Run(context.Background(), req)
			if !errors.Is(err, ErrPveGuestState) {
				t.Fatalf("raced state: %v", err)
			}
			if e.client.dispatchCount() != 0 || len(res.Steps) != 0 {
				t.Fatalf("raced state dispatched %d, steps %+v", e.client.dispatchCount(), res.Steps)
			}
		})
	}
	// A proposal for a guest that is not running is refused.
	e := newPowerEnv(t, "qemu")
	e.client.statusFn = func(int) string { return "stopped" }
	if _, err := e.propose(powerReq("qemu", "shutdown")); !errors.Is(err, ErrPveGuestState) {
		t.Fatalf("proposal for stopped guest: %v", err)
	}
	// Another kind under the same VMID (the guest was replaced) is refused.
	e.client.statusFn = nil
	req := e.approve(powerReq("qemu", "shutdown"))
	e.client.liveKind = "lxc"
	if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveTargetChanged) {
		t.Fatalf("kind changed: %v", err)
	}
	// A guest that moved nodes is refused.
	e.client.liveKind, e.client.liveNode = "qemu", "pve2"
	if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveTargetChanged) {
		t.Fatalf("moved guest: %v", err)
	}
	if e.client.dispatchCount() != 0 {
		t.Fatal("dispatched to a changed guest")
	}
}

func TestGuestPowerPermitBoundToExactTargetAndVerb(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	e.record("qemu", 102, canonical.RiskMedium, canonical.RiskMedium, canonical.RiskMedium)
	req := e.approve(powerReq("qemu", "shutdown"))
	for name, r := range map[string]PveGuestPowerRequest{
		"other verb":    {RemoteID: mutRemote, Kind: "qemu", Node: "pve1", VMID: 101, Verb: "stop", Digest: req.Digest},
		"other vmid":    {RemoteID: mutRemote, Kind: "qemu", Node: "pve1", VMID: 102, Verb: "shutdown", Digest: req.Digest},
		"other timeout": {RemoteID: mutRemote, Kind: "qemu", Node: "pve1", VMID: 101, Verb: "shutdown", TimeoutSec: 30, Digest: req.Digest},
	} {
		if _, err := e.g.Run(context.Background(), r); !errors.Is(err, ErrPveMutationDenied) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if e.client.dispatchCount() != 0 {
		t.Fatal("a mismatched request dispatched")
	}
	// The configuration changed after approval.
	e.client.digest = strings.Repeat("ab", 32)
	if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("changed config: %v", err)
	}
	e.client.digest = strings.Repeat("cd", 32)
	res, err := e.g.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.client.dispatched) != 1 || e.client.dispatched[0].Method != "guest.qemu.shutdown" {
		t.Fatalf("dispatched %+v", e.client.dispatched)
	}
	var args struct {
		VMID       uint64 `json:"vmid"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := json.Unmarshal(e.client.dispatched[0].Args, &args); err != nil || args.VMID != 101 || args.TimeoutSec != pveGuestPowerDefaultTimeoutSec {
		t.Fatalf("args %s: %v", e.client.dispatched[0].Args, err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[0].Action != PveGuestPowerAction || res.Steps[0].VMID != 101 || res.Steps[0].TaskType != "qmshutdown" {
		t.Fatalf("steps %+v", res.Steps)
	}
	// Single use.
	if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("second run: %v", err)
	}
	// The permit's parameters name the verb and the exact guest.
	p, err := e.propose(powerReq("qemu", "reboot"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Target     permit.ProviderMutationTarget `json:"provider_target"`
		Parameters struct {
			Verb         string `json:"verb"`
			Kind         string `json:"kind"`
			ExpectStatus string `json:"expect_status"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(p.Parameters, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Parameters.Verb != "reboot" || doc.Parameters.Kind != "qemu" || doc.Parameters.ExpectStatus != "running" ||
		doc.Target.Kind != "qemu" || doc.Target.Node != "pve1" || doc.Target.VMID != 101 || doc.Target.ConfigDigest != strings.Repeat("cd", 32) || doc.Target.Generation != strings.Repeat("9f", 20) {
		t.Fatalf("binding %+v", doc)
	}
	if p.Request.ArtifactSHA256 != sha256Hex(pveGuestPowerArtifact("reboot")) || p.Request.ActionID != PveGuestPowerAction {
		t.Fatalf("request %+v", p.Request)
	}
}

func TestGuestPowerFailedShutdownHasNoForceFallback(t *testing.T) {
	e := newPowerEnv(t, "lxc")
	req := e.approve(powerReq("lxc", "shutdown"))
	e.client.taskStatus = func(string) (PveTaskStatus, error) { return PveTaskStatus{ExitStatus: "shutdown timeout"}, nil }
	res, err := e.g.Run(context.Background(), req)
	if !errors.Is(err, ErrPveStepFailed) {
		t.Fatalf("failed shutdown: %v", err)
	}
	if len(e.client.dispatched) != 1 || e.client.dispatched[0].Method != "guest.lxc.shutdown" {
		t.Fatalf("dispatched %+v", e.client.dispatched)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobFailed {
		t.Fatalf("steps %+v", res.Steps)
	}
}

func TestGuestPowerRestartReconcileFindsTask(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	req := e.approve(powerReq("qemu", "reset"))
	e.client.onDispatch = func(PveMutationStep) (string, error) { return "", errors.New("connection reset") }
	res, err := e.g.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("lost response: %v", err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling || res.Steps[0].UPID != "" {
		t.Fatalf("steps %+v", res.Steps)
	}
	e.restart()
	// Tasks of another guest, another type and another token are not ours.
	now := time.Now()
	own := testTaskUPID("pve1", now, "qmreset", "101", mutActionUser, 7)
	e.client.recent = []string{
		testTaskUPID("pve1", now, "qmreset", "102", mutActionUser, 4),
		testTaskUPID("pve1", now, "qmstop", "101", mutActionUser, 5),
		testTaskUPID("pve1", now, "qmreset", "101", "root@pam", 6),
		own,
	}
	if err := e.g.Mutations.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, err := e.pe.db.PveJobSteps(res.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].UPID != own || steps[0].State != executordb.PveJobSucceeded {
		t.Fatalf("reconciled steps %+v", steps)
	}
	if e.client.dispatchCount() != 1 {
		t.Fatalf("reconcile dispatched again: %d", e.client.dispatchCount())
	}
}

type fakePowerWriter struct{ calls []string }

func (w *fakePowerWriter) ShutdownGuest(_ context.Context, kind pveapi.GuestKind, node string, vmid int64, timeout int) (string, error) {
	w.calls = append(w.calls, fmt.Sprintf("shutdown %s %s %d %d", kind, node, vmid, timeout))
	return "upid", nil
}

func (w *fakePowerWriter) RebootGuest(_ context.Context, kind pveapi.GuestKind, node string, vmid int64, timeout int) (string, error) {
	w.calls = append(w.calls, fmt.Sprintf("reboot %s %s %d %d", kind, node, vmid, timeout))
	return "upid", nil
}

func (w *fakePowerWriter) StopGuest(_ context.Context, kind pveapi.GuestKind, node string, vmid int64) (string, error) {
	w.calls = append(w.calls, fmt.Sprintf("stop %s %s %d", kind, node, vmid))
	return "upid", nil
}

func (w *fakePowerWriter) ResetGuest(_ context.Context, node string, vmid int64) (string, error) {
	w.calls = append(w.calls, fmt.Sprintf("reset %s %d", node, vmid))
	return "upid", nil
}

func TestDispatchGuestPowerStepCallsTypedWriter(t *testing.T) {
	cases := []struct {
		method, args, want string
	}{
		{"guest.qemu.shutdown", `{"vmid":101,"timeout_sec":180}`, "shutdown qemu pve1 101 180"},
		{"guest.lxc.reboot", `{"vmid":200,"timeout_sec":60}`, "reboot lxc pve1 200 60"},
		{"guest.lxc.stop", `{"vmid":200}`, "stop lxc pve1 200"},
		{"guest.qemu.reset", `{"vmid":101}`, "reset pve1 101"},
	}
	for _, c := range cases {
		w := &fakePowerWriter{}
		if _, err := DispatchGuestPowerStep(context.Background(), w, "pve1", PveMutationStep{Method: c.method, Args: json.RawMessage(c.args)}); err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		if len(w.calls) != 1 || w.calls[0] != c.want {
			t.Fatalf("%s: %v", c.method, w.calls)
		}
	}
	for _, bad := range []PveMutationStep{
		{Method: "guest.qemu.shutdown", Args: json.RawMessage(`{"vmid":101}`)},
		{Method: "guest.qemu.stop", Args: json.RawMessage(`{"vmid":101,"timeout_sec":5}`)},
		{Method: "guest.qemu.stop", Args: json.RawMessage(`{"vmid":101,"force":1}`)},
		{Method: "guest.qemu.stop", Args: json.RawMessage(`{"vmid":1}`)},
		{Method: "guest.qemu.start", Args: json.RawMessage(`{"vmid":101}`)},
	} {
		w := &fakePowerWriter{}
		if _, err := DispatchGuestPowerStep(context.Background(), w, "pve1", bad); !errors.Is(err, ErrPveRejected) || len(w.calls) != 0 {
			t.Fatalf("%+v: %v %v", bad, err, w.calls)
		}
	}
}

// TestMethodRolesGuestPower: the server may propose a power action, only
// the admin commits (dispatches) it.
func TestMethodRolesGuestPower(t *testing.T) {
	want := map[string][]peercred.Role{
		pb.ExecutorService_ProposePVEGuestPower_FullMethodName: {peercred.RoleServer, peercred.RoleAdmin},
		pb.ExecutorService_CommitPVEGuestPower_FullMethodName:  {peercred.RoleAdmin},
	}
	roles := MethodRoles()
	for method, w := range want {
		got := roles[method]
		if len(got) != len(w) {
			t.Fatalf("%s: roles %v, want %v", method, got, w)
		}
		for i := range w {
			if got[i] != w[i] {
				t.Fatalf("%s: roles %v, want %v", method, got, w)
			}
		}
	}
}

func TestServiceGuestPowerRPCRefusals(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	ctx := context.Background()
	target := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	codeOf := func(err error) codes.Code { return status.Code(err) }
	if _, err := e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{}); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("nil target: %v", err)
	}
	// Without a mutation client nothing can be proposed or run.
	if _, err := e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: target}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("no client: %v", err)
	}
	m := e.svc.pveMutations()
	client := &powerClient{liveNode: "pve1", liveKind: "qemu", digest: strings.Repeat("cd", 32), gen: strings.Repeat("9f", 20)}
	m.Client = client
	g, err := e.svc.pveGuestPower()
	if err != nil || g.Mutations != m || g.Bindings != &m.powerBindings {
		t.Fatalf("guest power engine: %v", err)
	}
	lxcReset := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "lxc", Node: "pve1", Vmid: 101, Verb: "reset"}
	if _, err := e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: lxcReset}); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("lxc reset: %v", err)
	}
	huge := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown", TimeoutSec: 1 << 31}
	if _, err := e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: huge}); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("huge timeout: %v", err)
	}
	// The read env's remote has no action token: read-only.
	if _, err := e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: target}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("read-only remote: %v", err)
	}
	if _, err := e.svc.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: "nope"}); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("bad digest: %v", err)
	}
	if _, err := e.svc.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: strings.Repeat("ab", 32)}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("commit on read-only remote: %v", err)
	}
	if n := client.dispatchCount(); n != 0 {
		t.Fatalf("dispatched %d", n)
	}
}

// TestGuestPowerFloorWithoutLinkedHostsIsHigh: a floor without a
// linked-host source proposes even a fully recorded MEDIUM guest HIGH
// (fail closed).
func TestGuestPowerFloorWithoutLinkedHostsIsHigh(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	e.g.Floor = GuestPowerRiskFloor{Next: fixedRisk{}, Criticality: e.crit, Bindings: e.g.Bindings}
	p, err := e.propose(powerReq("qemu", "shutdown"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("risk %s", p.Request.RiskClass)
	}
}

// newServicePowerEnv is a Service built by NewService whose authority uses
// the production risk policy (NewExecutorRiskPolicy) with the bindings
// wired into the service as cmd/nebula-executor does. The authority reads
// criticality from crit (every target of the guest recorded MEDIUM, the
// artifacts trusted MEDIUM), so the guest, node and remote can carry
// distinct records. The service has an action credential and a fake
// mutation client.
func newServicePowerEnv(t *testing.T) (*pveReadEnv, *powerClient, critSource, *PveGuestPowerBindings, map[string]canonical.Target) {
	t.Helper()
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	crit := critSource{artifact: canonical.RiskMedium, hosts: map[canonical.Target]canonical.Risk{}}
	b := &PveGuestPowerBindings{Now: e.clock.Now}
	pol, err := NewExecutorRiskPolicy(crit, b)
	if err != nil {
		t.Fatal(err)
	}
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth, err = permit.New(permit.Options{Verifier: v, Store: e.db, RiskPolicy: pol, Leases: e.db, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetPveGuestPowerBindings(b)
	actRef := PveVaultID(pveReadRemote, PvePurposeAction)
	actVersion, err := e.svc.vault.Put(actRef, []byte(mutActionToken), "test")
	if err != nil {
		t.Fatal(err)
	}
	creds := e.remote().Credentials
	creds.ActionRef, creds.ActionVersion = actRef, actVersion
	if _, err := e.db.SetRemoteCredentials(pveReadRemote, creds, "test"); err != nil {
		t.Fatal(err)
	}
	client := &powerClient{liveNode: "pve1", liveKind: "qemu", digest: strings.Repeat("cd", 32), gen: strings.Repeat("9f", 20)}
	m := e.svc.pveMutations()
	m.Client, m.PollInterval, m.MaxWait = client, time.Millisecond, 2*time.Second
	rm := e.remote()
	g, n, r, err := PveGuestRiskTargets(permit.ProviderMutationTarget{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, Kind: "qemu", Node: "pve1", VMID: 101})
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]canonical.Target{"guest": g, "node": n, "remote": r}
	for _, tg := range targets {
		crit.hosts[tg] = canonical.RiskMedium
	}
	return e, client, crit, b, targets
}

// TestServiceGuestPowerFloorWiring: the service's own floor reads the
// registry's linked hosts and the bindings shared with the authority.
func TestServiceGuestPowerFloorWiring(t *testing.T) {
	e, _, _, b, _ := newServicePowerEnv(t)
	g, err := e.svc.pveGuestPower()
	if err != nil {
		t.Fatal(err)
	}
	f, ok := g.Floor.(GuestPowerRiskFloor)
	if !ok || f.Linked == nil || f.Next == nil || f.Criticality == nil {
		t.Fatalf("service floor not fully wired: %+v", g.Floor)
	}
	if g.Bindings != b || f.Bindings != b {
		t.Fatal("service does not bind in the authority's bindings")
	}
}

// TestGuestPowerProductionFloorIsMediumOnKnownTargets: the production
// floor (NewGuestPowerRiskFloor, registry linked-host source) proposes a
// shutdown of a guest whose guest, node and remote are recorded MEDIUM as
// MEDIUM, and a stop as HIGH.
func TestGuestPowerProductionFloorIsMediumOnKnownTargets(t *testing.T) {
	for verb, want := range map[string]canonical.Risk{PveGuestPowerShutdown: canonical.RiskMedium, PveGuestPowerStop: canonical.RiskHigh} {
		e := newPowerEnv(t, "qemu")
		next, err := riskpolicy.New(e.crit)
		if err != nil {
			t.Fatal(err)
		}
		e.g.Floor = NewGuestPowerRiskFloor(next, e.crit, e.g.Bindings)
		p, err := e.propose(powerReq("qemu", verb))
		if err != nil {
			t.Fatal(err)
		}
		if p.Request.RiskClass != want {
			t.Fatalf("%s: risk %s, want %s", verb, p.Request.RiskClass, want)
		}
	}
}

// TestServiceGuestPowerAuthorityReevaluatesFloor: with the production
// authority policy, a node made more critical after the proposal is picked
// up on approval and on run authorization; nothing is sent.
func TestServiceGuestPowerAuthorityReevaluatesFloor(t *testing.T) {
	e, client, crit, _, targets := newServicePowerEnv(t)
	ctx := context.Background()
	target := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	propose := func() *pb.ProposeExecutionResponse {
		t.Helper()
		out, err := e.svc.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: target})
		if err != nil {
			t.Fatal(err)
		}
		return out.GetPermit()
	}
	digestOf := func(p *pb.ProposeExecutionResponse) canonical.Digest {
		t.Helper()
		d, err := canonical.ParseDigest(p.GetExecutionDigest())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	node := targets["node"]

	p := propose()
	if _, err := e.svc.auth.ApproveCLI(digestOf(p), 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: p.GetExecutionDigest()}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if n := client.dispatchCount(); n != 1 {
		t.Fatalf("dispatched %d, want 1", n)
	}

	// Raised after approval: the run authorization refuses.
	p = propose()
	if _, err := e.svc.auth.ApproveCLI(digestOf(p), 0, "admin"); err != nil {
		t.Fatal(err)
	}
	crit.hosts[node] = canonical.RiskCritical
	if _, err := e.svc.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: p.GetExecutionDigest()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("commit after node raised: %v", err)
	}
	if n := client.dispatchCount(); n != 1 {
		t.Fatalf("dispatched %d after the node was raised", n)
	}

	// Raised after proposal: the approval refuses the old risk.
	crit.hosts[node] = canonical.RiskMedium
	p = propose()
	crit.hosts[node] = canonical.RiskCritical
	if _, err := e.svc.auth.ApproveCLI(digestOf(p), 0, "admin"); err == nil {
		t.Fatal("approval accepted after the node was raised to CRITICAL")
	}
}

// TestGuestPowerPausedQemuIsNotRunning: PVE reports a paused or suspended
// QEMU guest as "running"; its QMP state decides, and an unreported one is
// refused.
func TestGuestPowerPausedQemuIsNotRunning(t *testing.T) {
	for _, qmp := range []string{"paused", "suspended", "prelaunch", "unknown-state"} {
		e := newPowerEnv(t, "qemu")
		e.client.qmp = qmp
		if _, err := e.propose(powerReq("qemu", "reset")); !errors.Is(err, ErrPveGuestState) {
			t.Fatalf("%s: proposal: %v", qmp, err)
		}
		e.client.qmp = ""
		req := e.approve(powerReq("qemu", "reset"))
		e.client.qmp = qmp
		if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveGuestState) {
			t.Fatalf("%s: run: %v", qmp, err)
		}
		if e.client.dispatchCount() != 0 {
			t.Fatalf("%s: dispatched", qmp)
		}
	}
	// Not reported: fail closed.
	err := mustMutation(t, powerReq("qemu", "stop")).precheck(PveTargetState{Node: "pve1", Kind: "qemu", Status: "running"})
	if !errors.Is(err, ErrPveGuestState) {
		t.Fatalf("unreported qmp status: %v", err)
	}
	// LXC has no QMP state.
	if err := mustMutation(t, powerReq("lxc", "stop")).precheck(PveTargetState{Node: "pve1", Kind: "lxc", Status: "running"}); err != nil {
		t.Fatalf("lxc: %v", err)
	}
}

func mustMutation(t *testing.T, r PveGuestPowerRequest) PveMutationRequest {
	t.Helper()
	m, err := r.mutation()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestGuestPowerBindingExpires: an entry nobody holds is not scored after
// its permit's expiry, even before the next hold prunes it.
func TestGuestPowerBindingExpires(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b := &PveGuestPowerBindings{Now: func() time.Time { return now }}
	tg := permit.ProviderMutationTarget{RemoteID: "r", Kind: "qemu", Node: "pve1", VMID: 101}
	release, err := b.hold(pveBindPower, "h", tg, PveGuestPowerShutdown)
	if err != nil {
		t.Fatal(err)
	}
	b.keep(pveBindPower, "h", now.Add(time.Minute))
	release()
	if _, _, ok := b.lookup(pveBindPower, "h"); !ok {
		t.Fatal("binding gone before expiry")
	}
	now = now.Add(2 * time.Minute)
	if _, _, ok := b.lookup(pveBindPower, "h"); ok {
		t.Fatal("expired binding still scored")
	}
}

// TestGuestPowerFloorErrorIsNotAStoreError: a failing risk source is
// reported as such, not as a job store failure.
func TestGuestPowerFloorErrorIsNotAStoreError(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	next, _ := riskpolicy.New(e.crit)
	e.g.Floor = GuestPowerRiskFloor{Next: next, Criticality: e.crit, Bindings: e.g.Bindings,
		Linked: func(canonical.Request, canonical.Target) ([]canonical.Target, error) { return nil, errors.New("store") }}
	_, err := e.propose(powerReq("qemu", "shutdown"))
	if !errors.Is(err, ErrPveGuestPowerRisk) || errors.Is(err, ErrPveJobStore) {
		t.Fatalf("floor error: %v", err)
	}
	if st := status.Convert(pveGuestPowerRPCError(err)); st.Code() != codes.Internal || !strings.Contains(st.Message(), "risk floor") {
		t.Fatalf("rpc error: %v", st)
	}
}

// TestServiceGuestPowerWithoutClientSaysSo: without a mutation client the
// RPCs say exactly that. pveMutations always wires the production client
// now (TestPveMutationsWiresProductionClient); the engine here is built
// without one to keep the defensive check covered.
func TestServiceGuestPowerWithoutClientSaysSo(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.svc.pveMutOnce.Do(func() {
		e.svc.pveMut = &PveMutations{DB: e.svc.db, Auth: e.svc.auth, Vault: e.svc.vault, Now: e.svc.clock, Log: e.svc.log}
	})
	target := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	_, perr := e.svc.ProposePVEGuestPower(context.Background(), &pb.ProposePVEGuestPowerRequest{Target: target})
	_, cerr := e.svc.CommitPVEGuestPower(context.Background(), &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: strings.Repeat("ab", 32)})
	for _, err := range []error{perr, cerr} {
		if st := status.Convert(err); st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "PVE mutation client not configured") {
			t.Fatalf("no client: %v", err)
		}
	}
}

// floorFixture is a bound guest whose guest, node and remote have exact LOW
// records, so a correctly bound request is scored at its op or verb base.
func floorFixture(t *testing.T) (permit.ProviderMutationTarget, canonical.Target, critSource) {
	t.Helper()
	bt := permit.ProviderMutationTarget{RemoteID: mutRemote, TrustPin: strings.Repeat("ab", 32), Kind: permit.ProviderKindQemu, Node: "pve1", VMID: 101}
	g, n, r, err := PveGuestRiskTargets(bt)
	if err != nil {
		t.Fatal(err)
	}
	crit := critSource{hosts: map[canonical.Target]canonical.Risk{g: canonical.RiskLow, n: canonical.RiskLow, r: canonical.RiskLow}}
	return bt, g, crit
}

// floorCase binds verb (a power verb or snapshot op) in fam's table and
// scores a request of the floor's action with artifact.
type floorCase struct {
	name     string
	fam      pveBindingFamily
	verb     string
	artifact []byte
	// otherTarget scores the request for another guest than the bound one.
	otherTarget bool
	want        canonical.Risk
}

// floorMaker builds the floor under test over next, crit and b.
type floorMaker func(next permit.RiskPolicy, crit PveCriticality, b *PveGuestPowerBindings) permit.RiskPolicy

// runFloorCases scores every case with Next LOW (the result is exactly
// want) and with Next CRITICAL (the result is CRITICAL: no branch
// under-reports Next).
func runFloorCases(t *testing.T, action string, mk floorMaker, cases []floorCase) {
	t.Helper()
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, c := range cases {
		for _, nextRisk := range []canonical.Risk{canonical.RiskLow, canonical.RiskCritical} {
			t.Run(c.name+"/next "+string(nextRisk), func(t *testing.T) {
				bt, guest, crit := floorFixture(t)
				b := &PveGuestPowerBindings{}
				release, err := b.hold(c.fam, hash, bt, c.verb)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				nr := nextRisk
				f := mk(switchRisk{r: &nr}, crit, b)
				targets := []canonical.Target{guest}
				if c.otherTarget {
					o := bt
					o.VMID = 102
					og, _, _, err := PveGuestRiskTargets(o)
					if err != nil {
						t.Fatal(err)
					}
					targets = []canonical.Target{og}
				}
				rq := canonical.Request{ActionID: action, ParametersHash: hash, ArtifactSHA256: sha256Hex(c.artifact)}
				got, why, err := f.MinimumRisk(rq, targets)
				if err != nil {
					t.Fatal(err)
				}
				want := c.want
				if nextRisk == canonical.RiskCritical {
					want = canonical.RiskCritical
				}
				if got != want {
					t.Fatalf("risk %s (%s), want %s", got, why, want)
				}
			})
		}
	}
}

// TestGuestPowerFloorNeverAcceptsSnapshotBindings: a snapshot binding or
// artifact is never scored at a power verb's MEDIUM base by the power
// floor; it is HIGH (or Next's higher floor). The control case shows the
// fixture otherwise yields MEDIUM, so a merged op/verb table, a lookup
// across both binding tables or a skipped artifact check fails here.
func TestGuestPowerFloorNeverAcceptsSnapshotBindings(t *testing.T) {
	M, H := canonical.RiskMedium, canonical.RiskHigh
	mk := func(next permit.RiskPolicy, crit PveCriticality, b *PveGuestPowerBindings) permit.RiskPolicy {
		return GuestPowerRiskFloor{Next: next, Criticality: crit, Linked: noLinkedHosts, Bindings: b}
	}
	runFloorCases(t, PveGuestPowerAction, mk, []floorCase{
		{"control power binding", pveBindPower, PveGuestPowerShutdown, pveGuestPowerArtifact(PveGuestPowerShutdown), false, M},
		{"snapshot binding of create", pveBindSnapshot, PveSnapshotCreate, pveSnapshotArtifact(PveSnapshotCreate), false, H},
		{"snapshot table holding a power verb", pveBindSnapshot, PveGuestPowerShutdown, pveGuestPowerArtifact(PveGuestPowerShutdown), false, H},
		{"power table holding a snapshot op", pveBindPower, PveSnapshotCreate, pveSnapshotArtifact(PveSnapshotCreate), false, H},
		{"power verb with snapshot artifact", pveBindPower, PveGuestPowerShutdown, pveSnapshotArtifact(PveSnapshotCreate), false, H},
		{"power verb with other verb's artifact", pveBindPower, PveGuestPowerShutdown, pveGuestPowerArtifact(PveGuestPowerReboot), false, H},
		{"other target", pveBindPower, PveGuestPowerShutdown, pveGuestPowerArtifact(PveGuestPowerShutdown), true, H},
	})
}

// TestGuestPowerFloorFailClosedRaisesToNext: the unbound and unconfigured
// branches report Next's floor when it is above HIGH, and HIGH otherwise.
func TestGuestPowerFloorFailClosedRaisesToNext(t *testing.T) {
	_, guest, crit := floorFixture(t)
	rq := canonical.Request{ActionID: PveGuestPowerAction, ParametersHash: strings.Repeat("cd", 32),
		ArtifactSHA256: sha256Hex(pveGuestPowerArtifact(PveGuestPowerShutdown))}
	for _, nr := range []canonical.Risk{canonical.RiskLow, canonical.RiskHigh, canonical.RiskCritical} {
		want := canonical.RiskHigh
		if nr == canonical.RiskCritical {
			want = nr
		}
		r := nr
		next := switchRisk{r: &r}
		for name, f := range map[string]GuestPowerRiskFloor{
			"unbound":        {Next: next, Criticality: crit, Linked: noLinkedHosts, Bindings: &PveGuestPowerBindings{}},
			"no bindings":    {Next: next, Criticality: crit, Linked: noLinkedHosts},
			"no criticality": {Next: next, Linked: noLinkedHosts, Bindings: &PveGuestPowerBindings{}},
		} {
			if got, _, err := f.MinimumRisk(rq, []canonical.Target{guest}); err != nil || got != want {
				t.Fatalf("%s, next %s: %s %v, want %s", name, nr, got, err, want)
			}
		}
	}
	if got, _, err := (GuestPowerRiskFloor{}).MinimumRisk(rq, nil); err != nil || got != canonical.RiskHigh {
		t.Fatalf("no next: %s %v", got, err)
	}
}

// TestGuestSnapshotBindingsDoNotBlockPower: a full snapshot binding table
// (a flood of snapshot proposals kept until permit expiry) leaves the power
// table usable, and vice versa; each full table refuses only its own
// family, and neither table answers for the other's hashes.
func TestGuestSnapshotBindingsDoNotBlockPower(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tg := permit.ProviderMutationTarget{RemoteID: "r", Kind: "qemu", Node: "pve1", VMID: 101}
	key := func(fam pveBindingFamily, i int) string { return fmt.Sprintf("%d-%d", fam, i) }
	fill := func(b *PveGuestPowerBindings, fam pveBindingFamily, verb string) {
		t.Helper()
		for i := range pveBindingCapacity[fam] {
			release, err := b.hold(fam, key(fam, i), tg, verb)
			if err != nil {
				t.Fatalf("family %d entry %d: %v", fam, i, err)
			}
			b.keep(fam, key(fam, i), now.Add(time.Hour))
			release()
		}
	}
	for _, first := range []pveBindingFamily{pveBindSnapshot, pveBindPower} {
		b := &PveGuestPowerBindings{Now: func() time.Time { return now }}
		other, verb, otherVerb := pveBindPower, PveSnapshotCreate, PveGuestPowerShutdown
		if first == pveBindPower {
			other, verb, otherVerb = pveBindSnapshot, PveGuestPowerShutdown, PveSnapshotCreate
		}
		fill(b, first, verb)
		if _, err := b.hold(first, "one-more", tg, verb); !errors.Is(err, ErrPveGuestPowerBusy) {
			t.Fatalf("full table %d: %v", first, err)
		}
		release, err := b.hold(other, "after-flood", tg, otherVerb)
		if err != nil {
			t.Fatalf("family %d blocked by a full table %d: %v", other, first, err)
		}
		release()
		if _, _, ok := b.lookup(other, key(first, 0)); ok {
			t.Fatalf("family %d binding visible in table %d", first, other)
		}
		if _, _, ok := b.lookup(first, key(first, 0)); !ok {
			t.Fatalf("family %d binding missing", first)
		}
	}
	b := &PveGuestPowerBindings{}
	if _, err := b.hold(pveBindingFamilies, "x", tg, PveGuestPowerShutdown); !errors.Is(err, ErrPveMutationPlan) {
		t.Fatalf("unknown family: %v", err)
	}
	if _, _, ok := b.lookup(-1, "x"); ok {
		t.Fatal("unknown family looked up")
	}
}

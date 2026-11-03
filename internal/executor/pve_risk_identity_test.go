// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// pinFingerprint is the bare trust pin in fingerprint form, the identity
// every PVE risk target of a remote carried before pvrisk01.
func pinFingerprint(t *testing.T, trustPin string) string {
	t.Helper()
	pin, err := hex.DecodeString(trustPin)
	if err != nil {
		t.Fatal(err)
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(pin)
}

// TestPveGuestRiskTargetsAreDistinct: the guest, node and remote risk
// targets of one remote each have their own host ID and fingerprint, none
// of them the bare trust pin, so each can carry its own exact record.
func TestPveGuestRiskTargetsAreDistinct(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	tg := permit.ProviderMutationTarget{RemoteID: "pve-lab", TrustPin: pin, Kind: permit.ProviderKindQemu, Node: "pve1", VMID: 101}
	g, n, r, err := PveGuestRiskTargets(tg)
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]canonical.Target{"guest": g, "node": n, "remote": r}
	ids, fps := map[string]string{}, map[string]string{}
	for name, x := range all {
		if !canonical.ValidHostID(x.HostID) || !canonical.ValidHostKeyFingerprint(x.HostKeyFingerprint) {
			t.Fatalf("%s: malformed %+v", name, x)
		}
		if x.HostKeyFingerprint == pinFingerprint(t, pin) {
			t.Fatalf("%s: fingerprint is the bare trust pin", name)
		}
		if o, dup := ids[x.HostID]; dup {
			t.Fatalf("%s and %s share host ID", name, o)
		}
		if o, dup := fps[x.HostKeyFingerprint]; dup {
			t.Fatalf("%s and %s share fingerprint", name, o)
		}
		ids[x.HostID], fps[x.HostKeyFingerprint] = name, name
	}
	g2, n2, r2, _ := PveGuestRiskTargets(tg)
	if g2 != g || n2 != n || r2 != r {
		t.Fatal("risk targets are not stable")
	}
}

// useExecutorDB rewires e as cmd/nebula-executor does: the authority's
// risk policy is NewExecutorRiskPolicy over the executor database, with
// the bindings shared with the guest power engine.
func (e *powerEnv) useExecutorDB() {
	e.t.Helper()
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "power.test", Origins: []string{"https://power.test"}, Counters: e.pe.db}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	b := &PveGuestPowerBindings{}
	pol, err := NewExecutorRiskPolicy(e.pe.db, b)
	if err != nil {
		e.t.Fatal(err)
	}
	e.auth, err = permit.New(permit.Options{Verifier: v, Store: e.pe.db, RiskPolicy: pol})
	if err != nil {
		e.t.Fatal(err)
	}
	m := &PveMutations{DB: e.pe.db, Auth: e.auth, Vault: e.pe.vault, Client: e.client, PollInterval: time.Millisecond,
		MaxWait: 2 * time.Second, Log: slog.New(slog.NewTextHandler(e.logs, nil))}
	e.pe.admin.Mutations = m
	e.g = &PveGuestPower{Mutations: m, Bindings: b}
}

func trustBuiltin(t *testing.T, db *executordb.DB, artifact []byte, action, version string, risk canonical.Risk) {
	t.Helper()
	if err := db.TrustArtifact(executordb.TrustedArtifact{SHA256: sha256Hex(artifact), ActionID: action,
		ModuleVersion: version, Risk: risk, Label: "built-in", TrustedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
}

func setCrit(t *testing.T, db *executordb.DB, tg canonical.Target, c canonical.Risk) {
	t.Helper()
	if _, err := db.SetHostCriticality(tg.HostID, tg.HostKeyFingerprint, c, "admin"); err != nil {
		t.Fatalf("record %s: %v", tg.HostID, err)
	}
}

// TestGuestPowerFloorOverExecutorDBIsMediumOnKnownTargets: with exact
// executor records for the guest, its node and its remote (all three can
// now be recorded) and the built-in artifacts trusted, the production floor
// proposes a shutdown MEDIUM and a stop HIGH; a guest, node or remote
// without a record keeps the shutdown HIGH; a CRITICAL node raises it.
func TestGuestPowerFloorOverExecutorDBIsMediumOnKnownTargets(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	e.useExecutorDB()
	db := e.pe.db
	for verb, base := range pveGuestPowerVerbs {
		trustBuiltin(t, db, pveGuestPowerArtifact(verb), PveGuestPowerAction, pveGuestPowerVersion, base)
	}
	g, n, r := e.targets("qemu", 101)
	risk := func(verb string) canonical.Risk {
		t.Helper()
		p, err := e.propose(powerReq("qemu", verb))
		if err != nil {
			t.Fatal(err)
		}
		return p.Request.RiskClass
	}

	if got := risk(PveGuestPowerShutdown); got != canonical.RiskHigh {
		t.Fatalf("nothing recorded: shutdown %s, want HIGH", got)
	}
	for _, tg := range []canonical.Target{g, n, r} {
		setCrit(t, db, tg, canonical.RiskMedium)
	}
	if got := risk(PveGuestPowerShutdown); got != canonical.RiskMedium {
		t.Fatalf("all known MEDIUM: shutdown %s, want MEDIUM", got)
	}
	if got := risk(PveGuestPowerStop); got != canonical.RiskHigh {
		t.Fatalf("all known MEDIUM: stop %s, want HIGH", got)
	}
	for name, tg := range map[string]canonical.Target{"guest": g, "node": n, "remote": r} {
		if _, err := db.ClearHostCriticality(tg.HostID); err != nil {
			t.Fatal(err)
		}
		if got := risk(PveGuestPowerShutdown); got != canonical.RiskHigh {
			t.Fatalf("unknown %s: shutdown %s, want HIGH", name, got)
		}
		setCrit(t, db, tg, canonical.RiskMedium)
	}
	setCrit(t, db, n, canonical.RiskCritical)
	if got := risk(PveGuestPowerShutdown); got != canonical.RiskCritical {
		t.Fatalf("critical node: shutdown %s, want CRITICAL", got)
	}
}

// TestGuestPowerFloorNeedsTrustedArtifact: known MEDIUM targets do not
// lower an untrusted built-in artifact below HIGH.
func TestGuestPowerFloorNeedsTrustedArtifact(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	e.useExecutorDB()
	g, n, r := e.targets("qemu", 101)
	for _, tg := range []canonical.Target{g, n, r} {
		setCrit(t, e.pe.db, tg, canonical.RiskMedium)
	}
	p, err := e.propose(powerReq("qemu", PveGuestPowerShutdown))
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("untrusted artifact: %s, want HIGH", p.Request.RiskClass)
	}
}

// TestOldPinKeyedPveRecordsFailClosed: records made under the old scheme
// (the bare trust pin as fingerprint) are no longer exact, so they leave
// the targets HIGH, and recording the target again replaces them.
func TestOldPinKeyedPveRecordsFailClosed(t *testing.T) {
	e := newPowerEnv(t, "qemu")
	e.useExecutorDB()
	db := e.pe.db
	trustBuiltin(t, db, pveGuestPowerArtifact(PveGuestPowerShutdown), PveGuestPowerAction, pveGuestPowerVersion, canonical.RiskMedium)
	g, n, r := e.targets("qemu", 101)
	rm, _, err := db.GetRemote(mutRemote)
	if err != nil {
		t.Fatal(err)
	}
	old := pinFingerprint(t, rm.TrustPin)
	// The old scheme allowed one of the three; the remote held the pin.
	setCrit(t, db, canonical.Target{HostID: r.HostID, HostKeyFingerprint: old}, canonical.RiskLow)
	setCrit(t, db, g, canonical.RiskMedium)
	setCrit(t, db, n, canonical.RiskMedium)
	p, err := e.propose(powerReq("qemu", PveGuestPowerShutdown))
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("old remote record: %s, want HIGH", p.Request.RiskClass)
	}
	setCrit(t, db, r, canonical.RiskMedium)
	if p, err = e.propose(powerReq("qemu", PveGuestPowerShutdown)); err != nil || p.Request.RiskClass != canonical.RiskMedium {
		t.Fatalf("re-recorded remote: %s, %v", p.Request.RiskClass, err)
	}
	recs, err := db.ListHostCriticality()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range recs {
		if h.HostKeyFingerprint == old {
			t.Fatalf("old record for %s survived re-recording", h.HostID)
		}
	}
}

// TestProvisionFloorOverExecutorDBIsMediumOnKnownTargets: the production
// policy (NewExecutorRiskPolicy over the executor database) scores
// pve.guest.provision with the node and the remote: MEDIUM with exact
// records for both, HIGH while either is unknown.
func TestProvisionFloorOverExecutorDBIsMediumOnKnownTargets(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	db := e.pe.db
	pol, err := NewExecutorRiskPolicy(db, &PveGuestPowerBindings{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: v, Store: db, RiskPolicy: pol})
	if err != nil {
		t.Fatal(err)
	}
	e.auth, e.m.Auth = auth, auth
	trustBuiltin(t, db, provArtifact, PveGuestProvisionAction, "1.0.0", canonical.RiskMedium)

	p, _ := e.propose(e.request())
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("nothing recorded: %s, want HIGH", p.Request.RiskClass)
	}
	rm, _, err := db.GetRemote(mutRemote)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := PveRemoteRiskTarget(rm.TrustPin)
	if err != nil {
		t.Fatal(err)
	}
	node := p.Request.ResolvedTargets[0]
	setCrit(t, db, node, canonical.RiskMedium)
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("unknown remote: %s, want HIGH", p.Request.RiskClass)
	}
	setCrit(t, db, remote, canonical.RiskMedium)
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskMedium {
		t.Fatalf("known node and remote: %s, want MEDIUM", p.Request.RiskClass)
	}
	if _, err := db.ClearHostCriticality(node.HostID); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("unknown node: %s, want HIGH", p.Request.RiskClass)
	}
}

type remoteList struct {
	rms []executordb.PveRemote
	err error
}

func (l remoteList) ListRemotes() ([]executordb.PveRemote, error) { return l.rms, l.err }

// TestPveRegistryRemoteOf: a node target resolves to the registered remote
// whose pin its fingerprint was made with; a target made with no
// registered pin, or a forged fingerprint, resolves to nothing.
func TestPveRegistryRemoteOf(t *testing.T) {
	pinA, pinB := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	node := func(remoteID, pin string) canonical.Target {
		rt, err := (permit.ProviderMutationTarget{RemoteID: remoteID, TrustPin: pin, Kind: permit.ProviderKindNode, Node: "pve1"}).RiskTarget()
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}
	reg := remoteList{rms: []executordb.PveRemote{{RemoteID: "a", TrustPin: pinA}, {RemoteID: "b", TrustPin: pinB}}}
	of := PveRegistryRemoteOf(reg)
	if pin, ok, err := of(node("b", pinB)); err != nil || !ok || pin != pinB {
		t.Fatalf("b: %q %t %v", pin, ok, err)
	}
	if _, ok, err := of(node("c", strings.Repeat("ef", 32))); err != nil || ok {
		t.Fatalf("unregistered pin resolved: %t %v", ok, err)
	}
	forged := node("a", pinA)
	sum := sha256.Sum256([]byte("forged"))
	forged.HostKeyFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if _, ok, err := of(forged); err != nil || ok {
		t.Fatalf("forged fingerprint resolved: %t %v", ok, err)
	}
	if _, _, err := PveRegistryRemoteOf(remoteList{err: errors.New("boom")})(node("a", pinA)); err == nil {
		t.Fatal("registry error swallowed")
	}
	if _, ok, err := PveRegistryRemoteOf(nil)(node("a", pinA)); err != nil || ok {
		t.Fatalf("nil registry: %t %v", ok, err)
	}
}

// TestGuestProvisionFloorRemoteRules: without a remote source, or for a
// node target of no known remote, provisioning is HIGH; a source error
// fails the floor.
func TestGuestProvisionFloorRemoteRules(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	node, err := (permit.ProviderMutationTarget{RemoteID: "pve-lab", TrustPin: pin, Kind: permit.ProviderKindNode, Node: "pve1"}).RiskTarget()
	if err != nil {
		t.Fatal(err)
	}
	req := canonical.Request{ActionID: PveGuestProvisionAction}
	known := func(canonical.Target) (string, bool, error) { return pin, true, nil }
	if r, _, err := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: known}).MinimumRisk(req, []canonical.Target{node}); err != nil || r != canonical.RiskMedium {
		t.Fatalf("known remote: %s %v", r, err)
	}
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("no remote source: %s", r)
	}
	unknown := func(canonical.Target) (string, bool, error) { return "", false, nil }
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: unknown}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("unknown remote: %s", r)
	}
	// A source claiming a pin the node fingerprint was not made with.
	lying := func(canonical.Target) (string, bool, error) { return strings.Repeat("cd", 32), true, nil }
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: lying}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("mismatched pin: %s", r)
	}
	// A CRITICAL node stays CRITICAL when its remote is unknown or
	// mismatched: HIGH is only a floor, the known targets are still scored.
	critical := criticalNodeRisk{fp: node.HostKeyFingerprint}
	for name, src := range map[string]PveRemoteOf{"unknown": unknown, "mismatched": lying} {
		if r, _, err := (GuestProvisionRiskFloor{Next: critical, Linked: noLinkedHosts, Remote: src}).MinimumRisk(req, []canonical.Target{node}); err != nil || r != canonical.RiskCritical {
			t.Fatalf("critical node, %s remote: %s %v", name, r, err)
		}
	}
	failing := func(canonical.Target) (string, bool, error) { return "", false, errors.New("boom") }
	if _, _, err := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: failing}).MinimumRisk(req, []canonical.Target{node}); err == nil {
		t.Fatal("remote source error swallowed")
	}
}

// criticalNodeRisk scores a target with fingerprint fp as CRITICAL and
// everything else as MEDIUM.
type criticalNodeRisk struct{ fp string }

func (c criticalNodeRisk) MinimumRisk(_ canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	for _, t := range targets {
		if t.HostKeyFingerprint == c.fp {
			return canonical.RiskCritical, "node is CRITICAL", nil
		}
	}
	return canonical.RiskMedium, "test", nil
}

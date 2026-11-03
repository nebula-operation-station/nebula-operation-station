// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
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
	e.useRiskPolicy(pol)

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

// useRiskPolicy makes pol the risk policy of e's authority and trusts the
// built-in provisioning artifact as MEDIUM.
func (e *provisionEnv) useRiskPolicy(pol permit.RiskPolicy) {
	e.t.Helper()
	db := e.pe.db
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "mut.test", Origins: []string{"https://mut.test"}, Counters: db}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: v, Store: db, RiskPolicy: pol})
	if err != nil {
		e.t.Fatal(err)
	}
	e.auth, e.m.Auth = auth, auth
	trustBuiltin(e.t, db, provArtifact, PveGuestProvisionAction, "1.0.0", canonical.RiskMedium)
}

// remoteHidingDB is the executor database with a registry that resolves
// no remote: every node target's remote is unknown to the risk policy.
type remoteHidingDB struct{ *executordb.DB }

func (remoteHidingDB) ListRemotes() ([]executordb.PveRemote, error) { return nil, nil }

// TestProvisionFloorOverExecutorDBCriticalRemote: with the production
// policy, a CRITICAL record on the remote risk target makes provisioning
// CRITICAL, even with a MEDIUM node.
func TestProvisionFloorOverExecutorDBCriticalRemote(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	db := e.pe.db
	pol, err := NewExecutorRiskPolicy(db, &PveGuestPowerBindings{})
	if err != nil {
		t.Fatal(err)
	}
	e.useRiskPolicy(pol)
	rm, _, err := db.GetRemote(mutRemote)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := PveRemoteRiskTarget(rm.TrustPin)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := e.propose(e.request())
	setCrit(t, db, p.Request.ResolvedTargets[0], canonical.RiskMedium)
	setCrit(t, db, remote, canonical.RiskCritical)
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskCritical {
		t.Fatalf("critical remote: %s, want CRITICAL", p.Request.RiskClass)
	}
}

// TestProvisionFloorOverExecutorDBCriticalNodeUnknownRemote: with the
// production policy, a CRITICAL node stays CRITICAL when its remote has no
// record or cannot be resolved in the registry; HIGH for an unknown remote
// is only a floor.
func TestProvisionFloorOverExecutorDBCriticalNodeUnknownRemote(t *testing.T) {
	for name, hide := range map[string]bool{"unrecorded remote": false, "unresolvable remote": true} {
		t.Run(name, func(t *testing.T) {
			e := newProvisionEnv(t, fixedRisk{})
			db := e.pe.db
			var src riskpolicy.Source = db
			if hide {
				src = remoteHidingDB{db}
			}
			pol, err := NewExecutorRiskPolicy(src, &PveGuestPowerBindings{})
			if err != nil {
				t.Fatal(err)
			}
			e.useRiskPolicy(pol)
			p, _ := e.propose(e.request())
			node := p.Request.ResolvedTargets[0]
			setCrit(t, db, node, canonical.RiskMedium)
			if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskHigh {
				t.Fatalf("medium node, %s: %s, want HIGH", name, p.Request.RiskClass)
			}
			setCrit(t, db, node, canonical.RiskCritical)
			if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskCritical {
				t.Fatalf("critical node, %s: %s, want CRITICAL", name, p.Request.RiskClass)
			}
		})
	}
}

// TestProvisionFloorOverExecutorDBCriticalLinkedHostUnknownRemote: over
// the executor database's criticality records and registry, a CRITICAL
// linked host keeps provisioning CRITICAL when the node's remote cannot be
// resolved. The production linked-host source returns no hosts yet
// (PveRegistryLinkedHosts), so the floor is built here with a fixed one.
func TestProvisionFloorOverExecutorDBCriticalLinkedHostUnknownRemote(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	db := e.pe.db
	base, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("linked host key"))
	host := canonical.Target{HostID: "host-crit", HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}
	linked := func(canonical.Request, canonical.Target) ([]canonical.Target, error) {
		return []canonical.Target{host}, nil
	}
	e.useRiskPolicy(GuestProvisionRiskFloor{Next: base, Linked: linked, Remote: PveRegistryRemoteOf(remoteHidingDB{db})})
	p, _ := e.propose(e.request())
	setCrit(t, db, p.Request.ResolvedTargets[0], canonical.RiskMedium)
	setCrit(t, db, host, canonical.RiskMedium)
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("medium linked host, unknown remote: %s, want HIGH", p.Request.RiskClass)
	}
	setCrit(t, db, host, canonical.RiskCritical)
	if p, _ := e.propose(e.request()); p.Request.RiskClass != canonical.RiskCritical {
		t.Fatalf("critical linked host, unknown remote: %s, want CRITICAL", p.Request.RiskClass)
	}
}

type remoteList struct {
	rms   []executordb.PveRemote
	err   error
	reads *int
}

func (l remoteList) ListRemotes() ([]executordb.PveRemote, error) {
	if l.reads != nil {
		*l.reads++
	}
	return l.rms, l.err
}

// eachRemote adapts a per-target remote source to PveRemoteOf.
func eachRemote(f func(canonical.Target) (string, bool, error)) PveRemoteOf {
	return func(nodes []canonical.Target) (map[canonical.Target]string, error) {
		out := map[canonical.Target]string{}
		for _, n := range nodes {
			pin, ok, err := f(n)
			if err != nil {
				return nil, err
			}
			if ok {
				out[n] = pin
			}
		}
		return out, nil
	}
}

func provNodeRiskTarget(t *testing.T, remoteID, pin, node string) canonical.Target {
	t.Helper()
	rt, err := (permit.ProviderMutationTarget{RemoteID: remoteID, TrustPin: pin, Kind: permit.ProviderKindNode, Node: node}).RiskTarget()
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// TestPveRegistryRemoteOf: a node target resolves to the registered remote
// whose pin its fingerprint was made with; a target made with no
// registered pin, or a forged fingerprint, resolves to nothing. The
// registry is read once per call.
func TestPveRegistryRemoteOf(t *testing.T) {
	pinA, pinB := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	reads := 0
	reg := remoteList{rms: []executordb.PveRemote{{RemoteID: "a", TrustPin: pinA}, {RemoteID: "b", TrustPin: pinB}}, reads: &reads}
	b := provNodeRiskTarget(t, "b", pinB, "pve1")
	unreg := provNodeRiskTarget(t, "c", strings.Repeat("ef", 32), "pve1")
	forged := provNodeRiskTarget(t, "a", pinA, "pve1")
	sum := sha256.Sum256([]byte("forged"))
	forged.HostKeyFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	got, err := PveRegistryRemoteOf(reg)([]canonical.Target{b, unreg, forged, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[b] != pinB {
		t.Fatalf("resolved %v, want only b", got)
	}
	if reads != 1 {
		t.Fatalf("registry read %d times, want 1", reads)
	}
	if _, err := PveRegistryRemoteOf(remoteList{err: errors.New("boom")})([]canonical.Target{b}); err == nil {
		t.Fatal("registry error swallowed")
	}
	if got, err := PveRegistryRemoteOf(nil)([]canonical.Target{b}); err != nil || len(got) != 0 {
		t.Fatalf("nil registry: %v %v", got, err)
	}
}

// TestGuestProvisionFloorReadsRegistryOnce: however many node targets a
// request names, MinimumRisk reads the remote registry once, and the
// targets of unknown remotes add a single reason; known remotes are still
// scored and unknown ones keep the floor at HIGH.
func TestGuestProvisionFloorReadsRegistryOnce(t *testing.T) {
	pinA := strings.Repeat("ab", 32)
	reads := 0
	reg := remoteList{rms: []executordb.PveRemote{{RemoteID: "a", TrustPin: pinA}}, reads: &reads}
	known := provNodeRiskTarget(t, "a", pinA, "pve1")
	var targets []canonical.Target
	for i := range 50 {
		targets = append(targets, provNodeRiskTarget(t, "x", strings.Repeat("ef", 32), "node"+strconv.Itoa(i)))
	}
	targets = append(targets, known, known)
	req := canonical.Request{ActionID: PveGuestProvisionAction}
	f := GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: PveRegistryRemoteOf(reg)}
	r, why, err := f.MinimumRisk(req, targets)
	if err != nil || r != canonical.RiskHigh {
		t.Fatalf("floor %s %v, want HIGH", r, err)
	}
	if reads != 1 {
		t.Fatalf("registry read %d times, want 1", reads)
	}
	if n := strings.Count(why, "unknown criticality is HIGH"); n != 1 {
		t.Fatalf("%d unknown-remote reasons, want 1: %s", n, why)
	}
	if !strings.Contains(why, "50 node targets") || !strings.Contains(why, targets[0].HostID) {
		t.Fatalf("reason does not name count and first target: %s", why)
	}
	// The known remote's risk target is scored: CRITICAL wins over HIGH.
	remote, err := PveRemoteRiskTarget(pinA)
	if err != nil {
		t.Fatal(err)
	}
	f.Next = criticalNodeRisk{fp: remote.HostKeyFingerprint}
	if r, _, err := f.MinimumRisk(req, targets); err != nil || r != canonical.RiskCritical {
		t.Fatalf("critical remote among unknown ones: %s %v", r, err)
	}
	if reads != 2 {
		t.Fatalf("registry read %d times over two calls, want 2", reads)
	}
}

// TestGuestProvisionFloorRemoteRules: without a remote source, or for a
// node target of no known remote, provisioning is HIGH; a source error
// fails the floor.
func TestGuestProvisionFloorRemoteRules(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	node := provNodeRiskTarget(t, "pve-lab", pin, "pve1")
	req := canonical.Request{ActionID: PveGuestProvisionAction}
	known := eachRemote(func(canonical.Target) (string, bool, error) { return pin, true, nil })
	if r, _, err := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: known}).MinimumRisk(req, []canonical.Target{node}); err != nil || r != canonical.RiskMedium {
		t.Fatalf("known remote: %s %v", r, err)
	}
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("no remote source: %s", r)
	}
	unknown := eachRemote(func(canonical.Target) (string, bool, error) { return "", false, nil })
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: unknown}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("unknown remote: %s", r)
	}
	// A source claiming a pin the node fingerprint was not made with.
	lying := eachRemote(func(canonical.Target) (string, bool, error) { return strings.Repeat("cd", 32), true, nil })
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}, Linked: noLinkedHosts, Remote: lying}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("mismatched pin: %s", r)
	}
	// A CRITICAL node stays CRITICAL when its remote is unknown or
	// mismatched: HIGH is only a floor, the known targets are still scored.
	critical := criticalNodeRisk{fp: node.HostKeyFingerprint}
	for name, src := range map[string]PveRemoteOf{"unknown": unknown, "mismatched": lying, "no source": nil} {
		if r, _, err := (GuestProvisionRiskFloor{Next: critical, Linked: noLinkedHosts, Remote: src}).MinimumRisk(req, []canonical.Target{node}); err != nil || r != canonical.RiskCritical {
			t.Fatalf("critical node, %s remote: %s %v", name, r, err)
		}
	}
	if r, _, err := (GuestProvisionRiskFloor{Next: critical, Remote: known}).MinimumRisk(req, []canonical.Target{node}); err != nil || r != canonical.RiskCritical {
		t.Fatalf("critical node, no linked-host source: %s %v", r, err)
	}
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}, Remote: known}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("no linked-host source: %s", r)
	}
	// A CRITICAL linked host is still scored when the remote is unknown or
	// no remote source is configured.
	linkedHost := canonical.Target{HostID: "host-crit", HostKeyFingerprint: strings.Repeat("ef", 32)}
	linked := func(canonical.Request, canonical.Target) ([]canonical.Target, error) {
		return []canonical.Target{linkedHost}, nil
	}
	critLinked := criticalNodeRisk{fp: linkedHost.HostKeyFingerprint}
	for name, src := range map[string]PveRemoteOf{"unknown": unknown, "mismatched": lying, "no source": nil} {
		if r, _, err := (GuestProvisionRiskFloor{Next: critLinked, Linked: linked, Remote: src}).MinimumRisk(req, []canonical.Target{node}); err != nil || r != canonical.RiskCritical {
			t.Fatalf("critical linked host, %s remote: %s %v", name, r, err)
		}
	}
	failing := eachRemote(func(canonical.Target) (string, bool, error) { return "", false, errors.New("boom") })
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

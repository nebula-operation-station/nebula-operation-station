// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// memSchedules is an in-memory ScheduleStore.
type memSchedules struct {
	*memLeases
}

func newMemSchedules() *memSchedules {
	return &memSchedules{memLeases: newMemLeases()}
}

func (m *memSchedules) SaveScheduleGrant(g StoredGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.ID] = g
	return nil
}

func (m *memSchedules) ScheduleGrant(id string) (StoredGrant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	return g, ok, nil
}

func (m *memSchedules) ScheduleGrants() ([]StoredGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredGrant
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}

func (m *memSchedules) RevokeScheduleGrant(id string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok || !g.RevokedAt.IsZero() {
		return false, nil
	}
	g.RevokedAt = at
	m.grants[id] = g
	return true, nil
}

func (m *memSchedules) ClaimScheduleRun(grantID, actionID, hostID string, now time.Time, minInterval time.Duration) (bool, error) {
	return m.ReserveReadRun(grantID, actionID, hostID, now, GlobalRunBudget, minInterval)
}

func (e *env) withSchedules(t *testing.T, mode Mode) *memSchedules {
	t.Helper()
	m := newMemSchedules()
	auth, err := New(Options{Mode: mode, Verifier: e.auth.verifier, Now: e.clk.Now, Store: e.auth.store, RiskPolicy: e.risk, Schedules: m,
		Audit: func(ev Event) { e.evtMu.Lock(); e.evts = append(e.evts, ev); e.evtMu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	e.auth = auth
	return m
}

func (e *env) grantDoc(id string) []byte {
	e.t.Helper()
	ph, _ := canonical.HashParameters(params)
	d := schedgrant.Doc{Grant: schedgrant.Format, ID: id,
		Actions:      []schedgrant.Action{{ActionID: "patching.install_security", ModuleVersion: "1.0.0", ArtifactSHA256: hexSum(artifact), ParametersHash: ph}},
		Targets:      []canonical.Target{{HostID: "dockerflux", HostKeyFingerprint: fpA}, {HostID: "strompi", HostKeyFingerprint: fpB}},
		MinIntervalS: 3600, ExpiryUnix: e.clk.Now().Add(30 * 24 * time.Hour).Unix()}
	b, err := json.Marshal(d)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

const grantID = "00000000-0000-4000-8000-0000000000aa"

func (e *env) approvedGrant() StoredGrant {
	e.t.Helper()
	pg, err := e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	if err != nil {
		e.t.Fatal(err)
	}
	g, err := e.auth.CommitScheduleGrant(pg.Digest, e.sign(pg.Challenge))
	if err != nil {
		e.t.Fatal(err)
	}
	return g
}

func TestScheduleGrantNeedsSessionLowAndAKey(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.withSchedules(t, ModeStandard)
	_, err := e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	wantCode(t, err, CodeSessionRequired)
	e.openSession()
	// The executor rates the action above LOW on one host: refused.
	e.risk.setHost("strompi", canonical.RiskMedium)
	_, err = e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	wantCode(t, err, CodeGrantInvalid)
	e.risk.setHost("strompi", canonical.RiskLow)

	pg, err := e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	if err != nil || pg.Requirement != RequireAssertionVerified || len(pg.Challenge) != 32 {
		t.Fatalf("%+v %v", pg, err)
	}
	// Without user verification it is refused, and the challenge is gone.
	e.dev.Options.UserNotVerified = true
	_, err = e.auth.CommitScheduleGrant(pg.Digest, e.sign(pg.Challenge))
	wantCode(t, err, CodeAssertionRejected)
	e.dev.Options.UserNotVerified = false
	_, err = e.auth.CommitScheduleGrant(pg.Digest, e.sign(pg.Challenge))
	wantCode(t, err, CodeNotFound)

	// A permit's challenge does not approve a grant.
	p := e.propose(e.request(canonical.RiskMedium))
	pg, _ = e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	_, err = e.auth.CommitScheduleGrant(pg.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeAssertionRejected)

	g := e.approvedGrant()
	if g.ID != grantID || g.ApprovedBy == "" || !g.ExpiresAt.After(e.clk.Now()) {
		t.Fatalf("%+v", g)
	}
	_, err = e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	wantCode(t, err, CodeGrantInvalid) // the ID is taken
}

func TestScheduledRunsStayInsideTheGrant(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.withSchedules(t, ModeStandard)
	e.openSession()
	e.approvedGrant()
	run := goodRun("dockerflux", fpA)
	gr, err := e.auth.AuthorizeScheduled(grantID, "00000000-0000-4000-8000-0000000000b1", run)
	if err != nil || gr.ExecutionID != "00000000-0000-4000-8000-0000000000b1" || string(gr.Parameters) != `{"packages":["openssl"]}` {
		t.Fatalf("%+v %v", gr, err)
	}
	// Once per interval per host.
	_, err = e.auth.AuthorizeScheduled(grantID, "x", run)
	wantCode(t, err, CodeTooSoon)
	if _, err := e.auth.AuthorizeScheduled(grantID, "x", goodRun("strompi", fpB)); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Hour)
	if _, err := e.auth.AuthorizeScheduled(grantID, "x", run); err != nil {
		t.Fatal(err)
	}

	bad := map[string]Run{}
	r := goodRun("web", fpA)
	bad["other host"] = r
	r = goodRun("dockerflux", fpB)
	bad["other key"] = r
	r = goodRun("dockerflux", fpA)
	r.Artifact = []byte("rm -rf /")
	bad["other artifact"] = r
	r = goodRun("dockerflux", fpA)
	r.ParametersJSON = []byte(`{"packages":["*"]}`)
	bad["other parameters"] = r
	r = goodRun("dockerflux", fpA)
	r.ActionID = "package.install_all"
	bad["other action"] = r
	r = goodRun("dockerflux", fpA)
	r.ModuleVersion = "2.0.0"
	bad["other version"] = r
	e.clk.Add(time.Hour)
	for name, r := range bad {
		if _, err := e.auth.AuthorizeScheduled(grantID, "x", r); err == nil {
			t.Errorf("%s authorized", name)
		}
	}
	// Trust withdrawn or criticality raised: the action is no longer LOW.
	e.risk.setHost("dockerflux", canonical.RiskMedium)
	_, err = e.auth.AuthorizeScheduled(grantID, "x", run)
	wantCode(t, err, CodeGrantInvalid)
	e.risk.setHost("dockerflux", canonical.RiskLow)

	// Unknown, revoked or expired grants run nothing.
	_, err = e.auth.AuthorizeScheduled("00000000-0000-4000-8000-0000000000ff", "x", run)
	wantCode(t, err, CodeNotFound)
	if err := e.auth.RevokeScheduleGrant(grantID, "test"); err != nil {
		t.Fatal(err)
	}
	_, err = e.auth.AuthorizeScheduled(grantID, "x", run)
	wantCode(t, err, CodeGrantInactive)
	wantCode(t, e.auth.RevokeScheduleGrant(grantID, "test"), CodeNotFound)
}

func TestScheduleGrantExpires(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.withSchedules(t, ModeStandard)
	e.openSession()
	e.approvedGrant()
	e.clk.Add(30*24*time.Hour + time.Second)
	_, err := e.auth.AuthorizeScheduled(grantID, "x", goodRun("dockerflux", fpA))
	wantCode(t, err, CodeGrantInactive)
}

func TestLegacyScheduleUsesReadGrantAuthorityWithoutExtendingScope(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.withSchedules(t, ModeStandard)
	e.openSession()
	var doc schedgrant.Doc
	if err := json.Unmarshal(e.grantDoc(grantID), &doc); err != nil {
		t.Fatal(err)
	}
	doc.ExpiryUnix = e.clk.Now().Add(90 * 24 * time.Hour).Unix()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.auth.ProposeScheduleGrant(raw)
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.auth.CommitScheduleGrant(p.Digest, e.sign(p.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	all, err := e.auth.ReadGrants()
	if err != nil || len(all) != 1 || string(all[0].Doc) != string(g.Doc) || all[0].Digest != g.Digest || !all[0].ExpiresAt.Equal(g.ExpiresAt) {
		t.Fatalf("legacy approval missing from shared registry: %+v, %v", all, err)
	}
	run := goodRun("dockerflux", fpA)
	_, err = e.auth.AuthorizeReadRun(g.ID, "on-demand", TriggerOnDemand, run)
	wantCode(t, err, CodeLeaseNotCovered)
	e.clk.Add(89 * 24 * time.Hour)
	if _, err := e.auth.AuthorizeReadRun(g.ID, "scheduled", TriggerScheduled, run); err != nil {
		t.Fatalf("legacy expiry shortened: %v", err)
	}
	_, err = e.auth.AuthorizeScheduled(g.ID, "again", run)
	wantCode(t, err, CodeTooSoon)
	if err := e.auth.RevokeReadGrant(g.ID, "test"); err != nil {
		t.Fatal(err)
	}
	_, err = e.auth.AuthorizeScheduled(g.ID, "revoked", run)
	wantCode(t, err, CodeGrantInactive)
}

func TestHardenedGrantsNeedTheCLIAndLockDropsPending(t *testing.T) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	e.withSchedules(t, ModeHardened)
	e.openSession()
	pg, err := e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	if err != nil || pg.Requirement != RequireCLI || pg.Challenge != nil {
		t.Fatalf("%+v %v", pg, err)
	}
	_, err = e.auth.CommitScheduleGrant(pg.Digest, nil)
	wantCode(t, err, CodeCLIRequired)
	if len(e.auth.PendingScheduleGrants()) != 1 {
		t.Fatal("pending grant missing")
	}
	e.auth.Lock("test")
	if len(e.auth.PendingScheduleGrants()) != 0 {
		t.Fatal("lock kept a pending grant")
	}
	e.openSession()
	pg, _ = e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	if _, err := e.auth.ApproveScheduleGrantCLI(pg.Digest, "root"); err != nil {
		t.Fatal(err)
	}
	// An approved grant survives a lock.
	e.auth.Lock("test")
	if _, err := e.auth.AuthorizeScheduled(grantID, "x", goodRun("dockerflux", fpA)); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulesDisabledWithoutAStore(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	_, err := e.auth.ProposeScheduleGrant(e.grantDoc(grantID))
	wantCode(t, err, CodeScheduleUnavailable)
	_, err = e.auth.AuthorizeScheduled(grantID, "x", goodRun("dockerflux", fpA))
	wantCode(t, err, CodeScheduleUnavailable)
}

// pairVerdict is the floor pairPolicy returns for one (action, host) pair.
type pairVerdict struct {
	risk canonical.Risk
	why  string
	err  bool
}

// pairPolicy is a RiskPolicy with a floor per (action, host) pair; pairs it
// does not know are LOW. lowEverywhere asks one target at a time.
type pairPolicy struct {
	mu    sync.Mutex
	pairs map[string]pairVerdict
}

func newPairPolicy() *pairPolicy { return &pairPolicy{pairs: map[string]pairVerdict{}} }

func (p *pairPolicy) set(action, host string, v pairVerdict) {
	p.mu.Lock()
	p.pairs[action+"|"+host] = v
	p.mu.Unlock()
}

func (p *pairPolicy) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	floor, why := canonical.RiskLow, r.ActionID+"@"+r.ModuleVersion+" is trusted as LOW"
	for _, t := range targets {
		v, ok := p.pairs[r.ActionID+"|"+t.HostID]
		if !ok {
			continue
		}
		if v.err {
			return "", "", errors.New("criticality store unavailable")
		}
		if v.risk.Rank() > floor.Rank() {
			floor, why = v.risk, v.why
		}
	}
	return floor, why, nil
}

// The reasons riskpolicy gives (internal/riskpolicy/riskpolicy.go).
var (
	vNoCrit = pairVerdict{risk: canonical.RiskMedium,
		why: "host h (SHA256:x) has no matching criticality record; read-only actions need MEDIUM there"}
	vCritical  = pairVerdict{risk: canonical.RiskMedium, why: "host h (SHA256:x) is CRITICAL; read-only actions need MEDIUM there"}
	vUntrusted = pairVerdict{risk: canonical.RiskHigh, why: "artifact is not trusted on the executor for this action and version"}
	vDeclared  = pairVerdict{risk: canonical.RiskMedium, why: "service.list@1.0.0 is trusted as MEDIUM"}
	vScanner   = pairVerdict{risk: canonical.RiskHigh, why: "safety scanner (v1): network"}
	vStoreDown = pairVerdict{err: true}
)

func refusalTargets(hosts ...string) []canonical.Target {
	out := make([]canonical.Target, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, canonical.Target{HostID: h, HostKeyFingerprint: fpA})
	}
	return out
}

func refusalActions(ids ...string) []schedgrant.Action {
	out := make([]schedgrant.Action, 0, len(ids))
	for _, id := range ids {
		out = append(out, schedgrant.Action{ActionID: id, ModuleVersion: "1.0.0", ArtifactSHA256: hexSum(artifact)})
	}
	return out
}

func refusalDetail(t *testing.T, err error) string {
	t.Helper()
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeGrantInvalid {
		t.Fatalf("want %s, got %v", CodeGrantInvalid, err)
	}
	return pe.Detail
}

// wantInOrder checks that every part occurs in s, each after the previous.
func wantInOrder(t *testing.T, s string, parts ...string) {
	t.Helper()
	at := 0
	for _, p := range parts {
		i := strings.Index(s[at:], p)
		if i < 0 {
			t.Fatalf("%q missing (or out of order) after offset %d in:\n%s", p, at, s)
		}
		at += i + len(p)
	}
}

func (e *env) countEvents(kind string, code Code) int {
	e.evtMu.Lock()
	defer e.evtMu.Unlock()
	n := 0
	for _, ev := range e.evts {
		if ev.Kind == kind && ev.Code == code {
			n++
		}
	}
	return n
}

func TestGrantRefusalListsEveryPairAtOnce(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := newPairPolicy()
	e.auth.risk = p
	p.set("core.facts", "dev-192.168.0.21", vNoCrit)
	p.set("core.facts", "dev-004", vCritical)
	p.set("service.list", "dev-001", vDeclared)
	p.set("service.list", "dev-004", vUntrusted)
	p.set("docker.list", "dev-001", vScanner)
	acts := refusalActions("core.facts", "service.list", "docker.list", "docker.update")
	targets := refusalTargets("dev-001", "dev-192.168.0.21", "dev-004")

	d := refusalDetail(t, e.auth.lowEverywhereAll(acts, targets))
	// Action order of the document, then target order; all six refusals.
	wantInOrder(t, d,
		"6 action/host pairs are not LOW",
		"core.facts@1.0.0 is MEDIUM on dev-192.168.0.21", "nebula host criticality dev-192.168.0.21 LEVEL",
		"core.facts@1.0.0 is MEDIUM on dev-004", "CRITICAL", "exclude the host",
		"service.list@1.0.0 is MEDIUM on dev-001", "trusted as MEDIUM",
		"service.list@1.0.0 is HIGH on dev-004", "nebula artifact trust",
		"docker.list@1.0.0 is HIGH on dev-001", "safety scanner",
		"docker.update@1.0.0 cannot be granted on any host",
	)
	if strings.Contains(d, " more") || strings.Contains(d, "SHA256:x") {
		t.Fatalf("unexpected text in %q", d)
	}
	// The same refusal twice reads the same (stable order).
	if d2 := refusalDetail(t, e.auth.lowEverywhereAll(acts, targets)); d2 != d {
		t.Fatalf("order not stable:\n%s\n%s", d, d2)
	}
	// One audit event per pair the risk policy refused (two calls).
	if n := e.countEvents("rejected", CodeGrantInvalid); n != 2*5 {
		t.Fatalf("want 10 rejected events, got %d", n)
	}
}

func TestGrantRefusalOneActionNamesEveryHost(t *testing.T) {
	// lowEverywhere (per action, as read leases call it) names all hosts.
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := newPairPolicy()
	e.auth.risk = p
	p.set("core.facts", "dev-003", vNoCrit)
	p.set("core.facts", "dev-001", vNoCrit)
	d := refusalDetail(t, e.auth.lowEverywhere("core.facts", "1.0.0", hexSum(artifact), refusalTargets("dev-001", "dev-002", "dev-003")))
	wantInOrder(t, d, "2 action/host pairs", "on dev-001", "on dev-003")
	if strings.Contains(d, "dev-002") {
		t.Fatalf("a LOW host is named: %s", d)
	}
}

func TestGrantRefusalProposalsNameEveryHost(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	e.risk.setHost("dockerflux", canonical.RiskMedium)
	e.risk.setHost("strompi", canonical.RiskHigh)
	_, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	wantInOrder(t, refusalDetail(t, err), "core.facts@1.0.0 is MEDIUM on dockerflux", "core.facts@1.0.0 is HIGH on strompi")

	e2 := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e2.withSchedules(t, ModeStandard)
	e2.openSession()
	e2.risk.set(canonical.RiskMedium)
	_, err = e2.auth.ProposeScheduleGrant(e2.grantDoc(grantID))
	wantInOrder(t, refusalDetail(t, err), "is MEDIUM on dockerflux", "is MEDIUM on strompi")
}

func TestGrantRefusalListIsBounded(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := newPairPolicy()
	e.auth.risk = p
	var hosts []string
	for i := range 70 {
		h := fmt.Sprintf("host-%03d", i)
		hosts = append(hosts, h)
		p.set("core.facts", h, vNoCrit)
	}
	d := refusalDetail(t, e.auth.lowEverywhereAll(refusalActions("core.facts", "service.list"), refusalTargets(hosts...)))
	if got := strings.Count(d, " is MEDIUM on "); got != maxListedRefusals {
		t.Fatalf("want %d listed pairs, got %d", maxListedRefusals, got)
	}
	wantInOrder(t, d, "70 action/host pairs", "on host-000", "on host-049", "… and 20 more")
	if strings.Contains(d, "host-050 ") || len(d) > maxRefusalDetailBytes {
		t.Fatalf("list not bounded (%d bytes): %s", len(d), d)
	}

	// Long host IDs: the byte bound wins over the pair bound.
	p2 := newPairPolicy()
	e.auth.risk = p2
	var long []string
	for i := range 50 {
		h := fmt.Sprintf("%03d-%s", i, strings.Repeat("x", 120))
		long = append(long, h)
		p2.set("core.facts", h, vNoCrit)
	}
	d = refusalDetail(t, e.auth.lowEverywhereAll(refusalActions("core.facts"), refusalTargets(long...)))
	if len(d) > maxRefusalDetailBytes || !strings.Contains(d, " more") {
		t.Fatalf("byte bound not applied (%d bytes)", len(d))
	}
}

func TestGrantRefusalTextIsSanitized(t *testing.T) {
	// Host IDs reach this check validated, but the text must stay one
	// bounded line of printable characters whatever it is given.
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := newPairPolicy()
	e.auth.risk = p
	evil := "a\n<script>\x1b[31m" + strings.Repeat("y", 400) + "\xff"
	p.set("core.facts", evil, vNoCrit)
	d := refusalDetail(t, e.auth.lowEverywhereAll(refusalActions("core.facts"), refusalTargets(evil)))
	for _, r := range d {
		if r == '\n' || r == '\x1b' || r == utf8.RuneError {
			t.Fatalf("unsafe rune %q in %q", r, d)
		}
	}
	if !utf8.ValidString(d) || strings.Contains(d, strings.Repeat("y", maxRefusalField)) {
		t.Fatalf("field not bounded or not UTF-8: %q", d)
	}
}

// oldLowEverywhere is lowEverywhere before every refusal was listed: it
// stops at the first pair that is not LOW. TestGrantRefusalDecisionUnchanged
// compares the decisions.
func oldLowEverywhere(a *Authority, actionID, version, artifactSHA256 string, targets []canonical.Target) error {
	if canonical.IsBatchOnlyContainerAction(actionID) {
		return fail(CodeGrantInvalid, "%s runs only as an approved batch member and cannot be granted", actionID)
	}
	r := canonical.Request{ActionID: actionID, ModuleVersion: version, ArtifactSHA256: artifactSHA256}
	for _, t := range targets {
		floor, _, err := a.floor(r, []canonical.Target{t}, nil)
		if err != nil || floor.Rank() == 0 {
			return a.storageFailure("", fmt.Errorf("risk policy: %v (floor %q)", err, floor))
		}
		if floor != canonical.RiskLow {
			return fail(CodeGrantInvalid, "%s@%s is %s on %s, not LOW", actionID, version, floor, t.HostID)
		}
	}
	return nil
}

func TestGrantRefusalDecisionUnchanged(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	verdicts := []*pairVerdict{nil, &vNoCrit, &vUntrusted, &vStoreDown}
	hosts := []string{"dev-001", "dev-002", "dev-003"}
	targets := refusalTargets(hosts...)
	for _, actIDs := range [][]string{
		{"core.facts", "service.list"},
		{"core.facts", "docker.update"},
		{"docker.update", "core.facts"},
	} {
		acts := refusalActions(actIDs...)
		pairs := len(acts) * len(hosts)
		combos := 1
		for range pairs {
			combos *= len(verdicts)
		}
		for c := range combos {
			p := newPairPolicy()
			n := c
			for i := range pairs {
				if v := verdicts[n%len(verdicts)]; v != nil {
					p.set(acts[i/len(hosts)].ActionID, hosts[i%len(hosts)], *v)
				}
				n /= len(verdicts)
			}
			e.auth.risk = p
			var old error
			for _, a := range acts {
				if old = oldLowEverywhere(e.auth, a.ActionID, a.ModuleVersion, a.ArtifactSHA256, targets); old != nil {
					break
				}
			}
			got := e.auth.lowEverywhereAll(acts, targets)
			if (old == nil) != (got == nil) || CodeOf(old) != CodeOf(got) {
				t.Fatalf("%v combo %d: old %v, new %v", actIDs, c, old, got)
			}
			// Per action (the read-lease call) too.
			for _, a := range acts {
				o := oldLowEverywhere(e.auth, a.ActionID, a.ModuleVersion, a.ArtifactSHA256, targets)
				g := e.auth.lowEverywhere(a.ActionID, a.ModuleVersion, a.ArtifactSHA256, targets)
				if (o == nil) != (g == nil) || CodeOf(o) != CodeOf(g) {
					t.Fatalf("%v combo %d action %s: old %v, new %v", actIDs, c, a.ActionID, o, g)
				}
			}
		}
	}
}

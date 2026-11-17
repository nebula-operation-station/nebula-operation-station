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
	// Action order of the document, then target order; all six refusals,
	// each as exactly "pair is LEVEL on host".
	wantInOrder(t, d,
		"6 action/host pairs are not LOW",
		"core.facts@1.0.0 is MEDIUM on dev-192.168.0.21;",
		"core.facts@1.0.0 is MEDIUM on dev-004;",
		"service.list@1.0.0 is MEDIUM on dev-001;",
		"service.list@1.0.0 is HIGH on dev-004;",
		"docker.list@1.0.0 is HIGH on dev-001;",
		"docker.update@1.0.0 cannot be granted on any host",
		refusalHint,
	)
	if strings.Contains(d, " more") || strings.Contains(d, "not checked") {
		t.Fatalf("unexpected text in %q", d)
	}
	wantNoReasonClass(t, d)
	// The same refusal twice reads the same (stable order).
	if d2 := refusalDetail(t, e.auth.lowEverywhereAll(acts, targets)); d2 != d {
		t.Fatalf("order not stable:\n%s\n%s", d, d2)
	}
	// One audit event per pair the risk policy refused (two calls).
	if n := e.countEvents("rejected", CodeGrantInvalid); n != 2*5 {
		t.Fatalf("want 10 rejected events, got %d", n)
	}
}

// reasonClassMarkers are words of the risk policy's reasons (vNoCrit and
// the others above) that must not reach the reply.
var reasonClassMarkers = []string{"CRITICAL", "criticality", "trusted as", "not trusted",
	"scanner", "artifact trust", "network", "SHA256:x", "exclude", "record"}

func wantNoReasonClass(t *testing.T, d string) {
	t.Helper()
	for _, m := range reasonClassMarkers {
		if strings.Contains(d, m) {
			t.Fatalf("reply reveals the reason class (%q): %s", m, d)
		}
	}
}

func TestGrantRefusalReplyHidesReasonClass(t *testing.T) {
	// m0.md item 20, riskpolicy.MinimumRisk: the reason goes to the audit
	// log only. Pairs at the same level read the same whatever the reason.
	targets := refusalTargets("dev-001", "dev-002")
	for _, level := range [][]pairVerdict{{vNoCrit, vCritical, vDeclared}, {vUntrusted, vScanner}} {
		var first string
		for i, v := range level {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			p := newPairPolicy()
			e.auth.risk = p
			p.set("core.facts", "dev-002", v)
			d := refusalDetail(t, e.auth.lowEverywhereAll(refusalActions("core.facts"), targets))
			wantNoReasonClass(t, d)
			if i == 0 {
				first = d
			} else if d != first {
				t.Fatalf("reply depends on the reason (%q):\n%s\n%s", v.why, first, d)
			}
			// The audit log keeps the reason.
			evs := e.eventsOf("rejected", CodeGrantInvalid)
			if len(evs) != 1 || !strings.Contains(evs[0].Detail, v.why) || evs[0].Host != "dev-002" {
				t.Fatalf("audit event lacks the reason: %+v", evs)
			}
		}
	}
}

func (e *env) eventsOf(kind string, code Code) []Event {
	e.evtMu.Lock()
	defer e.evtMu.Unlock()
	var out []Event
	for _, ev := range e.evts {
		if ev.Kind == kind && ev.Code == code {
			out = append(out, ev)
		}
	}
	return out
}

func TestGrantRefusalEarlyStopSaysSoAndAudits(t *testing.T) {
	// A refusal, then the risk policy fails: the grant is refused (as the
	// pair-by-pair check refused at the first pair), the text names what
	// was found and says the rest was not checked, and the policy failure
	// is in the audit log.
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := newPairPolicy()
	e.auth.risk = p
	p.set("core.facts", "dev-001", vNoCrit)
	p.set("core.facts", "dev-002", vStoreDown)
	p.set("core.facts", "dev-003", vCritical)
	d := refusalDetail(t, e.auth.lowEverywhereAll(refusalActions("docker.update", "core.facts"), refusalTargets("dev-001", "dev-002", "dev-003")))
	wantInOrder(t, d, "2 action/host pairs are not LOW",
		"docker.update@1.0.0 cannot be granted on any host (it runs only as an approved batch member);",
		"core.facts@1.0.0 is MEDIUM on dev-001;",
		" the remaining pairs were not checked (risk policy unavailable)", refusalHint)
	if strings.Contains(d, "dev-003") || strings.Contains(d, "dev-002") || strings.Contains(d, "unavailable)"+refusalHint+";") {
		t.Fatalf("pairs after the failure are named: %s", d)
	}
	wantNoReasonClass(t, d)
	if evs := e.eventsOf("rejected", CodeGrantInvalid); len(evs) != 1 || evs[0].Host != "dev-001" {
		t.Fatalf("want one per-pair event for dev-001, got %+v", evs)
	}
	evs := e.eventsOf("rejected", CodeStorage)
	if len(evs) != 1 || evs[0].Host != "dev-002" || !strings.Contains(evs[0].Detail, "criticality store unavailable") ||
		!strings.Contains(evs[0].Detail, "remaining pairs not checked") {
		t.Fatalf("want the policy failure audited, got %+v", evs)
	}
}

func TestGrantRefusalEventCapCountsEmittedEvents(t *testing.T) {
	// Batch-only refusals write no event, so they do not use up the cap:
	// 50 per-pair events, then one summary for the rest. Also on the
	// early-stop path.
	for _, early := range []bool{false, true} {
		e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
		p := newPairPolicy()
		e.auth.risk = p
		var hosts []string
		for i := range 60 {
			h := fmt.Sprintf("host-%03d", i)
			hosts = append(hosts, h)
			p.set("core.facts", h, vNoCrit)
		}
		if early {
			hosts = append(hosts, "down")
			p.set("core.facts", "down", vStoreDown)
		}
		d := refusalDetail(t, e.auth.lowEverywhereAll(refusalActions("docker.update", "docker.rollback", "core.facts"), refusalTargets(hosts...)))
		wantInOrder(t, d, "62 action/host pairs", "… and 12 more")
		if early != strings.Contains(d, "not checked") {
			t.Fatalf("early=%v: %s", early, d)
		}
		evs := e.eventsOf("rejected", CodeGrantInvalid)
		if len(evs) != maxRefusalEvents+1 {
			t.Fatalf("early=%v: want %d events, got %d", early, maxRefusalEvents+1, len(evs))
		}
		for i, ev := range evs[:maxRefusalEvents] {
			if want := fmt.Sprintf("host-%03d", i); ev.Host != want {
				t.Fatalf("event %d for %q, want %q", i, ev.Host, want)
			}
		}
		if last := evs[maxRefusalEvents]; last.Host != "" || last.Detail != "10 more action/host pairs not LOW" {
			t.Fatalf("summary event %+v", last)
		}
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

	// Long action, version and host IDs (each over the field cap): the
	// byte bound wins over the pair bound.
	p2 := newPairPolicy()
	e.auth.risk = p2
	longAct := schedgrant.Action{ActionID: "a." + strings.Repeat("z", 200), ModuleVersion: strings.Repeat("9", 200), ArtifactSHA256: hexSum(artifact)}
	var long []string
	for i := range 50 {
		h := fmt.Sprintf("%03d-%s", i, strings.Repeat("x", 200))
		long = append(long, h)
		p2.set(longAct.ActionID, h, vNoCrit)
	}
	d = refusalDetail(t, e.auth.lowEverywhereAll([]schedgrant.Action{longAct}, refusalTargets(long...)))
	if len(d) > maxRefusalDetailBytes || !strings.Contains(d, " more") || !strings.HasSuffix(d, refusalHint) {
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

// expectedRefusal is the refusal text lowEverywhereAll should give for
// acts × hosts under p (no limits reached); ok is false when it should not
// refuse with CodeGrantInvalid.
func expectedRefusal(acts []schedgrant.Action, hosts []string, p *pairPolicy) (string, bool) {
	var entries []string
	unchecked := false
walk:
	for _, a := range acts {
		if canonical.IsBatchOnlyContainerAction(a.ActionID) {
			entries = append(entries, a.ActionID+"@1.0.0 cannot be granted on any host (it runs only as an approved batch member)")
			continue
		}
		for _, h := range hosts {
			v, set := p.pairs[a.ActionID+"|"+h]
			switch {
			case !set:
			case v.err:
				if len(entries) == 0 {
					return "", false
				}
				unchecked = true
				break walk
			default:
				entries = append(entries, a.ActionID+"@1.0.0 is "+string(v.risk)+" on "+h)
			}
		}
	}
	if len(entries) == 0 {
		return "", false
	}
	noun := "pairs are"
	if len(entries) == 1 {
		noun = "pair is"
	}
	s := fmt.Sprintf("%d action/host %s not LOW; only actions the executor trusts as LOW (read-only) can be granted: %s",
		len(entries), noun, strings.Join(entries, "; "))
	if unchecked {
		s += "; the remaining pairs were not checked (risk policy unavailable)"
	}
	return s + refusalHint, true
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
			// The whole text, from an independent walk over the combo.
			if want, ok := expectedRefusal(acts, hosts, p); ok {
				var pe *Error
				if !errors.As(got, &pe) || pe.Detail != want {
					t.Fatalf("%v combo %d:\nwant %q\ngot  %v", actIDs, c, want, got)
				}
				// The first pair listed is the one the old check refused.
				var po *Error
				if !errors.As(old, &po) {
					t.Fatalf("%v combo %d: old %v", actIDs, c, old)
				}
				first, _, _ := strings.Cut(strings.SplitN(want, ": ", 2)[1], ";")
				oldPair, _, _ := strings.Cut(po.Detail, ", not LOW")
				if !strings.HasPrefix(first, strings.Fields(oldPair)[0]) ||
					(strings.Contains(oldPair, " on ") && !strings.HasPrefix(first, oldPair)) {
					t.Fatalf("%v combo %d: old refused %q, new lists %q first", actIDs, c, po.Detail, first)
				}
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

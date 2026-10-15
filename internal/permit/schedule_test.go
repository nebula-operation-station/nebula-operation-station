// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// memSchedules is an in-memory ScheduleStore.
type memSchedules struct {
	mu     sync.Mutex
	grants map[string]StoredGrant
	last   map[string]time.Time
}

func newMemSchedules() *memSchedules {
	return &memSchedules{grants: map[string]StoredGrant{}, last: map[string]time.Time{}}
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
	m.mu.Lock()
	defer m.mu.Unlock()
	k := grantID + "|" + actionID + "|" + hostID
	if last, ok := m.last[k]; ok && now.Sub(last) < minInterval {
		return false, nil
	}
	m.last[k] = now
	return true, nil
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

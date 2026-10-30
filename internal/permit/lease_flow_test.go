// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// memLeases is an in-memory ReadGrantStore for tests. It keeps the per-target
// rolling-hour reservation list and the per-action last-reservation time,
// shared across grants, and advances a high-water clock so a wall-clock
// rollback never moves the budget window backward.
type memLeases struct {
	mu          sync.Mutex
	grants      map[string]StoredReadGrant
	hostRes     map[string][]time.Time // hostID -> reservation times
	actionLast  map[string]time.Time   // actionID|hostID -> last reservation
	highWater   time.Time
	recovering  bool
	failRead    bool
	failReserve bool
}

func newMemLeases() *memLeases {
	return &memLeases{
		grants:     map[string]StoredReadGrant{},
		hostRes:    map[string][]time.Time{},
		actionLast: map[string]time.Time{},
	}
}

func (m *memLeases) SaveReadGrant(g StoredReadGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.ID] = g
	return nil
}

func (m *memLeases) ReadGrant(id string) (StoredReadGrant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead {
		return StoredReadGrant{}, false, errors.New("disk full")
	}
	g, ok := m.grants[id]
	return g, ok, nil
}

func (m *memLeases) ReadGrants() ([]StoredReadGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead {
		return nil, errors.New("disk full")
	}
	var out []StoredReadGrant
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}

func (m *memLeases) RevokeReadGrant(id string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead {
		return false, errors.New("disk full")
	}
	g, ok := m.grants[id]
	if !ok || !g.RevokedAt.IsZero() {
		return false, nil
	}
	g.RevokedAt = at
	m.grants[id] = g
	return true, nil
}

func (m *memLeases) ReserveReadRun(grantID, actionID, hostID string, now time.Time, budget int, minInterval time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReserve {
		return false, errors.New("disk full")
	}
	// The budget window is anchored to the latest time seen, so a wall-clock
	// rollback never moves it backward or refills the budget.
	effective := now
	if m.highWater.After(effective) {
		effective = m.highWater
	}
	m.highWater = effective
	g, ok := m.grants[grantID]
	if !ok || !g.RevokedAt.IsZero() || !effective.Before(g.ExpiresAt) {
		return false, ErrReadGrantInactive
	}
	cutoff := effective.Add(-RollingHour)
	var kept []time.Time
	for _, ts := range m.hostRes[hostID] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= budget {
		m.hostRes[hostID] = kept
		return false, nil
	}
	key := actionID + "|" + hostID
	if last, ok := m.actionLast[key]; ok && effective.Add(-minInterval).Before(last) {
		m.hostRes[hostID] = kept
		return false, nil
	}
	kept = append(kept, effective)
	m.hostRes[hostID] = kept
	m.actionLast[key] = effective
	return true, nil
}

func (m *memLeases) setDoc(id string, doc []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.grants[id]
	g.Doc = doc
	m.grants[id] = g
}

func (m *memLeases) setDigest(id, digest string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.grants[id]
	g.Digest = digest
	m.grants[id] = g
}

func newLeaseEnv(t *testing.T, mode Mode) (*env, *memLeases) {
	t.Helper()
	e := newEnv(t, mode, virtualwebauthn.AuthenticatorOptions{})
	le := newMemLeases()
	e.auth.leases = le
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	return e, le
}

func readRun(host, fp string) Run {
	return Run{HostID: host, HostKeyFingerprint: fp, ActionID: "core.facts",
		ModuleVersion: "1.0.0", Artifact: artifact, ParametersJSON: params, CredentialRef: "nebula-default", CredentialVersion: fpA}
}

func readGrantDocWith(t *testing.T, id string, now time.Time, lifetime time.Duration, budget int64, actions []string) ReadGrantDoc {
	t.Helper()
	d := readGrantDocAt(t, now, lifetime)
	d.ID = id
	d.RunBudget = budget
	ph, err := canonical.HashParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	d.Actions = nil
	for _, a := range actions {
		d.Actions = append(d.Actions, ReadGrantAction{ActionID: a, ModuleVersion: "1.0.0",
			ArtifactSHA256: hexSum(artifact), ParametersHash: ph})
	}
	return d
}

func approveReadGrant(t *testing.T, e *env, raw []byte) StoredReadGrant {
	t.Helper()
	p, err := e.auth.ProposeReadGrant(raw)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	g, err := e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return g
}

// Standard mode: one user-verified assertion approves the grant; no
// privileged session is needed (ADR 0007).
func TestReadGrantApprovalFlow(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	// No session is opened on purpose.
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	if g.ID != rgID || g.ApprovedBy == "" {
		t.Fatalf("stored %+v", g)
	}
	stored, ok, err := le.ReadGrant(rgID)
	if err != nil || !ok || stored.Digest == "" {
		t.Fatalf("read back: %v %v %q", err, ok, stored.Digest)
	}
	// The challenge is single-use: a second commit is refused.
	_, err = e.auth.CommitReadGrant(g.Digest, e.sign([]byte("again")))
	wantCode(t, err, CodeNotFound)
	if got := e.auth.PendingReadGrants(); len(got) != 0 {
		t.Fatalf("pending after commit: %d", len(got))
	}
}

func TestReadGrantRejectsBadAssertion(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	p, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	if err != nil {
		t.Fatal(err)
	}
	// An assertion over the wrong challenge does not verify.
	_, err = e.auth.CommitReadGrant(p.Digest, e.sign([]byte("some other challenge")))
	wantCode(t, err, CodeAssertionRejected)
	// The challenge was consumed: the grant is gone, not left pending.
	if got := e.auth.PendingReadGrants(); len(got) != 0 {
		t.Fatalf("pending after a bad assertion: %d", len(got))
	}
}

// Hardened mode keeps executor-local CLI approval.
func TestReadGrantHardenedMode(t *testing.T) {
	e, le := newLeaseEnv(t, ModeHardened)
	p, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Requirement != RequireCLI || len(p.Challenge) != 0 {
		t.Fatalf("hardened proposal: %v challenge %d", p.Requirement, len(p.Challenge))
	}
	_, err = e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeCLIRequired)
	// The CLI path approves.
	g, err := e.auth.ApproveReadGrantCLI(p.Digest, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if g.ApprovedBy != "cli:admin" {
		t.Fatalf("approved by %q", g.ApprovedBy)
	}
	if _, ok, _ := le.ReadGrant(rgID); !ok {
		t.Fatal("grant not stored")
	}
}

// The approval window is five minutes; a pending grant that outlives it is
// discarded and its challenge is unusable.
func TestReadGrantChallengeWindow(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	p, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	if err != nil {
		t.Fatal(err)
	}
	e.clk.Add(ApprovalWindow + time.Minute)
	if got := e.auth.PendingReadGrants(); len(got) != 0 {
		t.Fatalf("pending after the window: %d", len(got))
	}
	_, err = e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge))
	wantCode(t, err, CodeNotFound)
}

// Proposal checks: no store, invalid document, duplicate ID, a floor above
// LOW, and a store error all refuse without holding a grant.
func TestReadGrantProposalChecks(t *testing.T) {
	t.Run("no store", func(t *testing.T) {
		e, _ := newLeaseEnv(t, ModeStandard)
		e.auth.leases = nil
		_, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
		wantCode(t, err, CodeLeaseUnavailable)
	})
	t.Run("invalid document", func(t *testing.T) {
		e, _ := newLeaseEnv(t, ModeStandard)
		d := readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)
		d.Grant = "read-schedule-v1"
		_, err := e.auth.ProposeReadGrant(readGrantRaw(t, d))
		wantCode(t, err, CodeLeaseInvalid)
	})
	t.Run("duplicate id", func(t *testing.T) {
		e, _ := newLeaseEnv(t, ModeStandard)
		approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
		_, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
		wantCode(t, err, CodeLeaseInvalid)
	})
	t.Run("floor above low", func(t *testing.T) {
		e, _ := newLeaseEnv(t, ModeStandard)
		e.risk.setHost("dockerflux", canonical.RiskHigh)
		_, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
		wantCode(t, err, CodeGrantInvalid)
	})
	t.Run("store error", func(t *testing.T) {
		e, le := newLeaseEnv(t, ModeStandard)
		le.failRead = true
		_, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
		wantCode(t, err, CodeStorage)
	})
}

// Revoke needs no approval and is final.
func TestReadGrantRevoke(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	if err := e.auth.RevokeReadGrant(g.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	stored, ok, err := le.ReadGrant(g.ID)
	if err != nil || !ok || stored.RevokedAt.IsZero() {
		t.Fatalf("after revoke: %v %v %v", err, ok, stored.RevokedAt)
	}
	// A second revoke and a revoke of an unknown grant are not found.
	if err := e.auth.RevokeReadGrant(g.ID, "admin"); err == nil {
		t.Fatal("second revoke succeeded")
	}
	wantCode(t, e.auth.RevokeReadGrant("00000000-0000-4000-8000-0000000000ff", "admin"), CodeNotFound)
}

// Every pre-run check, one per case: the run must match the frozen grant
// exactly and the executor must still trust it as LOW.
func TestAuthorizeReadRunChecks(t *testing.T) {
	base := func() (*env, *memLeases, StoredReadGrant) {
		e, le := newLeaseEnv(t, ModeStandard)
		g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
		return e, le, g
	}
	t.Run("happy path", func(t *testing.T) {
		e, _, g := base()
		gr, err := e.auth.AuthorizeReadRun(g.ID, "exec-1", TriggerOnDemand, readRun("dockerflux", fpA))
		if err != nil {
			t.Fatal(err)
		}
		if gr.ExecutionID != "exec-1" {
			t.Fatalf("grant %q", gr.ExecutionID)
		}
	})
	t.Run("unknown grant", func(t *testing.T) {
		e, _, _ := base()
		_, err := e.auth.AuthorizeReadRun("00000000-0000-4000-8000-0000000000ff", "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeNotFound)
	})
	t.Run("revoked", func(t *testing.T) {
		e, _, g := base()
		if err := e.auth.RevokeReadGrant(g.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeLeaseInactive)
	})
	t.Run("expired", func(t *testing.T) {
		e, le := newLeaseEnv(t, ModeStandard)
		// A grant that lives exactly one hour, the minimum lifetime.
		g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, e.clk.Now(), ReadGrantMinLifetime, DefaultRunBudget, []string{"core.facts"})))
		e.clk.Add(ReadGrantMinLifetime + time.Minute)
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeLeaseInactive)
		_ = le
	})
	t.Run("trigger not covered", func(t *testing.T) {
		e, _ := newLeaseEnv(t, ModeStandard)
		d := readGrantDocWith(t, rgID, e.clk.Now(), DefaultReadGrantLifetime, DefaultRunBudget, []string{"core.facts"})
		d.Trigger = TriggerScheduled
		g := approveReadGrant(t, e, readGrantRaw(t, d))
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeLeaseNotCovered)
	})
	t.Run("action not in grant", func(t *testing.T) {
		e, _, g := base()
		run := readRun("dockerflux", fpA)
		run.ActionID = "docker.list"
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, run)
		wantCode(t, err, CodeLeaseNotCovered)
	})
	t.Run("host not in grant", func(t *testing.T) {
		e, _, g := base()
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("netbird-vps", fpA))
		wantCode(t, err, CodeLeaseNotCovered)
	})
	t.Run("fingerprint mismatch", func(t *testing.T) {
		e, _, g := base()
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpB))
		wantCode(t, err, CodeLeaseNotCovered)
	})
	t.Run("wrong artifact", func(t *testing.T) {
		e, _, g := base()
		run := readRun("dockerflux", fpA)
		run.Artifact = []byte("#!/bin/sh\necho tampered\n")
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, run)
		wantCode(t, err, CodeArtifactMismatch)
	})
	t.Run("wrong parameters", func(t *testing.T) {
		e, _, g := base()
		run := readRun("dockerflux", fpA)
		run.ParametersJSON = []byte(`{"packages":["curl"]}`)
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, run)
		wantCode(t, err, CodeParametersMismatch)
	})
	t.Run("floor rose", func(t *testing.T) {
		e, _, g := base()
		e.risk.setHost("dockerflux", canonical.RiskHigh)
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeGrantInvalid)
	})
	t.Run("secrets", func(t *testing.T) {
		e, _, g := base()
		run := readRun("dockerflux", fpA)
		run.ParametersJSON = []byte(`{"nebula_secrets":{"token":"telegraf-influx"}}`)
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, run)
		wantCode(t, err, CodeLeaseNotCovered)
	})
	t.Run("bad trigger", func(t *testing.T) {
		e, _, g := base()
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", "whenever", readRun("dockerflux", fpA))
		wantCode(t, err, CodeLeaseInvalid)
	})
	t.Run("empty artifact", func(t *testing.T) {
		e, _, g := base()
		run := readRun("dockerflux", fpA)
		run.Artifact = nil
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, run)
		wantCode(t, err, CodeArtifactMismatch)
	})
	t.Run("store read error", func(t *testing.T) {
		e, le, g := base()
		le.failRead = true
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeStorage)
	})
	t.Run("stored doc corrupted", func(t *testing.T) {
		e, le, g := base()
		le.setDoc(g.ID, []byte("corrupted"))
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeStorage)
	})
	t.Run("stored digest mismatch", func(t *testing.T) {
		e, le, g := base()
		le.setDigest(g.ID, strings.Repeat("0", 64))
		_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
		wantCode(t, err, CodeStorage)
	})
}

// The per-target rolling-hour budget is enforced and, once spent, denies.
func TestReadGrantBudgetExhausted(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, e.clk.Now(), DefaultReadGrantLifetime, 2, []string{"core.facts", "docker.list"})))
	run := readRun("dockerflux", fpA)
	if _, err := e.auth.AuthorizeReadRun(g.ID, "e1", TriggerOnDemand, run); err != nil {
		t.Fatal(err)
	}
	// A different action of the same grant still counts against the target.
	run2 := readRun("dockerflux", fpA)
	run2.ActionID = "docker.list"
	if _, err := e.auth.AuthorizeReadRun(g.ID, "e2", TriggerOnDemand, run2); err != nil {
		t.Fatal(err)
	}
	_, err := e.auth.AuthorizeReadRun(g.ID, "e3", TriggerOnDemand, run)
	wantCode(t, err, CodeLeaseBudget)
}

// Overlapping grants share the per-target ceiling: they cannot multiply it.
func TestReadGrantOverlappingGrantsShareCeiling(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	now := e.clk.Now()
	ga := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, now, DefaultReadGrantLifetime, 2, []string{"core.facts", "docker.list"})))
	gb := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID2, now, DefaultReadGrantLifetime, 2, []string{"docker.list"})))
	runA := readRun("dockerflux", fpA) // core.facts
	runA2 := readRun("dockerflux", fpA)
	runA2.ActionID = "docker.list"
	runB := readRun("dockerflux", fpA)
	runB.ActionID = "docker.list"
	// Fill grant A's per-target budget with two different actions.
	if _, err := e.auth.AuthorizeReadRun(ga.ID, "e1", TriggerOnDemand, runA); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.AuthorizeReadRun(ga.ID, "e2", TriggerOnDemand, runA2); err != nil {
		t.Fatal(err)
	}
	// The target has spent its shared ceiling; grant B cannot add more.
	_, err := e.auth.AuthorizeReadRun(gb.ID, "e3", TriggerOnDemand, runB)
	wantCode(t, err, CodeLeaseBudget)
}

// The 15-minute per-action floor is shared across grants and actions.
func TestReadGrantActionFloor(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	now := e.clk.Now()
	ga := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, now, DefaultReadGrantLifetime, 24, []string{"core.facts"})))
	run := readRun("dockerflux", fpA)
	if _, err := e.auth.AuthorizeReadRun(ga.ID, "e1", TriggerOnDemand, run); err != nil {
		t.Fatal(err)
	}
	// The same action on the same host again, 14 minutes later: too soon.
	e.clk.Add(14 * time.Minute)
	_, err := e.auth.AuthorizeReadRun(ga.ID, "e2", TriggerOnDemand, run)
	wantCode(t, err, CodeLeaseBudget)
	// One more minute clears the floor.
	e.clk.Add(2 * time.Minute)
	if _, err := e.auth.AuthorizeReadRun(ga.ID, "e3", TriggerOnDemand, run); err != nil {
		t.Fatalf("after the floor: %v", err)
	}
}

// A wall-clock rollback does not refill the budget: the window is anchored
// to the latest time seen.
func TestReadGrantClockRollbackDoesNotRefill(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	now := e.clk.Now()
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, now, DefaultReadGrantLifetime, 1, []string{"core.facts", "docker.list"})))
	runA := readRun("dockerflux", fpA)
	runB := readRun("dockerflux", fpA)
	runB.ActionID = "docker.list"
	// First run of each action.
	if _, err := e.auth.AuthorizeReadRun(g.ID, "e1", TriggerOnDemand, runA); err != nil {
		t.Fatal(err)
	}
	// Advance past the window so the target's budget legitimately refills.
	e.clk.Add(RollingHour + time.Minute)
	if _, err := e.auth.AuthorizeReadRun(g.ID, "e2", TriggerOnDemand, runB); err != nil {
		t.Fatal(err)
	}
	// Roll the clock back to before the first run. The budget must not refill.
	e.clk.Add(-(2*RollingHour + 2*time.Minute))
	_, err := e.auth.AuthorizeReadRun(g.ID, "e3", TriggerOnDemand, runA)
	wantCode(t, err, CodeLeaseBudget)
}

// A storage failure while reserving denies the run.
func TestReadGrantReserveStorageError(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	le.failReserve = true
	_, err := e.auth.AuthorizeReadRun(g.ID, "e", TriggerOnDemand, readRun("dockerflux", fpA))
	wantCode(t, err, CodeStorage)
}

type readGrantRiskHook struct {
	RiskPolicy
	before func()
}

func (p readGrantRiskHook) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	p.before()
	return p.RiskPolicy.MinimumRisk(r, targets)
}

func TestReadGrantExpiresBetweenLookupAndReservation(t *testing.T) {
	e, store := newLeaseEnv(t, ModeStandard)
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	// This check occurs after the active-grant lookup and immediately before
	// reservation. Advance to the exact expiry without sleeping or racing time.
	e.auth.risk = readGrantRiskHook{RiskPolicy: e.risk, before: func() { e.clk.Add(DefaultReadGrantLifetime) }}
	_, err := e.auth.AuthorizeReadRun(g.ID, "expired-before-claim", TriggerOnDemand, readRun("dockerflux", fpA))
	wantCode(t, err, CodeLeaseInactive)
	if len(store.hostRes["dockerflux"]) != 0 {
		t.Fatal("expired authorization spent budget")
	}
}

// Lock pauses grants: pending read grants are dropped, but stored grants and
// spent budgets survive a restart on the same persistent stores.
func TestReadGrantLockAndRestart(t *testing.T) {
	store, counters := newMemStore(), newMemCounters()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, counters)
	le := newMemLeases()
	e.auth.leases = le
	// A pending grant that the lock will drop.
	if _, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime))); err != nil {
		t.Fatal(err)
	}
	// A committed grant with budget 1, then spent.
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID2, e.clk.Now(), DefaultReadGrantLifetime, 1, []string{"core.facts"})))
	if _, err := e.auth.AuthorizeReadRun(g.ID, "e1", TriggerOnDemand, readRun("dockerflux", fpA)); err != nil {
		t.Fatal(err)
	}
	// Lock: the pending read grant is dropped.
	e.auth.Lock("test")
	if got := e.auth.PendingReadGrants(); len(got) != 0 {
		t.Fatalf("pending after lock: %d", len(got))
	}
	// Restart on the same stores: the stored grant and its spent budget are
	// preserved, so a further run is denied.
	e2 := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, counters)
	e2.auth.leases = le
	e2.clk.Add(16 * time.Minute) // clear the 15-minute per-action floor
	if _, err := e2.auth.AuthorizeReadRun(g.ID, "e2", TriggerOnDemand, readRun("dockerflux", fpA)); err == nil {
		t.Fatal("spent budget survived the restart but allowed a further run")
	} else {
		wantCode(t, err, CodeLeaseBudget)
	}
}

// Recovery state is durable authority state, independent of browser sessions.
func (m *memLeases) RecoveryPending() (time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead {
		return time.Time{}, false, errors.New("disk full")
	}
	return time.Time{}, m.recovering, nil
}

func TestReadGrantRecoveryRefusesEveryAuthorityEntryPoint(t *testing.T) {
	for _, operation := range []string{"propose", "commit", "cli", "run"} {
		for _, storageFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/store-error=%v", operation, storageFailure), func(t *testing.T) {
				e, store := newLeaseEnv(t, ModeStandard)
				raw := readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime))
				var p PendingReadGrant
				var g StoredReadGrant
				if operation == "run" {
					g = approveReadGrant(t, e, raw)
				} else if operation != "propose" {
					var err error
					p, err = e.auth.ProposeReadGrant(raw)
					if err != nil {
						t.Fatal(err)
					}
				}
				store.recovering, store.failRead = true, storageFailure
				var err error
				switch operation {
				case "propose":
					_, err = e.auth.ProposeReadGrant(raw)
				case "commit":
					_, err = e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge))
				case "cli":
					_, err = e.auth.ApproveReadGrantCLI(p.Digest, "admin")
				case "run":
					_, err = e.auth.AuthorizeReadRun(g.ID, "read", TriggerOnDemand, readRun("dockerflux", fpA))
				}
				if err == nil {
					t.Fatal("recovery allowed standing read authority")
				}
				if len(store.hostRes) != 0 {
					t.Fatal("recovery consumed a budget claim")
				}
			})
		}
	}
}

func TestReadGrantPendingScopeCannotBeMutatedByCaller(t *testing.T) {
	for _, listing := range []bool{false, true} {
		t.Run(fmt.Sprint(listing), func(t *testing.T) {
			e, _ := newLeaseEnv(t, ModeStandard)
			p, err := e.auth.ProposeReadGrant(readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
			if err != nil {
				t.Fatal(err)
			}
			copy := p
			if listing {
				copy = e.auth.PendingReadGrants()[0]
			}
			copy.Doc.Actions[0].ArtifactSHA256 = strings.Repeat("0", 64)
			copy.Doc.Targets[0].HostID = "replacement"
			copy.Doc.Credentials[0].CredentialRef = "replacement"
			pending := e.auth.PendingReadGrants()[0]
			if pending.Doc.Actions[0].ArtifactSHA256 != hexSum(artifact) || pending.Doc.Targets[0].HostID != "dockerflux" || pending.Doc.Credentials[0].CredentialRef != "nebula-default" {
				t.Fatal("caller mutated the executor's pending scope")
			}
			if _, err := e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge)); err != nil {
				t.Fatalf("caller mutated approval scope: %v", err)
			}
		})
	}
}

func TestReadGrantDispatchRechecksWithoutSpendingAgain(t *testing.T) {
	for _, change := range []string{"none", "revoke", "lock", "expiry", "risk", "recovery", "store error"} {
		t.Run(change, func(t *testing.T) {
			e, store := newLeaseEnv(t, ModeStandard)
			g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
			claim, err := e.auth.AuthorizeReadRun(g.ID, "dispatch", TriggerOnDemand, readRun("dockerflux", fpA))
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "revoke":
				if err := e.auth.RevokeReadGrant(g.ID, "admin"); err != nil {
					t.Fatal(err)
				}
			case "lock":
				e.auth.Lock("admin")
			case "expiry":
				e.clk.Add(DefaultReadGrantLifetime)
			case "risk":
				e.risk.setHost("dockerflux", canonical.RiskHigh)
			case "recovery":
				store.recovering = true
			case "store error":
				store.failRead = true
			}
			calls := 0
			err = e.auth.DispatchReadRun(claim, func() error { calls++; return nil })
			if change == "none" {
				if err != nil || calls != 1 {
					t.Fatalf("valid dispatch: %d, %v", calls, err)
				}
				if err := e.auth.DispatchReadRun(claim, func() error { calls++; return nil }); err == nil || calls != 1 {
					t.Fatal("claim dispatched twice")
				}
			} else if err == nil || calls != 0 {
				t.Fatalf("changed authority dispatched: %d, %v", calls, err)
			}
			if len(store.hostRes["dockerflux"]) != 1 {
				t.Fatal("final check changed the spent budget")
			}
		})
	}
}

func TestReadGrantDispatchSerializesRevocationAndLock(t *testing.T) {
	for _, operation := range []string{"revoke", "lock"} {
		t.Run(operation, func(t *testing.T) {
			e, _ := newLeaseEnv(t, ModeStandard)
			g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
			claim, err := e.auth.AuthorizeReadRun(g.ID, "dispatch", TriggerOnDemand, readRun("dockerflux", fpA))
			if err != nil {
				t.Fatal(err)
			}
			started, finish := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(finish) })
			defer release()
			dispatched := make(chan error, 1)
			go func() {
				dispatched <- e.auth.DispatchReadRun(claim, func() error { close(started); <-finish; return nil })
			}()
			<-started
			attempted, stopped := make(chan struct{}), make(chan error, 1)
			go func() {
				close(attempted)
				if operation == "revoke" {
					stopped <- e.auth.RevokeReadGrant(g.ID, "admin")
				} else {
					e.auth.Lock("admin")
					stopped <- nil
				}
			}()
			<-attempted
			select {
			case err := <-stopped:
				t.Fatalf("lifecycle completed inside dispatch: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			release()
			if err := <-dispatched; err != nil {
				t.Fatal(err)
			}
			if err := <-stopped; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadGrantExpiredObservationCannotBeUndoneByRollback(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), ReadGrantMinLifetime)))
	e.clk.Add(ReadGrantMinLifetime)
	if _, err := e.auth.AuthorizeReadRun(g.ID, "expired", TriggerOnDemand, readRun("dockerflux", fpA)); err == nil {
		t.Fatal("expired read authorized")
	}
	e.clk.Add(-ReadGrantMinLifetime)
	if _, err := e.auth.AuthorizeReadRun(g.ID, "rollback", TriggerOnDemand, readRun("dockerflux", fpA)); err == nil {
		t.Fatal("expired read resurrected on rollback")
	}
}

func (m *memLeases) ReadGrantClock(now time.Time) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead {
		return time.Time{}, errors.New("disk full")
	}
	if now.After(m.highWater) {
		m.highWater = now
	}
	return m.highWater, nil
}

func TestReadGrantRejectsCredentialSubstitutionAndRotation(t *testing.T) {
	for _, change := range []string{"reference", "version"} {
		t.Run(change, func(t *testing.T) {
			e, store := newLeaseEnv(t, ModeStandard)
			g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
			run := readRun("dockerflux", fpA)
			if change == "reference" {
				run.CredentialRef = "replacement"
			} else {
				run.CredentialVersion = fpB
			}
			if _, err := e.auth.AuthorizeReadRun(g.ID, "substitute", TriggerOnDemand, run); err == nil {
				t.Fatal("changed credential authorized")
			}
			if len(store.hostRes) != 0 {
				t.Fatal("credential rejection consumed budget")
			}
		})
	}
}

func TestReadGrantV1StoredScopeIsNotReinterpreted(t *testing.T) {
	e, store := newLeaseEnv(t, ModeStandard)
	d := readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)
	d.Grant, d.Trigger, d.RateProfile, d.Credentials = "read-grant-v1", TriggerScheduled, "", nil
	raw := readGrantRaw(t, d)
	if _, err := e.auth.ProposeReadGrant(raw); err == nil {
		t.Fatal("new approval accepted previous format")
	}
	doc, canon, digest, err := parseReadGrant(raw, e.clk.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	g := StoredReadGrant{ID: doc.ID, Doc: canon, Digest: digest, CreatedAt: e.clk.Now(), ExpiresAt: time.Unix(doc.ExpiryUnix, 0)}
	if err := store.SaveReadGrant(g); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.AuthorizeReadRun(g.ID, "on-demand", TriggerOnDemand, readRun("dockerflux", fpA)); err == nil {
		t.Fatal("previous scheduled scope widened")
	}
	if _, err := e.auth.AuthorizeReadRun(g.ID, "scheduled", TriggerScheduled, readRun("dockerflux", fpA)); err != nil {
		t.Fatalf("previous scope changed: %v", err)
	}
	got, _, _ := store.ReadGrant(g.ID)
	if string(got.Doc) != string(canon) || got.Digest != digest || !got.ExpiresAt.Equal(g.ExpiresAt) {
		t.Fatal("previous approval rewritten")
	}
}

func TestReadGrantCannotBeApprovedAfterItsAbsoluteExpiry(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	d := readGrantDocAt(t, e.clk.Now().Add(-ReadGrantMinLifetime+time.Minute), ReadGrantMinLifetime)
	p, err := e.auth.ProposeReadGrant(readGrantRaw(t, d))
	if err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Minute)
	if _, err := e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge)); err == nil {
		t.Fatal("expired grant approved inside challenge window")
	}
}

func TestReadGrantDispatchRejectsUnusableClaims(t *testing.T) {
	for _, change := range []string{"missing", "parameters", "execution id", "other authority", "nil callback", "guard predates lock"} {
		t.Run(change, func(t *testing.T) {
			e, _ := newLeaseEnv(t, ModeStandard)
			g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
			guard := e.auth.ReadDispatchGuard()
			if change == "guard predates lock" {
				e.auth.Lock("admin")
			}
			claim, err := e.auth.AuthorizeReadRun(g.ID, "original", TriggerOnDemand, readRun("dockerflux", fpA))
			if err != nil {
				t.Fatal(err)
			}
			called := false
			callback := func() error { called = true; return nil }
			switch change {
			case "missing":
				claim = Grant{}
			case "parameters":
				claim.Parameters = []byte(`{}`)
			case "execution id":
				claim.ExecutionID = "replacement"
			case "other authority":
				other, _ := newLeaseEnv(t, ModeStandard)
				guard = other.auth.ReadDispatchGuard()
			case "nil callback":
				callback = nil
			}
			if err := guard(claim, callback); err == nil || called {
				t.Fatalf("unusable claim dispatched: %v", err)
			}
		})
	}
}

func TestReadGrantLockPausesNewDispatchUntilExplicitResume(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	g := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, e.clk.Now(), DefaultReadGrantLifetime, 24, []string{"core.facts", "docker.list"})))
	e.auth.Lock("credential removed")
	claim, err := e.auth.AuthorizeReadRun(g.ID, "after-lock", TriggerOnDemand, readRun("dockerflux", fpA))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := e.auth.DispatchReadRun(claim, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("new read escaped a pause without local unlock")
	}
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	run := readRun("dockerflux", fpA)
	run.ActionID = "docker.list"
	claim, err = e.auth.AuthorizeReadRun(g.ID, "after-unlock", TriggerOnDemand, run)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.auth.DispatchReadRun(claim, func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("explicit resume failed: %v", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// E21 (ADR 0007): a compromised server holding a standing read lease can only
// request the exact frozen reads the admin approved, within durable budgets
// that overlapping grants, clock rollback and restart cannot inflate. These
// tests use the real permit authority, WebAuthn verifier and executor.db.

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
)

const (
	e21GrantA = "0e1d2c3b-4a59-4687-8a9b-0c1d2e3f4a5b"
	e21GrantB = "1f2e3d4c-5b6a-4798-9bac-1d2e3f4a5b6c"
	e21GrantC = "2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d"
)

// e21Clock is an injectable executor clock.
type e21Clock struct{ unix atomic.Int64 }

func newE21Clock() *e21Clock {
	c := &e21Clock{}
	c.unix.Store(time.Now().Unix())
	return c
}
func (c *e21Clock) now() time.Time      { return time.Unix(c.unix.Load(), 0) }
func (c *e21Clock) set(t time.Time)     { c.unix.Store(t.Unix()) }
func (c *e21Clock) add(d time.Duration) { c.unix.Add(int64(d / time.Second)) }

// e21LeaseAuthority is newLeaseAuthority with an injected clock and mode.
func e21LeaseAuthority(t *testing.T, h *harness, mode permit.Mode, now func() time.Time) *permit.Authority {
	t.Helper()
	risk, err := riskpolicy.New(h.db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{
		Mode: mode, Verifier: h.verifier, Store: h.db, RiskPolicy: risk,
		Schedules: h.db, Leases: h.db, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func e21TrustReadActions(t *testing.T, h *harness) {
	t.Helper()
	for _, action := range append(slicesClone(readGrantActions), "service.status") {
		if err := h.db.TrustArtifact(executordb.TrustedArtifact{
			SHA256: hexSum(readFactArtifact), ActionID: action, ModuleVersion: "1.0.0",
			Risk: canonical.RiskLow, TrustedBy: "acceptance",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// e21Doc returns the decoded grant document readFactGrantDoc builds, so tests
// can alter single fields before marshalling.
func e21Doc(t *testing.T, id string, now time.Time, budget int64) permit.ReadGrantDoc {
	t.Helper()
	var doc permit.ReadGrantDoc
	if err := json.Unmarshal(readFactGrantDoc(t, id, now, budget), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func e21Marshal(t *testing.T, doc permit.ReadGrantDoc) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func e21Approve(t *testing.T, h *harness, auth *permit.Authority, raw []byte) permit.StoredReadGrant {
	t.Helper()
	p, err := auth.ProposeReadGrant(raw)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	g, err := auth.CommitReadGrant(p.Digest, h.sign(p.Challenge))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return g
}

// TestE21CompromisedServerCannotWidenAnApprovedLease asks, as a compromised
// server would, for every variation of an approved read: another host, a
// replaced host key, an action or version outside the grant, a mutation,
// substituted artifact bytes, other parameters, a secret, another credential.
// Each is refused with its specific reason and spends no budget: the exact
// approved read still succeeds afterwards with a budget of one.
func TestE21CompromisedServerCannotWidenAnApprovedLease(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	e21TrustReadActions(t, h)
	auth := e21LeaseAuthority(t, h, permit.ModeStandard, time.Now)
	g := e21Approve(t, h, auth, readFactGrantDoc(t, e21GrantA, time.Now(), 1))

	mutated := []byte("#!/bin/sh\nset -eu\necho facts; rm -rf /\n")
	for _, tc := range []struct {
		name    string
		grant   string
		trigger string
		change  func(*permit.Run)
		want    permit.Code
	}{
		{"host outside the frozen snapshot", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.HostID = "newly-enrolled" }, permit.CodeLeaseNotCovered},
		{"replacement host key", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.HostKeyFingerprint = fpB }, permit.CodeLeaseNotCovered},
		{"allowlisted action not in this grant", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.ActionID = "service.status" }, permit.CodeLeaseNotCovered},
		{"mutation action", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.ActionID = "package.upgrade" }, permit.CodeLeaseNotCovered},
		{"other module version", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.ModuleVersion = "1.0.1" }, permit.CodeLeaseNotCovered},
		{"substituted artifact bytes", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.Artifact = mutated }, permit.CodeArtifactMismatch},
		{"empty artifact", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.Artifact = nil }, permit.CodeArtifactMismatch},
		{"oversize artifact", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.Artifact = bytes.Repeat([]byte("a"), permit.MaxArtifactSize+1) }, permit.CodeArtifactMismatch},
		{"other parameters", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.ParametersJSON = []byte(`{"scope":"/etc/shadow"}`) }, permit.CodeParametersMismatch},
		{"malformed parameters", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.ParametersJSON = []byte(`{"scope":`) }, permit.CodeParametersMismatch},
		{"vault secret reference", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.ParametersJSON = []byte(`{"nebula_secrets":{"token":"db-root"}}`) }, permit.CodeLeaseNotCovered},
		{"other credential", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.CredentialRef = "other-key" }, permit.CodeCredentialMismatch},
		{"rotated credential version", g.ID, permit.TriggerOnDemand, func(r *permit.Run) { r.CredentialVersion = fpB }, permit.CodeCredentialMismatch},
		{"invented trigger", g.ID, permit.TriggerBoth, func(*permit.Run) {}, permit.CodeLeaseInvalid},
		{"unknown grant", e21GrantB, permit.TriggerOnDemand, func(*permit.Run) {}, permit.CodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := readFactRun("core.facts")
			tc.change(&r)
			_, err := auth.AuthorizeReadRun(tc.grant, "denied-"+tc.name, tc.trigger, r)
			if permit.CodeOf(err) != tc.want {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	// None of the refusals consumed the single-run budget or the action floor.
	if _, err := auth.AuthorizeReadRun(g.ID, "exact", permit.TriggerOnDemand, readFactRun("core.facts")); err != nil {
		t.Fatalf("exact approved read after refusals: %v", err)
	}
	if _, err := auth.AuthorizeReadRun(g.ID, "second", permit.TriggerOnDemand, readFactRun("docker.list")); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("second read beyond budget 1: %v", err)
	}
}

// TestE21ScheduledOnlyLeaseIsNotOnDemandAuthority checks the trigger binding:
// a schedule-only approval never becomes on-demand permission.
func TestE21ScheduledOnlyLeaseIsNotOnDemandAuthority(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	e21TrustReadActions(t, h)
	auth := e21LeaseAuthority(t, h, permit.ModeStandard, time.Now)
	doc := e21Doc(t, e21GrantA, time.Now(), 4)
	doc.Trigger = permit.TriggerScheduled
	g := e21Approve(t, h, auth, e21Marshal(t, doc))
	if _, err := auth.AuthorizeReadRun(g.ID, "od", permit.TriggerOnDemand, readFactRun("core.facts")); permit.CodeOf(err) != permit.CodeLeaseNotCovered {
		t.Fatalf("on-demand run under schedule-only grant: %v", err)
	}
	if _, err := auth.AuthorizeReadRun(g.ID, "sc", permit.TriggerScheduled, readFactRun("core.facts")); err != nil {
		t.Fatalf("scheduled run: %v", err)
	}
}

// TestE21LeaseProposalRejectsUnboundedOrMutatingScope refuses grant documents
// a compromised server could use to obtain more than bounded reads: excluded
// or mutating actions, longer lifetimes, larger budgets, shorter intervals,
// out-of-scope credentials and malformed, ambiguous or oversize documents.
func TestE21LeaseProposalRejectsUnboundedOrMutatingScope(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	e21TrustReadActions(t, h)
	for _, action := range []string{"package.refresh", "docker.logs", "package.upgrade"} {
		// Even when the executor rates them LOW, they are not read-only contracts.
		if err := h.db.TrustArtifact(executordb.TrustedArtifact{SHA256: hexSum(readFactArtifact), ActionID: action, ModuleVersion: "1.0.0", Risk: canonical.RiskLow, TrustedBy: "acceptance"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	auth := e21LeaseAuthority(t, h, permit.ModeStandard, time.Now)
	valid := e21Marshal(t, e21Doc(t, e21GrantA, now, 4))
	edit := func(f func(*permit.ReadGrantDoc)) []byte {
		d := e21Doc(t, e21GrantA, now, 4)
		f(&d)
		return e21Marshal(t, d)
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"package.refresh is excluded", edit(func(d *permit.ReadGrantDoc) { d.Actions[0].ActionID = "package.refresh" })},
		{"docker.logs is excluded", edit(func(d *permit.ReadGrantDoc) { d.Actions[0].ActionID = "docker.logs" })},
		{"mutation action", edit(func(d *permit.ReadGrantDoc) { d.Actions[0].ActionID = "package.upgrade" })},
		{"lifetime above 30 days", edit(func(d *permit.ReadGrantDoc) { d.ExpiryUnix = d.CreatedUnix + 31*24*3600 })},
		{"backdated past 30 days", edit(func(d *permit.ReadGrantDoc) {
			d.CreatedUnix = now.Add(-30 * 24 * time.Hour).Unix()
			d.ExpiryUnix = now.Add(2 * time.Hour).Unix()
		})},
		{"created in the future", edit(func(d *permit.ReadGrantDoc) { d.CreatedUnix = now.Add(time.Hour).Unix() })},
		{"budget above 240", edit(func(d *permit.ReadGrantDoc) { d.RunBudget = permit.MaxRunBudget + 1 })},
		{"zero budget", edit(func(d *permit.ReadGrantDoc) { d.RunBudget = 0 })},
		{"interval below 15 minutes", edit(func(d *permit.ReadGrantDoc) { d.MinIntervalS = 899 })},
		{"telemetry profile with ordinary actions", edit(func(d *permit.ReadGrantDoc) { d.RateProfile = "telemetry"; d.MinIntervalS = 10 })},
		{"credential outside frozen targets", edit(func(d *permit.ReadGrantDoc) { d.Credentials[0].HostID = "elsewhere" })},
		{"target without credential", edit(func(d *permit.ReadGrantDoc) {
			d.Targets = append(d.Targets, canonical.Target{HostID: "second", HostKeyFingerprint: fpB})
		})},
		{"duplicate target", edit(func(d *permit.ReadGrantDoc) { d.Targets = append(d.Targets, d.Targets[0]) })},
		{"too many actions", edit(func(d *permit.ReadGrantDoc) {
			for len(d.Actions) <= permit.MaxReadGrantActions {
				d.Actions = append(d.Actions, d.Actions[0])
			}
		})},
		{"legacy format for a new grant", edit(func(d *permit.ReadGrantDoc) { d.Grant = "read-grant-v1" })},
		{"unknown member", bytes.Replace(valid, []byte(`{`), []byte(`{"all_hosts":true,`), 1)},
		{"duplicate member", bytes.Replace(valid, []byte(`{`), []byte(`{"run_budget":240,`), 1)},
		{"invalid UTF-8", bytes.Replace(valid, []byte(`"acceptance"`), []byte("\"accept\xffance\""), 1)},
		{"oversize document", append(bytes.Repeat([]byte(" "), permit.MaxReadGrantDocSize), valid...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.raw, valid) {
				t.Fatal("test case did not change the document")
			}
			_, err := auth.ProposeReadGrant(tc.raw)
			if permit.CodeOf(err) != permit.CodeLeaseInvalid {
				t.Fatalf("want %q, got %v", permit.CodeLeaseInvalid, err)
			}
		})
	}
	if got := auth.PendingReadGrants(); len(got) != 0 {
		t.Fatalf("rejected proposals left %d pending grants", len(got))
	}
	// The baseline document is accepted, so each rejection is due to its change.
	if _, err := auth.ProposeReadGrant(valid); err != nil {
		t.Fatalf("baseline document: %v", err)
	}
}

// TestE21LeaseApprovalIsBoundAndSingleUse replays and substitutes approval
// assertions: an assertion for one grant cannot approve another, a consumed
// challenge cannot be reused, an expired challenge is gone, hardened mode
// refuses browser approval and recovery mode cannot create grants.
func TestE21LeaseApprovalIsBoundAndSingleUse(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	e21TrustReadActions(t, h)
	clock := newE21Clock()
	auth := e21LeaseAuthority(t, h, permit.ModeStandard, clock.now)
	now := clock.now()

	pa, err := auth.ProposeReadGrant(readFactGrantDoc(t, e21GrantA, now, 2))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := auth.ProposeReadGrant(readFactGrantDoc(t, e21GrantB, now, 240))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pa.Challenge, pb.Challenge) || pa.Digest == pb.Digest {
		t.Fatal("distinct grants share a challenge or digest")
	}
	// Substitution: the admin approved A; the server submits it for B.
	assertionA := h.sign(pa.Challenge)
	if _, err := auth.CommitReadGrant(pb.Digest, assertionA); permit.CodeOf(err) != permit.CodeAssertionRejected {
		t.Fatalf("A's assertion approving B: %v", err)
	}
	// The failed attempt consumed B's challenge.
	if _, err := auth.CommitReadGrant(pb.Digest, h.sign(pb.Challenge)); permit.CodeOf(err) != permit.CodeNotFound {
		t.Fatalf("B after failed attempt: %v", err)
	}
	if _, err := auth.CommitReadGrant(pa.Digest, assertionA); err != nil {
		t.Fatalf("A with its own assertion: %v", err)
	}
	// Replay of A's assertion and digest.
	if _, err := auth.CommitReadGrant(pa.Digest, assertionA); permit.CodeOf(err) != permit.CodeNotFound {
		t.Fatalf("replayed commit: %v", err)
	}
	// Re-proposing the stored grant ID (e.g. with a bigger budget) is refused.
	if _, err := auth.ProposeReadGrant(readFactGrantDoc(t, e21GrantA, now, 240)); permit.CodeOf(err) != permit.CodeLeaseInvalid {
		t.Fatalf("re-proposed stored grant ID: %v", err)
	}
	// A captured assertion cannot approve a fresh proposal.
	pc, err := auth.ProposeReadGrant(readFactGrantDoc(t, e21GrantC, now, 240))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.CommitReadGrant(pc.Digest, assertionA); permit.CodeOf(err) != permit.CodeAssertionRejected {
		t.Fatalf("replayed assertion on fresh proposal: %v", err)
	}
	// Five-minute challenge expiry.
	pb2, err := auth.ProposeReadGrant(readFactGrantDoc(t, e21GrantB, now, 2))
	if err != nil {
		t.Fatal(err)
	}
	late := h.sign(pb2.Challenge)
	clock.add(permit.ApprovalWindow + time.Second)
	if _, err := auth.CommitReadGrant(pb2.Digest, late); permit.CodeOf(err) != permit.CodeNotFound {
		t.Fatalf("expired challenge: %v", err)
	}
	stored, err := auth.ReadGrants()
	if err != nil || len(stored) != 1 || stored[0].ID != e21GrantA {
		t.Fatalf("stored grants: %+v, %v", stored, err)
	}

	// Hardened mode: no browser approval at all.
	hard := e21LeaseAuthority(t, h, permit.ModeHardened, time.Now)
	ph, err := hard.ProposeReadGrant(readFactGrantDoc(t, e21GrantC, time.Now(), 2))
	if err != nil {
		t.Fatal(err)
	}
	if len(ph.Challenge) != 0 || ph.Requirement != permit.RequireCLI {
		t.Fatalf("hardened proposal offers a browser challenge: %+v", ph.Requirement)
	}
	if _, err := hard.CommitReadGrant(ph.Digest, assertionA); permit.CodeOf(err) != permit.CodeCLIRequired {
		t.Fatalf("hardened browser commit: %v", err)
	}

	// Recovery mode cannot create grants and pauses existing ones.
	if err := h.db.SetRecoveryPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ProposeReadGrant(readFactGrantDoc(t, e21GrantB, clock.now(), 2)); err == nil {
		t.Fatal("recovery mode accepted a read grant proposal")
	}
	if _, err := auth.AuthorizeReadRun(e21GrantA, "rec", permit.TriggerOnDemand, readFactRun("core.facts")); err == nil {
		t.Fatal("recovery mode authorized a read")
	}
}

// TestE21OverlappingLeasesAndClockRollbackCannotInflateBudgets: two grants on
// the same host share the per-target rolling-hour count and the per-action
// floor, a wall-clock rollback cannot replenish them, and a restart keeps them.
func TestE21OverlappingLeasesAndClockRollbackCannotInflateBudgets(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	e21TrustReadActions(t, h)
	clock := newE21Clock()
	start := clock.now()
	auth := e21LeaseAuthority(t, h, permit.ModeStandard, clock.now)
	ga := e21Approve(t, h, auth, readFactGrantDoc(t, e21GrantA, start, 2))
	gb := e21Approve(t, h, auth, readFactGrantDoc(t, e21GrantB, start, 2))

	if _, err := auth.AuthorizeReadRun(ga.ID, "a1", permit.TriggerOnDemand, readFactRun("core.facts")); err != nil {
		t.Fatal(err)
	}
	// The 15-minute per-action floor is shared: B cannot run core.facts now.
	if _, err := auth.AuthorizeReadRun(gb.ID, "b1", permit.TriggerScheduled, readFactRun("core.facts")); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("overlapping grant bypassed the action floor: %v", err)
	}
	if _, err := auth.AuthorizeReadRun(gb.ID, "b2", permit.TriggerOnDemand, readFactRun("docker.list")); err != nil {
		t.Fatal(err)
	}
	// Two runs on the host this hour: neither grant (budget 2) may run more.
	for _, id := range []string{ga.ID, gb.ID} {
		if _, err := auth.AuthorizeReadRun(id, "x-"+id, permit.TriggerOnDemand, readFactRun("service.list")); permit.CodeOf(err) != permit.CodeLeaseBudget {
			t.Fatalf("grant %s exceeded the shared target budget: %v", id, err)
		}
	}
	// Rolling the wall clock back two hours does not empty the window.
	clock.set(start.Add(-2 * time.Hour))
	if _, err := auth.AuthorizeReadRun(ga.ID, "rollback", permit.TriggerOnDemand, readFactRun("service.list")); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("clock rollback replenished the budget: %v", err)
	}
	// Coming back to 59 minutes after the first run is still inside the window.
	clock.set(start.Add(59 * time.Minute))
	if _, err := auth.AuthorizeReadRun(ga.ID, "late", permit.TriggerOnDemand, readFactRun("service.list")); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("budget refilled inside the rolling hour: %v", err)
	}
	// A restart (same data directory) keeps the high-water clock and the spends:
	// a rolled-back clock after restart is no better.
	h.stop()
	h2 := newHarness(t, harnessOptions{mode: permit.ModeStandard, dataDir: h.dataDir, identity: h.id})
	clock.set(start.Add(-time.Hour))
	auth2 := e21LeaseAuthority(t, h2, permit.ModeStandard, clock.now)
	if _, err := auth2.AuthorizeReadRun(gb.ID, "restart", permit.TriggerOnDemand, readFactRun("service.list")); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("restart with rolled-back clock replenished the budget: %v", err)
	}
	// After the hour has really passed, the bounded allowance returns.
	clock.set(start.Add(61 * time.Minute))
	if _, err := auth2.AuthorizeReadRun(gb.ID, "next-hour", permit.TriggerOnDemand, readFactRun("service.list")); err != nil {
		t.Fatalf("read after the rolling hour: %v", err)
	}
	// Elapsed paused/rolled-back time still counts toward expiry: past the
	// grant's absolute expiry no clock rollback revives it.
	clock.set(start.Add(7*24*time.Hour + time.Minute))
	if _, err := auth2.AuthorizeReadRun(gb.ID, "expired", permit.TriggerOnDemand, readFactRun("core.facts")); permit.CodeOf(err) != permit.CodeLeaseInactive {
		t.Fatalf("read after expiry: %v", err)
	}
	clock.set(start.Add(2 * time.Hour))
	if _, err := auth2.AuthorizeReadRun(gb.ID, "revived", permit.TriggerOnDemand, readFactRun("core.facts")); permit.CodeOf(err) != permit.CodeLeaseInactive {
		t.Fatalf("clock rollback revived an expired grant: %v", err)
	}
}

// TestE21TrustWithdrawalAndRiskFloorBlockLease: an approved lease does not
// survive a change of the executor's verdict. Withdrawing trust or recording the
// host as CRITICAL (where reads need MEDIUM) blocks further reads; a host
// raised only to HIGH keeps LOW reads by design (riskpolicy). A replaced
// host key is covered by
// TestE21CompromisedServerCannotWidenAnApprovedLease). A privileged session is
// never needed for reads, so its absence is not what blocks them.
func TestE21TrustWithdrawalAndRiskFloorBlockLease(t *testing.T) {
	for _, change := range []string{"untrust", "risk-floor"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
			e21TrustReadActions(t, h)
			clock := newE21Clock()
			auth := e21LeaseAuthority(t, h, permit.ModeStandard, clock.now)
			g := e21Approve(t, h, auth, readFactGrantDoc(t, e21GrantA, clock.now(), 24))
			if _, err := auth.AuthorizeReadRun(g.ID, "before", permit.TriggerOnDemand, readFactRun("core.facts")); err != nil {
				t.Fatalf("read before %s (no privileged session): %v", change, err)
			}
			switch change {
			case "untrust":
				if ok, err := h.db.UntrustArtifact(hexSum(readFactArtifact), "docker.list", "1.0.0"); err != nil || !ok {
					t.Fatalf("untrust: %v, %v", ok, err)
				}
			case "risk-floor":
				if _, err := h.db.SetHostCriticality("dockerflux", fpA, canonical.RiskCritical, "acceptance"); err != nil {
					t.Fatal(err)
				}
			}
			_, err := auth.AuthorizeReadRun(g.ID, "after", permit.TriggerOnDemand, readFactRun("docker.list"))
			if err == nil {
				t.Fatalf("read authorized after %s", change)
			}
			if strings.Contains(err.Error(), passphrase) {
				t.Fatal("denial leaks a secret")
			}
		})
	}
}

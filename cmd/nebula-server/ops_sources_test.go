// SPDX-License-Identifier: AGPL-3.0-or-later

// Tests of the ops projection sources over the stored findings (ADR 0016 D3,
// D4): the finding source against a real vulnerability store in a temporary
// server.db (newVTEnv), and the mapping tables.

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// opsTestInventory returns the one host web01 (HIGH, no exposure set).
type opsTestInventory struct{}

func (opsTestInventory) Hosts(context.Context) ([]opsfacts.Host, error) {
	return []opsfacts.Host{{ID: "web01", Label: "web01", Environment: "prod", Criticality: opsfacts.CriticalityHigh}}, nil
}

// opsTestAudit collects the skips of one projection.
type opsTestAudit struct{ skips *[]opsfacts.Skip }

func (a opsTestAudit) Skipped(_ context.Context, s opsfacts.Skip) error {
	*a.skips = append(*a.skips, s)
	return nil
}

// fixedDecision is a "fix with" source that gives the same decision for
// every finding. The real resolver needs the update lists of the host.
type fixedDecision vulnfix.Result

func (d fixedDecision) Decide(context.Context, vulnstore.Finding) vulnfix.Result {
	return vulnfix.Result(d)
}

// fixesOf returns the factory of a fixedDecision with decision r.
func fixesOf(r vulnfix.Result) func() fixDecider {
	return func() fixDecider { return fixedDecision(r) }
}

// failingReader is a finding store whose read fails.
type failingReader struct{ err error }

func (r failingReader) List(context.Context, vulnstore.ListQuery) ([]vulnstore.Finding, bool, error) {
	return nil, false, r.err
}

// truncatedReader reports that more findings exist than one read returns.
type truncatedReader struct{}

func (truncatedReader) List(context.Context, vulnstore.ListQuery) ([]vulnstore.Finding, bool, error) {
	return nil, true, nil
}

// opsGroupsOf runs the projector over the finding source fs and returns its
// eligible groups and the skips it reported.
func opsGroupsOf(t *testing.T, fs opsfacts.FindingSource) ([]opsfacts.Group, []opsfacts.Skip, error) {
	t.Helper()
	var skips []opsfacts.Skip
	p, err := opsfacts.New(opsfacts.Sources{Inventory: opsTestInventory{}, Listeners: opsVulnListeners{},
		Findings: fs, Catalog: opsCatalog{}, Audit: opsTestAudit{skips: &skips}})
	if err != nil {
		t.Fatalf("opsfacts.New: %v", err)
	}
	gs, err := p.EligibleGroups(context.Background())
	return gs, skips, err
}

// opsCriticalRecord is a host record of a KEV-listed CVE with a critical CVSS
// score; its fixed version is newer than the installed one.
func opsCriticalRecord(cve string) map[string]any {
	r := vtRecord(cve, false)
	r["scores"] = map[string]any{
		"cvss": map[string]any{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"base_score": 9.8, "source": "nvd"},
		"kev": map[string]any{"date_added": "2026-11-01"},
	}
	return r
}

// TestOpsFindingsCriticalVerifiedFixOffersInstallSecurity: an open critical
// finding with a verified OS fix makes a group of the host with the
// package.install_security candidate.
func TestOpsFindingsCriticalVerifiedFixOffersInstallSecurity(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7001"))
	src, err := newOpsVulnFindings(env.svc.store, fixesOf(vulnfix.Result{Status: vulnfix.StatusVerified,
		Action: vulnfix.ActionInstallSecurity, HostID: "web01"}))
	if err != nil {
		t.Fatal(err)
	}
	gs, skips, err := opsGroupsOf(t, src)
	if err != nil {
		t.Fatalf("EligibleGroups: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("skips = %+v, want none", skips)
	}
	if len(gs) != 1 || gs[0].Key != "web01/os" {
		t.Fatalf("groups = %+v, want one group web01/os", gs)
	}
	var offered bool
	for _, c := range gs[0].Projection.Candidates {
		if c.Action == "package.install_security" && c.HostID == "web01" {
			offered = true
		}
	}
	if !offered {
		t.Fatalf("candidates = %+v, want package.install_security", gs[0].Projection.Candidates)
	}
	if got := gs[0].Projection.Findings[0].Fix; got != opsfacts.FixVerified {
		t.Fatalf("fix status = %q, want %q", got, opsfacts.FixVerified)
	}
}

// TestOpsFindingsAcceptedRiskLeavesGroupOut: a finding the admin accepted as
// a risk is read but never enters a group.
func TestOpsFindingsAcceptedRiskLeavesGroupOut(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7002"))
	fs, _, err := env.svc.store.List(context.Background(), vulnstore.ListQuery{Limit: 10})
	if err != nil || len(fs) != 1 {
		t.Fatalf("List = %d findings, %v; want 1", len(fs), err)
	}
	if err := env.svc.store.SetAcceptedRisk(context.Background(), fs[0].Key,
		vulnstore.AcceptRisk{Approver: "admin", Reason: "tested in lab", BasisVersion: "3.0.15-1~deb12u1"}); err != nil {
		t.Fatalf("SetAcceptedRisk: %v", err)
	}
	src, err := newOpsVulnFindings(env.svc.store, fixesOf(vulnfix.Result{Status: vulnfix.StatusVerified,
		Action: vulnfix.ActionInstallSecurity, HostID: "web01"}))
	if err != nil {
		t.Fatal(err)
	}
	gs, _, err := opsGroupsOf(t, src)
	if err != nil {
		t.Fatalf("EligibleGroups: %v", err)
	}
	if len(gs) != 0 {
		t.Fatalf("groups = %+v, want none for an accepted risk", gs)
	}
}

// TestOpsFindingsReadErrorFailsProjection: a failed read of the store is an
// error of the projection, never an empty finding list.
func TestOpsFindingsReadErrorFailsProjection(t *testing.T) {
	errRead := errors.New("store unreadable")
	src, err := newOpsVulnFindings(failingReader{err: errRead}, fixesOf(vulnfix.Result{}))
	if err != nil {
		t.Fatal(err)
	}
	gs, _, err := opsGroupsOf(t, src)
	if !errors.Is(err, errRead) {
		t.Fatalf("EligibleGroups error = %v, want the read error", err)
	}
	if gs != nil {
		t.Fatalf("groups = %+v, want none on a read error", gs)
	}
}

// TestOpsFindingsEmptyStoreIsEmptyAndNoError: no stored findings give an empty
// list and no error, and so no group.
func TestOpsFindingsEmptyStoreIsEmptyAndNoError(t *testing.T) {
	env := newVTEnv(t)
	src, err := newOpsVulnFindings(env.svc.store, fixesOf(vulnfix.Result{}))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := src.Findings(context.Background())
	if err != nil || len(fs) != 0 {
		t.Fatalf("Findings = %d, %v; want none and no error", len(fs), err)
	}
	gs, _, err := opsGroupsOf(t, src)
	if err != nil || len(gs) != 0 {
		t.Fatalf("EligibleGroups = %d groups, %v; want none and no error", len(gs), err)
	}
}

// TestOpsFindingsTruncatedReadIsAnError: a store that holds more findings
// than one read returns fails the read; a partial list would hide findings.
func TestOpsFindingsTruncatedReadIsAnError(t *testing.T) {
	src, err := newOpsVulnFindings(truncatedReader{}, fixesOf(vulnfix.Result{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Findings(context.Background()); !errors.Is(err, errOpsFindingsTruncated) {
		t.Fatalf("Findings error = %v, want errOpsFindingsTruncated", err)
	}
}

// TestNewOpsVulnFindingsRejectsNilSources: a missing store or decision source
// is refused, so the projection cannot run on a partial set.
func TestNewOpsVulnFindingsRejectsNilSources(t *testing.T) {
	if _, err := newOpsVulnFindings(nil, fixesOf(vulnfix.Result{})); !errors.Is(err, opsfacts.ErrNoSource) {
		t.Fatalf("nil store: error = %v, want ErrNoSource", err)
	}
	if _, err := newOpsVulnFindings(failingReader{}, nil); !errors.Is(err, opsfacts.ErrNoSource) {
		t.Fatalf("nil decision factory: error = %v, want ErrNoSource", err)
	}
}

// TestOpsFindingsBuildsFixDeciderPerCall: every Findings call builds its own
// fix decider, so no resolver (with its cached lists) outlives one read.
func TestOpsFindingsBuildsFixDeciderPerCall(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7004"))
	var built int
	src, err := newOpsVulnFindings(env.svc.store, func() fixDecider {
		built++
		return fixedDecision{Status: vulnfix.StatusVerified, Action: vulnfix.ActionInstallSecurity, HostID: "web01"}
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := src.Findings(context.Background()); err != nil {
			t.Fatalf("Findings %d: %v", i, err)
		}
	}
	if built != 2 {
		t.Fatalf("fix deciders built = %d for 2 reads, want 2", built)
	}
}

// TestOpsFindingsNilFixDeciderFailsRead: a factory that gives no decider fails
// the read closed; it never yields findings without a decision.
func TestOpsFindingsNilFixDeciderFailsRead(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7005"))
	src, err := newOpsVulnFindings(env.svc.store, func() fixDecider { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Findings(context.Background()); !errors.Is(err, opsfacts.ErrNoSource) {
		t.Fatalf("Findings error = %v, want ErrNoSource", err)
	}
}

// TestOpsFixMappingUnknownValuesMapToUnknown: a status or action outside the
// table becomes the unknown outcome and the no-link value, never an error.
func TestOpsFixMappingUnknownValuesMapToUnknown(t *testing.T) {
	cases := []struct {
		name    string
		res     vulnfix.Result
		outcome opsfacts.FixOutcome
		link    opsfacts.FixLink
	}{
		{"verified with install security", vulnfix.Result{Status: vulnfix.StatusVerified, Action: vulnfix.ActionInstallSecurity}, opsfacts.OutcomeVerified, opsfacts.LinkInstallSecurity},
		{"not verified", vulnfix.Result{Status: vulnfix.StatusNotVerified, Action: vulnfix.ActionNone}, opsfacts.OutcomeNotVerified, opsfacts.LinkNone},
		{"advisory link", vulnfix.Result{Status: vulnfix.StatusDeviceNoPatch, Action: vulnfix.ActionCiscoAdvisory}, opsfacts.OutcomeDeviceNoPatch, opsfacts.LinkCiscoAdvisory},
		{"unknown status", vulnfix.Result{Status: vulnfix.Status(999), Action: vulnfix.ActionInstallAll}, opsfacts.OutcomeUnknown, opsfacts.LinkInstallAll},
		{"unknown action", vulnfix.Result{Status: vulnfix.StatusWontFix, Action: vulnfix.Action(999)}, opsfacts.OutcomeWontFix, opsfacts.LinkNone},
		{"reboot passes through", vulnfix.Result{Status: vulnfix.StatusVerified, Action: vulnfix.ActionInstallSecurity, Reboot: true}, opsfacts.OutcomeVerified, opsfacts.LinkInstallSecurity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := opsDecisionOf(c.res)
			if got.Outcome != c.outcome || got.Link != c.link || got.Reboot != c.res.Reboot {
				t.Fatalf("decision = %+v, want outcome %q link %q reboot %v", got, c.outcome, c.link, c.res.Reboot)
			}
		})
	}
}

// TestOpsFindingOfMapsStateTierAndKEV: the tier and KEV come from the episode
// (as the open-findings count does), states and tiers outside the table map
// to the empty value that opsfacts rejects as a skip.
func TestOpsFindingOfMapsStateTierAndKEV(t *testing.T) {
	base := vulnstore.Finding{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "web01"},
		State: vulnstore.StateOpen, EpisodePeakTier: vulnstore.TierCritical}
	base.Record = vulnfinding.Record{Component: vulnfinding.Component{SourcePackage: "openssl", SourceVersion: "3.0.15-1"},
		Vuln: vulnfinding.Vuln{ID: "CVE-2026-7003"}, Fix: vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.16-1"}}
	got, err := opsFindingOf(base, vulnfix.Result{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != opsfacts.SubjectOS || got.HostID != "web01" || got.Tier != opsfacts.TierCritical ||
		got.State != opsfacts.StateOpen || got.Package != "openssl" || got.Installed != "3.0.15-1" ||
		got.Fixed != "3.0.16-1" || got.VulnID != "CVE-2026-7003" || got.KEV {
		t.Fatalf("finding = %+v", got)
	}

	kev := base
	kev.EpisodeKEVDate = "2026-11-01"
	if got, _ := opsFindingOf(kev, vulnfix.Result{}); !got.KEV {
		t.Fatal("episode KEV date set: KEV = false, want true")
	}

	unknownTier := base
	unknownTier.EpisodePeakTier = vulnstore.TierUnknown
	if got, _ := opsFindingOf(unknownTier, vulnfix.Result{}); got.Tier != "" {
		t.Fatalf("unknown tier mapped to %q, want the empty value", got.Tier)
	}

	accepted := base
	accepted.State = vulnstore.StateAcceptedRisk
	if got, _ := opsFindingOf(accepted, vulnfix.Result{}); got.State != opsfacts.StateAcceptedRisk {
		t.Fatalf("accepted risk mapped to %q", got.State)
	}

	image := base
	image.Subject = vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: "web01",
		ImageDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	got, _ = opsFindingOf(image, vulnfix.Result{})
	if got.Subject != opsfacts.SubjectImage || got.ImageSubject != "img-0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("image finding = %+v", got)
	}

	badDigest := image
	badDigest.Subject.ImageDigest = "sha256:XYZ"
	if got, _ := opsFindingOf(badDigest, vulnfix.Result{}); got.ImageSubject != "" {
		t.Fatalf("malformed digest gave image subject %q, want empty", got.ImageSubject)
	}
}

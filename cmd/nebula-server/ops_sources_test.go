// SPDX-License-Identifier: AGPL-3.0-or-later

// Tests of the ops projection sources over the stored findings (ADR 0016 D3,
// D4): the finding source against a real vulnerability store in a temporary
// server.db (newVTEnv), and the mapping tables.

package main

import (
	"context"
	"errors"
	"fmt"
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
func fixesOf(r vulnfix.Result) func(vulnfix.PreviewSource) fixDecider {
	return func(vulnfix.PreviewSource) fixDecider { return fixedDecision(r) }
}

// fakePreviews is a container preview source that reads every host as "no
// preview" (an empty preview) and fails with err when err is set. reads counts
// the calls, when reads is not nil.
type fakePreviews struct {
	err   error
	reads *int
}

func (p fakePreviews) Preview(_ context.Context, _ string) (vulnfix.Preview, error) {
	if p.reads != nil {
		*p.reads++
	}
	return vulnfix.Preview{}, p.err
}

// opsTestPreviews is a preview source that reads without error.
var opsTestPreviews = fakePreviews{}

// failingReader is a finding store whose read fails.
type failingReader struct{ err error }

func (r failingReader) List(context.Context, vulnstore.ListQuery) ([]vulnstore.Finding, bool, error) {
	return nil, false, r.err
}

// sliceReader is a finding store that holds fs and returns all of it.
type sliceReader struct{ fs []vulnstore.Finding }

func (r sliceReader) List(context.Context, vulnstore.ListQuery) ([]vulnstore.Finding, bool, error) {
	return r.fs, false, nil
}

// opsTestFinding returns a stored finding in state st on a subject of kind
// kind (the host web01, or its image with a valid platform digest).
func opsTestFinding(st vulnstore.State, kind vulnfinding.SubjectKind) vulnstore.Finding {
	f := vulnstore.Finding{Subject: vulnstore.Subject{Kind: kind, ID: "web01"}, State: st,
		EpisodePeakTier: vulnstore.TierCritical}
	if kind == vulnfinding.SubjectImage {
		f.Subject.ImageDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}
	f.Record = vulnfinding.Record{Component: vulnfinding.Component{SourcePackage: "openssl", SourceVersion: "3.0.15-1"},
		Vuln: vulnfinding.Vuln{ID: "CVE-2026-7008"}}
	return f
}

// truncatedReader reports that more findings exist than one read returns.
type truncatedReader struct{}

func (truncatedReader) List(context.Context, vulnstore.ListQuery) ([]vulnstore.Finding, bool, error) {
	return nil, true, nil
}

// opsTestListeners is a listener source that reports that the test host has
// no listening ports. It is a fixture: the real source (opsVulnListeners)
// cannot make that statement.
type opsTestListeners struct{}

func (opsTestListeners) Listeners(context.Context, string) ([]opsfacts.Port, error) {
	return nil, nil
}

// opsGroupsOf runs the projector over the finding source fs, with the test
// listeners, and returns its eligible groups and the skips it reported.
func opsGroupsOf(t *testing.T, fs opsfacts.FindingSource) ([]opsfacts.Group, []opsfacts.Skip, error) {
	t.Helper()
	return opsGroupsWith(t, fs, opsTestListeners{})
}

// opsGroupsWith is opsGroupsOf with the listener source ls.
func opsGroupsWith(t *testing.T, fs opsfacts.FindingSource, ls opsfacts.ListenerSource) ([]opsfacts.Group, []opsfacts.Skip, error) {
	t.Helper()
	var skips []opsfacts.Skip
	p, err := opsfacts.New(opsfacts.Sources{Inventory: opsTestInventory{}, Listeners: ls,
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
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, fixesOf(vulnfix.Result{Status: vulnfix.StatusVerified,
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

// TestOpsFindingsFixedHistoryPastLimitStillReadsOpen: a server.db whose fixed
// history alone is past the list limit (vulnstore.MaxListFindings) still gives
// the open findings; the read is not truncated by the closed rows.
func TestOpsFindingsFixedHistoryPastLimitStillReadsOpen(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7003"), opsCriticalRecord("CVE-2026-7004"))
	fs, _, err := env.svc.store.List(context.Background(), vulnstore.ListQuery{Limit: 10})
	if err != nil || len(fs) != 2 {
		t.Fatalf("List = %d findings, %v; want 2", len(fs), err)
	}
	// Copies of an open finding as fixed rows: fixed history past the limit.
	_, err = env.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
		INSERT INTO vuln_findings (finding_key, subject, subject_kind, record, assessment, nos_checked, state, closed_by,
			closed_note, closed_at, state_run_seq, rev, episode, episode_opened_at, episode_opened_run_seq,
			episode_peak_tier, first_seen_at, last_seen_at, updated_at)
		SELECT randomblob(32), subject, subject_kind, record, NULL, nos_checked, 'fixed', 'nos_inventory',
			'', updated_at, state_run_seq, rev, episode, episode_opened_at, episode_opened_run_seq,
			episode_peak_tier, first_seen_at, last_seen_at, updated_at
		FROM n, vuln_findings WHERE finding_key = ?`, vulnstore.MaxListFindings+1, fs[0].Key[:])
	if err != nil {
		t.Fatalf("insert fixed history: %v", err)
	}
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, fixesOf(vulnfix.Result{Status: vulnfix.StatusVerified,
		Action: vulnfix.ActionInstallSecurity, HostID: "web01"}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Findings(context.Background())
	if err != nil {
		t.Fatalf("Findings with %d fixed findings: %v; want the open findings", vulnstore.MaxListFindings+1, err)
	}
	if len(got) != 2 {
		t.Fatalf("Findings = %d, want the 2 open findings", len(got))
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
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, fixesOf(vulnfix.Result{Status: vulnfix.StatusVerified,
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
	src, err := newOpsVulnFindings(failingReader{err: errRead}, opsTestPreviews, fixesOf(vulnfix.Result{}))
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
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, fixesOf(vulnfix.Result{}))
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
	src, err := newOpsVulnFindings(truncatedReader{}, opsTestPreviews, fixesOf(vulnfix.Result{}))
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
	if _, err := newOpsVulnFindings(nil, opsTestPreviews, fixesOf(vulnfix.Result{})); !errors.Is(err, opsfacts.ErrNoSource) {
		t.Fatalf("nil store: error = %v, want ErrNoSource", err)
	}
	if _, err := newOpsVulnFindings(failingReader{}, nil, fixesOf(vulnfix.Result{})); !errors.Is(err, opsfacts.ErrNoSource) {
		t.Fatalf("nil preview source: error = %v, want ErrNoSource", err)
	}
	if _, err := newOpsVulnFindings(failingReader{}, opsTestPreviews, nil); !errors.Is(err, opsfacts.ErrNoSource) {
		t.Fatalf("nil decision factory: error = %v, want ErrNoSource", err)
	}
}

// TestOpsListenersUnavailableIsNeverAnEmptyList: the server stores no ports, so
// the listener source fails; it never returns an empty list, which would read
// as "verified no listening ports".
func TestOpsListenersUnavailableIsNeverAnEmptyList(t *testing.T) {
	ps, err := opsVulnListeners{}.Listeners(context.Background(), "web01")
	if !errors.Is(err, errOpsListenersUnavailable) {
		t.Fatalf("Listeners error = %v, want errOpsListenersUnavailable", err)
	}
	if ps != nil {
		t.Fatalf("Listeners ports = %+v, want none with the error", ps)
	}
}

// TestOpsListenersUnavailableFailsProjection: a host with a high finding needs
// its listeners, so the projection fails and reports no group for it.
func TestOpsListenersUnavailableFailsProjection(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7006"))
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, fixesOf(vulnfix.Result{Status: vulnfix.StatusVerified,
		Action: vulnfix.ActionInstallSecurity, HostID: "web01"}))
	if err != nil {
		t.Fatal(err)
	}
	gs, _, err := opsGroupsWith(t, src, opsVulnListeners{})
	if !errors.Is(err, errOpsListenersUnavailable) {
		t.Fatalf("EligibleGroups error = %v, want errOpsListenersUnavailable", err)
	}
	if gs != nil {
		t.Fatalf("groups = %+v, want none on a listener error", gs)
	}
}

// failingUpdates is a update-list source that cannot be read.
type failingUpdates struct{ err error }

func (u failingUpdates) Lists(context.Context) (map[string]vulnfix.Updates, error) {
	return nil, u.err
}

// TestOpsFindingsUnreadUpdateListsIsAnError: when the real resolver cannot read
// the update lists, the finding read fails with errOpsUpdateListsUnread and
// the projection gets no group; the failure never reaches it as an unknown
// fix decision.
func TestOpsFindingsUnreadUpdateListsIsAnError(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7007"))
	errLists := errors.New("lists store down")
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, func(p vulnfix.PreviewSource) fixDecider {
		return vulnfix.NewResolver(failingUpdates{err: errLists}, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Findings(context.Background()); !errors.Is(err, errOpsUpdateListsUnread) {
		t.Fatalf("Findings error = %v, want errOpsUpdateListsUnread", err)
	}
	gs, _, err := opsGroupsWith(t, src, opsTestListeners{})
	if !errors.Is(err, errOpsUpdateListsUnread) || gs != nil {
		t.Fatalf("EligibleGroups = %+v, %v; want none and errOpsUpdateListsUnread", gs, err)
	}
}

// TestOpsFindingsNoPreviewStaysUnknownDecision: a missing container preview is
// an unknown decision, not a failed read: the finding is still listed. The
// real resolver reads the preview as empty (no preview exists).
func TestOpsFindingsNoPreviewStaysUnknownDecision(t *testing.T) {
	f := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectImage)
	// Only a fixed image finding is decided from the preview (vulnfix.ImageResult).
	f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.16-1"}
	fs := []vulnstore.Finding{f}
	src, err := newOpsVulnFindings(sliceReader{fs: fs}, opsTestPreviews, func(p vulnfix.PreviewSource) fixDecider {
		return vulnfix.NewResolver(nil, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Findings(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("Findings = %d, %v; want one finding and no error", len(got), err)
	}
	if got[0].Fix.Outcome != opsfacts.OutcomeUnknown || got[0].Fix.Link != opsfacts.LinkContainers {
		t.Fatalf("decision = %+v, want unknown outcome with containers link", got[0].Fix)
	}
}

// TestOpsFindingsFailedPreviewReadIsAnError: a failed container preview read
// is an error of the read, not a missing preview. The resolver would give the
// same unknown decision for both, so the adapter must not let the failure
// through as "no preview exists".
func TestOpsFindingsFailedPreviewReadIsAnError(t *testing.T) {
	f := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectImage)
	f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.16-1"}
	fs := []vulnstore.Finding{f}
	errPreview := errors.New("preview store down")
	src, err := newOpsVulnFindings(sliceReader{fs: fs}, fakePreviews{err: errPreview}, func(p vulnfix.PreviewSource) fixDecider {
		return vulnfix.NewResolver(nil, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Findings(context.Background())
	if !errors.Is(err, errOpsPreviewUnreadable) || !errors.Is(err, errPreview) {
		t.Fatalf("Findings error = %v, want errOpsPreviewUnreadable wrapping the read error", err)
	}
	if got != nil {
		t.Fatalf("Findings = %+v, want none with the error", got)
	}
	gs, _, err := opsGroupsWith(t, src, opsTestListeners{})
	if !errors.Is(err, errOpsPreviewUnreadable) || gs != nil {
		t.Fatalf("EligibleGroups = %+v, %v; want none and errOpsPreviewUnreadable", gs, err)
	}
}

// imageFindingsOn returns n open image findings on n distinct hosts.
func imageFindingsOn(n int) []vulnstore.Finding {
	fs := make([]vulnstore.Finding, 0, n)
	for i := 0; i < n; i++ {
		f := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectImage)
		f.Subject.ID = fmt.Sprintf("img-host%02d", i)
		fs = append(fs, f)
	}
	return fs
}

// TestOpsFindingsImageHostsPastPreviewLimitAreAnError: the resolver reads the
// previews of at most vulnfix.MaxPreviewHosts hosts; further image hosts would
// read as "no preview", so the read fails instead.
func TestOpsFindingsImageHostsPastPreviewLimitAreAnError(t *testing.T) {
	over := imageFindingsOn(vulnfix.MaxPreviewHosts + 1)
	src, err := newOpsVulnFindings(sliceReader{fs: over}, opsTestPreviews, func(p vulnfix.PreviewSource) fixDecider {
		return vulnfix.NewResolver(nil, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Findings(context.Background()); !errors.Is(err, errOpsPreviewLimited) {
		t.Fatalf("Findings error = %v, want errOpsPreviewLimited", err)
	}
}

// TestOpsFindingsImageHostsAtPreviewLimitAreRead: exactly vulnfix.MaxPreviewHosts
// image hosts are all read; the limit is not an error below it.
func TestOpsFindingsImageHostsAtPreviewLimitAreRead(t *testing.T) {
	var reads int
	fs := imageFindingsOn(vulnfix.MaxPreviewHosts)
	src, err := newOpsVulnFindings(sliceReader{fs: fs}, fakePreviews{reads: &reads}, func(p vulnfix.PreviewSource) fixDecider {
		return vulnfix.NewResolver(nil, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Findings(context.Background())
	if err != nil || len(got) != vulnfix.MaxPreviewHosts {
		t.Fatalf("Findings = %d, %v; want %d findings and no error", len(got), err, vulnfix.MaxPreviewHosts)
	}
	if reads != vulnfix.MaxPreviewHosts {
		t.Fatalf("preview reads = %d, want %d", reads, vulnfix.MaxPreviewHosts)
	}
}

// TestOpsFindingsFixedFindingsDoNotCountTowardPreviewLimit: a fixed image
// finding is never decided, so its host needs no preview read.
func TestOpsFindingsFixedFindingsDoNotCountTowardPreviewLimit(t *testing.T) {
	fs := imageFindingsOn(vulnfix.MaxPreviewHosts + 1)
	fs[0].State = vulnstore.StateFixed
	src, err := newOpsVulnFindings(sliceReader{fs: fs}, opsTestPreviews, func(p vulnfix.PreviewSource) fixDecider {
		return vulnfix.NewResolver(nil, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Findings(context.Background())
	if err != nil || len(got) != vulnfix.MaxPreviewHosts {
		t.Fatalf("Findings = %d, %v; want %d findings and no error", len(got), err, vulnfix.MaxPreviewHosts)
	}
}

// TestOpsFindingsOneUnscoreableFindingFailsWholeRead: a stored finding whose
// scores do not compute fails the whole read; the good finding beside it is
// not listed, and no partial list is returned (fail closed).
func TestOpsFindingsOneUnscoreableFindingFailsWholeRead(t *testing.T) {
	good := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectHost)
	bad := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectHost)
	bad.Record.Vuln.ID = "CVE-2026-7009"
	bad.Record.Scores.CVSS = &vulnfinding.CVSS{Version: "3.1", BaseScore: 11, Source: vulnfinding.CVSSSourceNVD}
	src, err := newOpsVulnFindings(sliceReader{fs: []vulnstore.Finding{good, bad}}, opsTestPreviews, fixesOf(vulnfix.Result{}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Findings(context.Background())
	if err == nil {
		t.Fatalf("Findings = %+v, want an error for the unscoreable finding", got)
	}
	if got != nil {
		t.Fatalf("Findings = %+v, want no partial list with the error", got)
	}
	gs, _, err := opsGroupsOf(t, src)
	if err == nil || gs != nil {
		t.Fatalf("EligibleGroups = %+v, %v; want none and an error", gs, err)
	}
}

// TestOpsFindingOfUnscoreableIsAnError: a finding whose scores do not compute
// gives an error, never a zero score.
func TestOpsFindingOfUnscoreableIsAnError(t *testing.T) {
	f := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectHost)
	f.Record.Scores.CVSS = &vulnfinding.CVSS{Version: "3.1", BaseScore: -1, Source: vulnfinding.CVSSSourceNVD}
	if got, err := opsFindingOf(f, vulnfix.Result{}); err == nil {
		t.Fatalf("opsFindingOf = %+v, want an error", got)
	}
}

// TestOpsFindingOfDeviceAndUnknownSubjectsLeaveSubjectEmpty: a device or unknown
// subject gets the empty subject kind, which opsfacts records as a skip (no
// fix notes for devices, ADR 0016 D3); it is never mapped to the OS subject.
func TestOpsFindingOfDeviceAndUnknownSubjectsLeaveSubjectEmpty(t *testing.T) {
	cases := []struct {
		name string
		kind vulnfinding.SubjectKind
	}{
		{"device", vulnfinding.SubjectDevice},
		{"unknown", vulnfinding.SubjectKind("other")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := opsTestFinding(vulnstore.StateOpen, c.kind)
			got, err := opsFindingOf(f, vulnfix.Result{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Subject != "" || got.ImageSubject != "" {
				t.Fatalf("subject = %q, image subject = %q; want both empty", got.Subject, got.ImageSubject)
			}
		})
	}
}

// TestOpsFindingOfFixedIsTheDecisionVersion: Fixed is the fixed version the
// decision used, which is the higher of the record's and the episode's; a
// decision without a comparable fixed version leaves Fixed empty.
func TestOpsFindingOfFixedIsTheDecisionVersion(t *testing.T) {
	f := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectHost)
	f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.16-1"}
	f.EpisodeFixedVersion = "3.0.17-1"

	got, err := opsFindingOf(f, vulnfix.Result{Status: vulnfix.StatusVerified, Fixed: "3.0.17-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed != "3.0.17-1" {
		t.Fatalf("Fixed = %q, want the decision's 3.0.17-1 (not the record's 3.0.16-1)", got.Fixed)
	}

	got, err = opsFindingOf(f, vulnfix.Result{Status: vulnfix.StatusUnknown, Reason: vulnfix.ReasonFixedNotComparable})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed != "" {
		t.Fatalf("Fixed = %q, want empty when the decision had no fixed version", got.Fixed)
	}
}

// TestOpsFindingsBuildsFixDeciderPerCall: every Findings call builds its own
// fix decider, so no resolver (with its cached lists) outlives one read.
func TestOpsFindingsBuildsFixDeciderPerCall(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7004"))
	var built int
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, func(vulnfix.PreviewSource) fixDecider {
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
	src, err := newOpsVulnFindings(env.svc.store, opsTestPreviews, func(vulnfix.PreviewSource) fixDecider { return nil })
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
	got, err := opsFindingOf(base, vulnfix.Result{Fixed: "3.0.16-1"})
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

// TestOpsFindingOfKEVFromRecordScore: a record that carries a KEV score is KEV
// even when the episode never had a KEV date (the parity rule with
// countFindings); without either, KEV is false.
func TestOpsFindingOfKEVFromRecordScore(t *testing.T) {
	f := opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectHost)
	if got, _ := opsFindingOf(f, vulnfix.Result{}); got.KEV {
		t.Fatal("no KEV date and no KEV score: KEV = true, want false")
	}
	f.Record.Scores.KEV = &vulnfinding.KEV{DateAdded: "2026-11-01"}
	if got, _ := opsFindingOf(f, vulnfix.Result{}); !got.KEV {
		t.Fatal("record KEV score: KEV = false, want true")
	}
}

// TestOpsFindingsExcludesFixedFindings: a fixed finding is closed and never
// reaches the projection; open, accepted and false-positive findings do.
func TestOpsFindingsExcludesFixedFindings(t *testing.T) {
	fs := []vulnstore.Finding{
		opsTestFinding(vulnstore.StateFixed, vulnfinding.SubjectHost),
		opsTestFinding(vulnstore.StateOpen, vulnfinding.SubjectHost),
		opsTestFinding(vulnstore.StateAcceptedRisk, vulnfinding.SubjectHost),
		opsTestFinding(vulnstore.StateFalsePositive, vulnfinding.SubjectHost),
	}
	src, err := newOpsVulnFindings(sliceReader{fs: fs}, opsTestPreviews, fixesOf(vulnfix.Result{}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Findings(context.Background())
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	want := []opsfacts.FindingState{opsfacts.StateOpen, opsfacts.StateAcceptedRisk, opsfacts.StateFalsePositive}
	if len(got) != len(want) {
		t.Fatalf("Findings = %d, want %d (fixed excluded)", len(got), len(want))
	}
	for i, w := range want {
		if got[i].State != w {
			t.Fatalf("finding %d state = %q, want %q", i, got[i].State, w)
		}
	}
}

// TestOpsTierMappingTable: every stored tier maps to its projection tier; the
// unknown tier and any value outside the table give the empty value.
func TestOpsTierMappingTable(t *testing.T) {
	cases := []struct {
		name string
		in   vulnstore.Tier
		want opsfacts.Tier
	}{
		{"low", vulnstore.TierLow, opsfacts.TierLow},
		{"medium", vulnstore.TierMedium, opsfacts.TierMedium},
		{"high", vulnstore.TierHigh, opsfacts.TierHigh},
		{"critical", vulnstore.TierCritical, opsfacts.TierCritical},
		{"unknown", vulnstore.TierUnknown, ""},
		{"outside the table", vulnstore.Tier(99), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := opsTierOf(c.in); got != c.want {
				t.Fatalf("opsTierOf(%d) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestOpsStateMappingTable: the open and closed-by-decision states map to their
// projection states; fixed and any other value give the empty state.
func TestOpsStateMappingTable(t *testing.T) {
	cases := []struct {
		name string
		in   vulnstore.State
		want opsfacts.FindingState
	}{
		{"open", vulnstore.StateOpen, opsfacts.StateOpen},
		{"accepted risk", vulnstore.StateAcceptedRisk, opsfacts.StateAcceptedRisk},
		{"false positive", vulnstore.StateFalsePositive, opsfacts.StateFalsePositive},
		{"fixed never maps", vulnstore.StateFixed, ""},
		{"outside the table", vulnstore.State("other"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := opsStateOf(c.in); got != c.want {
				t.Fatalf("opsStateOf(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestOpsOutcomeMappingTable: every decision status maps to its fix outcome; a
// status outside the table is the unknown outcome.
func TestOpsOutcomeMappingTable(t *testing.T) {
	cases := []struct {
		name string
		in   vulnfix.Status
		want opsfacts.FixOutcome
	}{
		{"none", vulnfix.StatusNone, opsfacts.OutcomeNone},
		{"verified", vulnfix.StatusVerified, opsfacts.OutcomeVerified},
		{"not verified", vulnfix.StatusNotVerified, opsfacts.OutcomeNotVerified},
		{"below fixed", vulnfix.StatusBelowFixed, opsfacts.OutcomeBelowFixed},
		{"no candidate", vulnfix.StatusNoCandidate, opsfacts.OutcomeNoCandidate},
		{"no fix yet", vulnfix.StatusNoFixYet, opsfacts.OutcomeNoFixYet},
		{"wont fix", vulnfix.StatusWontFix, opsfacts.OutcomeWontFix},
		{"unknown", vulnfix.StatusUnknown, opsfacts.OutcomeUnknown},
		{"image candidate", vulnfix.StatusImageCandidate, opsfacts.OutcomeImageCandidate},
		{"image no candidate", vulnfix.StatusImageNoCandidate, opsfacts.OutcomeImageNoCandidate},
		{"device no patch", vulnfix.StatusDeviceNoPatch, opsfacts.OutcomeDeviceNoPatch},
		{"outside the table", vulnfix.Status(999), opsfacts.OutcomeUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := opsOutcomeOf(c.in); got != c.want {
				t.Fatalf("opsOutcomeOf(%d) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestOpsLinkMappingTable: every decision action maps to its link; no action
// and an action outside the table give the no-link value.
func TestOpsLinkMappingTable(t *testing.T) {
	cases := []struct {
		name string
		in   vulnfix.Action
		want opsfacts.FixLink
	}{
		{"none", vulnfix.ActionNone, opsfacts.LinkNone},
		{"install security", vulnfix.ActionInstallSecurity, opsfacts.LinkInstallSecurity},
		{"install all", vulnfix.ActionInstallAll, opsfacts.LinkInstallAll},
		{"list updates", vulnfix.ActionListUpdates, opsfacts.LinkListUpdates},
		{"containers", vulnfix.ActionContainers, opsfacts.LinkContainers},
		{"cisco advisory", vulnfix.ActionCiscoAdvisory, opsfacts.LinkCiscoAdvisory},
		{"pan advisory", vulnfix.ActionPANAdvisory, opsfacts.LinkPANAdvisory},
		{"outside the table", vulnfix.Action(999), opsfacts.LinkNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := opsLinkOf(c.in); got != c.want {
				t.Fatalf("opsLinkOf(%d) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// e2eDevice is a device part of a Cisco CBS export as NOS sends it.
func e2eDevice(id, model, firmware string) nosclient.SubjectPart {
	return nosclient.SubjectPart{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: id},
		Ecosystem: "vendor:cisco:cbs",
		Device:    &nosclient.Device{Vendor: "cisco", Model: model, FirmwareVersion: firmware},
		Complete:  true, Part: 1, LastPart: true}
}

// cbsFixtureAdvisory is a signed Cisco CSAF fixture: CBS350 firmware 3.4.0.17
// is affected and fixed in 3.4.1.3. Its text fields are hostile on purpose:
// the matcher must carry them as text, and an ID it cannot validate must
// never become a finding.
func cbsFixtureAdvisory(cve string) vulnfeed.CSAFAdvisory {
	return vulnfeed.CSAFAdvisory{
		TrackingID: "cisco-sa-cbs-e2e", Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			devProduct("c1", "vendor:cisco:cbs", "CBS350-24P-4G", "3.4.0.17", "3.4"),
			devProduct("c2", "vendor:cisco:cbs", "CBS350-24P-4G", "3.4.1.3", "3.4"),
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cve, Affected: []string{"c1"}, Fixed: []string{"c2"}}},
	}
}

// TestDeviceFindingsFromExportEndToEnd: export pages through the NOS client
// to the matcher. Affected firmware of the named model is a finding; fixed
// firmware is no record and no gap; an unknown model or an unknown firmware
// train is a coverage gap, never clean.
func TestDeviceFindingsFromExportEndToEnd(t *testing.T) {
	subs, err := SubjectsFromExport(exportThroughClient(t, []nosclient.SubjectPart{
		e2eDevice("sw-affected", "CBS350-24P-4G", "3.4.0.17"),
		e2eDevice("sw-fixed", "CBS350-24P-4G", "3.4.1.3"),
		e2eDevice("sw-other-model", "CBS250-24P", "3.4.0.17"),
		e2eDevice("sw-unknown-train", "CBS350-24P-4G", "9.9.9.9"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	db := newDB(t)
	if err := db.AddCSAF(FeedCiscoCSAF, cbsFixtureAdvisory("CVE-2024-20430")); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, subs...)

	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only the affected firmware): %+v", len(r.Findings), r.Findings)
	}
	f := r.Findings[0]
	if f.Record.SubjectRef.ID != "sw-affected" || f.Record.Vuln.ID != "CVE-2024-20430" || f.Record.MatchBasis != vulnfinding.MatchVendorAdvisory {
		t.Fatalf("finding = %+v", f.Record)
	}
	if f.Record.Fix.State != vulnfinding.FixFixed || f.Record.Fix.Version != "3.4.1.3" {
		t.Fatalf("fix = %+v, want the fixed train release", f.Record.Fix)
	}
	if !hasSubjectGap(r, "sw-other-model", GapDeviceModelUnknown) {
		t.Fatalf("other model is not a model gap: %+v", r.Gaps)
	}
	if !hasSubjectGap(r, "sw-unknown-train", GapDeviceVersionUnknown) {
		t.Fatalf("unknown firmware is not a version gap: %+v", r.Gaps)
	}
	if hasSubjectGap(r, "sw-fixed", GapDeviceVersionUnknown) || hasSubjectGap(r, "sw-fixed", GapDeviceModelUnknown) {
		t.Fatalf("fixed firmware is a positive hit, not a gap: %+v", r.Gaps)
	}
}

// TestHostileAdvisoryTextStaysText: a hostile CVE string in an advisory does
// not pass the ID pattern, so the record carries only the advisory's own
// tracking ID, never the hostile text, and the device's finding is still
// the unique model and firmware hit.
func TestHostileAdvisoryTextStaysText(t *testing.T) {
	subs, err := SubjectsFromExport(exportThroughClient(t, []nosclient.SubjectPart{
		e2eDevice("sw01", "CBS350-24P-4G", "3.4.0.17"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	db := newDB(t)
	hostile := "<img src=x onerror=alert(1)> CVE-2024-1"
	if err := db.AddCSAF(FeedCiscoCSAF, cbsFixtureAdvisory(hostile)); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, subs...)
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	rec := r.Findings[0].Record
	if rec.Vuln.ID != "cisco-sa-cbs-e2e" || len(rec.Vuln.Aliases) != 0 {
		t.Fatalf("hostile text reached the record: id=%q aliases=%v", rec.Vuln.ID, rec.Vuln.Aliases)
	}
	if rec.Assessment.Text != "" {
		t.Fatalf("matcher wrote assessment text: %q", rec.Assessment.Text)
	}
}

// hasSubjectGap reports a device-level gap of reason for the subject ref.
func hasSubjectGap(r Result, id string, reason GapReason) bool {
	for _, g := range r.Gaps {
		if g.Ref.ID == id && g.Reason == reason {
			return true
		}
	}
	return false
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"reflect"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// viewDate returns midnight UTC of the given day, for test fixtures.
func viewDate(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// TestSnapshotViewPositionCountsEveryEntryPerSource pins that a record's
// position is its index among all entries of its own source, including
// the Debian entries and OSV records that the view does not keep, and that
// two sources count separately.
func TestSnapshotViewPositionCountsEveryEntryPerSource(t *testing.T) {
	v := newSnapshotView(map[string]bool{"bookworm/openssl": true})

	// Source "deb": wanted and unwanted Debian entries, an OSV record, then NVD.
	v.addDebian("deb", vulnfeed.DebianEntry{Package: "openssl", IssueID: "CVE-2026-0001", Release: "bookworm",
		State: vulnfinding.TrackerFixed, FixedVersion: "3.0.1"})
	v.addDebian("deb", vulnfeed.DebianEntry{Package: "curl", IssueID: "CVE-2026-0002", Release: "bookworm",
		State: vulnfinding.TrackerUnfixed})
	v.addOSV("deb", vulnfeed.OSVRecord{ID: "OSV-2026-0001"})
	v.addNVD("deb", vulnfeed.NVDRecord{ID: "CVE-2026-0003"})

	// Source "osv" counts from 0 on its own.
	v.addOSV("osv", vulnfeed.OSVRecord{ID: "OSV-2026-0002"})
	v.addOSV("osv", vulnfeed.OSVRecord{ID: "OSV-2026-0003"})

	// Source "nvd" and a second NVD source "nvd-mirror", interleaved.
	v.addNVD("nvd", vulnfeed.NVDRecord{ID: "CVE-2026-0004"})
	v.addNVD("nvd-mirror", vulnfeed.NVDRecord{ID: "CVE-2026-0005"})
	v.addNVD("nvd", vulnfeed.NVDRecord{ID: "CVE-2026-0006"})

	tests := []struct {
		cve  string
		want agent.RecordRef
	}{
		{"CVE-2026-0003", agent.RecordRef{SourceID: "deb", Position: 3}},
		{"CVE-2026-0004", agent.RecordRef{SourceID: "nvd", Position: 0}},
		{"CVE-2026-0005", agent.RecordRef{SourceID: "nvd-mirror", Position: 0}},
		{"CVE-2026-0006", agent.RecordRef{SourceID: "nvd", Position: 1}},
	}
	for _, tc := range tests {
		got := v.CVERecords(tc.cve)
		if len(got) != 1 {
			t.Fatalf("CVERecords(%s): got %d records, want 1", tc.cve, len(got))
		}
		if got[0].Ref != tc.want {
			t.Errorf("CVERecords(%s).Ref = %+v, want %+v", tc.cve, got[0].Ref, tc.want)
		}
	}

	// The OSV-only source advanced its own counter; nothing was kept for it.
	if got := v.pos["osv"]; got != 2 {
		t.Errorf("position counter of osv = %d, want 2", got)
	}
	if got := v.pos["deb"]; got != 4 {
		t.Errorf("position counter of deb = %d, want 4", got)
	}
}

// TestSnapshotViewNVDRecordFields pins the mapping of an NVD item into the
// CVE record: date text, CVSS entries carrying the source, CWEs and URLs.
func TestSnapshotViewNVDRecordFields(t *testing.T) {
	v := newSnapshotView(nil)
	v.addNVD("nvd", vulnfeed.NVDRecord{
		ID:           "CVE-2026-0100",
		Published:    viewDate(2026, time.January, 2).Add(15 * time.Hour),
		LastModified: viewDate(2026, time.February, 3),
		Description:  "test description",
		CWEs:         []string{"CWE-79"},
		CVSS: []vulnfeed.NVDCVSS{
			{Version: vulnfeed.NVDCVSS31, Vector: "CVSS:3.1/AV:N", BaseScore: 7.5},
		},
		References: []vulnfeed.NVDReference{{URL: "https://example.test/advisory"}},
	})

	got := v.CVERecords("CVE-2026-0100")
	if len(got) != 1 {
		t.Fatalf("CVERecords: got %d records, want 1", len(got))
	}
	c := got[0]
	if c.Ref != (agent.RecordRef{SourceID: "nvd", Position: 0}) {
		t.Errorf("Ref = %+v, want nvd/0", c.Ref)
	}
	if c.Published != "2026-01-02" || c.Modified != "2026-02-03" {
		t.Errorf("dates = %q/%q, want 2026-01-02/2026-02-03", c.Published, c.Modified)
	}
	if c.Description != "test description" || !reflect.DeepEqual(c.CWEs, []string{"CWE-79"}) {
		t.Errorf("description/CWEs = %q/%v", c.Description, c.CWEs)
	}
	wantCVSS := []agent.CVSS{{Version: vulnfeed.NVDCVSS31, Vector: "CVSS:3.1/AV:N", Score: 7.5, SourceID: "nvd"}}
	if !reflect.DeepEqual(c.CVSS, wantCVSS) {
		t.Errorf("CVSS = %+v, want %+v", c.CVSS, wantCVSS)
	}
	if !reflect.DeepEqual(c.References, []string{"https://example.test/advisory"}) {
		t.Errorf("References = %v", c.References)
	}
}

// TestSnapshotViewCVERecordsIgnoresIDCase pins that CVE lookups do not
// depend on the case of the ID, in either direction.
func TestSnapshotViewCVERecordsIgnoresIDCase(t *testing.T) {
	v := newSnapshotView(nil)
	v.addNVD("nvd", vulnfeed.NVDRecord{ID: "cve-2026-0101"})

	for _, id := range []string{"CVE-2026-0101", "cve-2026-0101", "Cve-2026-0101"} {
		got := v.CVERecords(id)
		if len(got) != 1 || got[0].Ref.Position != 0 {
			t.Errorf("CVERecords(%q) = %+v, want one record at position 0", id, got)
		}
	}
	if got := v.CVERecords("CVE-2026-9999"); got != nil {
		t.Errorf("CVERecords(unknown) = %+v, want nil", got)
	}
}

// TestSnapshotViewAdvisoryRecordsAlwaysEmpty pins that the view keeps no
// advisory text, so AdvisoryRecords is empty even for IDs the tracker
// history mentions.
func TestSnapshotViewAdvisoryRecordsAlwaysEmpty(t *testing.T) {
	v := newSnapshotView(map[string]bool{"bookworm/openssl": true})
	v.addDebian("deb", vulnfeed.DebianEntry{Package: "openssl", IssueID: "CVE-2026-0102", Release: "bookworm",
		State: vulnfinding.TrackerFixed, FixedVersion: "3.0.1"})

	for _, id := range []string{"DSA-1000-1", "DLA-1000-1", "CVE-2026-0102", ""} {
		if got := v.AdvisoryRecords(id); len(got) != 0 {
			t.Errorf("AdvisoryRecords(%q) = %+v, want empty", id, got)
		}
	}
}

// TestSnapshotViewPackageHistoryFilter pins that only "release/package"
// entries in wanted are kept, that they come back in insertion order, and
// that an unknown ecosystem, release or package yields nil.
func TestSnapshotViewPackageHistoryFilter(t *testing.T) {
	v := newSnapshotView(map[string]bool{"bookworm/openssl": true})
	v.addDebian("deb", vulnfeed.DebianEntry{Package: "openssl", IssueID: "CVE-2026-0201", Release: "bookworm",
		State: vulnfinding.TrackerFixed, FixedVersion: "3.0.1"})
	v.addDebian("deb", vulnfeed.DebianEntry{Package: "curl", IssueID: "CVE-2026-0202", Release: "bookworm",
		State: vulnfinding.TrackerFixed, FixedVersion: "8.0.0"})
	v.addDebian("deb", vulnfeed.DebianEntry{Package: "openssl", IssueID: "CVE-2026-0203", Release: "trixie",
		State: vulnfinding.TrackerFixed, FixedVersion: "3.5.0"})
	v.addDebian("deb", vulnfeed.DebianEntry{Package: "openssl", IssueID: "CVE-2026-0204", Release: "bookworm",
		State: vulnfinding.TrackerUnfixed})

	want := []agent.PackageRecord{
		{SourceID: "deb", RecordID: "CVE-2026-0201", FixedVersion: "3.0.1", TrackerState: "fixed"},
		{SourceID: "deb", RecordID: "CVE-2026-0204", TrackerState: "unfixed"},
	}
	if got := v.PackageHistory("debian:bookworm", "openssl"); !reflect.DeepEqual(got, want) {
		t.Errorf("PackageHistory(debian:bookworm, openssl) = %+v, want %+v", got, want)
	}

	tests := []struct {
		name, ecosystem, pkg string
	}{
		{"unwanted package of a wanted release", "debian:bookworm", "curl"},
		{"wanted package of an unwanted release", "debian:trixie", "openssl"},
		{"unknown release", "debian:bullseye", "openssl"},
		{"unknown package", "debian:bookworm", "nosuchpkg"},
		{"other ecosystem", "ubuntu:noble", "openssl"},
		{"ecosystem without prefix", "bookworm", "openssl"},
	}
	for _, tc := range tests {
		if got := v.PackageHistory(tc.ecosystem, tc.pkg); got != nil {
			t.Errorf("%s: PackageHistory(%s, %s) = %+v, want nil", tc.name, tc.ecosystem, tc.pkg, got)
		}
	}
}

// TestSnapshotViewKEVEPSS pins the KEV and EPSS lookup: the ID is matched
// without regard to case, an unknown ID or one with neither KEV nor EPSS
// returns false, and a KEV entry without a date is dropped by addKEV, so it
// reports false.
func TestSnapshotViewKEVEPSS(t *testing.T) {
	v := newSnapshotView(nil)
	scoreDate := viewDate(2026, time.November, 1)
	v.addKEV(vulnfeed.KEVEntry{CVE: "cve-2026-0300", DateAdded: viewDate(2026, time.March, 4)})
	v.addKEV(vulnfeed.KEVEntry{CVE: "CVE-2026-0301", DateAdded: viewDate(2026, time.March, 5)})
	v.addKEV(vulnfeed.KEVEntry{CVE: "CVE-2026-0302"}) // no DateAdded: dropped by addKEV
	v.setEPSS(vulnfeed.EPSSScores{Date: scoreDate, Scores: []vulnfeed.EPSSScore{
		{CVE: "CVE-2026-0301", Probability: 0.25, Percentile: 0.5},
		{CVE: "cve-2026-0303", Probability: 0.75, Percentile: 0.875},
	}})

	kevOnly, ok := v.KEVEPSS("CVE-2026-0300")
	if !ok || !kevOnly.KEV || kevOnly.KEVDateAdded != "2026-03-04" {
		t.Errorf("KEV only: got %+v, %t; want KEV on 2026-03-04", kevOnly, ok)
	}
	if kevOnly.EPSS != nil || kevOnly.Percentile != nil || kevOnly.ScoreDate != "" {
		t.Errorf("KEV only: EPSS fields set: %+v", kevOnly)
	}

	both, ok := v.KEVEPSS("cve-2026-0301")
	if !ok || !both.KEV || both.KEVDateAdded != "2026-03-05" {
		t.Errorf("KEV and EPSS: KEV part wrong: %+v, %t", both, ok)
	}
	if both.EPSS == nil || *both.EPSS != 0.25 || both.Percentile == nil || *both.Percentile != 0.5 {
		t.Errorf("KEV and EPSS: EPSS part wrong: %+v", both)
	}
	if both.ScoreDate != "2026-11-01" {
		t.Errorf("KEV and EPSS: ScoreDate = %q, want 2026-11-01", both.ScoreDate)
	}

	epssOnly, ok := v.KEVEPSS("CVE-2026-0303")
	if !ok || epssOnly.KEV || epssOnly.KEVDateAdded != "" {
		t.Errorf("EPSS only: got %+v, %t; want no KEV", epssOnly, ok)
	}
	if epssOnly.EPSS == nil || *epssOnly.EPSS != 0.75 || epssOnly.Percentile == nil || *epssOnly.Percentile != 0.875 {
		t.Errorf("EPSS only: EPSS part wrong: %+v", epssOnly)
	}

	for _, id := range []string{"CVE-2026-0302", "CVE-2026-0399"} {
		got, ok := v.KEVEPSS(id)
		if ok {
			t.Errorf("KEVEPSS(%s): ok = true, want false (got %+v)", id, got)
		}
		if got != (agent.KEVEPSS{}) {
			t.Errorf("KEVEPSS(%s): got %+v, want zero value", id, got)
		}
	}
}

// TestSnapshotViewSetEPSSSecondCallReplacesValues pins that a second
// setEPSS call replaces the score and the score date of a CVE it contains.
func TestSnapshotViewSetEPSSSecondCallReplacesValues(t *testing.T) {
	v := newSnapshotView(nil)
	v.setEPSS(vulnfeed.EPSSScores{Date: viewDate(2026, time.November, 1), Scores: []vulnfeed.EPSSScore{
		{CVE: "CVE-2026-0400", Probability: 0.125, Percentile: 0.25},
	}})
	v.setEPSS(vulnfeed.EPSSScores{Date: viewDate(2026, time.November, 2), Scores: []vulnfeed.EPSSScore{
		{CVE: "cve-2026-0400", Probability: 0.5, Percentile: 0.75},
	}})

	got, ok := v.KEVEPSS("CVE-2026-0400")
	if !ok {
		t.Fatal("KEVEPSS: ok = false, want true")
	}
	if got.EPSS == nil || *got.EPSS != 0.5 {
		t.Errorf("EPSS = %v, want 0.5", got.EPSS)
	}
	if got.Percentile == nil || *got.Percentile != 0.75 {
		t.Errorf("Percentile = %v, want 0.75", got.Percentile)
	}
	if got.ScoreDate != "2026-11-02" {
		t.Errorf("ScoreDate = %q, want 2026-11-02", got.ScoreDate)
	}
}

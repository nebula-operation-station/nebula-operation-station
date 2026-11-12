// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Fixture versions are illustrative (ADR 0011 D4 marks the concrete
// Debian/Ubuntu pairs *verify*); they follow the real version shapes:
// "~deb12u1" backports, "+deb12u1" security uploads, "+b1" binNMUs,
// epochs, Ubuntu "-0ubuntu3.4" and kernel "6.8.0-45.45".

func snap(n int) string { return fmt.Sprintf("sha256:%064x", n) }

// newDB returns a DB with a snapshot set for every feed of the table.
func newDB(t *testing.T) *DB {
	t.Helper()
	db := NewDB()
	for i, f := range vulnfeed.Feeds() {
		if err := db.SetFeed(f.Name, FeedRef{SourceID: f.SourceID, SnapshotID: snap(i + 1), Integrity: f.Integrity}); err != nil {
			t.Fatalf("SetFeed %s: %v", f.Name, err)
		}
	}
	return db
}

func addDeb(t *testing.T, db *DB, pkg, issue, release string, st vulnfinding.TrackerState, fixed string) {
	t.Helper()
	if err := db.AddDebian(vulnfeed.DebianEntry{Package: pkg, IssueID: issue, Release: release, State: st, FixedVersion: fixed}); err != nil {
		t.Fatalf("AddDebian: %v", err)
	}
}

func mkOSV(id string, aliases []string, eco, name string, events ...vulnfeed.OSVEvent) vulnfeed.OSVRecord {
	return vulnfeed.OSVRecord{
		ID: id, Aliases: aliases, Modified: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		Affected: []vulnfeed.OSVAffected{{Ecosystem: eco, Name: name, Ranges: []vulnfeed.OSVRange{{Type: vulnfeed.OSVRangeEcosystem, Events: events}}}},
	}
}

func intro(v string) vulnfeed.OSVEvent {
	return vulnfeed.OSVEvent{Kind: vulnfeed.OSVIntroduced, Version: v}
}
func fixed(v string) vulnfeed.OSVEvent { return vulnfeed.OSVEvent{Kind: vulnfeed.OSVFixed, Version: v} }

func host(eco string, comps ...Component) Subject {
	return Subject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "h1"}, Ecosystem: eco, Components: comps}
}

func comp(pkg, ver string, bins ...Binary) Component {
	return Component{SourcePackage: pkg, SourceVersion: ver, Binaries: bins}
}

func mustMatch(t *testing.T, db *DB, subs ...Subject) Result {
	t.Helper()
	r, err := Match(db, subs, Options{})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(r.Withheld) != 0 {
		t.Fatalf("withheld records: %+v", r.Withheld)
	}
	return r
}

func findingFor(r Result, pkg, id string) (Finding, bool) {
	for _, f := range r.Findings {
		if (f.Record.Component.SourcePackage == pkg || f.Record.Component.Model == pkg) && f.Record.Vuln.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func hasGap(r Result, pkg string, reason GapReason) bool {
	for _, g := range r.Gaps {
		if g.Package == pkg && g.Reason == reason {
			return true
		}
	}
	return false
}

// TestDebianBackportsCompareSourceVersions covers the D4 backport rule:
// source package + release + fixed version per release, dpkg ordering on
// source:Version, never the upstream or binary version.
func TestDebianBackportsCompareSourceVersions(t *testing.T) {
	const cve = "CVE-2024-9143"
	tests := []struct {
		name      string
		installed Component
		fixed     string
		wantOpen  bool
	}{
		{"backport ~deb12u1 equals fix although upstream 3.0.15 < NVD 3.0.16", comp("openssl", "3.0.15-1~deb12u1"), "3.0.15-1~deb12u1", false},
		{"older backport is affected", comp("openssl", "3.0.14-1~deb12u2"), "3.0.15-1~deb12u1", true},
		{"tilde sorts before the plain revision", comp("openssl", "3.0.15-1~deb12u1"), "3.0.15-1", true},
		{"+deb12u1 security upload is after the release version", comp("curl", "7.88.1-10+deb12u1"), "7.88.1-10", false},
		{"+deb12u5 is after +deb12u4", comp("curl", "7.88.1-10+deb12u5"), "7.88.1-10+deb12u4", false},
		{"+deb12u4 is before +deb12u5", comp("curl", "7.88.1-10+deb12u4"), "7.88.1-10+deb12u5", true},
		{"epoch beats a higher upstream", comp("pkg", "1:2.0-1"), "2.5-1", false},
		{"missing epoch is below the fix epoch", comp("pkg", "2.9-1"), "1:2.0-1", true},
		{"binNMU binary version is never the basis", comp("glibc", "1.2-3", Binary{Name: "libc6", Version: "1.2-3+b2"}), "1.2-3+b1", true},
		{"separately versioned binary is never the basis", comp("gcc-12", "12.2.0-14", Binary{Name: "libgcc-s1", Version: "14.0-1"}), "12.2.0-15", true},
		{"partial upgrade: lowest binary source version is the basis", comp("openssl", "3.0.15-1~deb12u1",
			Binary{Name: "libssl3", Version: "3.0.15-1~deb12u1", SourceVersion: "3.0.15-1~deb12u1"},
			Binary{Name: "openssl", Version: "3.0.14-1~deb12u2", SourceVersion: "3.0.14-1~deb12u2"}), "3.0.15-1~deb12u1", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			addDeb(t, db, tc.installed.SourcePackage, cve, "bookworm", vulnfinding.TrackerFixed, tc.fixed)
			r := mustMatch(t, db, host("debian:bookworm", tc.installed))
			f, ok := findingFor(r, tc.installed.SourcePackage, cve)
			if ok != tc.wantOpen {
				t.Fatalf("finding present = %v, want %v (%+v)", ok, tc.wantOpen, r)
			}
			if !ok {
				if len(r.Findings) != 0 {
					t.Fatalf("unexpected findings %+v", r.Findings)
				}
				return
			}
			rec := f.Record
			if rec.Fix != (vulnfinding.Fix{State: vulnfinding.FixFixed, Version: tc.fixed}) || rec.TrackerState != vulnfinding.TrackerFixed {
				t.Fatalf("fix = %+v state %q", rec.Fix, rec.TrackerState)
			}
			if rec.MatchBasis != vulnfinding.MatchDistroTracker || rec.Ecosystem != "debian:bookworm" {
				t.Fatalf("basis/eco = %s %s", rec.MatchBasis, rec.Ecosystem)
			}
			for _, b := range rec.Component.Binaries {
				if b.Version == rec.Component.SourceVersion && b.Name != rec.Component.SourcePackage && strings.Contains(b.Version, "+b") {
					t.Fatalf("binary version used as basis")
				}
			}
		})
	}
}

// TestPartialUpgradeReportsLowestBasis: the record's installed source
// version is the lowest one (what NOS re-checks), with every binary listed.
func TestPartialUpgradeReportsLowestBasis(t *testing.T) {
	db := newDB(t)
	addDeb(t, db, "openssl", "CVE-2024-9143", "bookworm", vulnfinding.TrackerFixed, "3.0.15-1~deb12u1")
	r := mustMatch(t, db, host("debian:bookworm", comp("openssl", "3.0.15-1~deb12u1",
		Binary{Name: "openssl", Version: "3.0.14-1~deb12u2", SourceVersion: "3.0.14-1~deb12u2"},
		Binary{Name: "libssl3", Version: "3.0.15-1~deb12u1", SourceVersion: "3.0.15-1~deb12u1"})))
	f, ok := findingFor(r, "openssl", "CVE-2024-9143")
	if !ok {
		t.Fatal("no finding")
	}
	if f.Record.Component.SourceVersion != "3.0.14-1~deb12u2" {
		t.Fatalf("basis = %s", f.Record.Component.SourceVersion)
	}
	if got := len(f.Record.Component.Binaries); got != 2 || f.Record.Component.Binaries[0].Name != "libssl3" {
		t.Fatalf("binaries = %+v", f.Record.Component.Binaries)
	}
}

// TestDebianTrackerStateMapping: one target per D4 tracker state.
func TestDebianTrackerStateMapping(t *testing.T) {
	tests := []struct {
		state   vulnfinding.TrackerState
		fixed   string
		want    vulnfinding.FixState
		present bool
	}{
		{vulnfinding.TrackerNotAffected, "", vulnfinding.FixNotAffected, true},
		{vulnfinding.TrackerFixed, "1:1.2.13.dfsg-2", vulnfinding.FixFixed, true},
		{vulnfinding.TrackerUnfixed, "", vulnfinding.FixNoFixYet, true},
		{vulnfinding.TrackerPostponed, "", vulnfinding.FixNoFixYet, true},
		{vulnfinding.TrackerNoDSA, "", vulnfinding.FixNoFixYet, true},
		{vulnfinding.TrackerIgnored, "", vulnfinding.FixWontFix, true},
		{vulnfinding.TrackerEndOfLife, "", vulnfinding.FixWontFix, true},
		{vulnfeed.DebianUndetermined, "", "", false},
	}
	covered := map[vulnfinding.TrackerState]bool{}
	for _, tc := range tests {
		covered[tc.state] = true
		t.Run(string(tc.state), func(t *testing.T) {
			db := newDB(t)
			addDeb(t, db, "zlib", "CVE-2023-45853", "bookworm", tc.state, tc.fixed)
			r := mustMatch(t, db, host("debian:bookworm", comp("zlib", "1:1.2.13.dfsg-1")))
			f, ok := findingFor(r, "zlib", "CVE-2023-45853")
			if ok != tc.present {
				t.Fatalf("present = %v, want %v", ok, tc.present)
			}
			if !ok {
				if !hasGap(r, "zlib", GapTrackerState) {
					t.Fatalf("undetermined state without gap: %+v", r.Gaps)
				}
				return
			}
			if f.Record.Fix.State != tc.want || f.Record.TrackerState != tc.state {
				t.Fatalf("fix = %+v, tracker_state %q", f.Record.Fix, f.Record.TrackerState)
			}
		})
	}
	for _, s := range vulnfinding.AllTrackerStates() {
		if !covered[s] {
			t.Errorf("tracker state %q not covered", s)
		}
	}
}

// TestUnknownVersionsNeverClaimFixed: a version that does not parse is a
// coverage gap and never a record, in particular never not_affected.
func TestUnknownVersionsNeverClaimFixed(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		state     vulnfinding.TrackerState
		fixed     string
		reason    GapReason
	}{
		{"invalid installed version vs fix", "Ä1.0-1", vulnfinding.TrackerFixed, "1.0-2", GapVersionUnknown},
		{"invalid installed version vs not-affected", "1.0-1 ", vulnfinding.TrackerNotAffected, "", GapVersionUnknown},
		{"invalid installed version vs unfixed", ":1.0", vulnfinding.TrackerUnfixed, "", GapVersionUnknown},
		{"invalid fixed version", "1.0-1", vulnfinding.TrackerFixed, "not a version", GapFixedVersionUnknown},
		{"fixed version with whitespace", "9.9-1", vulnfinding.TrackerFixed, "1.0 -2", GapFixedVersionUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			addDeb(t, db, "bash", "CVE-2022-3715", "bookworm", tc.state, tc.fixed)
			r := mustMatch(t, db, host("debian:bookworm", comp("bash", tc.installed)))
			if len(r.Findings) != 0 {
				t.Fatalf("findings for unknown version: %+v", r.Findings)
			}
			if !hasGap(r, "bash", tc.reason) {
				t.Fatalf("gaps = %+v, want %s", r.Gaps, tc.reason)
			}
		})
	}
}

// TestFixedVersionOverBoundsFailsClosed: a parseable fixed version over
// the record bound is sent as no_fix_yet, never dropped or closed (A1.3).
func TestFixedVersionOverBoundsFailsClosed(t *testing.T) {
	long := "2." + strings.Repeat("1", 130) + "-1"
	db := newDB(t)
	addDeb(t, db, "bash", "CVE-2022-3715", "bookworm", vulnfinding.TrackerFixed, long)
	r := mustMatch(t, db, host("debian:bookworm", comp("bash", "1.0-1")))
	f, ok := findingFor(r, "bash", "CVE-2022-3715")
	if !ok || f.Record.Fix.State != vulnfinding.FixNoFixYet || !slices.Contains(f.Notes, NoteFixedVersionOverBounds) {
		t.Fatalf("finding = %+v ok=%v", f, ok)
	}
	if r.FeedPartsCut != 1 {
		t.Fatalf("FeedPartsCut = %d", r.FeedPartsCut)
	}
}

// TestKernelBasisRules covers the D4 running-kernel rules.
func TestKernelBasisRules(t *testing.T) {
	const cve = "CVE-2024-50264"
	signed := comp("linux-signed-amd64", "6.1.115+3", Binary{Name: "linux-image-6.1.0-27-amd64", Version: "6.1.115-1"})
	tests := []struct {
		name     string
		kernel   *Kernel
		comps    []Component
		fixed    string
		wantOpen bool
		note     bool
		gap      bool
	}{
		{"running kernel below fix", &Kernel{Release: "6.1.0-27-amd64", Mapped: true, SourcePackage: "linux", SourceVersion: "6.1.115-1"},
			[]Component{signed, comp("linux", "6.1.115-1", Binary{Name: "linux-libc-dev", Version: "6.1.115-1"})}, "6.1.119-1", true, false, false},
		{"fixed kernel installed, not booted: open with reboot note",
			&Kernel{Release: "6.1.0-27-amd64", Mapped: true, SourcePackage: "linux", SourceVersion: "6.1.115-1",
				Installed: []InstalledKernel{{SourcePackage: "linux", SourceVersion: "6.1.119-1"}}},
			[]Component{comp("linux", "6.1.115-1")}, "6.1.119-1", true, true, false},
		{"running fixed kernel; older installed kernel never counts",
			&Kernel{Release: "6.1.0-28-amd64", Mapped: true, SourcePackage: "linux", SourceVersion: "6.1.119-1",
				Installed: []InstalledKernel{{SourcePackage: "linux", SourceVersion: "6.1.112-1"}}},
			[]Component{comp("linux", "6.1.112-1")}, "6.1.119-1", false, false, false},
		{"signed version 6.1.119+3 is never the basis",
			&Kernel{Release: "6.1.0-27-amd64", Mapped: true, SourcePackage: "linux", SourceVersion: "6.1.115-1"},
			[]Component{comp("linux-signed-amd64", "6.1.119+3")}, "6.1.119-1", true, false, false},
		{"unmapped running kernel: coverage unknown, no record",
			&Kernel{Release: "6.8.12-4-pve", Mapped: false}, []Component{comp("linux", "6.1.115-1")}, "6.1.119-1", false, false, true},
		{"no kernel facts but kernel packages: coverage unknown", nil, []Component{comp("linux", "6.1.115-1")}, "6.1.119-1", false, false, true},
		{"mapping to a signed source is rejected", &Kernel{Release: "x", Mapped: true, SourcePackage: "linux-signed-amd64", SourceVersion: "6.1.115+3"},
			nil, "6.1.119-1", false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			addDeb(t, db, "linux", cve, "bookworm", vulnfinding.TrackerFixed, tc.fixed)
			addDeb(t, db, "linux-signed-amd64", cve, "bookworm", vulnfinding.TrackerFixed, tc.fixed)
			s := host("debian:bookworm", tc.comps...)
			s.Kernel = tc.kernel
			r := mustMatch(t, db, s)
			for _, f := range r.Findings {
				if strings.HasPrefix(f.Record.Component.SourcePackage, "linux-signed") {
					t.Fatalf("finding on signed source: %+v", f)
				}
			}
			f, ok := findingFor(r, "linux", cve)
			if ok != tc.wantOpen {
				t.Fatalf("present = %v, want %v: %+v", ok, tc.wantOpen, r)
			}
			if ok {
				if f.Record.Component.SourceVersion != tc.kernel.SourceVersion {
					t.Fatalf("basis = %s, want running %s", f.Record.Component.SourceVersion, tc.kernel.SourceVersion)
				}
				if got := slices.Contains(f.Notes, NoteFixedAfterReboot); got != tc.note {
					t.Fatalf("reboot note = %v, want %v", got, tc.note)
				}
			}
			if got := hasGap(r, "", GapKernelUnknown); got != tc.gap {
				t.Fatalf("kernel gap = %v, want %v (%+v)", got, tc.gap, r.Gaps)
			}
		})
	}
}

// TestUbuntuKernelNeverUsesMeta: Ubuntu's linux-meta version 6.8.0.47.47
// would compare above the fix 6.8.0-47.47; the running linux basis is used.
func TestUbuntuKernelNeverUsesMeta(t *testing.T) {
	db := newDB(t)
	rec := mkOSV("UBUNTU-CVE-2024-26800", []string{"CVE-2024-26800"}, "Ubuntu:24.04:LTS", "linux", intro("0"), fixed("6.8.0-47.47"))
	if err := db.AddOSV(FeedOSVUbuntu, rec); err != nil {
		t.Fatal(err)
	}
	meta := mkOSV("UBUNTU-CVE-2024-26800", []string{"CVE-2024-26800"}, "Ubuntu:24.04:LTS", "linux-meta", intro("0"), fixed("6.8.0.47.47"))
	if err := db.AddOSV(FeedOSVUbuntu, meta); err != nil {
		t.Fatal(err)
	}
	s := host("ubuntu:24.04", comp("linux-meta", "6.8.0.45.45"), comp("linux", "6.8.0-45.45"))
	s.Kernel = &Kernel{Release: "6.8.0-45-generic", Mapped: true, SourcePackage: "linux", SourceVersion: "6.8.0-45.45"}
	r := mustMatch(t, db, s)
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	f := r.Findings[0].Record
	if f.Component.SourcePackage != "linux" || f.Fix.Version != "6.8.0-47.47" || f.Vuln.ID != "CVE-2024-26800" {
		t.Fatalf("record = %+v", f)
	}
	if !slices.Equal(f.Vuln.Aliases, []string{"UBUNTU-CVE-2024-26800"}) {
		t.Fatalf("aliases = %v", f.Vuln.Aliases)
	}
}

// TestUbuntuOSVBackports: Ubuntu security uploads compared with dpkg on
// the source version; ESM/Pro ecosystems are never consulted.
func TestUbuntuOSVBackports(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		eco       string
		events    []vulnfeed.OSVEvent
		want      vulnfinding.Fix
		present   bool
	}{
		{"older ubuntu upload affected", "3.0.13-0ubuntu3.4", "Ubuntu:24.04:LTS", []vulnfeed.OSVEvent{intro("0"), fixed("3.0.13-0ubuntu3.5")},
			vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.13-0ubuntu3.5"}, true},
		{"fixed upload not affected", "3.0.13-0ubuntu3.5", "Ubuntu:24.04:LTS", []vulnfeed.OSVEvent{intro("0"), fixed("3.0.13-0ubuntu3.5")}, vulnfinding.Fix{}, false},
		{"no fixed event: no fix yet", "3.0.13-0ubuntu3.5", "Ubuntu:24.04", []vulnfeed.OSVEvent{intro("0")}, vulnfinding.Fix{State: vulnfinding.FixNoFixYet}, true},
		{"Pro ecosystem ignored", "3.0.13-0ubuntu3.4", "Ubuntu:Pro:24.04:LTS", []vulnfeed.OSVEvent{intro("0"), fixed("3.0.13-0ubuntu3.5+esm1")}, vulnfinding.Fix{}, false},
		{"other release ignored", "3.0.13-0ubuntu3.4", "Ubuntu:22.04:LTS", []vulnfeed.OSVEvent{intro("0"), fixed("3.0.13-0ubuntu3.5")}, vulnfinding.Fix{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			if err := db.AddOSV(FeedOSVUbuntu, mkOSV("UBUNTU-CVE-2024-5535", []string{"CVE-2024-5535"}, tc.eco, "openssl", tc.events...)); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, host("ubuntu:24.04", comp("openssl", tc.installed, Binary{Name: "libssl3t64", Version: tc.installed})))
			f, ok := findingFor(r, "openssl", "CVE-2024-5535")
			if ok != tc.present {
				t.Fatalf("present = %v want %v", ok, tc.present)
			}
			if ok {
				if f.Record.Fix != tc.want || f.Record.MatchBasis != vulnfinding.MatchDistroTracker || f.Record.TrackerState != "" {
					t.Fatalf("record = %+v", f.Record)
				}
				osv := f.Record.Evidence.BasisSources[0]
				if osv.SourceID != "osv" || osv.SnapshotID != db.feeds[FeedOSVUbuntu].SnapshotID {
					t.Fatalf("basis = %+v", f.Record.Evidence.BasisSources)
				}
			}
		})
	}
}

// TestAlpineImageOSVRanges: image packages matched on OSV ECOSYSTEM ranges
// with apk ordering on the origin package version.
func TestAlpineImageOSVRanges(t *testing.T) {
	img := func(ver string) Subject {
		return Subject{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "h1", ImageDigest: "sha256:" + strings.Repeat("ab", 32)},
			Ecosystem: "alpine:3.20", Components: []Component{comp("openssl", ver, Binary{Name: "libcrypto3", Version: ver})}}
	}
	tests := []struct {
		name    string
		ver     string
		ranges  []vulnfeed.OSVRange
		skipped int
		want    vulnfinding.Fix
		present bool
		gap     bool
	}{
		{"revision below fix", "3.3.2-r0", []vulnfeed.OSVRange{{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("0"), fixed("3.3.2-r1")}}}, 0,
			vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.3.2-r1"}, true, false},
		{"at fix", "3.3.2-r1", []vulnfeed.OSVRange{{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("0"), fixed("3.3.2-r1")}}}, 0, vulnfinding.Fix{}, false, false},
		{"two windows: fix of the window that contains the version", "3.3.5-r0", []vulnfeed.OSVRange{
			{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("0"), fixed("3.1.0-r0")}},
			{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("3.3.0-r0"), fixed("3.3.6-r0")}},
		}, 0, vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.3.6-r0"}, true, false},
		{"overlapping windows: first version that leaves every window", "3.3.5-r0", []vulnfeed.OSVRange{
			{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("0"), fixed("3.4.0-r0")}},
			{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("3.3.0-r0"), fixed("3.3.6-r0")}},
		}, 0, vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.4.0-r0"}, true, false},
		{"semver range only: unknown, never clean", "3.3.2-r0", []vulnfeed.OSVRange{{Type: vulnfeed.OSVRangeSemver, Events: []vulnfeed.OSVEvent{intro("0"), fixed("3.3.3")}}}, 0,
			vulnfinding.Fix{}, false, true},
		{"not in ecosystem range but GIT ranges skipped: unknown", "3.3.2-r1", []vulnfeed.OSVRange{{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("0"), fixed("3.3.2-r1")}}}, 1,
			vulnfinding.Fix{}, false, true},
		{"invalid fixed event: unknown", "3.3.2-r0", []vulnfeed.OSVRange{{Type: vulnfeed.OSVRangeEcosystem, Events: []vulnfeed.OSVEvent{intro("0"), fixed("3.3.2-RC")}}}, 0,
			vulnfinding.Fix{}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			rec := vulnfeed.OSVRecord{ID: "CVE-2024-6119", Affected: []vulnfeed.OSVAffected{{Ecosystem: "Alpine:v3.20", Name: "openssl", Ranges: tc.ranges, SkippedRanges: tc.skipped}}}
			if err := db.AddOSV(FeedOSVAlpine, rec); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, img(tc.ver))
			f, ok := findingFor(r, "openssl", "CVE-2024-6119")
			if ok != tc.present {
				t.Fatalf("present = %v want %v: %+v", ok, tc.present, r)
			}
			if ok && (f.Record.Fix != tc.want || f.Record.MatchBasis != vulnfinding.MatchOSVRange || f.Record.SubjectKind != vulnfinding.SubjectImage) {
				t.Fatalf("record = %+v", f.Record)
			}
			if got := hasGap(r, "openssl", GapRangeUnknown); got != tc.gap {
				t.Fatalf("range gap = %v want %v", got, tc.gap)
			}
		})
	}
}

// TestWithdrawnOSVRecordIgnored: a withdrawn record opens nothing.
func TestWithdrawnOSVRecordIgnored(t *testing.T) {
	db := newDB(t)
	rec := mkOSV("CVE-2024-6119", nil, "Alpine:v3.20", "openssl", intro("0"), fixed("3.3.2-r1"))
	rec.Withdrawn = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := db.AddOSV(FeedOSVAlpine, rec); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "h1", ImageDigest: "sha256:" + strings.Repeat("cd", 32)},
		Ecosystem: "alpine:3.20", Components: []Component{comp("openssl", "3.3.2-r0")}})
	if len(r.Findings) != 0 {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

// TestCoverageUnknownNeverClean: Proxmox packages, unknown ecosystems and
// language ecosystems are gaps.
func TestCoverageUnknownNeverClean(t *testing.T) {
	db := newDB(t)
	addDeb(t, db, "pve-manager", "CVE-2024-1", "bookworm", vulnfinding.TrackerUnfixed, "")
	r := mustMatch(t, db,
		host("debian:bookworm", comp("pve-manager", "8.2.4"), comp("proxmox-backup-client", "3.2.7-1")),
		Subject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "h2"}, Ecosystem: ""},
		Subject{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "h3", ImageDigest: "sha256:" + strings.Repeat("ef", 32)}, Ecosystem: "Go"},
	)
	if len(r.Findings) != 0 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	for _, want := range []Gap{
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "h1"}, Ecosystem: "debian:bookworm", Package: "pve-manager", Reason: GapProxmox},
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "h1"}, Ecosystem: "debian:bookworm", Package: "proxmox-backup-client", Reason: GapProxmox},
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "h2"}, Reason: GapEcosystemUnknown},
		{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "h3", ImageDigest: "sha256:" + strings.Repeat("ef", 32)}, Ecosystem: "Go", Reason: GapEcosystemUnknown},
	} {
		if !slices.Contains(r.Gaps, want) {
			t.Errorf("missing gap %+v in %+v", want, r.Gaps)
		}
	}
}

// TestMissingFeedSnapshotIsGap: a covered ecosystem whose feed snapshot is
// not in the DB yields a gap, never an empty (clean-looking) result.
func TestMissingFeedSnapshotIsGap(t *testing.T) {
	tests := []struct {
		name string
		feed string
		sub  Subject
	}{
		{"debian tracker", FeedDebianTracker, host("debian:bookworm", comp("openssl", "3.0.14-1~deb12u2"))},
		{"osv ubuntu", FeedOSVUbuntu, host("ubuntu:24.04", comp("openssl", "3.0.13-0ubuntu3.4"))},
		{"osv alpine", FeedOSVAlpine, Subject{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "i1", ImageDigest: "sha256:" + strings.Repeat("ab", 32)},
			Ecosystem: "alpine:3.20", Components: []Component{comp("openssl", "3.3.2-r0")}}},
		{"cisco csaf", FeedCiscoCSAF, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: "vendor:cisco:cbs", Device: &Device{Model: "CBS350-24P", Firmware: "3.4.0.17"}}},
		{"paloalto csaf", FeedPaloAltoCSAF, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: "vendor:paloalto:panos", Device: &Device{Model: "PA-440", Firmware: "10.2.9"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := NewDB()
			for i, f := range vulnfeed.Feeds() {
				if f.Name == tc.feed {
					continue
				}
				if err := db.SetFeed(f.Name, FeedRef{SourceID: f.SourceID, SnapshotID: snap(i + 1), Integrity: f.Integrity}); err != nil {
					t.Fatal(err)
				}
			}
			r := mustMatch(t, db, tc.sub)
			want := Gap{Kind: tc.sub.Kind, Ref: tc.sub.Ref, Ecosystem: tc.sub.Ecosystem, Reason: GapFeedMissing}
			if len(r.Findings) != 0 || !slices.Contains(r.Gaps, want) {
				t.Fatalf("result = %+v, want gap %+v", r, want)
			}
			// With the snapshot set, the same subject is not a feed gap.
			if r := mustMatch(t, newDB(t), tc.sub); hasGap(r, "", GapFeedMissing) {
				t.Fatalf("feed gap with every snapshot set: %+v", r.Gaps)
			}
		})
	}
}

func csafProduct(id, eco, version, train string) vulnfeed.CSAFProduct {
	return vulnfeed.CSAFProduct{ProductID: id, Name: id, Version: version, Train: train, Ecosystem: eco}
}

// TestVendorTrains: devices against CSAF products of their train; only an
// exact firmware version decides, never an ordering guess.
func TestVendorTrains(t *testing.T) {
	const panos, cbs = "vendor:paloalto:panos", "vendor:cisco:cbs"
	panAdv := vulnfeed.CSAFAdvisory{
		TrackingID: "PAN-SA-2024-0015", Version: "1",
		Products: []vulnfeed.CSAFProduct{
			csafProduct("p1", panos, "10.2.9", "10.2"),
			csafProduct("p2", panos, "10.2.10", "10.2"),
			csafProduct("p3", panos, "11.1.3", "11.1"),
			csafProduct("p4", panos, "11.1.4", "11.1"),
			csafProduct("p5", panos, "11.1.5", "11.1"),
			csafProduct("p6", panos, "9.1.17", "9.1"),
			{ProductID: "p7", Name: "PAN-OS 11.2", VersionRange: "vers:generic/>=11.2.0|<11.2.4", Train: "11.2", Ecosystem: panos},
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: "CVE-2024-3400", Affected: []string{"p1", "p3", "p7"}, Fixed: []string{"p2", "p4", "p5"}, NotAffected: []string{"p6"}}},
	}
	cbsAdv := vulnfeed.CSAFAdvisory{
		TrackingID: "cisco-sa-cbs-xss-2024", Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			csafProduct("c1", cbs, "3.4.0.17", "3.4"),
			csafProduct("c2", cbs, "3.4.1.3", "3.4"),
			csafProduct("c3", cbs, "3.3.0.16", "3.3"),
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: "CVE-2024-20430", Affected: []string{"c1", "c3"}, Fixed: []string{"c2"}}},
	}
	tests := []struct {
		name     string
		eco      string
		model    string
		firmware string
		id       string
		want     vulnfinding.Fix
		present  bool
		gap      bool
	}{
		{"PAN-OS affected, single fixed release of the train", panos, "PA-440", "10.2.9", "CVE-2024-3400", vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "10.2.10"}, true, false},
		{"PAN-OS fixed release: no record", panos, "PA-440", "10.2.10", "CVE-2024-3400", vulnfinding.Fix{}, false, false},
		{"PAN-OS train with two fixed releases: no fix version guessed", panos, "PA-440", "11.1.3", "CVE-2024-3400", vulnfinding.Fix{State: vulnfinding.FixNoFixYet}, true, false},
		{"PAN-OS not affected list", panos, "PA-440", "9.1.17", "CVE-2024-3400", vulnfinding.Fix{State: vulnfinding.FixNotAffected}, true, false},
		{"PAN-OS only a range covers the firmware: unknown", panos, "PA-440", "11.2.1", "CVE-2024-3400", vulnfinding.Fix{}, false, true},
		{"CBS firmware affected", cbs, "CBS350-24P", "3.4.0.17", "CVE-2024-20430", vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.4.1.3"}, true, false},
		{"CBS train without fixed release", cbs, "CBS350-24P", "3.3.0.16", "CVE-2024-20430", vulnfinding.Fix{State: vulnfinding.FixNoFixYet}, true, false},
		{"CBS firmware absent from advisory: nothing", cbs, "CBS350-24P", "3.5.0.1", "CVE-2024-20430", vulnfinding.Fix{}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			if err := db.AddCSAF(FeedPaloAltoCSAF, panAdv); err != nil {
				t.Fatal(err)
			}
			if err := db.AddCSAF(FeedCiscoCSAF, cbsAdv); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: tc.eco, Device: &Device{Model: tc.model, Firmware: tc.firmware}})
			f, ok := findingFor(r, tc.model, tc.id)
			if ok != tc.present {
				t.Fatalf("present = %v want %v: %+v", ok, tc.present, r)
			}
			if ok {
				rec := f.Record
				if rec.Fix != tc.want || rec.MatchBasis != vulnfinding.MatchVendorAdvisory || rec.Component.Firmware != tc.firmware {
					t.Fatalf("record = %+v", rec)
				}
				if len(rec.Vuln.Aliases) != 1 || !strings.Contains(rec.Vuln.Aliases[0], "-") {
					t.Fatalf("aliases = %v", rec.Vuln.Aliases)
				}
				b := rec.Evidence.BasisSources
				if len(b) != 1 || b[0].Integrity != vulnfinding.IntegritySigned || !strings.HasSuffix(b[0].SourceID, "-csaf") {
					t.Fatalf("basis = %+v", b)
				}
			}
			if got := hasGap(r, tc.model, GapVendorRange); got != tc.gap {
				t.Fatalf("vendor gap = %v want %v", got, tc.gap)
			}
		})
	}
}

// TestVendorContradictingStatusIsUnknown: a firmware listed as affected and
// fixed for one vulnerability is a gap, not a record.
func TestVendorContradictingStatusIsUnknown(t *testing.T) {
	db := newDB(t)
	adv := vulnfeed.CSAFAdvisory{TrackingID: "PAN-SA-2024-0001", Version: "1",
		Products:        []vulnfeed.CSAFProduct{csafProduct("a", "vendor:paloalto:panos", "10.2.9", "10.2"), csafProduct("b", "vendor:paloalto:panos", "10.2.9", "10.2")},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: "CVE-2024-0001", Affected: []string{"a"}, Fixed: []string{"b"}}}}
	if err := db.AddCSAF(FeedPaloAltoCSAF, adv); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: "vendor:paloalto:panos", Device: &Device{Model: "PA-440", Firmware: "10.2.9"}})
	if len(r.Findings) != 0 || !hasGap(r, "PA-440", GapVendorRange) {
		t.Fatalf("result = %+v", r)
	}
}

// TestRecordsPassValidation: every record round-trips through the NOS-side
// parser (vulnfinding.ParseRecord) and carries no finding_key.
func TestRecordsPassValidation(t *testing.T) {
	db, subs := richFixture(t)
	r := mustMatch(t, db, subs...)
	if len(r.Findings) < 5 {
		t.Fatalf("fixture produced %d findings", len(r.Findings))
	}
	for _, f := range r.Findings {
		b, err := json.Marshal(f.Record)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "finding_key") {
			t.Fatalf("record carries finding_key")
		}
		if _, err := vulnfinding.ParseRecord(b); err != nil {
			t.Fatalf("ParseRecord(%s): %v", b, err)
		}
		if len(f.Record.Evidence.BasisSources) == 0 {
			t.Fatalf("empty basis sources")
		}
		if f.Record.Evidence.MatcherVersion != MatcherVersion {
			t.Fatalf("matcher version %q", f.Record.Evidence.MatcherVersion)
		}
	}
}

// TestSameInputSameOutput: the result is independent of input order.
func TestSameInputSameOutput(t *testing.T) {
	db1, subs := richFixture(t)
	r1 := mustMatch(t, db1, subs...)
	db2, subs2 := richFixture(t)
	slices.Reverse(subs2)
	r2 := mustMatch(t, db2, subs2...)
	r3 := mustMatch(t, db1, subs...)
	j := func(r Result) string {
		b, err := json.Marshal(struct {
			F []Finding
			G []Gap
		}{r.Findings, r.Gaps})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if j(r1) != j(r2) || j(r1) != j(r3) {
		t.Fatalf("results differ:\n%s\n%s", j(r1), j(r2))
	}
}

// TestBasisSourcesWithinBound: every match path names each source ID from
// the fixed list at most once, within MaxRecordBasisSources, even for a
// vulnerability with NVD CVSS, KEV and EPSS and both DSA/DLA companions.
func TestBasisSourcesWithinBound(t *testing.T) {
	db, subs := richFixture(t)
	r := mustMatch(t, db, subs...)
	listed := map[string]bool{}
	for _, f := range vulnfeed.Feeds() {
		listed[f.SourceID] = true
	}
	var debianFull bool
	for _, f := range r.Findings {
		b := f.Record.Evidence.BasisSources
		if len(b) == 0 || len(b) > MaxRecordBasisSources {
			t.Fatalf("basis sources %d", len(b))
		}
		seen := map[string]bool{}
		for _, s := range b {
			if !listed[s.SourceID] || seen[s.SourceID] {
				t.Fatalf("basis source %q unlisted or repeated: %+v", s.SourceID, b)
			}
			seen[s.SourceID] = true
		}
		if seen["debian-tracker"] && seen["dsa"] && seen["dla"] && seen["nvd"] && seen["kev"] && seen["epss"] {
			debianFull = true
			if b[0].SourceID != "debian-tracker" {
				t.Fatalf("match source not first: %+v", b)
			}
		}
	}
	if !debianFull {
		t.Fatal("fixture lacks a finding with every score source")
	}
	// The cut fail-safe keeps the match source and its companions first.
	ev, cut := db.evidence(FeedDebianTracker, []string{FeedNVD, FeedKEV, FeedEPSS, FeedCiscoCSAF, FeedPaloAltoCSAF, FeedOSVAlpine, FeedOSVUbuntu})
	if cut != 0 || len(ev.BasisSources) != 9 {
		t.Fatalf("all nine sources: %d cut %d", len(ev.BasisSources), cut)
	}
}

// TestMatcherVersionWithinBound: at most 128 bytes and the D5 pattern.
func TestMatcherVersionWithinBound(t *testing.T) {
	if len(MatcherVersion) > 128 {
		t.Fatalf("matcher version %d bytes", len(MatcherVersion))
	}
	rec := vulnfinding.Record{
		SubjectKind: vulnfinding.SubjectHost, SubjectRef: vulnfinding.SubjectRef{ID: "h1"}, Ecosystem: "debian:bookworm",
		Component: vulnfinding.Component{SourcePackage: "zlib", SourceVersion: "1.0-1"},
		Vuln:      vulnfinding.Vuln{ID: "CVE-2024-0001"}, Fix: vulnfinding.Fix{State: vulnfinding.FixNoFixYet},
		TrackerState: vulnfinding.TrackerUnfixed, MatchBasis: vulnfinding.MatchDistroTracker,
		Evidence: vulnfinding.Evidence{BasisSources: []vulnfinding.BasisSource{{SourceID: "debian-tracker", SnapshotID: snap(1), Integrity: vulnfinding.IntegrityNone}}, MatcherVersion: MatcherVersion},
	}
	if _, err := vulnfinding.Validate(rec); err != nil {
		t.Fatalf("matcher version rejected: %v", err)
	}
}

// TestPrimaryIDRules: anchors stick, then smallest CVE, then smallest ID;
// invalid IDs are dropped and aliases cut to 16.
func TestPrimaryIDRules(t *testing.T) {
	many := []string{"GHSA-zzzz-zzzz-zzzz"}
	for i := range 20 {
		many = append(many, fmt.Sprintf("CVE-2024-%05d", 10000+i))
	}
	tests := []struct {
		name        string
		ids         []string
		anchors     []string
		wantPrimary string
		wantAliases int
		ok          bool
	}{
		{"smallest CVE", []string{"UBUNTU-CVE-2024-2", "CVE-2024-2000", "CVE-2024-1000"}, nil, "CVE-2024-1000", 2, true},
		{"lower-case CVE canonicalised", []string{"cve-2024-1000"}, nil, "CVE-2024-1000", 0, true},
		{"no CVE: smallest ID", []string{"PAN-SA-2024-1", "GHSA-aaaa-bbbb-cccc"}, nil, "GHSA-aaaa-bbbb-cccc", 1, true},
		{"anchor sticks over a smaller CVE", []string{"CVE-2026-1", "CVE-2026-1234"}, []string{"CVE-2026-1234"}, "CVE-2026-1234", 1, true},
		{"two anchors fall to rule 2", []string{"CVE-2026-2000", "CVE-2026-1000", "CVE-2026-0999"}, []string{"CVE-2026-2000", "CVE-2026-1000"}, "CVE-2026-1000", 2, true},
		{"invalid IDs dropped", []string{"CVE-2024-1000", "bad id", strings.Repeat("A", 65)}, nil, "CVE-2024-1000", 0, true},
		{"aliases cut to 16", many, nil, "CVE-2024-10000", 16, true},
		{"no valid ID", []string{"", "x y"}, nil, "", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			anchors := map[Anchor]struct{}{}
			for _, a := range tc.anchors {
				anchors[Anchor{Ecosystem: "debian:bookworm", Package: "zlib", VulnID: a}] = struct{}{}
			}
			// An anchor for another pair plays no part.
			anchors[Anchor{Ecosystem: "debian:bookworm", Package: "other", VulnID: "CVE-2024-2000"}] = struct{}{}
			p, al, _, ok := chooseIDs(tc.ids, "debian:bookworm", "zlib", anchors)
			if ok != tc.ok || p != tc.wantPrimary || len(al) != tc.wantAliases {
				t.Fatalf("primary %q aliases %v ok %v", p, al, ok)
			}
			if slices.Contains(al, p) || !slices.IsSorted(al) {
				t.Fatalf("aliases %v", al)
			}
		})
	}
}

// TestDBRejectsUnknownFeeds: source IDs only from the fixed table, data
// only after its snapshot is named.
func TestDBRejectsUnknownFeeds(t *testing.T) {
	db := NewDB()
	if err := db.SetFeed("evil-feed", FeedRef{SourceID: "evil", SnapshotID: snap(1), Integrity: vulnfinding.IntegrityNone}); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("unknown feed: %v", err)
	}
	if err := db.SetFeed(FeedDebianTracker, FeedRef{SourceID: "osv", SnapshotID: snap(1), Integrity: vulnfinding.IntegrityNone}); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("wrong source id: %v", err)
	}
	if err := db.SetFeed(FeedCiscoCSAF, FeedRef{SourceID: "cisco-csaf", SnapshotID: snap(1), Integrity: vulnfinding.IntegrityNone}); !errors.Is(err, ErrInvalidFeedRef) {
		t.Fatalf("lowered integrity: %v", err)
	}
	if err := db.SetFeed(FeedDebianTracker, FeedRef{SourceID: "debian-tracker", SnapshotID: "bad id", Integrity: vulnfinding.IntegrityNone}); !errors.Is(err, ErrInvalidFeedRef) {
		t.Fatalf("bad snapshot: %v", err)
	}
	if err := db.AddDebian(vulnfeed.DebianEntry{Package: "zlib", IssueID: "CVE-2024-1", Release: "bookworm", State: vulnfinding.TrackerUnfixed}); !errors.Is(err, ErrNoFeedSnapshot) {
		t.Fatalf("data without snapshot: %v", err)
	}
	if err := db.AddOSV("nvd-modified", vulnfeed.OSVRecord{ID: "CVE-2024-1"}); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("osv on non-osv feed: %v", err)
	}
	if _, err := Match(nil, nil, Options{}); err == nil {
		t.Fatal("nil db accepted")
	}
}

// TestMergeSameKeyKeepsOpenState: two records with one finding_key merge
// to the one that keeps the finding open; not_affected never hides one.
func TestMergeSameKeyKeepsOpenState(t *testing.T) {
	db := newDB(t)
	recs := []vulnfeed.OSVRecord{
		mkOSV("UBUNTU-CVE-2024-1111", []string{"CVE-2024-1111"}, "Ubuntu:24.04", "zlib", intro("0"), fixed("1.3.dfsg-3.1ubuntu2.1")),
		mkOSV("USN-7000-1", []string{"CVE-2024-1111"}, "Ubuntu:24.04:LTS", "zlib", intro("0"), fixed("1.3.dfsg-3.1ubuntu2.3")),
	}
	for _, r := range recs {
		if err := db.AddOSV(FeedOSVUbuntu, r); err != nil {
			t.Fatal(err)
		}
	}
	r := mustMatch(t, db, host("ubuntu:24.04", comp("zlib", "1.3.dfsg-3.1ubuntu2")))
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	f := r.Findings[0].Record
	if f.Fix.Version != "1.3.dfsg-3.1ubuntu2.3" || !slices.Equal(f.Vuln.Aliases, []string{"UBUNTU-CVE-2024-1111", "USN-7000-1"}) {
		t.Fatalf("merged = %+v", f)
	}
}

// richFixture is a lab with Debian, Ubuntu, Alpine and device subjects and
// every score source, for the cross-cutting tests.
func richFixture(t *testing.T) (*DB, []Subject) {
	t.Helper()
	db := newDB(t)
	addDeb(t, db, "openssl", "CVE-2024-9143", "bookworm", vulnfinding.TrackerFixed, "3.0.15-1~deb12u1")
	addDeb(t, db, "openssl", "CVE-2024-13176", "bookworm", vulnfinding.TrackerNoDSA, "")
	addDeb(t, db, "zlib", "CVE-2023-45853", "bookworm", vulnfinding.TrackerIgnored, "")
	addDeb(t, db, "zlib", "TEMP-0000000-ABCDEF", "bookworm", vulnfinding.TrackerNotAffected, "")
	addDeb(t, db, "linux", "CVE-2024-50264", "bookworm", vulnfinding.TrackerFixed, "6.1.119-1")
	if err := db.AddOSV(FeedOSVUbuntu, mkOSV("UBUNTU-CVE-2024-5535", []string{"CVE-2024-5535"}, "Ubuntu:24.04:LTS", "openssl", intro("0"), fixed("3.0.13-0ubuntu3.5"))); err != nil {
		t.Fatal(err)
	}
	if err := db.AddOSV(FeedOSVAlpine, mkOSV("CVE-2024-6119", nil, "Alpine:v3.20", "openssl", intro("0"), fixed("3.3.2-r1"))); err != nil {
		t.Fatal(err)
	}
	if err := db.AddKEV(vulnfeed.KEVEntry{CVE: "CVE-2024-9143", DateAdded: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetEPSS(vulnfeed.EPSSScores{Date: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), Scores: []vulnfeed.EPSSScore{{CVE: "CVE-2024-9143", Probability: 0.5, Percentile: 0.9}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddNVD(vulnfeed.NVDRecord{ID: "CVE-2024-9143", CVSS: []vulnfeed.NVDCVSS{
		{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8},
		{Version: "3.1", Vector: "CVSS:3.1/" + strings.Repeat("X", 260), BaseScore: 10},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCSAF(FeedPaloAltoCSAF, vulnfeed.CSAFAdvisory{TrackingID: "PAN-SA-2024-0015", Version: "1",
		Products:        []vulnfeed.CSAFProduct{csafProduct("p1", "vendor:paloalto:panos", "10.2.9", "10.2"), csafProduct("p2", "vendor:paloalto:panos", "10.2.10", "10.2")},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: "CVE-2024-3400", Affected: []string{"p1"}, Fixed: []string{"p2"}}}}); err != nil {
		t.Fatal(err)
	}
	deb := host("debian:bookworm", comp("openssl", "3.0.14-1~deb12u2", Binary{Name: "libssl3", Version: "3.0.14-1~deb12u2"}), comp("zlib", "1:1.2.13.dfsg-1"),
		comp("linux", "6.1.115-1"), comp("linux-signed-amd64", "6.1.115+3"))
	deb.Kernel = &Kernel{Release: "6.1.0-27-amd64", Mapped: true, SourcePackage: "linux", SourceVersion: "6.1.115-1"}
	ubu := host("ubuntu:24.04", comp("openssl", "3.0.13-0ubuntu3.4"))
	ubu.Ref.ID = "h2"
	alp := Subject{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "h1", ImageDigest: "sha256:" + strings.Repeat("ab", 32)},
		Ecosystem: "alpine:3.20", Components: []Component{comp("openssl", "3.3.2-r0")}}
	dev := Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "fw1"}, Ecosystem: "vendor:paloalto:panos", Device: &Device{Model: "PA-440", Firmware: "10.2.9"}}
	pve := host("debian:bookworm", comp("pve-manager", "8.2.4"))
	pve.Ref.ID = "pve1"
	pve.Kernel = &Kernel{Release: "6.8.12-4-pve"}
	return db, []Subject{deb, ubu, alp, dev, pve}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// FuzzMatchVersions: arbitrary installed and fixed versions never panic,
// every record passes validation, and a record is only ever emitted with a
// fixed version when vulnver says installed < fixed.
func FuzzMatchVersions(f *testing.F) {
	f.Add("3.0.14-1~deb12u2", "3.0.15-1~deb12u1", "3.3.2-r0", "3.3.2-r1", "10.2.9")
	f.Add("1:2.0-1", "2.5-1", "1.0", "1.0_rc1", "x")
	f.Add("", "", "", "", "")
	f.Fuzz(func(t *testing.T, debInst, debFix, apkInst, apkFix, fw string) {
		db := NewDB()
		for i, fd := range vulnfeed.Feeds() {
			if err := db.SetFeed(fd.Name, FeedRef{SourceID: fd.SourceID, SnapshotID: snap(i + 1), Integrity: fd.Integrity}); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.AddDebian(vulnfeed.DebianEntry{Package: "pkg", IssueID: "CVE-2024-1000", Release: "bookworm", State: vulnfinding.TrackerFixed, FixedVersion: debFix}); err != nil {
			t.Fatal(err)
		}
		if err := db.AddOSV(FeedOSVAlpine, mkOSV("CVE-2024-1001", nil, "Alpine:v3.20", "pkg", intro("0"), fixed(apkFix))); err != nil {
			t.Fatal(err)
		}
		if err := db.AddCSAF(FeedPaloAltoCSAF, vulnfeed.CSAFAdvisory{TrackingID: "PAN-SA-2024-1", Version: "1",
			Products:        []vulnfeed.CSAFProduct{csafProduct("a", "vendor:paloalto:panos", fw, "10.2")},
			Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: "CVE-2024-1002", Affected: []string{"a"}}}}); err != nil {
			t.Fatal(err)
		}
		subs := []Subject{
			host("debian:bookworm", comp("pkg", debInst)),
			{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "h1", ImageDigest: "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
				Ecosystem: "alpine:3.20", Components: []Component{comp("pkg", apkInst)}},
			{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: "vendor:paloalto:panos", Device: &Device{Model: "PA-440", Firmware: fw}},
		}
		r, err := Match(db, subs, Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Findings {
			if _, err := vulnfinding.Validate(f.Record); err != nil {
				t.Fatalf("invalid record: %v", err)
			}
			if f.Record.Fix.State == vulnfinding.FixNotAffected && f.Record.SubjectKind != vulnfinding.SubjectDevice {
				t.Fatalf("not_affected from a fixed-version entry")
			}
			if f.Record.Fix.State == vulnfinding.FixFixed && f.Record.SubjectKind != vulnfinding.SubjectDevice {
				s, err := vulnver.SchemeForEcosystem(f.Record.Ecosystem)
				if err != nil {
					t.Fatal(err)
				}
				if aff, err := vulnver.Affected(s, f.Record.Component.SourceVersion, f.Record.Fix.Version); err != nil || !aff {
					t.Fatalf("record with fix %q not above installed %q", f.Record.Fix.Version, f.Record.Component.SourceVersion)
				}
			}
		}
	})
}

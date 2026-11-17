// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// spellingE2E matches the export devices against the parsed
// synthetic-cisco-model-spellings.json fixture. The fixture holds an
// OS-wide IOS XE product (CVE-2099-1001), so every IOS XE device has an
// applying product and the device-level fallback gap never fires: each
// model-scoped vulnerability has to stand on its own.
func spellingE2E(t *testing.T, parts []nosclient.SubjectPart) Result {
	t.Helper()
	subs, err := SubjectsFromExport(exportThroughClient(t, parts))
	if err != nil {
		t.Fatal(err)
	}
	db := newDB(t)
	if err := db.AddCSAF(FeedCiscoCSAF, parsedCSAF(t, "synthetic-cisco-model-spellings.json", vulnfeed.CSAFVendorCisco)); err != nil {
		t.Fatal(err)
	}
	return mustMatch(t, db, subs...)
}

// TestParsedCSAFModelSpellingsFailClosed: a product of the device's vendor
// that is not the device's exact model is skipped only when both sides are
// distinct exact SKUs. A series name, a CPE spelling or a hardware family
// is coverage unknown for that vulnerability, even when another advisory
// of the feed applies to the device.
func TestParsedCSAFModelSpellingsFailClosed(t *testing.T) {
	const iosxe, cbs = "vendor:cisco:ios-xe", "vendor:cisco:cbs"
	r := spellingE2E(t, []nosclient.SubjectPart{
		csafDevice("cat", iosxe, "cisco", "C9300-24T", "17.9.1"),
		csafDevice("cbs350-24p", cbs, "cisco", "CBS350-24P", "3.4.0.17"),
		csafDevice("cbs350-8t", cbs, "cisco", "CBS350-8T", "3.4.0.17"),
		csafDevice("cbs250", cbs, "cisco", "CBS250-24T-4G", "3.4.0.17"),
	})

	t.Run("OS-wide product applies to the Catalyst", func(t *testing.T) {
		if _, ok := subjectFindings(r, "cat")["CVE-2099-1001"]; !ok {
			t.Fatalf("no OS-wide finding: %+v", r.Findings)
		}
	})
	t.Run("series name Catalyst 9300 Series Switches vs C9300-24T: gap", func(t *testing.T) {
		if _, ok := subjectFindings(r, "cat")["CVE-2099-1002"]; ok {
			t.Fatalf("series name decided a finding: %+v", r.Findings)
		}
		if !hasVulnGap(r, "C9300-24T", canonicalID("CVE-2099-1002"), GapDeviceModelUnknown) {
			t.Fatalf("series name dropped silently: %+v", subjectGaps(r, "cat"))
		}
	})
	t.Run("CPE spelling catalyst_9300-24t vs C9300-24T: gap", func(t *testing.T) {
		if _, ok := subjectFindings(r, "cat")["CVE-2099-1003"]; ok {
			t.Fatalf("CPE spelling decided a finding: %+v", r.Findings)
		}
		if !hasVulnGap(r, "C9300-24T", canonicalID("CVE-2099-1003"), GapDeviceModelUnknown) {
			t.Fatalf("CPE spelling dropped silently: %+v", subjectGaps(r, "cat"))
		}
	})
	t.Run("exact SKU: finding; distinct sibling SKU: skipped as different", func(t *testing.T) {
		for _, d := range []struct{ id, model, own, other string }{
			{"cbs350-24p", "CBS350-24P", "CVE-2099-1004", "CVE-2099-1005"},
			{"cbs350-8t", "CBS350-8T", "CVE-2099-1005", "CVE-2099-1004"},
		} {
			fs := subjectFindings(r, d.id)
			if _, ok := fs[d.own]; !ok {
				t.Fatalf("%s: no finding for its own SKU %s: %+v", d.id, d.own, fs)
			}
			if _, ok := fs[d.other]; ok {
				t.Fatalf("%s: sibling SKU %s decided a finding", d.id, d.other)
			}
			for _, g := range subjectGaps(r, d.id) {
				if g.VulnID == canonicalID(d.other) {
					t.Fatalf("%s: distinct sibling SKU %s is a gap, want skipped: %+v", d.id, d.other, g)
				}
			}
		}
	})
	t.Run("Cisco Business 350 Series family does not apply to CBS250", func(t *testing.T) {
		if fs := subjectFindings(r, "cbs250"); len(fs) != 0 {
			t.Fatalf("CBS250 has findings: %+v", fs)
		}
		if !hasVulnGap(r, "CBS250-24T-4G", canonicalID("CVE-2099-1006"), GapDeviceModelUnknown) {
			t.Fatalf("fixed version of the CBS350 family silenced CBS250: %+v", subjectGaps(r, "cbs250"))
		}
		for _, id := range []string{"CVE-2099-1004", "CVE-2099-1005"} {
			if hasVulnGap(r, "CBS250-24T-4G", canonicalID(id), GapDeviceModelUnknown) {
				t.Fatalf("CBS250: distinct SKU %s is a gap, want skipped", id)
			}
		}
	})
	t.Run("CBS350 family is model-scoped for a CBS350 SKU too: gap, never clean", func(t *testing.T) {
		if !hasVulnGap(r, "CBS350-24P", canonicalID("CVE-2099-1006"), GapDeviceModelUnknown) {
			t.Fatalf("family fixed version silenced CBS350-24P: %+v", subjectGaps(r, "cbs350-24p"))
		}
	})
}

// TestSiblingSKUSkippedWithAnotherApplyingAdvisory: with a second advisory
// that applies to the device (OS-wide), a distinct sibling SKU is skipped
// as a different model, while a series name or a lower-case spelling of the
// device is a per-vulnerability gap, not left to the device-level fallback.
func TestSiblingSKUSkippedWithAnotherApplyingAdvisory(t *testing.T) {
	const cbs = "vendor:cisco:cbs"
	tests := []struct {
		name, advModel string
		wantGap        bool
	}{
		{"distinct sibling SKU: skipped", "CBS350-24P", false},
		{"longer SKU of the device: gap", "CBS350-8T-E-2G", true},
		{"series name: gap", "CBS350 Series", true},
		{"lower-case spelling of a sibling SKU: gap", "cbs350_24p", true},
		{"same SKU up to case and separators: exact, no gap", "cbs350_8t", false},
		{"single family word: gap", "CBS350", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const cve = "CVE-2024-30010"
			scoped := vulnfeed.CSAFAdvisory{
				TrackingID: "cisco-sa-scoped", Version: "1.0",
				Products:        []vulnfeed.CSAFProduct{devProduct("s1", cbs, tc.advModel, "3.4.0.17", "3.4")},
				Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cve, Fixed: []string{"s1"}}},
			}
			wide := vulnfeed.CSAFAdvisory{
				TrackingID: "cisco-sa-wide", Version: "1.0",
				Products:        []vulnfeed.CSAFProduct{osProduct("w1", cbs, "3.4.0.17", "3.4")},
				Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: "CVE-2024-30011", Affected: []string{"w1"}}},
			}
			db := newDB(t)
			for _, a := range []vulnfeed.CSAFAdvisory{scoped, wide} {
				if err := db.AddCSAF(FeedCiscoCSAF, a); err != nil {
					t.Fatal(err)
				}
			}
			r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: cbs,
				Device: &Device{Model: "CBS350-8T", Firmware: "3.4.0.17"}})
			if _, ok := findingFor(r, "CBS350-8T", "CVE-2024-30011"); !ok {
				t.Fatalf("OS-wide advisory does not apply: %+v", r)
			}
			if got := hasVulnGap(r, "CBS350-8T", canonicalID(cve), GapDeviceModelUnknown); got != tc.wantGap {
				t.Fatalf("gap = %v, want %v: %+v", got, tc.wantGap, r.Gaps)
			}
		})
	}
}

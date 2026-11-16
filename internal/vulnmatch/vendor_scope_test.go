// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// hasVulnGap reports whether r holds a gap of the device model pkg with
// reason, for the vulnerability id.
func hasVulnGap(r Result, pkg, id string, reason GapReason) bool {
	for _, g := range r.Gaps {
		if g.Package == pkg && g.VulnID == id && g.Reason == reason {
			return true
		}
	}
	return false
}

// TestAdvisoryWithoutFirmwareIsGapDespiteOtherAdvisories: an advisory that
// names the device's model but lists neither its firmware nor a range stays
// coverage unknown, even when another advisory lists the firmware (HIGH:
// the firmware decision is per advisory, not per feed).
func TestAdvisoryWithoutFirmwareIsGapDespiteOtherAdvisories(t *testing.T) {
	const cbs = "vendor:cisco:cbs"
	const cveA, cveB = "CVE-2024-30001", "CVE-2024-30002"
	advA := vulnfeed.CSAFAdvisory{
		TrackingID: "cisco-sa-aaa-model-only", Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			devProduct("a1", cbs, "CBS350-24P", "3.3.0.16", "3.3"),
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cveA, Affected: []string{"a1"}}},
	}
	advB := vulnfeed.CSAFAdvisory{
		TrackingID: "cisco-sa-bbb-firmware", Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			devProduct("b1", cbs, "CBS350-24P", "3.4.0.17", "3.4"),
			devProduct("b2", cbs, "CBS350-24P", "3.4.1.3", "3.4"),
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cveB, Affected: []string{"b1"}, Fixed: []string{"b2"}}},
	}
	db := newDB(t)
	if err := db.AddCSAF(FeedCiscoCSAF, advA); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCSAF(FeedCiscoCSAF, advB); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: cbs,
		Device: &Device{Model: "CBS350-24P", Firmware: "3.4.0.17"}})
	if _, ok := findingFor(r, "CBS350-24P", cveB); !ok {
		t.Fatalf("no finding from the advisory that lists the firmware: %+v", r)
	}
	if _, ok := findingFor(r, "CBS350-24P", cveA); ok {
		t.Fatalf("finding from the advisory that does not list the firmware: %+v", r)
	}
	if !hasVulnGap(r, "CBS350-24P", canonicalID(cveA), GapDeviceVersionUnknown) {
		t.Fatalf("advisory %s names the model without firmware: want a coverage gap, got %+v", cveA, r.Gaps)
	}
	if hasVulnGap(r, "CBS350-24P", canonicalID(cveB), GapDeviceVersionUnknown) {
		t.Fatalf("gap for the advisory that lists the firmware: %+v", r.Gaps)
	}
}

// TestSiblingSKUNeverDecidesDeviceModel: a product of another SKU of the
// family (CBS350-24P for a CBS350-8T device) is never a model hit: no
// finding and no clean status for the device rest on it, only coverage
// unknown (MEDIUM: exact model or unknown).
func TestSiblingSKUNeverDecidesDeviceModel(t *testing.T) {
	const cbs = "vendor:cisco:cbs"
	const cve = "CVE-2024-30003"
	adv := vulnfeed.CSAFAdvisory{
		TrackingID: "cisco-sa-sibling", Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			devProduct("s1", cbs, "CBS350-24P", "3.4.0.17", "3.4"),
			devProduct("s2", cbs, "CBS350-24P", "3.4.1.3", "3.4"),
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cve, Affected: []string{"s1"}, Fixed: []string{"s2"}}},
	}
	tests := []struct {
		name  string
		model string
		// wantFinding: the device is the advisory's exact model.
		wantFinding bool
		// wantGap: the device is only covered by the family, so unknown.
		wantGap GapReason
	}{
		{"sibling SKU of the family: unknown, no finding", "CBS350-8T", false, GapDeviceModelUnknown},
		{"longer SKU of the family: unknown, no finding", "CBS350-24P-4G", false, GapDeviceModelUnknown},
		{"exact model of the advisory: finding", "CBS350-24P", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			if err := db.AddCSAF(FeedCiscoCSAF, adv); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: cbs,
				Device: &Device{Model: tc.model, Firmware: "3.4.0.17"}})
			_, ok := findingFor(r, tc.model, cve)
			if ok != tc.wantFinding {
				t.Fatalf("finding = %v, want %v: %+v", ok, tc.wantFinding, r)
			}
			if tc.wantGap != "" && !hasGap(r, tc.model, tc.wantGap) {
				t.Fatalf("gap %s missing: %+v", tc.wantGap, r.Gaps)
			}
			if tc.wantGap == "" && len(r.Gaps) != 0 {
				t.Fatalf("exact model has gaps: %+v", r.Gaps)
			}
		})
	}
}

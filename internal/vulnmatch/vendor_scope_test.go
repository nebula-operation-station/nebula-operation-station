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
// family never decides a device's finding or clean status, in either
// direction: a longer device model against a shorter product name and a
// shorter device model against a longer product SKU (HIGH: exact means
// equality of the model string, not a token run). Only coverage unknown.
func TestSiblingSKUNeverDecidesDeviceModel(t *testing.T) {
	const cbs = "vendor:cisco:cbs"
	const cve = "CVE-2024-30003"
	tests := []struct {
		name string
		// advModel is the product model the advisory lists: 3.4.0.17 is
		// affected, 3.4.1.3 fixed.
		advModel string
		// model and firmware are the device.
		model, firmware string
		// wantFinding: the device is the advisory's exact model.
		wantFinding bool
		// wantGap: the device is only covered by the family, so unknown.
		wantGap GapReason
	}{
		{"longer device model, shorter product: unknown", "CBS350-24P", "CBS350-24P-4G", "3.4.0.17", false, GapDeviceModelUnknown},
		{"shorter device model, longer product SKU affected: unknown", "CBS350-24P-4G", "CBS350-24P", "3.4.0.17", false, GapDeviceModelUnknown},
		{"shorter device model, longer product SKU fixed: unknown, no clean", "CBS350-24P-4G", "CBS350-24P", "3.4.1.3", false, GapDeviceModelUnknown},
		{"sibling SKU of the family: unknown", "CBS350-24P", "CBS350-8T", "3.4.0.17", false, GapDeviceModelUnknown},
		{"exact model of the advisory: finding", "CBS350-24P", "CBS350-24P", "3.4.0.17", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adv := vulnfeed.CSAFAdvisory{
				TrackingID: "cisco-sa-sibling", Version: "1.0",
				Products: []vulnfeed.CSAFProduct{
					devProduct("s1", cbs, tc.advModel, "3.4.0.17", "3.4"),
					devProduct("s2", cbs, tc.advModel, "3.4.1.3", "3.4"),
				},
				Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cve, Affected: []string{"s1"}, Fixed: []string{"s2"}}},
			}
			db := newDB(t)
			if err := db.AddCSAF(FeedCiscoCSAF, adv); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: cbs,
				Device: &Device{Model: tc.model, Firmware: tc.firmware}})
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

// TestSiblingNameNeverMakesModelHit: the product's model is its product
// name. A model string that only sits inside the full name (which carries
// version and vendor words) is no exact hit, and a version's digits never
// form a device model (LOW: no match across field boundaries).
func TestSiblingNameNeverMakesModelHit(t *testing.T) {
	const cbs = "vendor:cisco:cbs"
	const cve = "CVE-2024-30004"
	adv := vulnfeed.CSAFAdvisory{
		TrackingID: "cisco-sa-name", Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			{ProductID: "n1", Name: "Cisco CBS350-24P 3.4.0.17", Product: "CBS350", Version: "3.4.0.17", Train: "3.4", Ecosystem: cbs},
			{ProductID: "n2", Name: "Cisco CBS350-24P 3.4.1.3", Product: "CBS350", Version: "3.4.1.3", Train: "3.4", Ecosystem: cbs},
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cve, Affected: []string{"n1"}, Fixed: []string{"n2"}}},
	}
	db := newDB(t)
	if err := db.AddCSAF(FeedCiscoCSAF, adv); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: cbs,
		Device: &Device{Model: "CBS350-24P", Firmware: "3.4.1.3"}})
	if _, ok := findingFor(r, "CBS350-24P", cve); ok {
		t.Fatalf("model found in the full name, not in the product: %+v", r)
	}
	if !hasGap(r, "CBS350-24P", GapDeviceModelUnknown) {
		t.Fatalf("want coverage unknown, got %+v", r.Gaps)
	}
}

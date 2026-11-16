// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// nearCase is one device model and a product of the same ecosystem whose
// model string is not equal to it. The firmware pair is affected and fixed.
type nearCase struct {
	name, eco, feed string
	model, near     string
	fw, fixedFW     string
}

var nearCases = []nearCase{
	{"space instead of hyphen, series word", "vendor:paloalto:panos", FeedPaloAltoCSAF, "PA-440", "PA 440 Series", "10.2.9", "10.2.10"},
	{"series word", "vendor:paloalto:panos", FeedPaloAltoCSAF, "PA-440", "PA-440 Series", "10.2.9", "10.2.10"},
	{"vendor prefix", "vendor:paloalto:panos", FeedPaloAltoCSAF, "PA-440", "X-PA-440", "10.2.9", "10.2.10"},
	{"version word in model", "vendor:paloalto:panos", FeedPaloAltoCSAF, "PA-440", "PA-440 10.2.9", "10.2.9", "10.2.10"},
	{"shorter number", "vendor:paloalto:panos", FeedPaloAltoCSAF, "PA-440", "PA-44", "10.2.9", "10.2.10"},
	{"longer SKU of the device", "vendor:cisco:cbs", FeedCiscoCSAF, "CBS350-24P", "CBS350-24P-4G", "3.4.0.17", "3.4.1.3"},
	{"shorter SKU of the device", "vendor:cisco:cbs", FeedCiscoCSAF, "CBS350-24P-4G", "CBS350-24P", "3.4.0.17", "3.4.1.3"},
	{"sibling SKU of the family", "vendor:cisco:cbs", FeedCiscoCSAF, "CBS350-24P", "CBS350-8T", "3.4.0.17", "3.4.1.3"},
}

// nearAdvisory is an advisory that lists the near product (affected at fw,
// fixed at fixedFW) under CVE id.
func nearAdvisory(c nearCase, id string) vulnfeed.CSAFAdvisory {
	return vulnfeed.CSAFAdvisory{
		TrackingID: "near-" + id, Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			devProduct("n1", c.eco, c.near, c.fw, "x"),
			devProduct("n2", c.eco, c.near, c.fixedFW, "x"),
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: id, Affected: []string{"n1"}, Fixed: []string{"n2"}}},
	}
}

// exactAdvisory is an advisory that lists the device's exact model with the
// same firmware pair under CVE id.
func exactAdvisory(c nearCase, id string) vulnfeed.CSAFAdvisory {
	return vulnfeed.CSAFAdvisory{
		TrackingID: "exact-" + id, Version: "1.0",
		Products: []vulnfeed.CSAFProduct{
			devProduct("e1", c.eco, c.model, c.fw, "x"),
			devProduct("e2", c.eco, c.model, c.fixedFW, "x"),
		},
		Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: id, Affected: []string{"e1"}, Fixed: []string{"e2"}}},
	}
}

// TestNearNameProductIsCoverageGapNeverSilent: a product whose model is only
// a near name of the device is never silent. When it is the only advisory,
// the device has no finding and no clean status: coverage is unknown. When
// an exact advisory covers the firmware, the near advisory's vulnerability is
// still a coverage gap, so the device is never clean (HIGH: a near-name
// advisory must not vanish while another advisory hits the model).
func TestNearNameProductIsCoverageGapNeverSilent(t *testing.T) {
	const cveNear, cveExact = "CVE-2024-40001", "CVE-2024-40002"
	for _, c := range nearCases {
		t.Run(c.name+": only the near advisory", func(t *testing.T) {
			db := newDB(t)
			if err := db.AddCSAF(c.feed, nearAdvisory(c, cveNear)); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, deviceSubject(c.eco, c.model, c.fw))
			if _, ok := findingFor(r, c.model, cveNear); ok {
				t.Fatalf("near name decided a finding: %+v", r)
			}
			if !hasGap(r, c.model, GapDeviceModelUnknown) {
				t.Fatalf("near name is silent, want coverage unknown: %+v", r.Gaps)
			}
		})
		t.Run(c.name+": near advisory beside an exact one", func(t *testing.T) {
			db := newDB(t)
			if err := db.AddCSAF(c.feed, nearAdvisory(c, cveNear)); err != nil {
				t.Fatal(err)
			}
			if err := db.AddCSAF(c.feed, exactAdvisory(c, cveExact)); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, deviceSubject(c.eco, c.model, c.fw))
			if _, ok := findingFor(r, c.model, cveExact); !ok {
				t.Fatalf("exact advisory gives no finding: %+v", r)
			}
			if _, ok := findingFor(r, c.model, cveNear); ok {
				t.Fatalf("near name decided a finding: %+v", r)
			}
			if !hasVulnGap(r, c.model, canonicalID(cveNear), GapDeviceModelUnknown) {
				t.Fatalf("near advisory %s is silent: want coverage gap, got %+v", cveNear, r.Gaps)
			}
			if len(r.Gaps) == 0 {
				t.Fatalf("device is clean despite a near-name advisory: %+v", r)
			}
		})
	}
}

// TestFoldedEqualModelIsExactHit: a product whose model equals the device's
// model after folding case, white space and separators is the exact model. It
// decides a finding and leaves no gap ("CBS350 24P" is "CBS350-24P").
func TestFoldedEqualModelIsExactHit(t *testing.T) {
	tests := []struct {
		name, eco, feed, device, product, fw, fixedFW string
	}{
		{"white space for hyphen", "vendor:cisco:cbs", FeedCiscoCSAF, "CBS350-24P", "CBS350 24P", "3.4.0.17", "3.4.1.3"},
		{"case and white space", "vendor:paloalto:panos", FeedPaloAltoCSAF, "PA-440", "pa 440", "10.2.9", "10.2.10"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const cve = "CVE-2024-40003"
			adv := vulnfeed.CSAFAdvisory{
				TrackingID: "folded", Version: "1.0",
				Products: []vulnfeed.CSAFProduct{
					devProduct("f1", tc.eco, tc.product, tc.fw, "x"),
					devProduct("f2", tc.eco, tc.product, tc.fixedFW, "x"),
				},
				Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cve, Affected: []string{"f1"}, Fixed: []string{"f2"}}},
			}
			db := newDB(t)
			if err := db.AddCSAF(tc.feed, adv); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, deviceSubject(tc.eco, tc.device, tc.fw))
			if _, ok := findingFor(r, tc.device, cve); !ok {
				t.Fatalf("folded-equal model gives no finding: %+v", r)
			}
			if len(r.Gaps) != 0 {
				t.Fatalf("folded-equal model left gaps: %+v", r.Gaps)
			}
		})
	}
}

// TestSiblingSKUBothDirectionsIsGapNeverClean: with an exact advisory and a
// sibling SKU advisory for the same firmware, the sibling's vulnerability is a
// coverage gap in both directions, and the device is never clean.
func TestSiblingSKUBothDirectionsIsGapNeverClean(t *testing.T) {
	const cveNear, cveExact = "CVE-2024-40004", "CVE-2024-40005"
	for _, c := range nearCases {
		if c.eco != "vendor:cisco:cbs" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			db := newDB(t)
			if err := db.AddCSAF(c.feed, nearAdvisory(c, cveNear)); err != nil {
				t.Fatal(err)
			}
			if err := db.AddCSAF(c.feed, exactAdvisory(c, cveExact)); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, deviceSubject(c.eco, c.model, c.fw))
			if !hasVulnGap(r, c.model, canonicalID(cveNear), GapDeviceModelUnknown) {
				t.Fatalf("sibling SKU is not a gap: %+v", r.Gaps)
			}
			if len(r.Gaps) == 0 {
				t.Fatalf("device is clean with a sibling-SKU advisory: %+v", r)
			}
		})
	}
}

// deviceSubject is a device of ecosystem eco with the given model and firmware.
func deviceSubject(eco, model, fw string) Subject {
	return Subject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "d1"}, Ecosystem: eco,
		Device: &Device{Model: model, Firmware: fw}}
}

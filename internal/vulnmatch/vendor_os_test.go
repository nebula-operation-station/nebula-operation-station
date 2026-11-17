// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// TestProductModelScope: how a product's structured models relate to the
// device's model. No model is OS-wide; the exact model is the device; a
// near name or an unreadable scope is unknown; only other models is not the
// device.
func TestProductModelScope(t *testing.T) {
	tests := []struct {
		name       string
		models     []string
		incomplete bool
		device     string
		want       modelScope
	}{
		{"no model: every device of the OS", nil, false, "PA-440", scopeAll},
		{"exact model", []string{"PA-220", "PA-440"}, false, "PA-440", scopeDevice},
		{"exact model despite an incomplete rest", []string{"PA-440"}, true, "PA-440", scopeDevice},
		{"other models only", []string{"PA-220", "PA-3220"}, false, "PA-440", scopeOther},
		{"near name among others", []string{"PA-220", "PA-440 Series"}, false, "PA-440", scopeUnknown},
		{"shorter SKU", []string{"CBS350-24P"}, false, "CBS350-24P-4G", scopeUnknown},
		{"incomplete scope", nil, true, "PA-440", scopeUnknown},
		{"incomplete scope with other models", []string{"PA-220"}, true, "PA-440", scopeUnknown},
		{"blank model is unreadable", []string{" - "}, false, "PA-440", scopeUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := newIndexedProduct(vulnfeed.CSAFProduct{Models: tc.models, ModelsIncomplete: tc.incomplete})
			if got := newDeviceModel(tc.device).scope(ip); got != tc.want {
				t.Fatalf("scope = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestDeviceMatchModelOSVersion: a device is affected when the product's OS
// (ecosystem) and exact version match and the product names no model or the
// device's model. Another OS or another version never decides; a product
// naming only other models leaves the device not affected; a device without
// a finding is never clean unless an applying product lists its firmware.
func TestDeviceMatchModelOSVersion(t *testing.T) {
	const panos, iosxe, cve = "vendor:paloalto:panos", "vendor:cisco:ios-xe", "CVE-2024-50001"
	tests := []struct {
		name        string
		eco         string
		models      []string
		incomplete  bool
		version     string
		wantFinding bool
		wantVulnGap GapReason
	}{
		{"OS and version, no model named", panos, nil, false, "10.2.9", true, ""},
		{"OS and version, device model named", panos, []string{"PA-440"}, false, "10.2.9", true, ""},
		{"OS and version, other model named: not affected", panos, []string{"PA-220"}, false, "10.2.9", false, ""},
		{"OS and version, near model named: unknown", panos, []string{"PA-440 Series"}, false, "10.2.9", false, GapDeviceModelUnknown},
		{"OS and version, unreadable model scope: unknown", panos, nil, true, "10.2.9", false, GapDeviceModelUnknown},
		{"other OS, same version: not this device", iosxe, nil, false, "10.2.9", false, ""},
		{"OS, other version, no model: not listed", panos, nil, false, "10.2.8", false, ""},
		{"OS, other version, device model: version unknown", panos, []string{"PA-440"}, false, "10.2.8", false, GapDeviceVersionUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := osProduct("a", tc.eco, tc.version, "10.2")
			p.Models, p.ModelsIncomplete = tc.models, tc.incomplete
			db := newDB(t)
			adv := vulnfeed.CSAFAdvisory{TrackingID: "PAN-SA-2024-0100", Version: "1",
				Products:        []vulnfeed.CSAFProduct{p},
				Vulnerabilities: []vulnfeed.CSAFVulnerability{{CVE: cve, Affected: []string{"a"}}}}
			if err := db.AddCSAF(FeedPaloAltoCSAF, adv); err != nil {
				t.Fatal(err)
			}
			r := mustMatch(t, db, deviceSubject(panos, "PA-440", "10.2.9"))
			if _, ok := findingFor(r, "PA-440", cve); ok != tc.wantFinding {
				t.Fatalf("finding = %v, want %v: %+v", ok, tc.wantFinding, r)
			}
			for _, g := range []GapReason{GapDeviceModelUnknown, GapDeviceVersionUnknown} {
				want := g == tc.wantVulnGap
				if got := hasVulnGap(r, "PA-440", canonicalID(cve), g); got != want {
					t.Fatalf("vulnerability gap %s = %v, want %v: %+v", g, got, want, r.Gaps)
				}
			}
			if !tc.wantFinding && len(r.Gaps) == 0 {
				t.Fatalf("device without a finding is clean: %+v", r)
			}
		})
	}
}

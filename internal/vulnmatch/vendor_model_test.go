// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import "testing"

// TestProductNamesDeviceModel: a CSAF product names a device's model only as
// whole tokens; a longer or shorter number, or a bare vendor word, is no hit
// (ADR 0011 D4: no guessing a model from a near name).
func TestProductNamesDeviceModel(t *testing.T) {
	tests := []struct {
		name    string
		product string
		model   string
		want    bool
	}{
		{"exact family in a product name", "Cisco CBS350 Series Managed Switches", "CBS350-24P-4G", true},
		{"whole model in a product name", "PA-440", "PA-440", true},
		{"family must not match a longer number", "Cisco CBS3504 Series", "CBS350-24P", false},
		{"family must not match a shorter number", "Cisco CBS35 Series", "CBS350-24P", false},
		{"other family of the same vendor", "Cisco CBS250 Series", "CBS350-24P", false},
		{"bare vendor word is no key for PA-220", "PAN-OS 10.2", "PA-220", false},
		{"product without any model", "PAN-OS", "PA-440", false},
		{"empty model names nothing", "PA-440", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := namesModel(tc.product, modelKeys(tc.model)); got != tc.want {
				t.Fatalf("namesModel(%q, %q) = %v, want %v", tc.product, tc.model, got, tc.want)
			}
		})
	}
}

// TestModelKeysKeepOnlyDigitFamilies: the family key exists only for a
// family with a letter and a digit, so "PA" never names a product.
func TestModelKeysKeepOnlyDigitFamilies(t *testing.T) {
	if got := len(modelKeys("PA-440")); got != 1 {
		t.Fatalf("keys for PA-440 = %d, want 1 (the whole model)", got)
	}
	if got := len(modelKeys("CBS350-24P-4G")); got != 2 {
		t.Fatalf("keys for CBS350-24P-4G = %d, want 2 (model and family)", got)
	}
}

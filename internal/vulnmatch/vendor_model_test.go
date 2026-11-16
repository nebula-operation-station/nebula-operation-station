// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import "testing"

// TestProductNamesDeviceModel: a CSAF product names a device's model only as
// whole tokens. Only the exact model is a model hit; a sibling SKU of the
// family names the family, which is a coverage hint and never a hit (ADR
// 0011 D4: no guessing a model from a near name).
func TestProductNamesDeviceModel(t *testing.T) {
	tests := []struct {
		name    string
		product string
		model   string
		want    modelNaming
	}{
		{"whole model in a product name", "PA-440", "PA-440", namesExact},
		{"whole model with its family in the name", "Cisco CBS350-24P-4G Switch", "CBS350-24P-4G", namesExact},
		{"family only: a sibling SKU is no model hit", "Cisco CBS350 Series Managed Switches", "CBS350-24P-4G", namesFamily},
		{"sibling SKU of the family is no model hit", "Cisco CBS350-24P", "CBS350-8T", namesFamily},
		{"family must not match a longer number", "Cisco CBS3504 Series", "CBS350-24P", namesNothing},
		{"family must not match a shorter number", "Cisco CBS35 Series", "CBS350-24P", namesNothing},
		{"other family of the same vendor", "Cisco CBS250 Series", "CBS350-24P", namesNothing},
		{"bare vendor word is no key for PA-220", "PAN-OS 10.2", "PA-220", namesNothing},
		{"product without any model", "PAN-OS", "PA-440", namesNothing},
		{"empty model names nothing", "PA-440", "", namesNothing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newDeviceModel(tc.model).naming(modelTokens(tc.product))
			if got != tc.want {
				t.Fatalf("naming(%q, %q) = %v, want %v", tc.product, tc.model, got, tc.want)
			}
		})
	}
}

// TestDeviceFamilyKeyNeedsLetterAndDigit: the family key exists only for a
// family with a letter and a digit, so "PA" never names a product.
func TestDeviceFamilyKeyNeedsLetterAndDigit(t *testing.T) {
	if got := newDeviceModel("PA-440").family; got != nil {
		t.Fatalf("family of PA-440 = %v, want none", got)
	}
	if got := newDeviceModel("CBS350-24P-4G").family; len(got) != 1 || got[0] != "cbs350" {
		t.Fatalf("family of CBS350-24P-4G = %v, want [cbs350]", got)
	}
}

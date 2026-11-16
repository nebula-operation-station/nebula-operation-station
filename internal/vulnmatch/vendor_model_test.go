// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import "testing"

// TestProductNamesDeviceModel: a CSAF product names a device's model only by
// equality of the normalised model strings (case and white space). Only the
// exact model is a model hit. A sibling SKU in either direction, a prefix or
// a suffix is no hit: a sibling of the family is a coverage hint at most (ADR
// 0011 D4: no guessing a model from a near name).
func TestProductNamesDeviceModel(t *testing.T) {
	tests := []struct {
		name    string
		product string
		model   string
		want    modelNaming
	}{
		{"whole model equal", "PA-440", "PA-440", namesExact},
		{"model equal up to case", "pa-440", "PA-440", namesExact},
		{"model equal up to white space", " CBS350 24P ", "CBS350 24P", namesExact},
		{"shorter device model, longer product SKU", "CBS350-24P-4G", "CBS350-24P", namesFamily},
		{"longer device model, shorter product SKU", "CBS350-24P", "CBS350-24P-4G", namesFamily},
		{"sibling SKU of the family is no model hit", "CBS350-24P", "CBS350-8T", namesFamily},
		{"family only: a sibling SKU is no model hit", "CBS350 Series", "CBS350-24P-4G", namesFamily},
		{"prefix of the model is no model hit", "PA-44", "PA-440", namesNothing},
		{"suffix of the model is no model hit", "X-PA-440", "PA-440", namesNothing},
		{"family must not match a longer number", "CBS3504 Series", "CBS350-24P", namesNothing},
		{"family must not match a shorter number", "CBS35 Series", "CBS350-24P", namesNothing},
		{"other family of the same vendor", "CBS250 Series", "CBS350-24P", namesNothing},
		{"bare vendor word is no key for PA-220", "PAN-OS", "PA-220", namesNothing},
		{"version digits are no device model", "PAN-OS 10.2.9", "10-2", namesNothing},
		{"model string across a field boundary is no hit", "PA-440 10.2.9", "PA-440", namesNothing},
		{"empty model names nothing", "PA-440", "", namesNothing},
		{"empty product names nothing", "", "PA-440", namesNothing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newDeviceModel(tc.model).naming(newProductModel(tc.product))
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

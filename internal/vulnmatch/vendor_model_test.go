// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"strings"
	"testing"
)

// TestProductIsExactModelOnlyByFoldedEquality: a CSAF product is the device's
// model only when the normalised model strings are equal. Normalisation folds
// case, white space, '-' and '_' to one separator and nothing else. Every
// other string, a sibling SKU, a prefix, a suffix or a near name with a
// series or version word, is not an exact hit (ADR 0011 D4: no guessing a
// model from a near name).
func TestProductIsExactModelOnlyByFoldedEquality(t *testing.T) {
	tests := []struct {
		name    string
		product string
		model   string
		want    bool
	}{
		{"whole model equal", "PA-440", "PA-440", true},
		{"model equal up to case", "pa-440", "PA-440", true},
		{"white space folds to the separator", "PA 440", "PA-440", true},
		{"underscore folds to the separator", "PA_440", "PA-440", true},
		{"model equal up to white space", " CBS350 24P ", "CBS350-24P", true},
		{"separator run folds to one", "CBS350--24P", "CBS350-24P", true},
		{"series word is no exact hit", "PA-440 Series", "PA-440", false},
		{"vendor prefix is no exact hit", "X-PA-440", "PA-440", false},
		{"version suffix is no exact hit", "PA-440 10.2.9", "PA-440", false},
		{"longer product SKU is no exact hit", "CBS350-24P-4G", "CBS350-24P", false},
		{"shorter product SKU is no exact hit", "CBS350-24P", "CBS350-24P-4G", false},
		{"sibling SKU of the family is no exact hit", "CBS350-8T", "CBS350-24P", false},
		{"family word is no exact hit", "CBS350 Series", "CBS350-24P", false},
		{"longer number is no exact hit", "CBS3504 Series", "CBS350-24P", false},
		{"prefix of the model is no exact hit", "PA-44", "PA-440", false},
		{"empty product is no exact hit", "", "PA-440", false},
		{"empty model is no exact hit", "PA-440", "", false},
		{"both empty is no exact hit", "", "", false},
		{"blank model is no exact hit", "PA-440", "  ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newDeviceModel(tc.model).isExact(newProductModel(tc.product))
			if got != tc.want {
				t.Fatalf("isExact(%q, %q) = %v, want %v", tc.product, tc.model, got, tc.want)
			}
		})
	}
}

// TestOnlyDistinctExactSKUsDiffer: a product model is provably another
// model only when both it and the device model are exact SKUs (upper-case
// letters and digits in '-'-separated parts), they differ and neither is a
// whole-word run of the other. Series names, CPE and lower-case spellings
// and family words never prove a device not affected.
func TestOnlyDistinctExactSKUsDiffer(t *testing.T) {
	tests := []struct {
		name, product, model string
		want                 bool
	}{
		{"distinct sibling SKUs", "CBS350-24P", "CBS350-8T", true},
		{"distinct PAN-OS appliances", "PA-440", "PA-3220", true},
		{"distinct Catalyst SKUs", "C9300-48T", "C9300-24T", true},
		{"series name", "Catalyst 9300 Series Switches", "C9300-24T", false},
		{"CPE spelling", "catalyst_9300-24t", "C9300-24T", false},
		{"lower-case sibling", "cbs350-24p", "CBS350-8T", false},
		{"family word without part", "CBS350", "CBS350-8T", false},
		{"longer SKU of the device", "CBS350-24P-4G", "CBS350-24P", false},
		{"shorter SKU of the device", "CBS350-24P", "CBS350-24P-4G", false},
		{"device model not an exact SKU", "CBS350-24P", "cbs350-8t", false},
		{"letters only", "PA-ABC", "PA-440", false},
		{"over-long SKU", "C9300-" + strings.Repeat("A", MaxExactSKULen), "C9300-24T", false},
		{"equal", "PA-440", "PA-440", false},
		// Series designations written like SKUs are coverage gaps, never a
		// distinct model: a round PAN-OS series name ends in 00, and a Cisco
		// SKU without its type letter is a family or port count.
		{"PAN-OS series PA-400 vs PA-440: gap", "PA-400", "PA-440", false},
		{"PAN-OS series PA-5400 vs PA-5450: gap", "PA-5400", "PA-5450", false},
		{"PAN-OS device is the series: gap", "PA-440", "PA-400", false},
		{"Catalyst port count vs SKU: gap", "C9300-24", "C9300-24T", false},
		{"Catalyst SKU vs port count of the device: gap", "C9300-24T", "C9300-24", false},
		{"PAN-OS distinct appliance still differs", "PA-3220", "PA-440", true},
		{"Catalyst sibling SKUs still differ", "C9300-48T", "C9300-24T", true},
		{"unknown vendor scheme: gap", "FOO-12A", "FOO-34B", false},
		{"mixed schemes: gap", "CBS350-8T", "PA-440", false},
		{"prefix of the other SKU: gap", "CBS350-24P", "CBS350-24PX", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := newDeviceModel(tc.model).differs(newProductModel(tc.product)); got != tc.want {
				t.Fatalf("differs(%q, %q) = %v, want %v", tc.product, tc.model, got, tc.want)
			}
		})
	}
}

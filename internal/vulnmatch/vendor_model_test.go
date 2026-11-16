// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import "testing"

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

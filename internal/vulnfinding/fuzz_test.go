// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import "testing"

// FuzzParseRecord checks ParseRecord never panics and that every accepted
// record re-validates to the same key.
func FuzzParseRecord(f *testing.F) {
	for _, s := range []string{validHostJSON, validImageJSON, validDeviceJSON, validHostJSONReordered, `{}`, `{"finding_key":"x"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseRecord(data)
		if err != nil {
			return
		}
		again, err := Validate(got.Record)
		if err != nil {
			t.Fatalf("accepted record fails re-validation: %v", err)
		}
		if again.Key != got.Key {
			t.Fatalf("key not stable across re-validation")
		}
	})
}

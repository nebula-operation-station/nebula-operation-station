// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import "testing"

// TestLiveWantRejectsCaseVariantKeys pins that a want-list key must match the
// schema name byte for byte. encoding/json would otherwise bind "VERSION" to
// version, so a document could carry a field the schema does not define.
func TestLiveWantRejectsCaseVariantKeys(t *testing.T) {
	cases := map[string]string{
		"top-level case variant": `{"VERSION":1,"written_unix":1000,"expires_unix":1030,"targets":[]}`,
		"target case variant":    `{"version":1,"written_unix":1000,"expires_unix":1030,"targets":[{"Remote":"remote-a","kind":"node","node":"pve1","vmid":0}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLiveWant([]byte(raw)); err == nil {
				t.Fatal("DecodeLiveWant accepted a case-variant key")
			}
		})
	}
}

// TestLiveWantRejectsDuplicateKeys pins that a repeated key is refused rather
// than letting the last occurrence win.
func TestLiveWantRejectsDuplicateKeys(t *testing.T) {
	raw := `{"version":1,"version":1,"written_unix":1000,"expires_unix":1030,"targets":[]}`
	if _, err := DecodeLiveWant([]byte(raw)); err == nil {
		t.Fatal("DecodeLiveWant accepted a duplicate key")
	}
}

// TestLiveSamplesRejectsCaseVariantKeys is the samples counterpart of
// TestLiveWantRejectsCaseVariantKeys, for top-level and sample members.
func TestLiveSamplesRejectsCaseVariantKeys(t *testing.T) {
	cases := map[string]string{
		"top-level case variant": `{"version":1,"Remote":"remote-a","written_unix":1000,"samples":[]}`,
		"sample case variant":    `{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"node","node":"pve1","vmid":0,"CPU":0.5,"mem_used":1,"mem_total":2,"disk_used":1,"disk_total":2,"net_in":1,"net_out":1,"observed_unix":1}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLiveSamples([]byte(raw)); err == nil {
				t.Fatal("DecodeLiveSamples accepted a case-variant key")
			}
		})
	}
}

// TestLiveSamplesRejectsDuplicateSampleKeys pins that a repeated sample key is
// refused, so one sample cannot carry two cpu values.
func TestLiveSamplesRejectsDuplicateSampleKeys(t *testing.T) {
	raw := `{"version":1,"remote":"remote-a","written_unix":1000,"samples":[{"kind":"node","node":"pve1","vmid":0,"cpu":0.9,"cpu":0.5,"mem_used":1,"mem_total":2,"disk_used":1,"disk_total":2,"net_in":1,"net_out":1,"observed_unix":1}]}`
	if _, err := DecodeLiveSamples([]byte(raw)); err == nil {
		t.Fatal("DecodeLiveSamples accepted a duplicate sample key")
	}
}

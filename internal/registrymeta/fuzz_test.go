// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"strings"
	"testing"
)

// FuzzLatestStable drives LatestStable with arbitrary current tags and tag
// lists. It must never panic, must never return an error for the zero Policy,
// and must only report a non-unknown status together with a concrete tag.
func FuzzLatestStable(f *testing.F) {
	f.Add("1.2.3", "1.2.3 1.3.0 latest")
	f.Add("1.2.3-alpine", "1.2.3-alpine 1.4.0-alpine 1.4.0")
	f.Add("latest", "1.2.3 1.3.0")
	f.Add("", "1.2.3")
	f.Add("1.2.3-rc1", "1.2.3 1.2.4")
	f.Add("2024-01-15", "2024-01-15 2024-02-20")
	f.Add("1.2.0", "1.2 1.2.0")
	f.Add("v1.2.0", "v1.3.0 1.3.0")

	f.Fuzz(func(t *testing.T, current string, tagBlob string) {
		var tags []string
		for _, s := range strings.Fields(tagBlob) {
			tags = append(tags, s)
			if len(tags) >= 64 {
				break
			}
		}

		res, err := LatestStable(current, tags, Policy{})
		if err != nil {
			t.Fatalf("zero Policy must not error, got %v", err)
		}
		switch res.Status {
		case StatusUnknown, StatusUpToDate, StatusNewer:
		default:
			t.Fatalf("invalid status %v", res.Status)
		}
		if res.Status != StatusUnknown && res.Latest == "" {
			t.Fatalf("status %v requires a concrete Latest tag", res.Status)
		}
		if res.PolicyVersion == "" {
			t.Fatal("PolicyVersion must be recorded")
		}
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// TestSuffixOnlyDifferenceIsNeverAnotherModel: two Cisco SKUs with the same
// base model and different license or bundle suffixes ("C9300-24T-E" vs
// "C9300-24T-A") are the same hardware. The product is not an exact hit, so
// the vulnerability is coverage unknown for the device and is never skipped
// as another model. Only a different base ("C9300-48P") is provably another
// model. The fixture is parsed by the production CSAF parser.
func TestSuffixOnlyDifferenceIsNeverAnotherModel(t *testing.T) {
	const iosxe = "vendor:cisco:ios-xe"
	subs, err := SubjectsFromExport(exportThroughClient(t, []nosclient.SubjectPart{
		csafDevice("e-suffix", iosxe, "cisco", "C9300-24T-E", "17.9.1"),
		csafDevice("p48-suffix", iosxe, "cisco", "C9300-48P-E", "17.9.1"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	db := newDB(t)
	if err := db.AddCSAF(FeedCiscoCSAF, parsedCSAF(t, "synthetic-cisco-suffix-skus.json", vulnfeed.CSAFVendorCisco)); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, subs...)

	t.Run("C9300-24T-E vs product C9300-24T-A: same base, gap, never skipped", func(t *testing.T) {
		if fs := subjectFindings(r, "e-suffix"); len(fs) != 0 {
			t.Fatalf("suffix-only product decided a finding: %+v", fs)
		}
		if !hasVulnGap(r, "C9300-24T-E", canonicalID("CVE-2099-3001"), GapDeviceModelUnknown) {
			t.Fatalf("suffix-only product skipped silently: %+v", subjectGaps(r, "e-suffix"))
		}
	})
	t.Run("C9300-24T-E vs product C9300-48P: other base, skipped as another model", func(t *testing.T) {
		if hasVulnGap(r, "C9300-24T-E", canonicalID("CVE-2099-3002"), GapDeviceModelUnknown) {
			t.Fatalf("distinct base C9300-48P is a gap, want skipped: %+v", subjectGaps(r, "e-suffix"))
		}
	})
	t.Run("C9300-48P-E vs product C9300-24T-A: other base, skipped as another model", func(t *testing.T) {
		if hasVulnGap(r, "C9300-48P-E", canonicalID("CVE-2099-3001"), GapDeviceModelUnknown) {
			t.Fatalf("distinct base C9300-24T-A is a gap, want skipped: %+v", subjectGaps(r, "p48-suffix"))
		}
	})
}

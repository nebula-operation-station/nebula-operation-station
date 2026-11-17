// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// TestSeriesWrittenLikeSKUIsCoverageGap: a PAN-OS product that names a series
// designation in SKU shape ("PA-400", "PA-5400") is not a different model of
// the device. It is coverage unknown for the device, and only a distinct
// complete SKU ("PA-3220") is skipped as another model (fail closed, ADR 0011
// D4). The fixture is parsed by the production CSAF parser.
func TestSeriesWrittenLikeSKUIsCoverageGap(t *testing.T) {
	const panos = "vendor:paloalto:panos"
	subs, err := SubjectsFromExport(exportThroughClient(t, []nosclient.SubjectPart{
		csafDevice("pa440", panos, "paloalto", "PA-440", "10.2.9"),
		csafDevice("pa5450", panos, "paloalto", "PA-5450", "10.2.9"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	db := newDB(t)
	if err := db.AddCSAF(FeedPaloAltoCSAF, parsedCSAF(t, "synthetic-series-like-skus.json", vulnfeed.CSAFVendorPaloAlto)); err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, db, subs...)

	for _, d := range []struct{ id, model string }{{"pa440", "PA-440"}, {"pa5450", "PA-5450"}} {
		t.Run(d.model+" with series-like products: gap, never clean", func(t *testing.T) {
			if fs := subjectFindings(r, d.id); len(fs) != 0 {
				t.Fatalf("%s: findings from series-like products: %+v", d.id, fs)
			}
			for _, cve := range []string{"CVE-2099-2001", "CVE-2099-2002"} {
				if !hasVulnGap(r, d.model, canonicalID(cve), GapDeviceModelUnknown) {
					t.Fatalf("%s: %s is not a gap: %+v", d.id, cve, subjectGaps(r, d.id))
				}
			}
		})
		t.Run(d.model+" vs distinct SKU PA-3220: skipped as another model", func(t *testing.T) {
			if hasVulnGap(r, d.model, canonicalID("CVE-2099-2003"), GapDeviceModelUnknown) {
				t.Fatalf("%s: distinct SKU PA-3220 is a gap, want skipped: %+v", d.id, subjectGaps(r, d.id))
			}
		})
	}
}

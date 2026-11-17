// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// parsedCSAF parses a CSAF fixture with the production parser and round-trips
// the result through JSON, as the accepted state stores it between syncs.
//
// cisco-sa-iosxe-webui-privesc-j22saa4z.json and cve-2024-3400.json are
// abridged after the public Cisco and Palo Alto Networks CSAF advisories:
// their product tree shape (vendor, OS family or product name, versions and
// ranges) follows the providers'; products and status entries are cut down.
// synthetic-model-scoped.json is not a real advisory: it covers the
// model-scoped tree shapes (relationships, CPE, wildcard model numbers).
func parsedCSAF(t *testing.T, file string, vendor vulnfeed.CSAFVendor) vulnfeed.CSAFAdvisory {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "csaf", file))
	if err != nil {
		t.Fatal(err)
	}
	adv, err := vulnfeed.ParseCSAFAdvisory(b, vendor)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	state, err := json.Marshal(adv)
	if err != nil {
		t.Fatal(err)
	}
	var stored vulnfeed.CSAFAdvisory
	if err := json.Unmarshal(state, &stored); err != nil {
		t.Fatal(err)
	}
	return stored
}

// csafDevice is a device part of an export as NOS sends it.
func csafDevice(id, eco, vendor, model, firmware string) nosclient.SubjectPart {
	return nosclient.SubjectPart{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: id},
		Ecosystem: eco,
		Device:    &nosclient.Device{Vendor: vendor, Model: model, FirmwareVersion: firmware},
		Complete:  true, Part: 1, LastPart: true}
}

// csafE2E matches the export devices against the parsed fixtures.
func csafE2E(t *testing.T, parts []nosclient.SubjectPart) Result {
	t.Helper()
	subs, err := SubjectsFromExport(exportThroughClient(t, parts))
	if err != nil {
		t.Fatal(err)
	}
	db := newDB(t)
	if err := db.AddCSAF(FeedCiscoCSAF, parsedCSAF(t, "cisco-sa-iosxe-webui-privesc-j22saa4z.json", vulnfeed.CSAFVendorCisco)); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCSAF(FeedPaloAltoCSAF, parsedCSAF(t, "cve-2024-3400.json", vulnfeed.CSAFVendorPaloAlto)); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCSAF(FeedPaloAltoCSAF, parsedCSAF(t, "synthetic-model-scoped.json", vulnfeed.CSAFVendorPaloAlto)); err != nil {
		t.Fatal(err)
	}
	return mustMatch(t, db, subs...)
}

// subjectFindings returns the findings of one subject by vuln ID.
func subjectFindings(r Result, id string) map[string]vulnfinding.Record {
	out := map[string]vulnfinding.Record{}
	for _, f := range r.Findings {
		if f.Record.SubjectRef.ID == id {
			out[f.Record.Vuln.ID] = f.Record
		}
	}
	return out
}

// subjectGaps returns the gaps of one subject.
func subjectGaps(r Result, id string) []Gap {
	var out []Gap
	for _, g := range r.Gaps {
		if g.Ref.ID == id {
			out = append(out, g)
		}
	}
	return out
}

// TestDeviceFindingsFromParsedCSAFEndToEnd: export pages through the NOS
// client, CSAF fixtures through the production parser, both into the
// matcher. Real Cisco and Palo Alto trees name the OS and its versions, not
// device models: every device of that OS on a listed version is matched,
// whatever its model. Model-scoped trees decide by the exact model; another
// model is not affected; an unreadable scope or a firmware no product lists
// is a coverage gap, never clean.
func TestDeviceFindingsFromParsedCSAFEndToEnd(t *testing.T) {
	const iosxe, panos = "vendor:cisco:ios-xe", "vendor:paloalto:panos"
	r := csafE2E(t, []nosclient.SubjectPart{
		csafDevice("cat-affected", iosxe, "cisco", "C9300-24T", "17.9.1"),
		csafDevice("isr-affected", iosxe, "cisco", "ISR4331", "16.12.4"),
		csafDevice("cat-fixed", iosxe, "cisco", "C9300-24T", "17.9.4a"),
		csafDevice("cat-unlisted", iosxe, "cisco", "C9300-24T", "17.12.9"),
		csafDevice("pa-fixed", panos, "paloalto", "PA-3220", "11.1.2-h3"),
		csafDevice("pa-range", panos, "paloalto", "PA-3220", "11.1.1"),
		csafDevice("pa-not-affected", panos, "paloalto", "PA-3220", "10.1.12"),
		csafDevice("pa440-model", panos, "paloalto", "PA-440", "10.2.9"),
		csafDevice("pa220-model", panos, "paloalto", "PA-220", "10.2.9"),
		csafDevice("pa5450-wildcard", panos, "paloalto", "PA-5450", "10.2.9"),
	})

	t.Run("Cisco IOS XE affected on any model, fixed release of the train", func(t *testing.T) {
		for _, id := range []string{"cat-affected", "isr-affected"} {
			fs := subjectFindings(r, id)
			for _, cve := range []string{"CVE-2023-20198", "CVE-2023-20273"} {
				rec, ok := fs[cve]
				if !ok {
					t.Fatalf("%s: no finding %s: %+v", id, cve, r.Findings)
				}
				if rec.MatchBasis != vulnfinding.MatchVendorAdvisory || rec.Ecosystem != iosxe {
					t.Fatalf("%s: record = %+v", id, rec)
				}
				if len(rec.Vuln.Aliases) != 1 || rec.Vuln.Aliases[0] != "cisco-sa-iosxe-webui-privesc-j22SaA4z" {
					t.Fatalf("%s: aliases = %v", id, rec.Vuln.Aliases)
				}
			}
			if gs := subjectGaps(r, id); len(gs) != 0 {
				t.Fatalf("%s: gaps = %+v", id, gs)
			}
		}
		if fix := subjectFindings(r, "cat-affected")["CVE-2023-20198"].Fix; fix.State != vulnfinding.FixFixed || fix.Version != "17.9.4a" {
			t.Fatalf("17.9 train fix = %+v, want 17.9.4a", fix)
		}
		if fix := subjectFindings(r, "isr-affected")["CVE-2023-20198"].Fix; fix.State != vulnfinding.FixNoFixYet {
			t.Fatalf("16.12 train fix = %+v, want no_fix_yet (no fixed release of the train)", fix)
		}
	})
	t.Run("Cisco IOS XE fixed release: no record, no gap", func(t *testing.T) {
		if len(subjectFindings(r, "cat-fixed")) != 0 || len(subjectGaps(r, "cat-fixed")) != 0 {
			t.Fatalf("fixed device: findings %+v gaps %+v", subjectFindings(r, "cat-fixed"), subjectGaps(r, "cat-fixed"))
		}
	})
	t.Run("Cisco IOS XE firmware no product lists: version unknown, never clean", func(t *testing.T) {
		if len(subjectFindings(r, "cat-unlisted")) != 0 || !hasSubjectGap(r, "cat-unlisted", GapDeviceVersionUnknown) {
			t.Fatalf("unlisted firmware: findings %+v gaps %+v", subjectFindings(r, "cat-unlisted"), subjectGaps(r, "cat-unlisted"))
		}
	})
	t.Run("PAN-OS exact fixed release: no record", func(t *testing.T) {
		if fs := subjectFindings(r, "pa-fixed"); len(fs) != 0 {
			t.Fatalf("fixed device has findings: %+v", fs)
		}
		if hasSubjectGap(r, "pa-fixed", GapVendorRange) {
			t.Fatalf("exact fixed release left a range gap: %+v", subjectGaps(r, "pa-fixed"))
		}
	})
	t.Run("PAN-OS firmware only inside a range: unknown, never clean", func(t *testing.T) {
		if fs := subjectFindings(r, "pa-range"); len(fs) != 0 {
			t.Fatalf("range decided a finding: %+v", fs)
		}
		if !hasSubjectGap(r, "pa-range", GapVendorRange) {
			t.Fatalf("range firmware is not a gap: %+v", subjectGaps(r, "pa-range"))
		}
	})
	t.Run("PAN-OS known not affected: not_affected record", func(t *testing.T) {
		rec, ok := subjectFindings(r, "pa-not-affected")["CVE-2024-3400"]
		if !ok || rec.Fix.State != vulnfinding.FixNotAffected {
			t.Fatalf("not affected: %+v", subjectFindings(r, "pa-not-affected"))
		}
	})
	t.Run("model-scoped: exact model via relationship, fix of that model", func(t *testing.T) {
		rec, ok := subjectFindings(r, "pa440-model")["CVE-2099-0001"]
		if !ok || rec.Fix.State != vulnfinding.FixFixed || rec.Fix.Version != "10.2.10" {
			t.Fatalf("PA-440: %+v", subjectFindings(r, "pa440-model"))
		}
	})
	t.Run("model-scoped: model from a hardware CPE, never another model's fix", func(t *testing.T) {
		rec, ok := subjectFindings(r, "pa220-model")["CVE-2099-0001"]
		if !ok || rec.Fix.State != vulnfinding.FixNoFixYet {
			t.Fatalf("PA-220: %+v", subjectFindings(r, "pa220-model"))
		}
	})
	t.Run("model-scoped: wildcard model numbers are unknown for every other model, never clean", func(t *testing.T) {
		for _, d := range []struct{ id, model string }{{"pa5450-wildcard", "PA-5450"}, {"pa-fixed", "PA-3220"}} {
			if _, ok := subjectFindings(r, d.id)["CVE-2099-0002"]; ok {
				t.Fatalf("%s: wildcard scope decided a finding: %+v", d.id, r.Findings)
			}
			if !hasVulnGap(r, d.model, canonicalID("CVE-2099-0002"), GapDeviceModelUnknown) {
				t.Fatalf("%s: wildcard scope is silent: %+v", d.id, subjectGaps(r, d.id))
			}
		}
	})
	t.Run("model-scoped: another model is not affected", func(t *testing.T) {
		// PA-3220 and PA-5450 devices are not among the exact models of
		// CVE-2099-0001.
		for _, d := range []struct{ id, model string }{{"pa-fixed", "PA-3220"}, {"pa-range", "PA-3220"}, {"pa5450-wildcard", "PA-5450"}} {
			if _, ok := subjectFindings(r, d.id)["CVE-2099-0001"]; ok {
				t.Fatalf("%s: other-model advisory decided a finding", d.id)
			}
			if hasVulnGap(r, d.model, canonicalID("CVE-2099-0001"), GapDeviceModelUnknown) {
				t.Fatalf("%s: other-model advisory is a gap, want not affected: %+v", d.id, subjectGaps(r, d.id))
			}
		}
	})
}

// TestParsedCSAFDeviceOfUncoveredOSIsGap: a device whose OS no parsed
// advisory covers has no applying product: its model is unknown to the feed
// and it is never clean, even though the feed holds advisories.
func TestParsedCSAFDeviceOfUncoveredOSIsGap(t *testing.T) {
	r := csafE2E(t, []nosclient.SubjectPart{
		csafDevice("sw-cbs", "vendor:cisco:cbs", "cisco", "CBS350-24P-4G", "3.4.0.17"),
	})
	if len(r.Findings) != 0 || !hasSubjectGap(r, "sw-cbs", GapDeviceModelUnknown) {
		t.Fatalf("uncovered OS: findings %+v gaps %+v", r.Findings, r.Gaps)
	}
}

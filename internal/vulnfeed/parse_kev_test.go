// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func TestParseKEVFlagsWithDates(t *testing.T) {
	cat, err := ParseKEV(context.Background(), bytes.NewReader(readFixture(t, "parse_kev", "catalog.json")))
	if err != nil {
		t.Fatal(err)
	}
	want := KEVCatalog{
		Version:  "2024.10.21",
		Released: time.Date(2024, 10, 21, 15, 0, 15, 123400000, time.UTC),
		Entries: []KEVEntry{
			{CVE: "CVE-2021-44228", VendorProject: "Apache", Product: "Log4j2", Name: "Apache Log4j2 Remote Code Execution Vulnerability",
				DateAdded: day(2021, 12, 10), DueDate: day(2021, 12, 24), KnownRansomware: true},
			{CVE: "CVE-2024-0001", VendorProject: "Example", Product: "Widget Ünicode", Name: "Example Widget Flaw",
				DateAdded: day(2024, 10, 21), DueDate: day(2024, 11, 11)},
		},
	}
	if !reflect.DeepEqual(cat, want) {
		t.Fatalf("catalog:\n got %+v\nwant %+v", cat, want)
	}
}

func TestParseKEVRejectsMalformed(t *testing.T) {
	doc := func(count, entries string) string {
		return `{"catalogVersion":"2024.10.21","dateReleased":"2024-10-21T15:00:15Z","count":` + count + `,"vulnerabilities":[` + entries + `]}`
	}
	entry := func(fields string) string {
		return `{"cveID":"CVE-2024-0001","vendorProject":"V","product":"P","vulnerabilityName":"N","dateAdded":"2024-10-21"` + fields + `}`
	}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"not json", `x`, ErrFeedMalformed},
		{"trailing data", doc("0", ``) + `{}`, ErrFeedMalformed},
		{"missing version", `{"dateReleased":"2024-10-21T15:00:15Z","count":0,"vulnerabilities":[]}`, ErrFeedMalformed},
		{"missing released", `{"catalogVersion":"1","count":0,"vulnerabilities":[]}`, ErrFeedMalformed},
		{"date only released", `{"catalogVersion":"1","dateReleased":"2024-10-21","count":0,"vulnerabilities":[]}`, ErrFeedMalformed},
		{"missing count", `{"catalogVersion":"1","dateReleased":"2024-10-21T15:00:15Z","vulnerabilities":[]}`, ErrFeedMalformed},
		{"count mismatch", doc("2", entry(``)), ErrFeedMalformed},
		{"count wrong type", doc(`"1"`, entry(``)), ErrFeedMalformed},
		{"lower-case cve", doc("1", strings.Replace(entry(``), "CVE-2024", "cve-2024", 1)), ErrFeedMalformed},
		{"duplicate cve", doc("2", entry(``)+","+entry(``)), ErrFeedMalformed},
		{"case shadow cveID", doc("1", entry(`,"CVEID":"CVE-2024-9999"`)), ErrFeedMalformed},
		{"bad dateAdded", doc("1", strings.Replace(entry(``), "2024-10-21", "21.10.2024", 1)), ErrFeedMalformed},
		{"bad dueDate", doc("1", entry(`,"dueDate":"soon"`)), ErrFeedMalformed},
		{"bad ransomware", doc("1", entry(`,"knownRansomwareCampaignUse":"Maybe"`)), ErrFeedMalformed},
		{"control in name", doc("1", strings.Replace(entry(``), `"product":"P"`, `"product":"P\u001b]8;;x"`, 1)), ErrFeedMalformed},
		{"long name", doc("1", strings.Replace(entry(``), `"product":"P"`, `"product":"`+strings.Repeat("p", MaxKEVNameBytes+1)+`"`, 1)), ErrFeedLimit},
		{"too large", `{"x":"` + strings.Repeat("a", MaxKEVBytes) + `"}`, ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseKEV(context.Background(), strings.NewReader(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func FuzzParseKEV(f *testing.F) {
	f.Add(readFixture(f, "parse_kev", "catalog.json"))
	f.Add([]byte(`{"catalogVersion":"1","dateReleased":"2024-10-21T15:00:15Z","count":0,"vulnerabilities":[]}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		cat, err := ParseKEV(context.Background(), bytes.NewReader(in))
		if err != nil {
			if !errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit) {
				t.Fatalf("unexpected error class %v", err)
			}
			return
		}
		if cat.Released.IsZero() {
			t.Fatal("accepted catalog without content date")
		}
		for _, e := range cat.Entries {
			if !cveIDRe.MatchString(e.CVE) || e.DateAdded.IsZero() {
				t.Fatalf("unvalidated entry %+v", e)
			}
		}
	})
}

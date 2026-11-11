// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strconv"
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

func kevDoc(count, entries string) string {
	return `{"catalogVersion":"2024.10.21","dateReleased":"2024-10-21T15:00:15Z","count":` + count + `,"vulnerabilities":[` + entries + `]}`
}

func kevEntry(fields string) string {
	return `{"cveID":"CVE-2024-0001","vendorProject":"V","product":"P","vulnerabilityName":"N","dateAdded":"2024-10-21"` + fields + `}`
}

func TestParseKEVRejectsMalformed(t *testing.T) {
	doc, entry := kevDoc, kevEntry
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"not json", `x`, ErrFeedMalformed},
		{"top level array", `[]`, ErrFeedMalformed},
		{"trailing data", doc("0", ``) + `{}`, ErrFeedMalformed},
		{"missing version", `{"dateReleased":"2024-10-21T15:00:15Z","count":0,"vulnerabilities":[]}`, ErrFeedMalformed},
		{"missing released", `{"catalogVersion":"1","count":0,"vulnerabilities":[]}`, ErrFeedMalformed},
		{"date only released", `{"catalogVersion":"1","dateReleased":"2024-10-21","count":0,"vulnerabilities":[]}`, ErrFeedMalformed},
		{"missing count", `{"catalogVersion":"1","dateReleased":"2024-10-21T15:00:15Z","vulnerabilities":[]}`, ErrFeedMalformed},
		{"missing vulnerabilities", `{"catalogVersion":"1","dateReleased":"2024-10-21T15:00:15Z","count":0}`, ErrFeedMalformed},
		{"vulnerabilities not array", `{"catalogVersion":"1","dateReleased":"2024-10-21T15:00:15Z","count":0,"vulnerabilities":{}}`, ErrFeedMalformed},
		{"count mismatch", doc("2", entry(``)), ErrFeedMalformed},
		{"count wrong type", doc(`"1"`, entry(``)), ErrFeedMalformed},
		{"duplicate cve", doc("2", entry(``)+","+entry(``)), ErrFeedMalformed},
		{"duplicate top key", `{"count":0,` + doc("0", ``)[1:], ErrFeedMalformed},
		{"case shadow top key", `{"Count":5,` + doc("0", ``)[1:], ErrFeedMalformed},
		{"case top key", strings.Replace(doc("0", ``), `"vulnerabilities"`, `"Vulnerabilities"`, 1), ErrFeedMalformed},
		{"truncated entry", `{"catalogVersion":"1","dateReleased":"2024-10-21T15:00:15Z","count":1,"vulnerabilities":[{"cveID":`, ErrFeedMalformed},
		{"long name", doc("1", strings.Replace(entry(``), `"product":"P"`, `"product":"`+strings.Repeat("p", MaxKEVNameBytes+1)+`"`, 1)), ErrFeedLimit},
		{"entry too deep", doc("1", entry(`,"x":`+strings.Repeat("[", MaxJSONDepth)+strings.Repeat("]", MaxJSONDepth))), ErrFeedLimit},
		{"entry too large", doc("1", entry(`,"notes":"`+strings.Repeat("a", MaxKEVEntryBytes)+`"`)), ErrFeedLimit},
		{"header value too large", `{"x":"` + strings.Repeat("a", MaxKEVHeaderValueBytes) + `",` + doc("0", ``)[1:], ErrFeedLimit},
		{"too large", doc("600", strings.TrimSuffix(strings.Repeat(`{"x":"`+strings.Repeat("a", 60_000)+`"},`, 600), ",")), ErrFeedLimit},
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

func TestParseKEVSkipsMalformedEntry(t *testing.T) {
	entry := kevEntry
	good := strings.Replace(entry(``), "CVE-2024-0001", "CVE-2024-0002", 1)
	bad := map[string]string{
		"lower-case cve":    strings.Replace(entry(``), "CVE-2024", "cve-2024", 1),
		"missing cve":       `{}`,
		"case shadow cveID": entry(`,"CVEID":"CVE-2024-9999"`),
		"bad dateAdded":     strings.Replace(entry(``), "2024-10-21", "21.10.2024", 1),
		"bad dueDate":       entry(`,"dueDate":"soon"`),
		"bad ransomware":    entry(`,"knownRansomwareCampaignUse":"Maybe"`),
		"control in name":   strings.Replace(entry(``), `"product":"P"`, `"product":"P\u001b]8;;x"`, 1),
		"name wrong type":   strings.Replace(entry(``), `"product":"P"`, `"product":7`, 1),
		"entry not object":  `"CVE-2024-0001"`,
		"non-ASCII key":     entry(`,"nötes":"x"`),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			cat, err := ParseKEV(context.Background(), strings.NewReader(kevDoc("3", good+","+b+","+strings.Replace(good, "0002", "0003", 1))))
			if err != nil {
				t.Fatalf("err = %v, want the entry skipped", err)
			}
			if cat.Skipped != 1 || len(cat.Entries) != 2 || cat.Entries[0].CVE != "CVE-2024-0002" || cat.Entries[1].CVE != "CVE-2024-0003" {
				t.Fatalf("skipped %d, entries %+v", cat.Skipped, cat.Entries)
			}
		})
	}
}

// kevBody is a catalog of n empty entries, each of which is skipped.
func kevBody(n int) []byte {
	return []byte(kevDoc(strconv.Itoa(n), strings.TrimSuffix(strings.Repeat("{},", n), ",")))
}

func TestParseKEVEntryLimit(t *testing.T) {
	cat, err := ParseKEV(context.Background(), bytes.NewReader(kevBody(MaxKEVEntries)))
	if err != nil || cat.Skipped != MaxKEVEntries {
		t.Fatalf("at the limit: skipped %d, %v", cat.Skipped, err)
	}
	if _, err := ParseKEV(context.Background(), bytes.NewReader(kevBody(MaxKEVEntries+1))); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestParseKEVEntryLimitFiresBeforeTheRestIsDecoded(t *testing.T) {
	// A body just over the limit and one ten times longer must cost the
	// same: the limit fires while streaming, not after unmarshalling.
	shortIn, longIn := kevBody(MaxKEVEntries+1), kevBody(10*(MaxKEVEntries+1))
	short := measureAllocs(t, func() error {
		_, err := ParseKEV(context.Background(), bytes.NewReader(shortIn))
		return err
	})
	long := measureAllocs(t, func() error {
		_, err := ParseKEV(context.Background(), bytes.NewReader(longIn))
		return err
	})
	short.assertCovers(t, long)
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func collectNVD(in []byte) ([]NVDRecord, NVDSummary, error) {
	var got []NVDRecord
	sum, err := ParseNVD(context.Background(), bytes.NewReader(in), func(r NVDRecord) error {
		got = append(got, r)
		return nil
	})
	return got, sum, err
}

func TestParseNVDScoresCWEsAndReferences(t *testing.T) {
	got, sum, err := collectNVD(readFixture(t, "parse_nvd", "feed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Records != 2 || !sum.Newest.Equal(time.Date(2024, 11, 1, 20, 0, 0, 0, time.UTC)) ||
		!sum.Timestamp.Equal(time.Date(2024, 11, 2, 3, 0, 1, 234567800, time.UTC)) {
		t.Fatalf("summary %+v", sum)
	}
	want := NVDRecord{
		ID:           "CVE-2024-0001",
		Published:    time.Date(2024, 10, 21, 13, 15, 2, 413000000, time.UTC),
		LastModified: time.Date(2024, 11, 1, 20, 0, 0, 0, time.UTC),
		Status:       "Analyzed",
		Description:  "A flaw in example allows remote code execution.\nSee <script>alert(1)</script> for details.",
		CVSS: []NVDCVSS{
			{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8, BaseSeverity: "CRITICAL", Source: "nvd@nist.gov", Type: "Primary"},
			{Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", BaseScore: 9.3, BaseSeverity: "CRITICAL", Source: "cna@example.org", Type: "Secondary"},
		},
		CWEs: []string{"CWE-787", "CWE-20"},
		References: []NVDReference{
			{URL: `https://example.org/advisory?id=1&x="y"`, Source: "cna@example.org", Tags: []string{"Vendor Advisory", "Patch"}},
			{URL: "javascript:alert(1)"},
		},
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("record:\n got %+v\nwant %+v", got[0], want)
	}
	if got[1].ID != "CVE-1999-0001" || got[1].CVSS != nil || got[1].CWEs != nil || got[1].References != nil {
		t.Fatalf("second record %+v", got[1])
	}
}

const nvdHead = `"format":"NVD_CVE","version":"2.0","timestamp":"2024-11-02T03:00:01.000",`

func nvdFeed(items string) string { return `{` + nvdHead + `"vulnerabilities":[` + items + `]}` }

// nvdItem is a valid item for cve with extra fields appended to "cve".
func nvdItem(cve, extra string) string {
	return `{"cve":{"id":"` + cve + `","published":"2024-10-21T13:15:02.413","lastModified":"2024-11-01T20:00:00.000"` + extra + `}}`
}

// nvdRepeat joins n copies of s with commas.
func nvdRepeat(s string, n int) string { return strings.TrimSuffix(strings.Repeat(s+",", n), ",") }

func TestParseNVDRejectsMalformed(t *testing.T) {
	head, feed := nvdHead, nvdFeed
	item := func(cve string) string { return nvdItem("CVE-2024-0001", cve) }
	metric := `{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":5.0,"baseSeverity":"MEDIUM"}}`
	weakness := func(n int) string {
		return `{"description":[` + nvdRepeat(`{"lang":"en","value":"NVD-CWE-Other"}`, n) + `]}`
	}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"not object", `[]`, ErrFeedMalformed},
		{"missing format", `{"version":"2.0","timestamp":"2024-11-02T03:00:01","vulnerabilities":[]}`, ErrFeedMalformed},
		{"wrong version", `{"format":"NVD_CVE","version":"1.1","timestamp":"2024-11-02T03:00:01","vulnerabilities":[]}`, ErrFeedMalformed},
		{"missing timestamp", `{"format":"NVD_CVE","version":"2.0","vulnerabilities":[]}`, ErrFeedMalformed},
		{"bad timestamp", `{"format":"NVD_CVE","version":"2.0","timestamp":"now","vulnerabilities":[]}`, ErrFeedMalformed},
		{"missing vulnerabilities", `{` + strings.TrimSuffix(head, ",") + `}`, ErrFeedMalformed},
		{"vulnerabilities not array", `{` + head + `"vulnerabilities":{}}`, ErrFeedMalformed},
		{"duplicate top key", `{` + head + `"vulnerabilities":[],"vulnerabilities":[]}`, ErrFeedMalformed},
		{"case top key", `{` + head + `"Vulnerabilities":[]}`, ErrFeedMalformed},
		{"case shadow format", `{"Format":"x",` + head + `"vulnerabilities":[]}`, ErrFeedMalformed},
		{"trailing data", feed(``) + `{}`, ErrFeedMalformed},
		{"truncated", `{` + head + `"vulnerabilities":[` + item(``), ErrFeedMalformed},
		{"item syntax", feed(`{"cve":{"id" "x"}}`), ErrFeedMalformed},
		{"huge header value", `{"x":"` + strings.Repeat("a", MaxNVDHeaderValueBytes+10) + `",` + head + `"vulnerabilities":[]}`, ErrFeedLimit},
		{"whitespace run", `{` + head + `"vulnerabilities":[` + item(``) + strings.Repeat(" ", recordWindowSlack+1) + `]}`, ErrFeedLimit},
		{"duplicate cve", feed(item(``) + `,` + item(``)), ErrFeedMalformed},
		{"long description", feed(item(`,"descriptions":[{"lang":"en","value":"` + strings.Repeat("a", MaxNVDDescriptionBytes+1) + `"}]`)), ErrFeedLimit},
		{"url too long", feed(item(`,"references":[{"url":"https://` + strings.Repeat("a", MaxNVDReferenceURLBytes) + `"}]`)), ErrFeedLimit},
		{"too many references", feed(item(`,"references":[` + nvdRepeat(`{"url":"u"}`, MaxNVDReferences+1) + `]`)), ErrFeedLimit},
		{"too many descriptions", feed(item(`,"descriptions":[` + nvdRepeat(`{"lang":"de","value":"x"}`, MaxNVDDescriptions+1) + `]`)), ErrFeedLimit},
		{"too many metrics", feed(item(`,"metrics":{"cvssMetricV31":[` + nvdRepeat(metric, MaxNVDMetrics+1) + `]}`)), ErrFeedLimit},
		{"too many weaknesses", feed(item(`,"weaknesses":[` + nvdRepeat(weakness(1), MaxNVDWeaknesses+1) + `]`)), ErrFeedLimit},
		{"too many weakness entries", feed(item(`,"weaknesses":[` + weakness(MaxNVDWeaknesses+1) + `]`)), ErrFeedLimit},
		{"too many CWEs", feed(item(`,"weaknesses":[{"description":[` + func() string {
			var b strings.Builder
			for i := range MaxNVDWeaknesses + 1 {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"lang":"en","value":"CWE-%d"}`, i)
			}
			return b.String()
		}() + `]}]`)), ErrFeedLimit},
		{"too many tags", feed(item(`,"references":[{"url":"https://a","tags":[` + nvdRepeat(`"Patch"`, MaxNVDReferenceTags+1) + `]}]`)), ErrFeedLimit},
		{"too many members", feed(item(`,"x":[` + nvdRepeat("0", MaxJSONMembers+1) + `]`)), ErrFeedLimit},
		{"too deep", feed(item(`,"configurations":` + strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth))), ErrFeedLimit},
		{"record too large", feed(item(`,"x":"` + strings.Repeat("a", MaxNVDRecordBytes) + `"`)), ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := collectNVD([]byte(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// At the limits the item is accepted.
	at := nvdItem("CVE-2024-0001", `,"metrics":{"cvssMetricV31":[`+nvdRepeat(metric, MaxNVDMetrics)+`]},"weaknesses":[`+
		nvdRepeat(weakness(MaxNVDWeaknesses), MaxNVDWeaknesses)+`],"references":[{"url":"https://a","tags":[`+nvdRepeat(`"Patch"`, MaxNVDReferenceTags)+`]}]`)
	if got, _, err := collectNVD([]byte(feed(at))); err != nil || len(got) != 1 || len(got[0].CVSS) != MaxNVDMetrics || len(got[0].References[0].Tags) != MaxNVDReferenceTags {
		t.Fatalf("at the limits: %v", err)
	}
}

func TestParseNVDSkipsMalformedItem(t *testing.T) {
	item := func(extra string) string { return nvdItem("CVE-2024-0002", extra) }
	metric := func(list, data string) string {
		return item(`,"metrics":{"` + list + `":[{"source":"nvd@nist.gov","type":"Primary","cvssData":` + data + `}]}`)
	}
	bad := map[string]string{
		"missing cve":            `{}`,
		"item not object":        `"CVE-2024-0002"`,
		"cve wrong type":         `{"cve":[]}`,
		"bad cve id":             `{"cve":{"id":"cve-2024-1","published":"2024-10-21T13:15:02","lastModified":"2024-10-21T13:15:02"}}`,
		"bad lastModified":       `{"cve":{"id":"CVE-2024-0002","published":"2024-10-21T13:15:02","lastModified":"x"}}`,
		"bad status":             item(`,"vulnStatus":"<b>"`),
		"control in description": item(`,"descriptions":[{"lang":"en","value":"a\u001b[31m"}]`),
		"bidi in description":    item(`,"descriptions":[{"lang":"en","value":"a` + `\` + `u202eb"}]`),
		"case shadow key":        item(`,"ID":"CVE-2024-9999"`),
		"non-ASCII key":          item(`,"ünknown":1`),
		"version mismatch":       metric("cvssMetricV31", `{"version":"3.0","vectorString":"CVSS:3.1/AV:N","baseScore":5.0,"baseSeverity":"MEDIUM"}`),
		"vector prefix":          metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:4.0/AV:N","baseScore":5.0,"baseSeverity":"MEDIUM"}`),
		"score above 10":         metric("cvssMetricV40", `{"version":"4.0","vectorString":"CVSS:4.0/AV:N","baseScore":10.1,"baseSeverity":"CRITICAL"}`),
		"score negative":         metric("cvssMetricV40", `{"version":"4.0","vectorString":"CVSS:4.0/AV:N","baseScore":-1,"baseSeverity":"NONE"}`),
		"score two decimals":     metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":5.55,"baseSeverity":"MEDIUM"}`),
		"score missing":          metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseSeverity":"MEDIUM"}`),
		"score string":           metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":"9.8","baseSeverity":"MEDIUM"}`),
		"score overflow":         metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":1e999,"baseSeverity":"MEDIUM"}`),
		"bad severity":           metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":5.0,"baseSeverity":"medium"}`),
		"bad cwe":                item(`,"weaknesses":[{"description":[{"lang":"en","value":"CWE-79; drop"}]}]`),
		"url with space":         item(`,"references":[{"url":"https://a b"}]`),
		"bad tag":                item(`,"references":[{"url":"https://a","tags":["<x>"]}]`),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			in := nvdFeed(nvdItem("CVE-2024-0001", ``) + "," + b + "," + nvdItem("CVE-2024-0003", ``))
			got, sum, err := collectNVD([]byte(in))
			if err != nil {
				t.Fatalf("err = %v, want the item skipped", err)
			}
			if sum.Skipped != 1 || sum.Records != 2 || len(got) != 2 || got[0].ID != "CVE-2024-0001" || got[1].ID != "CVE-2024-0003" {
				t.Fatalf("summary %+v, records %+v", sum, got)
			}
		})
	}
}

func TestParseNVDRecordLimit(t *testing.T) {
	in := []byte(nvdFeed(nvdItem("CVE-2024-0001", ``) + `,{},` + nvdItem("CVE-2024-0002", ``)))
	visit := func(NVDRecord) error { return nil }
	if sum, err := parseNVD(context.Background(), bytes.NewReader(in), 3, visit); err != nil || sum.Records != 2 || sum.Skipped != 1 {
		t.Fatalf("at the limit: %+v, %v", sum, err)
	}
	// Skipped items count towards the limit.
	if _, err := parseNVD(context.Background(), bytes.NewReader(in), 2, visit); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	if MaxNVDRecords != 2_000_000 {
		t.Fatalf("MaxNVDRecords = %d", MaxNVDRecords)
	}
}

func TestParseNVDWindowIgnoresReadAhead(t *testing.T) {
	// Items just below MaxNVDRecordBytes, read through a reader that
	// returns large chunks: the decoder's read-ahead into the next item
	// while it finishes one must not count against either item.
	pad := strings.Repeat("a", MaxNVDRecordBytes-200)
	var items []string
	for i := range 4 {
		items = append(items, nvdItem(fmt.Sprintf("CVE-2024-%04d", i+1), `,"x":"`+pad+`"`))
	}
	got, sum, err := collectNVD([]byte(nvdFeed(strings.Join(items, ","))))
	if err != nil || sum.Records != 4 || len(got) != 4 {
		t.Fatalf("summary %+v, err %v", sum, err)
	}
	// Over the limit by one byte still fails.
	over := nvdItem("CVE-2024-0001", `,"x":"`+pad+`"`)
	over = nvdItem("CVE-2024-0001", `,"x":"`+pad+strings.Repeat("a", MaxNVDRecordBytes-len(over)+1)+`"`)
	if _, _, err := collectNVD([]byte(nvdFeed(over))); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("one byte over: %v", err)
	}
}

func TestParseNVDLateBadFormatAfterDeliveredItems(t *testing.T) {
	// The header may follow the items: they are delivered first and the
	// late bad format fails the feed, so the caller must discard them.
	in := `{"vulnerabilities":[` + nvdItem("CVE-2024-0001", ``) + `],"format":"wrong","version":"2.0","timestamp":"2024-11-02T03:00:01"}`
	got, _, err := collectNVD([]byte(in))
	if !errors.Is(err, ErrFeedMalformed) {
		t.Fatalf("err = %v, want ErrFeedMalformed", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2024-0001" {
		t.Fatalf("delivered %+v before the error", got)
	}
}

func TestParseNVDThroughGzip(t *testing.T) {
	gz := gzipBytes(t, readFixture(t, "parse_nvd", "feed.json"))
	zr, err := DecompressGzip(bytes.NewReader(gz), MaxNVDFeedBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	sum, err := ParseNVD(context.Background(), zr, func(NVDRecord) error { return nil })
	if err != nil || sum.Records != 2 {
		t.Fatalf("sum %+v, err %v", sum, err)
	}
	// A decompression limit below the feed size surfaces as ErrFeedLimit.
	zr2, err := DecompressGzip(bytes.NewReader(gz), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr2.Close() }()
	if _, err := ParseNVD(context.Background(), zr2, func(NVDRecord) error { return nil }); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("limited: %v", err)
	}
}

func TestParseNVDHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ParseNVD(ctx, bytes.NewReader(readFixture(t, "parse_nvd", "feed.json")), func(NVDRecord) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func FuzzParseNVD(f *testing.F) {
	f.Add(readFixture(f, "parse_nvd", "feed.json"))
	f.Add([]byte(`{"format":"NVD_CVE","version":"2.0","timestamp":"2024-11-02T03:00:01","vulnerabilities":[]}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		_, err := ParseNVD(context.Background(), bytes.NewReader(in), func(r NVDRecord) error {
			if !cveIDRe.MatchString(r.ID) || r.LastModified.IsZero() {
				t.Fatalf("unvalidated record %+v", r)
			}
			for _, s := range r.CVSS {
				if s.BaseScore < 0 || s.BaseScore > 10 {
					t.Fatalf("score out of range %+v", s)
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit) {
			t.Fatalf("unexpected error class %v", err)
		}
	})
}

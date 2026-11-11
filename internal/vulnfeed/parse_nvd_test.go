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

func TestParseNVDRejectsMalformed(t *testing.T) {
	head := `"format":"NVD_CVE","version":"2.0","timestamp":"2024-11-02T03:00:01.000",`
	feed := func(items string) string { return `{` + head + `"vulnerabilities":[` + items + `]}` }
	item := func(cve string) string {
		return `{"cve":{"id":"CVE-2024-0001","published":"2024-10-21T13:15:02.413","lastModified":"2024-11-01T20:00:00.000"` + cve + `}}`
	}
	metric := func(list, data string) string {
		return item(`,"metrics":{"` + list + `":[{"source":"nvd@nist.gov","type":"Primary","cvssData":` + data + `}]}`)
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
		{"huge header value", `{"x":"` + strings.Repeat("a", MaxNVDHeaderValueBytes+10) + `",` + head + `"vulnerabilities":[]}`, ErrFeedLimit},
		{"missing cve", feed(`{}`), ErrFeedMalformed},
		{"bad cve id", feed(`{"cve":{"id":"cve-2024-1","published":"2024-10-21T13:15:02","lastModified":"2024-10-21T13:15:02"}}`), ErrFeedMalformed},
		{"duplicate cve", feed(item(``) + `,` + item(``)), ErrFeedMalformed},
		{"bad lastModified", feed(`{"cve":{"id":"CVE-2024-0001","published":"2024-10-21T13:15:02","lastModified":"x"}}`), ErrFeedMalformed},
		{"bad status", feed(item(`,"vulnStatus":"<b>"`)), ErrFeedMalformed},
		{"control in description", feed(item(`,"descriptions":[{"lang":"en","value":"a\u001b[31m"}]`)), ErrFeedMalformed},
		{"bidi in description", feed(item(`,"descriptions":[{"lang":"en","value":"a` + `\` + `u202eb"}]`)), ErrFeedMalformed},
		{"version mismatch", feed(metric("cvssMetricV31", `{"version":"3.0","vectorString":"CVSS:3.1/AV:N","baseScore":5.0,"baseSeverity":"MEDIUM"}`)), ErrFeedMalformed},
		{"vector prefix", feed(metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:4.0/AV:N","baseScore":5.0,"baseSeverity":"MEDIUM"}`)), ErrFeedMalformed},
		{"score above 10", feed(metric("cvssMetricV40", `{"version":"4.0","vectorString":"CVSS:4.0/AV:N","baseScore":10.1,"baseSeverity":"CRITICAL"}`)), ErrFeedMalformed},
		{"score negative", feed(metric("cvssMetricV40", `{"version":"4.0","vectorString":"CVSS:4.0/AV:N","baseScore":-1,"baseSeverity":"NONE"}`)), ErrFeedMalformed},
		{"score two decimals", feed(metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":5.55,"baseSeverity":"MEDIUM"}`)), ErrFeedMalformed},
		{"score missing", feed(metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseSeverity":"MEDIUM"}`)), ErrFeedMalformed},
		{"score string", feed(metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":"9.8","baseSeverity":"MEDIUM"}`)), ErrFeedMalformed},
		{"score overflow", feed(metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":1e999,"baseSeverity":"MEDIUM"}`)), ErrFeedMalformed},
		{"bad severity", feed(metric("cvssMetricV31", `{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":5.0,"baseSeverity":"medium"}`)), ErrFeedMalformed},
		{"bad cwe", feed(item(`,"weaknesses":[{"description":[{"lang":"en","value":"CWE-79; drop"}]}]`)), ErrFeedMalformed},
		{"url with space", feed(item(`,"references":[{"url":"https://a b"}]`)), ErrFeedMalformed},
		{"url too long", feed(item(`,"references":[{"url":"https://` + strings.Repeat("a", MaxNVDReferenceURLBytes) + `"}]`)), ErrFeedLimit},
		{"bad tag", feed(item(`,"references":[{"url":"https://a","tags":["<x>"]}]`)), ErrFeedMalformed},
		{"too many references", feed(item(`,"references":[` + strings.TrimSuffix(strings.Repeat(`{"url":"u"},`, MaxNVDReferences+1), ",") + `]`)), ErrFeedLimit},
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

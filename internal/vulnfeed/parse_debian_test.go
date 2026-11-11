// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func collectDebian(t *testing.T, in []byte) ([]DebianEntry, DebianTrackerSummary, error) {
	t.Helper()
	var got []DebianEntry
	sum, err := ParseDebianTracker(context.Background(), bytes.NewReader(in), func(e DebianEntry) error {
		got = append(got, e)
		return nil
	})
	return got, sum, err
}

func TestParseDebianTrackerMapsEveryState(t *testing.T) {
	got, sum, err := collectDebian(t, readFixture(t, "parse_debian", "tracker.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := []DebianEntry{
		{"openssl", "CVE-2024-0001", "bookworm", vulnfinding.TrackerFixed, "3.0.11-1~deb12u2", "medium"},
		{"openssl", "CVE-2024-0001", "bullseye", vulnfinding.TrackerNoDSA, "", "low"},
		{"openssl", "CVE-2024-0001", "buster", vulnfinding.TrackerEndOfLife, "", "end-of-life"},
		{"openssl", "CVE-2024-0001", "trixie", vulnfinding.TrackerNotAffected, "", "unimportant"},
		{"openssl", "TEMP-0000000-ABCDEF", "bookworm", vulnfinding.TrackerPostponed, "", "not yet assigned"},
		{"openssl", "TEMP-0000000-ABCDEF", "bullseye", vulnfinding.TrackerIgnored, "", "low**"},
		{"openssl", "TEMP-0000000-ABCDEF", "sid", DebianUndetermined, "", "not yet assigned"},
		{"zlib", "CVE-2023-9999", "bookworm", vulnfinding.TrackerUnfixed, "", "high"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("entries:\n got %+v\nwant %+v", got, want)
	}
	if sum != (DebianTrackerSummary{Packages: 2, Issues: 3, Entries: 8}) {
		t.Fatalf("summary %+v", sum)
	}
	// Every mapped state except undetermined has a D4 target.
	for _, e := range got {
		_, err := vulnfinding.MapDebianTrackerState(e.State)
		if (e.State == DebianUndetermined) != (err != nil) {
			t.Errorf("state %s: map err %v", e.State, err)
		}
	}
}

// debianGoodPackage is a package with one valid entry.
const debianGoodPackage = `"zlib":{"CVE-2024-1111":{"releases":{"bookworm":{"status":"open"}}}}`

// debianGoodEntry is the entry of debianGoodPackage.
var debianGoodEntry = DebianEntry{Package: "zlib", IssueID: "CVE-2024-1111", Release: "bookworm", State: vulnfinding.TrackerUnfixed}

// debianIssues is a package object with n distinct issues of body.
func debianIssues(n int, body string) string {
	var b strings.Builder
	b.WriteString("{")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"CVE-2024-%d":%s`, 10000+i, body)
	}
	b.WriteString("}")
	return b.String()
}

// debianReleases is n distinct open release members of a releases object.
func debianReleases(n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"r%c%c":{"status":"open"}`, 'a'+i/26, 'a'+i%26)
	}
	return b.String()
}

// TestParseDebianIssueDecodeStaysWithinFieldCaps: an issue whose releases
// map holds far more entries than MaxDebianReleasesPerIssue is rejected
// while the walk counts the map members, before json.Unmarshal builds the
// map, and the issue is skipped and counted.
func TestParseDebianIssueDecodeStaysWithinFieldCaps(t *testing.T) {
	const n = 60_000 // the generic member limit is 65,536
	var b strings.Builder
	b.WriteString(`{"releases":{`)
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"r%d":{}`, i)
	}
	b.WriteString(`}}`)
	raw := []byte(b.String())
	p := &debianParse{ctx: context.Background(), visit: func(DebianEntry) error { return nil }, maxEntries: MaxDebianEntries}
	assertRecordDecodeBudget(t, func() error {
		var issue debianIssueJSON
		return decodeChecked(raw, &issue, debianIssuePaths)
	})
	if err := p.parseIssue("zlib", "CVE-2024-1", raw); err != nil || p.sum.Skipped != 1 || p.sum.Issues != 0 || p.entries != 0 {
		t.Fatalf("parseIssue: %v, %+v, entries %d", err, p.sum, p.entries)
	}
}

func TestParseDebianTrackerRejectsMalformed(t *testing.T) {
	releases := debianReleases
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"top level array", `[]`, ErrFeedMalformed},
		{"truncated", `{"openssl":{`, ErrFeedMalformed},
		{"truncated issue", `{"openssl":{"CVE-2024-1":{"releases":`, ErrFeedMalformed},
		{"trailing data", `{} {}`, ErrFeedMalformed},
		{"trailing garbage", `{}x`, ErrFeedMalformed},
		{"duplicate package", `{"zlib":{},"zlib":{}}`, ErrFeedMalformed},
		{"duplicate issue", `{"zlib":{"CVE-2024-1":{},"CVE-2024-1":{}}}`, ErrFeedMalformed},
		{"case duplicate issue", `{"zlib":{"CVE-2024-1":{},"cve-2024-1":{}}}`, ErrFeedMalformed},
		{"too deep", `{"zlib":{"CVE-2024-1111":{"x":` + strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth) + `}}}`, ErrFeedLimit},
		{"skipped package too deep", `{"Bad Name":` + strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1) + `}`, ErrFeedLimit},
		{"whitespace run", `{"zlib":{}` + strings.Repeat(" ", recordWindowSlack+1) + `,"aa":{}}`, ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := collectDebian(t, []byte(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// At the limits the export is accepted.
	at := `{"zlib":{"CVE-2024-1":{"releases":{` + releases(MaxDebianReleasesPerIssue) + `}}},"aa":` + debianIssues(MaxDebianIssuesPerPackage, "{}") + `}`
	if _, sum, err := collectDebian(t, []byte(at)); err != nil || sum.Entries != MaxDebianReleasesPerIssue || sum.Issues != 1+MaxDebianIssuesPerPackage {
		t.Fatalf("at the limits: %+v, %v", sum, err)
	}
}

func TestParseDebianTrackerSkipsMalformedRecords(t *testing.T) {
	// Each case adds one bad package, issue or release entry next to a
	// good one; only the bad record is left out and counted.
	pkg := func(p string) string { return `{` + p + `,` + debianGoodPackage + `}` }
	issue := func(i string) string {
		return `{"zlib":{` + i + `,"CVE-2024-1111":{"releases":{"bookworm":{"status":"open"}}}}}`
	}
	rel := func(r string) string {
		return `{"zlib":{"CVE-2024-1111":{"releases":{"bookworm":{"status":"open"}}},"CVE-2024-2222":{"releases":{"sid":` + r + `}}}}`
	}
	tests := []struct {
		name string
		in   string
	}{
		{"bad package name", pkg(`"Bad Name":{"CVE-2024-1":{"releases":{"sid":{"status":"open"}}}}`)},
		{"non-ASCII package name", pkg(`"zlïb":{}`)},
		{"package not object", pkg(`"aa":[1,{"x":[2]}]`)},
		{"package null", pkg(`"aa":null`)},
		{"package string", pkg(`"aa":"x"`)},
		{"bad issue id", issue(`"../x":{"releases":{"sid":{"status":"open"}}}`)},
		{"releases wrong type", issue(`"CVE-2024-2222":{"releases":"x"}`)},
		{"case shadow key", issue(`"CVE-2024-2222":{"releases":{"sid":{"status":"open","Status":"resolved"}}}`)},
		{"invalid utf8", issue("\"CVE-2024-2222\":{\"description\":\"\xff\"}")},
		{"issue not object", issue(`"CVE-2024-2222":[]`)},
		{"bad release name", `{"zlib":{"CVE-2024-1111":{"releases":{"Book worm":{"status":"open"},"bookworm":{"status":"open"}}}}}`},
		{"unknown status", rel(`{"status":"maybe"}`)},
		{"missing status", rel(`{"urgency":"low"}`)},
		{"status wrong type", rel(`{"status":1}`)},
		{"resolved without version", rel(`{"status":"resolved"}`)},
		{"bad fixed version", rel(`{"status":"resolved","fixed_version":"1.0 ; rm"}`)},
		{"unknown nodsa reason", rel(`{"status":"open","nodsa":"x","nodsa_reason":"later"}`)},
		{"bad urgency", rel(`{"status":"open","urgency":"HIGH!"}`)},
		// Per-issue field and count limits skip the issue, not the export.
		{"too many releases", issue(`"CVE-2024-2222":{"releases":{` + debianReleases(MaxDebianReleasesPerIssue+1) + `}}`)},
		{"long release value", issue(`"CVE-2024-2222":{"releases":{"sid":{"status":"open","fixed_version":"` + strings.Repeat("1", maxDebianReleaseValueBytes+1) + `"}}}`)},
		{"too many members", issue(`"CVE-2024-2222":{"x":[` + strings.TrimSuffix(strings.Repeat("0,", MaxJSONMembers+1), ",") + `]}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, sum, err := collectDebian(t, []byte(tc.in))
			if err != nil {
				t.Fatalf("err = %v, want the record skipped", err)
			}
			if sum.Skipped != 1 || !slices.Equal(got, []DebianEntry{debianGoodEntry}) {
				t.Fatalf("summary %+v, entries %+v", sum, got)
			}
		})
	}
}

func TestParseDebianTrackerPackageLimit(t *testing.T) {
	export := func(n int) []byte {
		var b strings.Builder
		b.WriteString("{")
		for i := range n {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"p%d":{}`, i)
		}
		b.WriteString("}")
		return []byte(b.String())
	}
	if _, sum, err := collectDebian(t, export(MaxDebianPackages)); err != nil || sum.Packages != MaxDebianPackages {
		t.Fatalf("at the limit: %+v, %v", sum, err)
	}
	if _, _, err := collectDebian(t, export(MaxDebianPackages+1)); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestParseDebianTrackerPackageByteLimit(t *testing.T) {
	// 65 issues of 1 MiB each: more than MaxDebianPackageBytes in one
	// package, streamed without building the export in memory.
	pad := strings.Repeat("a", 1<<20)
	readers := []io.Reader{strings.NewReader(`{"zlib":{`)}
	for i := range MaxDebianPackageBytes>>20 + 1 {
		sep := ","
		if i == 0 {
			sep = ""
		}
		readers = append(readers, strings.NewReader(fmt.Sprintf(`%s"CVE-2024-%d":{"x":"`, sep, 10000+i)), strings.NewReader(pad), strings.NewReader(`"}`))
	}
	readers = append(readers, strings.NewReader(`}}`))
	_, err := ParseDebianTracker(context.Background(), io.MultiReader(readers...), func(DebianEntry) error { return nil })
	if !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("err = %v, want ErrFeedLimit", err)
	}
}

func TestParseDebianTrackerEntryLimit(t *testing.T) {
	in := []byte(`{"zlib":{"CVE-2024-1":{"releases":{"bookworm":{"status":"open"},"sid":{"status":"open"}}},"CVE-2024-2":{"releases":{"sid":{"status":"bad"}}}}}`)
	visit := func(DebianEntry) error { return nil }
	if sum, err := parseDebianTracker(context.Background(), bytes.NewReader(in), 3, visit); err != nil || sum.Entries != 2 || sum.Skipped != 1 {
		t.Fatalf("at the limit: %+v, %v", sum, err)
	}
	// Skipped entries count towards the limit.
	if _, err := parseDebianTracker(context.Background(), bytes.NewReader(in), 2, visit); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	// The exported parser uses the named limit.
	if MaxDebianEntries != 20_000_000 {
		t.Fatalf("MaxDebianEntries = %d", MaxDebianEntries)
	}
}

func TestParseDebianTrackerIssueLimitFiresBeforeTheRestIsDecoded(t *testing.T) {
	// One package just over the issue limit (rejected, see
	// measureAllocs) and one ten times longer must cost the same: issues
	// are decoded one at a time.
	shortIn := []byte(`{"zlib":` + debianIssues(MaxDebianIssuesPerPackage+1, "{}") + `}`)
	longIn := []byte(`{"zlib":` + debianIssues(10*(MaxDebianIssuesPerPackage+1), "{}") + `}`)
	visit := func(DebianEntry) error { return nil }
	short := measureAllocs(t, func() error {
		_, err := ParseDebianTracker(context.Background(), bytes.NewReader(shortIn), visit)
		return err
	})
	long := measureAllocs(t, func() error {
		_, err := ParseDebianTracker(context.Background(), bytes.NewReader(longIn), visit)
		return err
	})
	short.assertCovers(t, long)
}

func TestParseDebianTrackerIgnoresUnknownFields(t *testing.T) {
	in := `{"zlib":{"CVE-2024-1111":{"new":{"deep":[1,{"a":"b"}]},"releases":{"bookworm":{"status":"open","extra":[1,2],"repositories":{"bookworm":"1.0"}}}}}}`
	got, _, err := collectDebian(t, []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].State != vulnfinding.TrackerUnfixed {
		t.Fatalf("got %+v", got)
	}
}

func TestParseDebianTrackerStopsOnVisitError(t *testing.T) {
	stop := errors.New("stop")
	_, err := ParseDebianTracker(context.Background(), bytes.NewReader(readFixture(t, "parse_debian", "tracker.json")),
		func(DebianEntry) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDebianTrackerHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ParseDebianTracker(ctx, bytes.NewReader(readFixture(t, "parse_debian", "tracker.json")),
		func(DebianEntry) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDebianAdvisoryListNewestDate(t *testing.T) {
	ctx := context.Background()
	dsa, err := ParseDebianAdvisoryList(ctx, bytes.NewReader(readFixture(t, "parse_debian", "dsa_list")))
	if err != nil {
		t.Fatal(err)
	}
	if dsa.Kind != "DSA" || dsa.Entries != 3 || !dsa.Newest.Equal(time.Date(2024, 11, 3, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("dsa %+v", dsa)
	}
	dla, err := ParseDebianAdvisoryList(ctx, bytes.NewReader(readFixture(t, "parse_debian", "dla_list")))
	if err != nil {
		t.Fatal(err)
	}
	if dla.Kind != "DLA" || dla.Entries != 2 || !dla.Newest.Equal(time.Date(2024, 11, 5, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("dla %+v", dla)
	}
	// CRLF line endings are accepted.
	crlf := "[01 Feb 2024] DSA-1-1 x - y\r\n\t{CVE-2024-1}\r\n"
	if got, err := ParseDebianAdvisoryList(ctx, strings.NewReader(crlf)); err != nil || got.Entries != 1 {
		t.Fatalf("crlf: %+v %v", got, err)
	}
}

func TestParseDebianAdvisoryListRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrNoContentDate},
		{"only continuation", "\t{CVE-2024-1}\n", ErrNoContentDate},
		{"only garbage", "<html>\n<body>\n", ErrNoContentDate},
		{"mixed kinds", "[01 Feb 2024] DSA-1-1 x\n[01 Feb 2024] DLA-1-1 x\n", ErrFeedMalformed},
		{"long line", "[01 Feb 2024] DSA-1-1 x\n\t" + strings.Repeat("a", MaxDebianListLineBytes) + "\n", ErrFeedLimit},
		{"too many entries", strings.Repeat("[01 Feb 2024] DSA-1-1 x\n", MaxDebianListEntries+1), ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDebianAdvisoryList(context.Background(), strings.NewReader(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseDebianAdvisoryListSkipsMalformedLines(t *testing.T) {
	const good = "[01 Feb 2024] DSA-1-1 x\n\t{CVE-2024-1}\n"
	bad := map[string]string{
		"garbage line":      "hello\n",
		"bad date":          "[31 Feb 2024] DSA-2-1 x\n",
		"bad month":         "[01 Foo 2024] DSA-2-1 x\n",
		"year out of range": "[01 Feb 1969] DSA-2-1 x\n",
		"bad id":            "[01 Feb 2024] DSX-2-1 x\n",
		"id glued":          "[01 Feb 2024] DSA-2-1x\n",
		"late date in bad":  "[01 Feb 2999x DSA-2-1 x\n",
		"control char":      "\t\x1b[31m\n",
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			got, err := ParseDebianAdvisoryList(context.Background(), strings.NewReader(good+b))
			if err != nil {
				t.Fatalf("err = %v, want the line skipped", err)
			}
			if got.Kind != "DSA" || got.Entries != 1 || got.Skipped != 1 || !got.Newest.Equal(day(2024, 2, 1)) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func FuzzParseDebianTracker(f *testing.F) {
	f.Add(readFixture(f, "parse_debian", "tracker.json"))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"a1":{"CVE-2024-1":{"releases":{"sid":{"status":"resolved","fixed_version":"0"}}}}}`))
	f.Add([]byte(`{"a1":{"CVE-2024-1":{"releases":{"sid":{"status":"open","nodsa":"","nodsa_reason":"ignored"}}}}}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		_, err := ParseDebianTracker(context.Background(), bytes.NewReader(in), func(e DebianEntry) error {
			if !debianPackageRe.MatchString(e.Package) || !feedVulnIDRe.MatchString(e.IssueID) || !debianReleaseRe.MatchString(e.Release) {
				t.Fatalf("unvalidated entry %+v", e)
			}
			if (e.State == vulnfinding.TrackerFixed) != (e.FixedVersion != "") {
				t.Fatalf("fixed version without fixed state %+v", e)
			}
			return nil
		})
		if err != nil && !errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit) {
			t.Fatalf("unexpected error class %v", err)
		}
	})
}

func FuzzParseDebianAdvisoryList(f *testing.F) {
	f.Add(readFixture(f, "parse_debian", "dsa_list"))
	f.Add(readFixture(f, "parse_debian", "dla_list"))
	f.Add([]byte("[01 Feb 2024] DSA-1-1 x\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseDebianAdvisoryList(context.Background(), bytes.NewReader(in))
		if err == nil && (got.Entries == 0 || got.Newest.IsZero()) {
			t.Fatalf("accepted list without a date: %+v", got)
		}
		if err != nil && !errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit) && !errors.Is(err, ErrNoContentDate) {
			t.Fatalf("unexpected error class %v", err)
		}
	})
}

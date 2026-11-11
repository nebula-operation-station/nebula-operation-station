// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"errors"
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

func TestParseDebianTrackerRejectsMalformed(t *testing.T) {
	rel := func(body string) string {
		return `{"openssl":{"CVE-2024-0001":{"releases":{"bookworm":` + body + `}}}}`
	}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"top level array", `[]`, ErrFeedMalformed},
		{"truncated", `{"openssl":{`, ErrFeedMalformed},
		{"trailing data", `{} {}`, ErrFeedMalformed},
		{"trailing garbage", `{}x`, ErrFeedMalformed},
		{"duplicate package", `{"zlib":{},"zlib":{}}`, ErrFeedMalformed},
		{"bad package name", `{"Bad Name":{}}`, ErrFeedMalformed},
		{"package not object", `{"zlib":[]}`, ErrFeedMalformed},
		{"package null", `{"zlib":null}`, ErrFeedMalformed},
		{"bad issue id", `{"zlib":{"../x":{"releases":{}}}}`, ErrFeedMalformed},
		{"duplicate issue", `{"zlib":{"CVE-2024-1":{},"CVE-2024-1":{}}}`, ErrFeedMalformed},
		{"bad release name", `{"zlib":{"CVE-2024-1111":{"releases":{"Book worm":{"status":"open"}}}}}`, ErrFeedMalformed},
		{"releases wrong type", `{"zlib":{"CVE-2024-1111":{"releases":"x"}}}`, ErrFeedMalformed},
		{"unknown status", rel(`{"status":"maybe"}`), ErrFeedMalformed},
		{"missing status", rel(`{"urgency":"low"}`), ErrFeedMalformed},
		{"status wrong type", rel(`{"status":1}`), ErrFeedMalformed},
		{"resolved without version", rel(`{"status":"resolved"}`), ErrFeedMalformed},
		{"bad fixed version", rel(`{"status":"resolved","fixed_version":"1.0 ; rm"}`), ErrFeedMalformed},
		{"unknown nodsa reason", rel(`{"status":"open","nodsa":"x","nodsa_reason":"later"}`), ErrFeedMalformed},
		{"bad urgency", rel(`{"status":"open","urgency":"HIGH!"}`), ErrFeedMalformed},
		{"case shadow key", rel(`{"status":"open","Status":"resolved"}`), ErrFeedMalformed},
		{"too deep", `{"zlib":{"CVE-2024-1111":{"x":` + strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth) + `}}}`, ErrFeedLimit},
		{"invalid utf8", "{\"zlib\":{\"CVE-2024-1111\":{\"description\":\"\xff\"}}}", ErrFeedMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := collectDebian(t, []byte(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
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
		{"garbage line", "[01 Feb 2024] DSA-1-1 x\nhello\n", ErrFeedMalformed},
		{"bad date", "[31 Feb 2024] DSA-1-1 x\n", ErrFeedMalformed},
		{"bad month", "[01 Foo 2024] DSA-1-1 x\n", ErrFeedMalformed},
		{"year out of range", "[01 Feb 1969] DSA-1-1 x\n", ErrFeedMalformed},
		{"bad id", "[01 Feb 2024] DSX-1-1 x\n", ErrFeedMalformed},
		{"id glued", "[01 Feb 2024] DSA-1-1x\n", ErrFeedMalformed},
		{"mixed kinds", "[01 Feb 2024] DSA-1-1 x\n[01 Feb 2024] DLA-1-1 x\n", ErrFeedMalformed},
		{"control char", "[01 Feb 2024] DSA-1-1 x\n\t\x1b[31m\n", ErrFeedMalformed},
		{"long line", "[01 Feb 2024] DSA-1-1 x\n\t" + strings.Repeat("a", MaxDebianListLineBytes) + "\n", ErrFeedLimit},
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

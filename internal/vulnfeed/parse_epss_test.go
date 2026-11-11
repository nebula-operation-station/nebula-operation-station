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

func TestParseEPSSScoresWithDate(t *testing.T) {
	got, err := ParseEPSS(context.Background(), bytes.NewReader(readFixture(t, "parse_epss", "scores.csv")))
	if err != nil {
		t.Fatal(err)
	}
	want := EPSSScores{
		Model: "v2023.03.01",
		Date:  day(2024, 10, 21),
		Scores: []EPSSScore{
			{"CVE-1999-0001", 0.01141, 0.78433},
			{"CVE-2021-44228", 0.97565, 0.99996},
			{"CVE-2024-0001", 4e-05, 0.00012},
			{"CVE-2024-0002", 1, 1},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scores:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseEPSSDateForms(t *testing.T) {
	for in, want := range map[string]time.Time{
		"2024-10-21T00:00:00+0000": day(2024, 10, 21),
		"2025-03-14T12:55:00Z":     time.Date(2025, 3, 14, 12, 55, 0, 0, time.UTC),
		"2022-02-04":               day(2022, 2, 4),
	} {
		doc := "#model_version:v1,score_date:" + in + "\r\ncve,epss,percentile\r\nCVE-2024-1234,0.1,0.2\r\n"
		got, err := ParseEPSS(context.Background(), strings.NewReader(doc))
		if err != nil || !got.Date.Equal(want) || len(got.Scores) != 1 {
			t.Errorf("%s: %+v, %v", in, got, err)
		}
	}
}

func TestParseEPSSRejectsMalformed(t *testing.T) {
	const meta = "#model_version:v2023.03.01,score_date:2024-10-21T00:00:00+0000\n"
	const head = meta + "cve,epss,percentile\n"
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrFeedMalformed},
		{"only meta", meta, ErrFeedMalformed},
		{"no meta", "cve,epss,percentile\nCVE-2024-1234,0.1,0.2\n", ErrFeedMalformed},
		{"no score date", "#model_version:v1\ncve,epss,percentile\n", ErrFeedMalformed},
		{"no model", "#score_date:2024-10-21\ncve,epss,percentile\n", ErrFeedMalformed},
		{"bad date", "#model_version:v1,score_date:today\ncve,epss,percentile\n", ErrFeedMalformed},
		{"repeated meta key", "#model_version:v1,score_date:2024-10-21,score_date:2030-01-01\ncve,epss,percentile\n", ErrFeedMalformed},
		{"meta with space", "#model_version:v 1,score_date:2024-10-21\ncve,epss,percentile\n", ErrFeedMalformed},
		{"wrong header", meta + "cve,percentile,epss\n", ErrFeedMalformed},
		{"two fields", head + "CVE-2024-1234,0.1\n", ErrFeedMalformed},
		{"four fields", head + "CVE-2024-1234,0.1,0.2,0.3\n", ErrFeedMalformed},
		{"quoted", head + "\"CVE-2024-1234\",0.1,0.2\n", ErrFeedMalformed},
		{"bad cve", head + "CVE-24-1,0.1,0.2\n", ErrFeedMalformed},
		{"above one", head + "CVE-2024-1234,1.5,0.2\n", ErrFeedMalformed},
		{"negative", head + "CVE-2024-1234,-0.1,0.2\n", ErrFeedMalformed},
		{"nan", head + "CVE-2024-1234,NaN,0.2\n", ErrFeedMalformed},
		{"inf", head + "CVE-2024-1234,0.1,Inf\n", ErrFeedMalformed},
		{"hex float", head + "CVE-2024-1234,0x1p-2,0.2\n", ErrFeedMalformed},
		{"duplicate cve", head + "CVE-2024-1234,0.1,0.2\nCVE-2024-1234,0.3,0.4\n", ErrFeedMalformed},
		{"long line", head + "CVE-2024-1234,0." + strings.Repeat("1", MaxEPSSLineBytes) + ",0.2\n", ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseEPSS(context.Background(), strings.NewReader(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseEPSSThroughGzip(t *testing.T) {
	gz := gzipBytes(t, readFixture(t, "parse_epss", "scores.csv"))
	zr, err := DecompressGzip(bytes.NewReader(gz), MaxEPSSBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	got, err := ParseEPSS(context.Background(), zr)
	if err != nil || len(got.Scores) != 4 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func FuzzParseEPSS(f *testing.F) {
	f.Add(readFixture(f, "parse_epss", "scores.csv"))
	f.Add([]byte("#model_version:v1,score_date:2024-10-21\ncve,epss,percentile\nCVE-2024-1234,0.1,0.2\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseEPSS(context.Background(), bytes.NewReader(in))
		if err != nil {
			if !errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit) {
				t.Fatalf("unexpected error class %v", err)
			}
			return
		}
		if got.Date.IsZero() {
			t.Fatal("accepted scores without a date")
		}
		for _, s := range got.Scores {
			if !cveIDRe.MatchString(s.CVE) || s.Probability < 0 || s.Probability > 1 || s.Percentile < 0 || s.Percentile > 1 {
				t.Fatalf("unvalidated score %+v", s)
			}
		}
	})
}

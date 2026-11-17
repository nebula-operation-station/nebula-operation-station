// SPDX-License-Identifier: AGPL-3.0-or-later

package opsdigest

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const testLink = "https://nos.lab.example/ops"

func sampleInput() Input {
	return Input{
		OpenUpdates:    3,
		RebootsPending: 1,
		HostsNotReady:  2,
		GrantsExpiring: 1,
		Findings:       Findings{Critical: 1, High: 4, Medium: 0, Low: 7, Unknown: 0, KEV: 1},
		FailedRuns24h:  2,
	}
}

func TestBuildGoldenGerman(t *testing.T) {
	want := "NOS Tagesübersicht\n" +
		"Offene Updates: 3\n" +
		"Neustarts ausstehend: 1\n" +
		"Hosts nicht READY: 2\n" +
		"Grants mit Ablauf in 7 Tagen: 1\n" +
		"Offene Findings: kritisch 1, hoch 4, mittel 0, niedrig 7, unbekannt 0\n" +
		"Davon in KEV: 1\n" +
		"Fehlgeschlagene Ausführungen (24 h): 2\n" +
		testLink
	got, err := Build(sampleInput(), Options{Lang: LangDE, NOSLink: testLink})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got != want {
		t.Fatalf("de digest mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestBuildGoldenEnglish(t *testing.T) {
	want := "NOS daily digest\n" +
		"Open updates: 3\n" +
		"Reboots pending: 1\n" +
		"Hosts not READY: 2\n" +
		"Grants expiring within 7 days: 1\n" +
		"Open findings: critical 1, high 4, medium 0, low 7, unknown 0\n" +
		"Of which KEV: 1\n" +
		"Failed runs (24 h): 2\n" +
		testLink
	got, err := Build(sampleInput(), Options{Lang: LangEN, NOSLink: testLink})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got != want {
		t.Fatalf("en digest mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestBuildIsPlainTextWithoutMarkdownOrExtraLinks(t *testing.T) {
	for _, lang := range []Lang{LangDE, LangEN} {
		got, err := Build(sampleInput(), Options{Lang: lang, NOSLink: testLink})
		if err != nil {
			t.Fatalf("%s: Build: %v", lang, err)
		}
		for _, bad := range []string{"*", "_", "`", "[", "](", "<", ">"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: digest contains markup %q: %q", lang, bad, got)
			}
		}
		if n := strings.Count(got, "://"); n != 1 {
			t.Errorf("%s: want exactly one link, got %d", lang, n)
		}
	}
}

func TestBuildEmptyDayUnsuppressed(t *testing.T) {
	cases := map[Lang]string{
		LangDE: "NOS Tagesübersicht: nichts offen.\n" + testLink,
		LangEN: "NOS daily digest: nothing open.\n" + testLink,
	}
	for lang, want := range cases {
		got, err := Build(Input{}, Options{Lang: lang, NOSLink: testLink})
		if err != nil {
			t.Fatalf("%s: Build: %v", lang, err)
		}
		if got != want {
			t.Fatalf("%s empty digest\n got: %q\nwant: %q", lang, got, want)
		}
	}
}

func TestBuildEmptyDaySkipped(t *testing.T) {
	_, err := Build(Input{}, Options{Lang: LangDE, NOSLink: testLink, SkipEmpty: true})
	if !errors.Is(err, ErrNothingToSend) {
		t.Fatalf("want ErrNothingToSend, got %v", err)
	}
}

func TestSkipEmptyDoesNotSuppressNonEmptyDay(t *testing.T) {
	in := Input{Findings: Findings{KEV: 1}}
	if _, err := Build(in, Options{Lang: LangEN, NOSLink: testLink, SkipEmpty: true}); err != nil {
		t.Fatalf("only KEV count set: Build: %v", err)
	}
	in = Input{FailedRuns24h: 1}
	if _, err := Build(in, Options{Lang: LangEN, NOSLink: testLink, SkipEmpty: true}); err != nil {
		t.Fatalf("only failed runs set: Build: %v", err)
	}
}

func TestBuildRejectsUnknownLanguage(t *testing.T) {
	for _, lang := range []Lang{"", "fr", "DE"} {
		if _, err := Build(sampleInput(), Options{Lang: lang, NOSLink: testLink}); !errors.Is(err, ErrUnknownLang) {
			t.Errorf("lang %q: want ErrUnknownLang, got %v", lang, err)
		}
	}
}

func TestBuildRejectsNegativeCounts(t *testing.T) {
	cases := map[string]Input{
		"updates":   {OpenUpdates: -1},
		"reboots":   {RebootsPending: -1},
		"not ready": {HostsNotReady: -1},
		"grants":    {GrantsExpiring: -1},
		"critical":  {Findings: Findings{Critical: -1}},
		"kev":       {Findings: Findings{KEV: -1}},
		"failed":    {FailedRuns24h: -1},
	}
	for name, in := range cases {
		if _, err := Build(in, Options{Lang: LangEN, NOSLink: testLink}); !errors.Is(err, ErrInvalidCount) {
			t.Errorf("%s: want ErrInvalidCount, got %v", name, err)
		}
	}
}

func TestBuildLinkValidation(t *testing.T) {
	long := "https://nos.lab.example/" + strings.Repeat("a", MaxLinkBytes-len("https://nos.lab.example/"))
	if len(long) != MaxLinkBytes {
		t.Fatalf("test setup: link length %d", len(long))
	}
	tooLong := long + "a"
	cases := map[string]struct {
		link    string
		wantErr bool
	}{
		"empty":           {"", true},
		"no scheme":       {"nos.lab.example/ops", true},
		"ftp scheme":      {"ftp://nos.lab.example/ops", true},
		"no host":         {"https:///ops", true},
		"user info":       {"https://user:pw@nos.lab.example/ops", true},
		"space":           {"https://nos.lab.example/a b", true},
		"newline":         {"https://nos.lab.example/ops\nX: y", true},
		"markdown link":   {"[NOS](https://nos.lab.example/ops)", true},
		"angle brackets":  {"<https://nos.lab.example/ops>", true},
		"too long":        {tooLong, true},
		"max length":      {long, false},
		"plain https":     {testLink, false},
		"plain http loop": {"http://127.0.0.1:8080/ops", false},
	}
	for name, tc := range cases {
		_, err := Build(sampleInput(), Options{Lang: LangDE, NOSLink: tc.link})
		if tc.wantErr && !errors.Is(err, ErrInvalidLink) {
			t.Errorf("%s: want ErrInvalidLink, got %v", name, err)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: Build: %v", name, err)
		}
	}
}

func TestBuildLengthLimitHoldsForMaximalInput(t *testing.T) {
	huge := int(^uint(0) >> 1) // math.MaxInt, largest possible count
	in := Input{
		OpenUpdates:    huge,
		RebootsPending: huge,
		HostsNotReady:  huge,
		GrantsExpiring: huge,
		Findings:       Findings{Critical: huge, High: huge, Medium: huge, Low: huge, Unknown: huge, KEV: huge},
		FailedRuns24h:  huge,
	}
	link := "https://nos.lab.example/" + strings.Repeat("a", MaxLinkBytes-len("https://nos.lab.example/"))
	for _, lang := range []Lang{LangDE, LangEN} {
		got, err := Build(in, Options{Lang: lang, NOSLink: link})
		if err != nil {
			t.Fatalf("%s: Build: %v", lang, err)
		}
		if len(got) > MaxDigestBytes {
			t.Fatalf("%s: digest is %d bytes, limit %d", lang, len(got), MaxDigestBytes)
		}
	}
}

type fakeCount struct {
	n   int
	err error
}

func (f fakeCount) Count(context.Context) (int, error) { return f.n, f.err }

type fakeFindings struct {
	f   Findings
	err error
}

func (f fakeFindings) Findings(context.Context) (Findings, error) { return f.f, f.err }

func TestCollectFillsInputFromSources(t *testing.T) {
	src := Sources{
		Updates:        fakeCount{n: 3},
		Reboots:        fakeCount{n: 1},
		NotReady:       fakeCount{n: 2},
		GrantsExpiring: fakeCount{n: 1},
		FailedRuns:     fakeCount{n: 2},
		Findings:       fakeFindings{f: Findings{Critical: 1, High: 4, Low: 7, KEV: 1}},
	}
	got, err := Collect(context.Background(), src)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if want := sampleInput(); got != want {
		// sampleInput has Medium 0 and Unknown 0, matching the fakes.
		t.Fatalf("Collect = %+v, want %+v", got, want)
	}
}

func TestCollectFailsClosedOnSourceError(t *testing.T) {
	boom := errors.New("db down")
	base := Sources{
		Updates:        fakeCount{},
		Reboots:        fakeCount{},
		NotReady:       fakeCount{},
		GrantsExpiring: fakeCount{},
		FailedRuns:     fakeCount{},
		Findings:       fakeFindings{},
	}
	cases := map[string]Sources{}
	withUpdates := base
	withUpdates.Updates = fakeCount{err: boom}
	cases["updates"] = withUpdates
	withFindings := base
	withFindings.Findings = fakeFindings{err: boom}
	cases["findings"] = withFindings
	withFailed := base
	withFailed.FailedRuns = fakeCount{err: boom}
	cases["failed runs"] = withFailed

	for name, src := range cases {
		if _, err := Collect(context.Background(), src); !errors.Is(err, boom) {
			t.Errorf("%s: want wrapped source error, got %v", name, err)
		}
	}
}

func TestCollectRejectsMissingSourceAndNegativeCount(t *testing.T) {
	if _, err := Collect(context.Background(), Sources{}); !errors.Is(err, ErrMissingSource) {
		t.Fatalf("nil sources: want ErrMissingSource, got %v", err)
	}
	src := Sources{
		Updates:        fakeCount{n: -1},
		Reboots:        fakeCount{},
		NotReady:       fakeCount{},
		GrantsExpiring: fakeCount{},
		FailedRuns:     fakeCount{},
		Findings:       fakeFindings{},
	}
	if _, err := Collect(context.Background(), src); !errors.Is(err, ErrInvalidCount) {
		t.Fatalf("negative count: want ErrInvalidCount, got %v", err)
	}
}

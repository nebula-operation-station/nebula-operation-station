// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"testing"
	"time"
)

func TestListBoundsAndReportsTruncation(t *testing.T) {
	e := newEnv(t)
	e.seed(t, "h1", 3)
	all, trunc, err := e.st.List(e.ctx, 10)
	if err != nil || trunc || len(all) != 3 {
		t.Fatalf("List(10) = %d rows, truncated %v, err %v; want 3, false", len(all), trunc, err)
	}
	two, trunc, err := e.st.List(e.ctx, 2)
	if err != nil || !trunc || len(two) != 2 {
		t.Fatalf("List(2) = %d rows, truncated %v, err %v; want 2, true", len(two), trunc, err)
	}
	if _, _, err := e.st.List(e.ctx, 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("List(0) err = %v, want ErrInvalidInput", err)
	}
	if _, _, err := e.st.List(e.ctx, MaxListFindings+1); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("List(max+1) err = %v, want ErrInvalidInput", err)
	}
}

func TestRunAlertFindingsReturnsOpenKEVOrCriticalOfThatRun(t *testing.T) {
	e := newEnv(t)
	r := e.start(t)
	plain := item(t, "h1", cve(1))
	kev := item(t, "h1", cve(2), withKEV("2026-11-01"))
	crit := item(t, "h1", cve(3), withCVSS(9.8))
	e.submit(t, r, 0, nil, plain, kev, crit)
	got, err := e.st.RunAlertFindings(e.ctx, r.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("RunAlertFindings = %d findings, want 2 (KEV and critical)", len(got))
	}
	for _, f := range got {
		if f.Key == plain.Finding.Key {
			t.Fatal("a finding that is neither KEV nor critical was returned")
		}
	}
	// Another run's findings are not returned for this run.
	r2 := e.start(t)
	got, err = e.st.RunAlertFindings(e.ctx, r2.ID, 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("RunAlertFindings(other run) = %d, %v; want none", len(got), err)
	}
	if _, err := e.st.RunAlertFindings(e.ctx, "nope", 10); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("unknown run err = %v, want ErrRunNotFound", err)
	}
	if got, _ := e.st.RunAlertFindings(e.ctx, r.ID, 1); len(got) != 1 {
		t.Fatalf("limit 1 returned %d", len(got))
	}
}

func TestFeedStatusesFollowSourceListAndMaxAge(t *testing.T) {
	e := newEnv(t)
	e.start(t) // osv and kev accepted, content date one hour ago
	st, err := e.st.FeedStatuses(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != len(testSources) {
		t.Fatalf("FeedStatuses = %d entries, want %d", len(st), len(testSources))
	}
	by := map[string]FeedState{}
	for i, s := range st {
		if s.SourceID != testSources[i].ID {
			t.Fatalf("entry %d = %s, want list order %s", i, s.SourceID, testSources[i].ID)
		}
		by[s.SourceID] = s
	}
	if by["osv"].Stale || by["osv"].ContentDate.IsZero() || by["osv"].LastVerdict != SourceAccepted {
		t.Fatalf("osv = %+v, want fresh, dated, accepted", by["osv"])
	}
	if !by["nvd"].Stale || !by["nvd"].ContentDate.IsZero() {
		t.Fatalf("nvd never named = %+v, want stale and undated", by["nvd"])
	}
	e.clk.Add(72 * time.Hour)
	st, _ = e.st.FeedStatuses(e.ctx)
	if !st[0].Stale {
		t.Fatalf("osv after max age = %+v, want stale", st[0])
	}
	if want := by["osv"].ContentDate.Add(72 * time.Hour); !st[0].StaleSince.Equal(want) {
		t.Fatalf("osv stale since %v, want %v", st[0].StaleSince, want)
	}
}

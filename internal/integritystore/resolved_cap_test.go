// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"sort"
	"testing"
	"time"
)

// TestTrimResolvedKeepsNewestClosedFindings: resolved rows of a subject are
// bounded; the oldest closed ones are removed first, and open findings are
// never removed.
func TestTrimResolvedKeepsNewestClosedFindings(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	const total = 5
	for i := 0; i < total; i++ {
		run := mustBegin(t, s, subj)
		if _, err := s.Record(t.Context(), run.ID, []Observation{obs(ClassEtcChanged, sizedPathStr(i))}); err != nil {
			t.Fatal(err)
		}
		finishComplete(t, s, run.ID)
		clk.Add(time.Minute)
	}
	// Paths 0..3 were resolved by the runs that replaced them; path 4 is open.

	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := trimResolved(t.Context(), tx, subj, 2); err != nil {
		tx.Rollback()
		t.Fatalf("trimResolved: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query(`SELECT path, state FROM integrity_findings WHERE subject = ?`, string(subj))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var resolved, open []string
	for rows.Next() {
		var path []byte
		var state string
		if err := rows.Scan(&path, &state); err != nil {
			t.Fatal(err)
		}
		if state == string(StateResolved) {
			resolved = append(resolved, string(path))
		} else {
			open = append(open, string(path))
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(resolved)
	want := []string{sizedPathStr(2), sizedPathStr(3)}
	if len(resolved) != len(want) || resolved[0] != want[0] || resolved[1] != want[1] {
		t.Fatalf("resolved after trim = %q, want the two newest %q", resolved, want)
	}
	if len(open) != 1 || open[0] != sizedPathStr(4) {
		t.Fatalf("open findings = %q, want only %q", open, sizedPathStr(4))
	}
}

// sizedPathStr is the path of the i-th finding in TestTrimResolvedKeepsNewestClosedFindings.
func sizedPathStr(i int) string { return string(sizedPath(i, 24)) }

// TestRotatingPathsCannotGrowRowsPastBound: a host that reports a new set of
// paths in every round, and whose previous set is resolved by a complete
// run that sees nothing, stores at most MaxFindingsPerSubject active and
// MaxResolvedPerSubject resolved rows. Without the bound on resolved rows
// the table would reach 18000 rows here.
func TestRotatingPathsCannotGrowRowsPastBound(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	const perRun = 9000
	for round := 0; round < 2; round++ {
		run := mustBegin(t, s, subj)
		fillFindings(t, s, run.ID, ClassEtcChanged, round*perRun, perRun)
		finishComplete(t, s, run.ID)
		clk.Add(time.Hour)
		// A complete run that sees nothing resolves the set just reported.
		empty := mustBegin(t, s, subj)
		finishComplete(t, s, empty.ID)
		clk.Add(time.Hour)
	}
	if n := rowCount(t, db, subj); n > MaxFindingsPerSubject+MaxResolvedPerSubject {
		t.Fatalf("rows = %d, want at most %d", n, MaxFindingsPerSubject+MaxResolvedPerSubject)
	}
}

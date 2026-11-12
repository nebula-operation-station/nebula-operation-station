// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRecordInsertsOpenFindingWithSeverityFromClass(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	o := obs(ClassPkgFileMismatch, "/usr/bin/openssl")
	o.OldRecord = "sha256=bb"
	res, err := s.Record(t.Context(), run.ID, []Observation{o})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if res.Inserted != 1 || res.Updated != 0 {
		t.Fatalf("result = %+v, want one insert", res)
	}
	f, err := s.Get(t.Context(), keyOf(subj, o))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if f.State != StateOpen {
		t.Errorf("state = %s, want open", f.State)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical (D9 class table)", f.Severity)
	}
	if f.OldRecord != "sha256=bb" || f.NewRecord != o.NewRecord {
		t.Errorf("records = %q / %q", f.OldRecord, f.NewRecord)
	}
	if f.OpenedRunID != run.ID || f.LastRunID != run.ID {
		t.Errorf("run ids opened=%s last=%s, want %s", f.OpenedRunID, f.LastRunID, run.ID)
	}
	if !f.FirstSeen.Equal(t0) || !f.LastSeen.Equal(t0) {
		t.Errorf("first/last seen = %v / %v, want %v", f.FirstSeen, f.LastSeen, t0)
	}
}

func TestRecordUpdatesExistingFindingAndKeepsFirstSeen(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	o := obs(ClassEtcChanged, "/etc/ssh/sshd_config")
	first := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), first.ID, []Observation{o}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, first.ID)

	clk.Add(24 * time.Hour)
	second := mustBegin(t, s, subj)
	o.NewRecord = "sha256=cc owner=root mode=0600"
	res, err := s.Record(t.Context(), second.ID, []Observation{o})
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 || res.Inserted != 0 {
		t.Fatalf("result = %+v, want one update", res)
	}
	f, err := s.Get(t.Context(), keyOf(subj, o))
	if err != nil {
		t.Fatal(err)
	}
	if !f.FirstSeen.Equal(t0) {
		t.Errorf("first seen moved to %v", f.FirstSeen)
	}
	if !f.LastSeen.Equal(t0.Add(24 * time.Hour)) {
		t.Errorf("last seen = %v", f.LastSeen)
	}
	if f.OpenedRunID != first.ID || f.LastRunID != second.ID {
		t.Errorf("run ids opened=%s last=%s", f.OpenedRunID, f.LastRunID)
	}
	if f.NewRecord != o.NewRecord {
		t.Errorf("new record = %q, want updated value", f.NewRecord)
	}
}

func TestCompleteRunResolvesFindingsItDidNotSee(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	a := obs(ClassEtcChanged, "/etc/a")
	b := obs(ClassEtcChanged, "/etc/b")

	r1 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r1.ID, []Observation{a, b}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r1.ID)

	clk.Add(time.Hour)
	r2 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r2.ID, []Observation{a}); err != nil {
		t.Fatal(err)
	}
	res := finishComplete(t, s, r2.ID)
	if res.Outcome != OutcomeComplete || res.Closed != 1 {
		t.Fatalf("finish = %+v, want complete with one closed", res)
	}
	fb, err := s.Get(t.Context(), keyOf(subj, b))
	if err != nil {
		t.Fatal(err)
	}
	if fb.State != StateResolved || fb.ClosedRunID != r2.ID || fb.ClosedAt.IsZero() {
		t.Errorf("b = %+v, want resolved by run %s", fb, r2.ID)
	}
	fa, _ := s.Get(t.Context(), keyOf(subj, a))
	if fa.State != StateOpen {
		t.Errorf("seen finding a state = %s, want open", fa.State)
	}
}

func TestIncompleteRunClosesNothing(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	b := obs(ClassEtcChanged, "/etc/b")
	r1 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r1.ID, []Observation{b}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r1.ID)

	clk.Add(time.Hour)
	r2 := mustBegin(t, s, subj)
	res, err := s.Finish(t.Context(), r2.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeIncomplete || res.Closed != 0 {
		t.Fatalf("finish = %+v, want incomplete and nothing closed", res)
	}
	f, _ := s.Get(t.Context(), keyOf(subj, b))
	if f.State != StateOpen {
		t.Errorf("state = %s after incomplete run, want open", f.State)
	}
}

func TestRunWithDroppedObservationCannotClose(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	b := obs(ClassEtcChanged, "/etc/b")
	r1 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r1.ID, []Observation{b}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r1.ID)

	clk.Add(time.Hour)
	r2 := mustBegin(t, s, subj)
	// A path over the limit is not stored; the run did see b's path
	// partly, so b must not be closed by this run.
	over := Observation{Class: ClassEtcChanged, Path: sizedPath(9, MaxPathBytes+1)}
	res, err := s.Record(t.Context(), r2.ID, []Observation{over})
	if err != nil {
		t.Fatal(err)
	}
	if res.PathRejected != 1 {
		t.Fatalf("PathRejected = %d, want 1", res.PathRejected)
	}
	fin := finishComplete(t, s, r2.ID)
	if fin.Outcome != OutcomeIncomplete || fin.Closed != 0 || fin.Dropped != 1 {
		t.Fatalf("finish = %+v, want incomplete, nothing closed, one dropped", fin)
	}
	f, _ := s.Get(t.Context(), keyOf(subj, b))
	if f.State != StateOpen {
		t.Errorf("b state = %s, want open", f.State)
	}
}

func TestExpiredRunIsAbortedAndClosesNothing(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	b := obs(ClassEtcChanged, "/etc/b")
	r1 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r1.ID, []Observation{b}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r1.ID)

	clk.Add(time.Hour)
	r2 := mustBegin(t, s, subj)
	clk.Add(MaxRunDuration + time.Minute)
	_, err := s.Record(t.Context(), r2.ID, []Observation{obs(ClassEtcChanged, "/etc/x")})
	if !errors.Is(err, ErrRunExpired) {
		t.Fatalf("Record on expired run: %v, want ErrRunExpired", err)
	}
	if _, err := s.Finish(t.Context(), r2.ID, true); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("Finish on aborted run: %v, want ErrRunNotRunning", err)
	}
	f, _ := s.Get(t.Context(), keyOf(subj, b))
	if f.State != StateOpen {
		t.Errorf("b state = %s, want open", f.State)
	}
}

func TestOnlyOneRunPerSubject(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	web := mustHost(t, "web-1")
	db := mustHost(t, "db-1")
	r1 := mustBegin(t, s, web)
	if _, err := s.BeginRun(t.Context(), web); !errors.Is(err, ErrRunActive) {
		t.Fatalf("second run for same subject: %v, want ErrRunActive", err)
	}
	mustBegin(t, s, db)
	finishComplete(t, s, r1.ID)
	mustBegin(t, s, web)
}

func TestRawInvalidUTF8PathStaysRawAndIsEscapedForDisplay(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := NOSSubject
	raw := []byte("/etc/caf\xe9\x00\\x")
	run := mustBegin(t, s, subj)
	o := Observation{Class: ClassEtcChanged, Path: raw}
	// The NUL byte is not a valid path (Linux paths cannot contain it), so
	// the observation is rejected, not stored with a silently cut path.
	res, err := s.Record(t.Context(), run.ID, []Observation{o})
	if err != nil {
		t.Fatal(err)
	}
	if res.PathRejected != 1 || res.Inserted != 0 {
		t.Fatalf("path with NUL: result = %+v, want one rejected path", res)
	}
	finishComplete(t, s, run.ID)
	if rowCount(t, db, subj) != 0 {
		t.Fatal("path with NUL stored")
	}

	run2 := mustBegin(t, s, subj)
	raw2 := []byte("/etc/caf\xe9")
	o2 := Observation{Class: ClassEtcChanged, Path: raw2}
	if _, err := s.Record(t.Context(), run2.ID, []Observation{o2}); err != nil {
		t.Fatal(err)
	}
	f, err := s.Get(t.Context(), keyOf(subj, o2))
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Path) != string(raw2) {
		t.Errorf("stored path = %q, want the raw bytes %q", f.Path, raw2)
	}
	if f.PathDisplay != `/etc/caf\xe9` {
		t.Errorf("display = %q, want escaped form", f.PathDisplay)
	}
}

func TestEscapePathKeepsPrintableUTF8AndEscapesTheRest(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"ascii", []byte("/etc/hosts"), "/etc/hosts"},
		{"backslash", []byte(`/etc/a\b`), `/etc/a\\b`},
		{"newline", []byte("/etc/a\nb"), `/etc/a\x0ab`},
		{"invalid byte", []byte{'/', 0xff}, `/\xff`},
		{"truncated multibyte", []byte{'/', 0xc3}, `/\xc3`},
		{"printable utf8", []byte("/etc/ä"), "/etc/ä"},
		{"bidi override", []byte{'/', 'e', 't', 'c', '/', 0xe2, 0x80, 0xae, 'x'}, `/etc/\xe2\x80\xaex`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EscapePath(tc.raw); got != tc.want {
				t.Errorf("EscapePath(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestSeverityTableAndHighestMatchingWins(t *testing.T) {
	cases := map[Class]Severity{
		ClassPkgFileMismatch:        SeverityCritical,
		ClassCriticalPathChanged:    SeverityCritical,
		ClassEtcChanged:             SeverityHigh,
		ClassPkgUpdatedOutsideNOS:   SeverityMedium,
		ClassScanPartial:            SeverityMedium,
		ClassExpectedChange:         SeverityInfo,
		ClassMountUnexpectedCrit:    SeverityCritical,
		ClassMountUnexpected:        SeverityHigh,
		ClassSSHKeyExtra:            SeverityCritical,
		ClassPkgDowngraded:          SeverityHigh,
		ClassBaselineDigestMismatch: SeverityHigh,
	}
	for c, want := range cases {
		got, err := c.Severity()
		if err != nil || got != want {
			t.Errorf("%s.Severity() = %s, %v; want %s", c, got, err, want)
		}
	}
	if _, err := Class("nope").Severity(); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unknown class: %v, want ErrInvalidInput", err)
	}
	got, ok := Escalate(ClassEtcChanged, ClassMountUnexpectedCrit, ClassScanPartial)
	if !ok || got != ClassMountUnexpectedCrit {
		t.Errorf("Escalate = %s, %v; want the critical class", got, ok)
	}
	if _, ok := Escalate(); ok {
		t.Error("Escalate with no classes reported a match")
	}
}

func TestDuplicateObservationsInBatchAreCountedOnce(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	a := obs(ClassEtcChanged, "/etc/a")
	a2 := obs(ClassEtcChanged, "/etc/a")
	a2.NewRecord = "sha256=dd"
	res, err := s.Record(t.Context(), run.ID, []Observation{a, a2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 1 || res.Duplicates != 1 {
		t.Fatalf("result = %+v, want one insert and one duplicate", res)
	}
	if rowCount(t, db, subj) != 1 {
		t.Fatal("duplicate key stored twice")
	}
	f, _ := s.Get(t.Context(), keyOf(subj, a))
	if f.NewRecord != "sha256=dd" {
		t.Errorf("later observation should win, got %q", f.NewRecord)
	}
}

func TestBatchAboveLimitIsRefusedWhole(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	batch := make([]Observation, MaxObservationsPerBatch+1)
	for i := range batch {
		batch[i] = Observation{Class: ClassEtcChanged, Path: sizedPath(i, 30)}
	}
	if _, err := s.Record(t.Context(), run.ID, batch); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("err = %v, want ErrBatchTooLarge", err)
	}
	if rowCount(t, db, subj) != 0 {
		t.Fatal("refused batch partly stored")
	}
}

func TestUnknownClassRefusesBatch(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	batch := []Observation{obs(ClassEtcChanged, "/etc/a"), obs(Class("made-up"), "/etc/b")}
	if _, err := s.Record(t.Context(), run.ID, batch); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
	if rowCount(t, db, subj) != 0 {
		t.Fatal("batch with an unknown class partly stored")
	}
}

func TestFindingsPerSubjectLimitCountsOverflow(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	for start := 0; start < MaxFindingsPerSubject; start += MaxObservationsPerBatch {
		batch := make([]Observation, 0, MaxObservationsPerBatch)
		for i := start; i < start+MaxObservationsPerBatch; i++ {
			batch = append(batch, Observation{Class: ClassCriticalPathChanged, Path: sizedPath(i, 40)})
		}
		res, err := s.Record(t.Context(), run.ID, batch)
		if err != nil {
			t.Fatalf("Record at %d: %v", start, err)
		}
		if res.OverLimit != 0 {
			t.Fatalf("OverLimit = %d before the limit", res.OverLimit)
		}
	}
	if rowCount(t, db, subj) != MaxFindingsPerSubject {
		t.Fatalf("rows = %d, want %d", rowCount(t, db, subj), MaxFindingsPerSubject)
	}
	extra := Observation{Class: ClassCriticalPathChanged, Path: []byte("/etc/over-the-limit")}
	res, err := s.Record(t.Context(), run.ID, []Observation{extra})
	if err != nil {
		t.Fatal(err)
	}
	if res.OverLimit != 1 || res.Inserted != 0 {
		t.Fatalf("result = %+v, want the new finding counted as over limit", res)
	}
	if rowCount(t, db, subj) != MaxFindingsPerSubject {
		t.Fatal("finding over the limit was stored")
	}
	// An already stored finding is still updated at the limit.
	res, err = s.Record(t.Context(), run.ID, []Observation{{Class: ClassCriticalPathChanged, Path: sizedPath(0, 40)}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 || res.OverLimit != 0 {
		t.Fatalf("existing finding at the limit: %+v", res)
	}
	fin := finishComplete(t, s, run.ID)
	if fin.Outcome != OutcomeIncomplete || fin.Dropped != 1 {
		t.Fatalf("finish = %+v, want incomplete because of the overflow", fin)
	}
}

func TestOversizedRecordIsCountedAndStoredEmpty(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	o := obs(ClassEtcChanged, "/etc/big")
	o.NewRecord = strings.Repeat("a", MaxRecordBytes+1)
	res, err := s.Record(t.Context(), run.ID, []Observation{o})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordsDropped != 1 || res.Inserted != 1 {
		t.Fatalf("result = %+v", res)
	}
	f, _ := s.Get(t.Context(), keyOf(subj, o))
	if f.NewRecord != "" {
		t.Errorf("oversized record kept: %d bytes", len(f.NewRecord))
	}
	if res2, _ := s.Finish(t.Context(), run.ID, true); res2.Outcome != OutcomeComplete {
		t.Errorf("an oversized record must not make the run incomplete: %+v", res2)
	}
}

func TestInvalidUTF8RecordIsDropped(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	o := obs(ClassEtcChanged, "/etc/bad")
	o.NewRecord = "sha256=\xff"
	res, err := s.Record(t.Context(), run.ID, []Observation{o})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordsDropped != 1 {
		t.Fatalf("RecordsDropped = %d, want 1", res.RecordsDropped)
	}
	f, _ := s.Get(t.Context(), keyOf(subj, o))
	if f.NewRecord != "" {
		t.Errorf("invalid UTF-8 record kept as %q", f.NewRecord)
	}
}

func TestExpectedPendingAndAcceptTransitions(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	a := obs(ClassPkgUpdatedOutsideNOS, "/usr/bin/x")
	b := obs(ClassEtcChanged, "/etc/b")
	ka, kb := keyOf(subj, a), keyOf(subj, b)

	run := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), run.ID, []Observation{a, b}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExpectedPending(t.Context(), run.ID, ka); err != nil {
		t.Fatalf("MarkExpectedPending: %v", err)
	}
	if err := s.MarkExpectedPending(t.Context(), run.ID, ka); !errors.Is(err, ErrWrongState) {
		t.Errorf("second MarkExpectedPending: %v, want ErrWrongState", err)
	}
	fa, _ := s.Get(t.Context(), ka)
	if fa.State != StateExpectedPending || fa.StateRunID != run.ID {
		t.Errorf("a = state %s run %s", fa.State, fa.StateRunID)
	}
	if err := s.Accept(t.Context(), kb, ""); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("Accept without actor: %v, want ErrInvalidInput", err)
	}
	if err := s.Accept(t.Context(), kb, "admin"); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	fb, _ := s.Get(t.Context(), kb)
	if fb.State != StateAccepted || fb.StateBy != "admin" {
		t.Errorf("b = %s by %q", fb.State, fb.StateBy)
	}

	// Transitions need a running run of the same subject.
	if err := s.ClearExpectedPending(t.Context(), run.ID, ka); err != nil {
		t.Fatalf("ClearExpectedPending: %v", err)
	}
	finishComplete(t, s, run.ID)
	if err := s.MarkExpectedPending(t.Context(), run.ID, ka); !errors.Is(err, ErrRunNotRunning) {
		t.Errorf("transition on finished run: %v, want ErrRunNotRunning", err)
	}

	// An accepted finding that is not seen by a complete run is resolved.
	clk.Add(time.Hour)
	r2 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r2.ID, []Observation{a}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r2.ID)
	fb, _ = s.Get(t.Context(), kb)
	if fb.State != StateResolved {
		t.Errorf("unseen accepted finding = %s, want resolved", fb.State)
	}
}

func TestTransitionOnOtherSubjectsRunIsRefused(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	web := mustHost(t, "web-1")
	db := mustHost(t, "db-1")
	a := obs(ClassEtcChanged, "/etc/a")
	r := mustBegin(t, s, web)
	if _, err := s.Record(t.Context(), r.ID, []Observation{a}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExpectedPending(t.Context(), r.ID, keyOf(db, a)); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("transition for another subject: %v, want ErrInvalidInput", err)
	}
}

func TestSubjectValidation(t *testing.T) {
	for _, id := range []string{"", "a/b", "A", "../x", strings.Repeat("a", 64)} {
		if _, err := HostSubject(id); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("HostSubject(%q): %v, want ErrInvalidInput", id, err)
		}
	}
	if s, err := HostSubject("web-1"); err != nil || s != "host/web-1" {
		t.Errorf("HostSubject(web-1) = %q, %v", s, err)
	}
	if NOSSubject != "nos" {
		t.Errorf("NOSSubject = %q", NOSSubject)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClock is an injected clock for the store.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

var baseTime = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// openTestStore opens a store in a fresh temporary directory.
func openTestStore(t *testing.T, clock *fakeClock) *Store {
	t.Helper()
	s, err := Open(filepath.Join(privateTestDir(t), "notes.db"), clock.Now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

const testSnapshot = `{"group":"vu:host1:openssl","findings":3}`

func TestPutStoresValidatedNoteWithSnapshot(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	r := newFakeResolver()

	n, created, err := s.Put(context.Background(), r, validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !created || n.ID == 0 {
		t.Fatalf("Put created=%v id=%d, want created with an ID", created, n.ID)
	}
	got, err := s.Get(context.Background(), n.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Kind != KindFix || got.Ref != "vu:host1:openssl" || got.Digest != "d1" {
		t.Errorf("Get key = %s %s %s", got.Kind, got.Ref, got.Digest)
	}
	if got.Snapshot != testSnapshot {
		t.Errorf("Snapshot = %q, want the caller's snapshot", got.Snapshot)
	}
	if got.Body.Summary != "Paket aktualisieren" || len(got.Body.Steps) != 1 {
		t.Errorf("Body = %+v", got.Body)
	}
	if !got.CreatedAt.Equal(baseTime) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, baseTime)
	}
	if got.Superseded || got.Dismissed {
		t.Errorf("new note superseded=%v dismissed=%v", got.Superseded, got.Dismissed)
	}
}

func TestPutRejectsInvalidDraftAndStoresNothing(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	d := validFix()
	d.Steps[0].HostID = "host9"

	_, _, err := s.Put(context.Background(), newFakeResolver(), d, testSnapshot)
	if !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("Put error = %v, want ErrUnknownHost", err)
	}
	all, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("List has %d notes after a rejected Put", len(all))
	}
}

func TestPutRejectsBadSnapshot(t *testing.T) {
	tests := []struct {
		name     string
		snapshot string
		wantIs   error
	}{
		{"not JSON", "{", ErrInvalidSnapshot},
		{"invalid UTF-8", "\"\xff\"", ErrInvalidSnapshot},
		{"over the limit", `"` + strings.Repeat("a", MaxSnapshotBytes) + `"`, ErrLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t, &fakeClock{t: baseTime})
			_, _, err := s.Put(context.Background(), newFakeResolver(), validFix(), tc.snapshot)
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("Put error = %v, want %v", err, tc.wantIs)
			}
		})
	}
}

func TestPutSameDigestSameBodyIsNoOp(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	r := newFakeResolver()
	first, _, err := s.Put(context.Background(), r, validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}
	second, created, err := s.Put(context.Background(), r, validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if created || second.ID != first.ID {
		t.Fatalf("second Put created=%v id=%d, want no-op with id %d", created, second.ID, first.ID)
	}
	all, _ := s.List(context.Background())
	if len(all) != 1 {
		t.Fatalf("List has %d notes, want 1", len(all))
	}
}

func TestPutSameDigestDifferentBodyIsConflict(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	r := newFakeResolver()
	if _, _, err := s.Put(context.Background(), r, validFix(), testSnapshot); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	changed := validFix()
	changed.Summary = "etwas anderes"
	_, created, err := s.Put(context.Background(), r, changed, testSnapshot)
	if !errors.Is(err, ErrConflict) || created {
		t.Fatalf("Put error = %v created=%v, want ErrConflict", err, created)
	}
	all, _ := s.List(context.Background())
	if len(all) != 1 || all[0].Body.Summary != "Paket aktualisieren" {
		t.Fatalf("stored note changed by a conflicting Put: %+v", all)
	}
}

func TestNewerNoteSupersedesOlderOfSameRef(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	r := newFakeResolver()
	old, _, err := s.Put(context.Background(), r, validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("Put old: %v", err)
	}
	// The findings changed: the server's digest for the ref moves on.
	r.digests["vu:host1:openssl"] = "d2"
	r.cands["vu:host1:openssl|d2"] = r.cands["vu:host1:openssl|d1"]
	next := validFix()
	next.Digest = "d2"
	fresh, created, err := s.Put(context.Background(), r, next, testSnapshot)
	if err != nil || !created {
		t.Fatalf("Put new: created=%v err=%v", created, err)
	}
	gotOld, err := s.Get(context.Background(), old.ID)
	if err != nil {
		t.Fatalf("Get old: %v", err)
	}
	if !gotOld.Superseded {
		t.Errorf("older note not superseded")
	}
	gotNew, _ := s.Get(context.Background(), fresh.ID)
	if gotNew.Superseded {
		t.Errorf("newer note superseded")
	}
}

func TestSummaryWithCollidingRefDoesNotSupersedeFixNote(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	r := newFakeResolver()
	fix, _, err := s.Put(ctx, r, validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("Put fix: %v", err)
	}
	// A summary whose ref equals the fix group's ref: supersession is per
	// kind, so the fix note must stay current.
	sum := Draft{Kind: KindSummary, Ref: validFix().Ref, Digest: "d1", Body: Body{Text: "Tag."}}
	if _, _, err := s.Put(ctx, r, sum, testSnapshot); err != nil {
		t.Fatalf("Put summary: %v", err)
	}
	got, err := s.Get(ctx, fix.ID)
	if err != nil {
		t.Fatalf("Get fix: %v", err)
	}
	if got.Superseded {
		t.Errorf("fix note superseded by a summary with a colliding ref")
	}
}

func TestAnswerWithCollidingRefDoesNotSupersedeSummary(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	r := newFakeResolver()
	sum, _, err := s.Put(ctx, r, validText(KindSummary), testSnapshot)
	if err != nil {
		t.Fatalf("Put summary: %v", err)
	}
	ans := Draft{Kind: KindAnswer, Ref: validText(KindSummary).Ref, Digest: validText(KindSummary).Digest, Body: Body{Text: "Antwort."}}
	if _, _, err := s.Put(ctx, r, ans, testSnapshot); err != nil {
		t.Fatalf("Put answer: %v", err)
	}
	got, err := s.Get(ctx, sum.ID)
	if err != nil {
		t.Fatalf("Get summary: %v", err)
	}
	if got.Superseded {
		t.Errorf("summary superseded by an answer with a colliding ref")
	}
}

func TestPutRefusesStaleDigestAfterChange(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	r := newFakeResolver()
	r.digests["vu:host1:openssl"] = "d2"
	_, _, err := s.Put(context.Background(), r, validFix(), testSnapshot)
	if !errors.Is(err, ErrStaleDigest) {
		t.Fatalf("Put error = %v, want ErrStaleDigest", err)
	}
}

func TestDailyLimitCountsUTCDayAndIgnoresDuplicates(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	r := newFakeResolver()
	ctx := context.Background()
	summary := func(i int) Draft {
		ref := fmt.Sprintf("day-%d", i)
		return Draft{Kind: KindSummary, Ref: ref, Digest: "dig-" + ref, Body: Body{Text: "Tag."}}
	}
	for i := 0; i < MaxNotesPerDay; i++ {
		if _, _, err := s.Put(ctx, r, summary(i), testSnapshot); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	if _, _, err := s.Put(ctx, r, summary(MaxNotesPerDay), testSnapshot); !errors.Is(err, ErrDailyLimit) {
		t.Fatalf("Put over the day limit: %v, want ErrDailyLimit", err)
	}
	// A duplicate is a no-op and does not count against the limit.
	if _, created, err := s.Put(ctx, r, summary(0), testSnapshot); err != nil || created {
		t.Fatalf("duplicate at the limit: created=%v err=%v, want no-op", created, err)
	}
	// The next UTC day starts with a fresh allowance.
	clock.t = baseTime.Add(24 * time.Hour)
	if _, _, err := s.Put(ctx, r, summary(MaxNotesPerDay), testSnapshot); err != nil {
		t.Fatalf("Put on the next day: %v", err)
	}
}

func TestDismissHidesOnlyAndMatchingStillFinds(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	n, _, err := s.Put(ctx, newFakeResolver(), validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Dismiss(ctx, n.ID); err != nil {
		t.Fatalf("Dismiss: %v", err)
	}
	got, err := s.Get(ctx, n.ID)
	if err != nil || !got.Dismissed {
		t.Fatalf("Get after Dismiss: dismissed=%v err=%v", got.Dismissed, err)
	}
	if got.Body.Summary == "" || got.Snapshot != testSnapshot {
		t.Errorf("Dismiss changed the note content")
	}
	if all, _ := s.List(ctx); len(all) != 1 {
		t.Errorf("List after Dismiss has %d notes, want the dismissed one listed", len(all))
	}
	if _, ok, err := s.MatchStep(ctx, "os-update", "host1"); err != nil || !ok {
		t.Errorf("MatchStep after Dismiss = %v, %v; want a match", ok, err)
	}
	if _, ok, err := s.Step(ctx, n.ID, 1); err != nil || !ok {
		t.Errorf("Step after Dismiss = %v, %v; want the step", ok, err)
	}
	if err := s.Dismiss(ctx, n.ID+1000); !errors.Is(err, ErrNotFound) {
		t.Errorf("Dismiss unknown = %v, want ErrNotFound", err)
	}
}

func TestMatchStepFindsSupersededNotesAndNewestFirst(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	r := newFakeResolver()
	old, _, err := s.Put(ctx, r, validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("Put old: %v", err)
	}
	r.digests["vu:host1:openssl"] = "d2"
	r.cands["vu:host1:openssl|d2"] = r.cands["vu:host1:openssl|d1"]
	next := validFix()
	next.Digest = "d2"
	fresh, _, err := s.Put(ctx, r, next, testSnapshot)
	if err != nil {
		t.Fatalf("Put new: %v", err)
	}
	got, ok, err := s.MatchStep(ctx, "os-update", "host1")
	if err != nil || !ok {
		t.Fatalf("MatchStep = %v, %v; want a match", ok, err)
	}
	if got.NoteID != fresh.ID {
		t.Errorf("MatchStep NoteID = %d, want the newest note %d (older was %d)", got.NoteID, fresh.ID, old.ID)
	}
}

func TestMatchStepNeedsFamilyAndHost(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	d := validFix()
	d.Steps = append(d.Steps, StepInput{ActionID: "service.restart", HostID: "host1"})
	n, _, err := s.Put(ctx, newFakeResolver(), d, testSnapshot)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := s.MatchStep(ctx, "service-restart", "host1")
	if err != nil || !ok {
		t.Fatalf("MatchStep svc/host1 = %v, %v", ok, err)
	}
	if got.NoteID != n.ID || got.Index != 2 || got.ActionID != "service.restart" || got.Family != "service-restart" {
		t.Errorf("MatchStep = %+v, want step 2 of note %d", got, n.ID)
	}
	if _, ok, _ := s.MatchStep(ctx, "os-update", "host2"); ok {
		t.Errorf("MatchStep pkg/host2 matched; no such step exists")
	}
	if _, ok, _ := s.Step(ctx, n.ID, 3); ok {
		t.Errorf("Step index 3 found; the note has two steps")
	}
	st, ok, err := s.Step(ctx, n.ID, 1)
	if err != nil || !ok || st.ActionID != "package.install_security" || st.HostID != "host1" || st.Why != "behebt CVE" {
		t.Errorf("Step 1 = %+v, %v, %v", st, ok, err)
	}
}

func TestPruneRemovesByAgeAfterRetention(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	ctx := context.Background()
	n, _, err := s.Put(ctx, newFakeResolver(), validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	removed, err := s.Prune(ctx, baseTime.Add(Retention))
	if err != nil || removed != 0 {
		t.Fatalf("Prune at exactly the retention = %d, %v; want 0 removed", removed, err)
	}
	removed, err = s.Prune(ctx, baseTime.Add(Retention+time.Second))
	if err != nil || removed != 1 {
		t.Fatalf("Prune after the retention = %d, %v; want 1 removed", removed, err)
	}
	if _, err := s.Get(ctx, n.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get pruned note = %v, want ErrNotFound", err)
	}
	if _, ok, _ := s.MatchStep(ctx, "os-update", "host1"); ok {
		t.Errorf("MatchStep after prune matched a deleted note")
	}
	if _, ok, _ := s.Step(ctx, n.ID, 1); ok {
		t.Errorf("Step after prune found a deleted note's step")
	}
}

func TestPutKeepsOnlyNewestMaxNotes(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	ctx := context.Background()
	r := newFakeResolver()
	days := MaxNotes/MaxNotesPerDay + 1
	total := 0
	for day := 0; day < days; day++ {
		clock.t = baseTime.Add(time.Duration(day) * 24 * time.Hour)
		for j := 0; j < MaxNotesPerDay && total < MaxNotes+MaxNotesPerDay/2; j++ {
			ref := fmt.Sprintf("d%d-%d", day, j)
			d := Draft{Kind: KindSummary, Ref: ref, Digest: "dig-" + ref, Body: Body{Text: "Tag."}}
			clock.t = clock.t.Add(time.Second)
			if _, _, err := s.Put(ctx, r, d, testSnapshot); err != nil {
				t.Fatalf("Put %s: %v", ref, err)
			}
			total++
		}
	}
	all, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != MaxNotes {
		t.Fatalf("List has %d notes, want %d", len(all), MaxNotes)
	}
	if all[0].Ref != fmt.Sprintf("d%d-%d", days-1, (total-1)%MaxNotesPerDay) {
		t.Errorf("newest note ref = %s", all[0].Ref)
	}
	// 550 notes were stored; the 50 oldest are pruned, so the oldest
	// survivor is the 51st.
	if want := "d0-50"; all[len(all)-1].Ref != want {
		t.Errorf("oldest surviving note = %s, want %s", all[len(all)-1].Ref, want)
	}
}

func TestGetMissingNoteIsNotFound(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	if _, err := s.Get(context.Background(), 42); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestNotesPersistAcrossReopen(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	path := filepath.Join(privateTestDir(t), "notes.db")
	s, err := Open(path, clock.Now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	n, _, err := s.Put(context.Background(), newFakeResolver(), validFix(), testSnapshot)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := Open(path, clock.Now)
	if err != nil {
		t.Fatalf("reopen (migrations already applied): %v", err)
	}
	defer func() { _ = s2.Close() }()
	if _, err := s2.Get(context.Background(), n.ID); err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
}

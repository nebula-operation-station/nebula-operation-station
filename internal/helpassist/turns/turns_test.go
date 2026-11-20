// SPDX-License-Identifier: AGPL-3.0-or-later

package turns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is an injected clock for the store under test.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newClockStore(t *testing.T) (*Store, *fakeClock) {
	t.Helper()
	c := &fakeClock{now: time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)}
	return New(c.Now), c
}

func turn(user, q string) Turn {
	return Turn{User: user, Question: q, Answer: "answer to " + q}
}

func questions(ts []Turn) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Question)
	}
	return out
}

func TestSeventhTurnDropsOldestAndKeepsLastSix(t *testing.T) {
	s, _ := newClockStore(t)
	for i := 1; i <= 7; i++ {
		if err := s.Append("sess-a", turn("alice", fmt.Sprintf("q%d", i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	got := questions(s.History("sess-a"))
	want := []string{"q2", "q3", "q4", "q5", "q6", "q7"}
	if len(got) != MaxTurns || MaxTurns != 6 {
		t.Fatalf("history length = %d (MaxTurns %d), want 6", len(got), MaxTurns)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("history = %v, want %v", got, want)
		}
	}
}

func TestTurnExpiresThirtyMinutesAfterItsOwnAppend(t *testing.T) {
	if MaxAge != 30*time.Minute {
		t.Fatalf("MaxAge = %v, want 30m", MaxAge)
	}
	s, c := newClockStore(t)
	if err := s.Append("sess-a", turn("alice", "old")); err != nil {
		t.Fatal(err)
	}
	c.Advance(20 * time.Minute)
	if err := s.Append("sess-a", turn("alice", "new")); err != nil {
		t.Fatal(err)
	}
	c.Advance(10*time.Minute + time.Second) // old is 30m1s old, new is 10m1s old
	got := questions(s.History("sess-a"))
	if len(got) != 1 || got[0] != "new" {
		t.Fatalf("history = %v, want [new]", got)
	}
	c.Advance(20 * time.Minute) // new is now 30m1s old
	if got := s.History("sess-a"); len(got) != 0 {
		t.Fatalf("history after all turns expired = %v, want none", got)
	}
}

func TestTurnStillLiveJustBeforeMaxAge(t *testing.T) {
	s, c := newClockStore(t)
	if err := s.Append("sess-a", turn("alice", "q")); err != nil {
		t.Fatal(err)
	}
	c.Advance(MaxAge - time.Nanosecond)
	if got := s.History("sess-a"); len(got) != 1 {
		t.Fatalf("turn at MaxAge-1ns: history len = %d, want 1", len(got))
	}
	c.Advance(time.Nanosecond)
	if got := s.History("sess-a"); len(got) != 0 {
		t.Fatalf("turn at exactly MaxAge: history len = %d, want 0", len(got))
	}
}

func TestExpiredTurnsAreRemovedOnAccess(t *testing.T) {
	s, c := newClockStore(t)
	if err := s.Append("sess-a", turn("alice", "q")); err != nil {
		t.Fatal(err)
	}
	c.Advance(MaxAge)
	_ = s.History("sess-a")
	s.mu.Lock()
	_, present := s.sessions["sess-a"]
	s.mu.Unlock()
	if present {
		t.Fatalf("expired session still held after History")
	}
}

func TestClearRemovesOnlyThatSession(t *testing.T) {
	s, _ := newClockStore(t)
	mustAppend(t, s, "sess-a", turn("alice", "a"))
	mustAppend(t, s, "sess-b", turn("alice", "b"))
	s.Clear("sess-a")
	if got := s.History("sess-a"); len(got) != 0 {
		t.Fatalf("after Clear sess-a = %v, want none", got)
	}
	if got := questions(s.History("sess-b")); len(got) != 1 || got[0] != "b" {
		t.Fatalf("sess-b after Clear(sess-a) = %v, want [b]", got)
	}
}

func TestClearUserEndsAllPanelsOfThatUserOnly(t *testing.T) {
	s, _ := newClockStore(t)
	mustAppend(t, s, "alice-panel-1", turn("alice", "a1"))
	mustAppend(t, s, "alice-panel-2", turn("alice", "a2"))
	mustAppend(t, s, "bob-panel", turn("bob", "b1"))
	s.ClearUser("alice")
	if got := s.History("alice-panel-1"); len(got) != 0 {
		t.Fatalf("alice-panel-1 after logout = %v, want none", got)
	}
	if got := s.History("alice-panel-2"); len(got) != 0 {
		t.Fatalf("alice-panel-2 after logout = %v, want none", got)
	}
	if got := questions(s.History("bob-panel")); len(got) != 1 || got[0] != "b1" {
		t.Fatalf("bob-panel after ClearUser(alice) = %v, want [b1]", got)
	}
}

func TestClearUserFreesSessionSlotsForReuse(t *testing.T) {
	s, _ := newClockStore(t)
	for i := 0; i < MaxSessions; i++ {
		mustAppend(t, s, fmt.Sprintf("s%d", i), turn("alice", "q"))
	}
	if err := s.Append("extra", turn("bob", "q")); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("append beyond MaxSessions: err = %v, want ErrTooManySessions", err)
	}
	s.ClearUser("alice")
	if err := s.Append("extra", turn("bob", "q")); err != nil {
		t.Fatalf("append after ClearUser freed slots: %v", err)
	}
}

func TestSessionsOfDifferentUsersNeverSeeEachOther(t *testing.T) {
	s, _ := newClockStore(t)
	mustAppend(t, s, "sess-alice", turn("alice", "secret of alice"))
	if err := s.Append("sess-alice", turn("bob", "bob writes into alice's session")); !errors.Is(err, ErrSessionOwner) {
		t.Fatalf("foreign user appended to session: err = %v, want ErrSessionOwner", err)
	}
	if got := s.History("sess-alice"); len(got) != 1 || got[0].Question != "secret of alice" {
		t.Fatalf("history after rejected foreign append = %v", questions(got))
	}
	s.ClearUser("bob")
	if got := questions(s.History("sess-alice")); len(got) != 1 {
		t.Fatalf("ClearUser(bob) removed alice's session: %v", got)
	}
}

func TestHistoryReturnsCopies(t *testing.T) {
	s, _ := newClockStore(t)
	mustAppend(t, s, "sess-a", turn("alice", "original"))
	got := s.History("sess-a")
	got[0].Question = "changed"
	got[0].Answer = "changed"
	again := s.History("sess-a")
	if len(again) != 1 || again[0].Question != "original" || again[0].Answer != "answer to original" {
		t.Fatalf("store changed through returned copy: %+v", again)
	}
}

func TestEmptyKeysRejected(t *testing.T) {
	s, _ := newClockStore(t)
	if err := s.Append("", turn("alice", "q")); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("empty session: err = %v, want ErrEmptyKey", err)
	}
	if err := s.Append("sess", turn("", "q")); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("empty user: err = %v, want ErrEmptyKey", err)
	}
	if err := s.Append("sess", Turn{User: "alice"}); !errors.Is(err, ErrEmptyTurn) {
		t.Fatalf("empty question: err = %v, want ErrEmptyTurn", err)
	}
}

func TestOversizedTurnsRejected(t *testing.T) {
	long := strings.Repeat("k", MaxKeyBytes+1)
	cases := []struct {
		name string
		key  string
		t    Turn
	}{
		{"question over limit", "sess", Turn{User: "alice", Question: strings.Repeat("q", MaxQuestionBytes+1), Answer: "a"}},
		{"answer over limit", "sess", Turn{User: "alice", Question: "q", Answer: strings.Repeat("a", MaxAnswerBytes+1)}},
		{"session key over limit", long, Turn{User: "alice", Question: "q", Answer: "a"}},
		{"user key over limit", "sess", Turn{User: long, Question: "q", Answer: "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newClockStore(t)
			key := tc.key
			if err := s.Append(key, tc.t); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}
			if got := s.History(key); len(got) != 0 {
				t.Fatalf("rejected turn was stored")
			}
		})
	}
}

func TestLimitsAreExactlyAtBoundaryAccepted(t *testing.T) {
	s, _ := newClockStore(t)
	ok := Turn{
		User:     strings.Repeat("u", MaxKeyBytes),
		Question: strings.Repeat("q", MaxQuestionBytes),
		Answer:   strings.Repeat("a", MaxAnswerBytes),
	}
	if err := s.Append(strings.Repeat("s", MaxKeyBytes), ok); err != nil {
		t.Fatalf("turn at exact limits: %v", err)
	}
}

func TestSessionLimitEvictsExpiredFirst(t *testing.T) {
	s, c := newClockStore(t)
	for i := 0; i < MaxSessions; i++ {
		mustAppend(t, s, fmt.Sprintf("s%d", i), turn("alice", "q"))
	}
	c.Advance(MaxAge)
	if err := s.Append("fresh", turn("bob", "q")); err != nil {
		t.Fatalf("expired sessions should make room: %v", err)
	}
	if got := questions(s.History("fresh")); len(got) != 1 {
		t.Fatalf("fresh session = %v", got)
	}
}

func TestSessionLimitRejectsWhenAllLive(t *testing.T) {
	s, _ := newClockStore(t)
	for i := 0; i < MaxSessions; i++ {
		mustAppend(t, s, fmt.Sprintf("s%d", i), turn("alice", "q"))
	}
	if err := s.Append("fresh", turn("bob", "q")); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("err = %v, want ErrTooManySessions", err)
	}
	// An existing session can still take turns at the limit.
	if err := s.Append("s0", turn("alice", "again")); err != nil {
		t.Fatalf("existing session at limit: %v", err)
	}
}

func TestRedactedRenderingsDoNotContainQuestion(t *testing.T) {
	const marker = "MARKER-7f3a-question"
	tn := Turn{User: "alice", Question: "how do I " + marker, Answer: "answer " + marker}
	outputs := map[string]string{
		"%v":  fmt.Sprintf("%v", tn),
		"%+v": fmt.Sprintf("%+v", tn),
		"%#v": fmt.Sprintf("%#v", tn),
	}
	for verb, out := range outputs {
		if strings.Contains(out, marker) {
			t.Errorf("%s leaked the question: %q", verb, out)
		}
	}
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, nil)
	slog.New(h).Info("turn", "turn", tn, "turns", []Turn{tn})
	if strings.Contains(buf.String(), marker) {
		t.Errorf("slog leaked the question: %s", buf.String())
	}
	buf.Reset()
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("turn", "turn", tn)
	if strings.Contains(buf.String(), marker) {
		t.Errorf("slog JSON leaked the question: %s", buf.String())
	}
}

func TestConcurrentAppendHistoryClearUser(t *testing.T) {
	s, _ := newClockStore(t)
	const workers = 8
	const rounds = 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(3)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				_ = s.Append("shared", turn("alice", fmt.Sprintf("w%d-%d", w, i)))
			}
		}(w)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if got := s.History("shared"); len(got) > MaxTurns {
					t.Errorf("history length %d exceeds MaxTurns", len(got))
					return
				}
			}
		}()
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if i%10 == 0 {
					s.ClearUser("alice")
				}
				_ = s.Append("shared", turn("alice", "x"))
			}
		}(w)
	}
	wg.Wait()
	if got := s.History("shared"); len(got) > MaxTurns {
		t.Fatalf("final history length %d exceeds MaxTurns", len(got))
	}
}

func mustAppend(t *testing.T, s *Store, session string, tn Turn) {
	t.Helper()
	if err := s.Append(session, tn); err != nil {
		t.Fatalf("append %q: %v", session, err)
	}
}

func TestIdleSessionTextGoneAfterMaxAgeWithoutAccess(t *testing.T) {
	s, c := newClockStore(t)
	mustAppend(t, s, "idle", turn("alice", "idle secret"))
	c.Advance(MaxAge)
	s.Sweep()
	if textHeld(s, "idle secret") {
		t.Fatalf("idle session text still held after MaxAge without access")
	}
}

func TestAppendForOtherSessionSweepsIdleSession(t *testing.T) {
	s, c := newClockStore(t)
	mustAppend(t, s, "idle", turn("alice", "idle secret"))
	c.Advance(MaxAge)
	mustAppend(t, s, "other", turn("bob", "bob question"))
	if textHeld(s, "idle secret") {
		t.Fatalf("expired idle session still held after an append to another session")
	}
	if got := questions(s.History("other")); len(got) != 1 || got[0] != "bob question" {
		t.Fatalf("other session = %v, want [bob question]", got)
	}
}

func TestSweepKeepsLiveTurnsOfIdleSessions(t *testing.T) {
	s, c := newClockStore(t)
	mustAppend(t, s, "old", turn("alice", "old"))
	c.Advance(20 * time.Minute)
	mustAppend(t, s, "new", turn("bob", "new"))
	c.Advance(MaxAge - 20*time.Minute)
	s.Sweep()
	if textHeld(s, "old") {
		t.Fatalf("expired turn still held after Sweep")
	}
	if got := questions(s.History("new")); len(got) != 1 {
		t.Fatalf("live turn removed by Sweep: %v", got)
	}
}

func TestRunRejectsNonPositiveInterval(t *testing.T) {
	s, _ := newClockStore(t)
	if err := s.Run(context.Background(), 0); !errors.Is(err, ErrBadInterval) {
		t.Fatalf("Run(0) err = %v, want ErrBadInterval", err)
	}
}

func TestRunStopsWhenContextIsDone(t *testing.T) {
	s, _ := newClockStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Run(ctx, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run after cancel err = %v, want context.Canceled", err)
	}
}

// textHeld reports whether any stored turn still holds text, questions or
// answers, that contains marker. It inspects the store directly.
func textHeld(s *Store, marker string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		for _, e := range sess.turns {
			if strings.Contains(e.turn.Question, marker) || strings.Contains(e.turn.Answer, marker) {
				return true
			}
		}
	}
	return false
}

func TestNonUTF8QuestionAndAnswerRejected(t *testing.T) {
	bad := "\xff\xfe broken"
	cases := []struct {
		name string
		t    Turn
	}{
		{"question not UTF-8", Turn{User: "alice", Question: bad, Answer: "a"}},
		{"answer not UTF-8", Turn{User: "alice", Question: "q", Answer: bad}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newClockStore(t)
			if err := s.Append("sess", tc.t); !errors.Is(err, ErrInvalidUTF8) {
				t.Fatalf("err = %v, want ErrInvalidUTF8", err)
			}
			if got := s.History("sess"); len(got) != 0 {
				t.Fatalf("rejected turn was stored")
			}
		})
	}
}

func TestAppendErrorsCarryContextAndKeepSentinel(t *testing.T) {
	s, _ := newClockStore(t)
	err := s.Append("", turn("alice", "q"))
	if !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("err = %v, want ErrEmptyKey in chain", err)
	}
	if !strings.HasPrefix(err.Error(), "append turn: ") {
		t.Fatalf("error %q does not start with the operation context", err)
	}
}

func TestLiveReleasesDroppedTurnText(t *testing.T) {
	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	turns := []timed{
		{at: now.Add(-2 * MaxAge), turn: Turn{User: "alice", Question: "gone-1", Answer: "gone-1"}},
		{at: now.Add(-MaxAge), turn: Turn{User: "alice", Question: "gone-2", Answer: "gone-2"}},
		{at: now, turn: Turn{User: "alice", Question: "kept", Answer: "kept"}},
	}
	backing := turns[:cap(turns)]
	got := live(turns, now)
	if len(got) != 1 || got[0].turn.Question != "kept" {
		t.Fatalf("live = %+v, want only the kept turn", got)
	}
	for i := len(got); i < len(backing); i++ {
		if backing[i].turn.Question != "" || backing[i].turn.Answer != "" {
			t.Fatalf("dropped element %d still holds text %q", i, backing[i].turn.Question)
		}
	}
}

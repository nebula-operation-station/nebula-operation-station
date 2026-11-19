// SPDX-License-Identifier: AGPL-3.0-or-later

package ratelimit

import (
	"errors"
	"testing"
	"time"
)

// fakeClock is an injected clock the test moves by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}
}

// ask runs one question: a successful Acquire is released at once. It
// returns the Acquire error.
func ask(l *Limiter, user string) error {
	release, err := l.Acquire(user)
	if err != nil {
		return err
	}
	release()
	return nil
}

// TestConstantsMatchADR0014 pins the limits of ADR 0014 D5 and Q9.
func TestConstantsMatchADR0014(t *testing.T) {
	if PerUserPerHour != 20 {
		t.Fatalf("PerUserPerHour = %d, want 20", PerUserPerHour)
	}
	if PerUserInFlight != 1 {
		t.Fatalf("PerUserInFlight = %d, want 1", PerUserInFlight)
	}
	if GlobalPerDay != 300 {
		t.Fatalf("GlobalPerDay = %d, want 300", GlobalPerDay)
	}
}

// TestTwentyQuestionsPerHourPerUser: the 20th question is allowed, the 21st
// is refused with ErrUserLimit, and another user is not affected.
func TestTwentyQuestionsPerHourPerUser(t *testing.T) {
	clk := newClock()
	l := New(clk.now)
	for i := 0; i < PerUserPerHour; i++ {
		if err := ask(l, "alice"); err != nil {
			t.Fatalf("question %d: %v, want nil", i+1, err)
		}
	}
	if err := ask(l, "alice"); !errors.Is(err, ErrUserLimit) {
		t.Fatalf("question 21: %v, want ErrUserLimit", err)
	}
	if err := ask(l, "bob"); err != nil {
		t.Fatalf("bob's first question: %v, want nil", err)
	}
}

// TestHourlyWindowSlides: one question leaves the window one hour after it
// was asked; only that one slot comes back.
func TestHourlyWindowSlides(t *testing.T) {
	clk := newClock()
	l := New(clk.now)
	for i := 0; i < PerUserPerHour; i++ {
		clk.t = clk.t.Add(time.Minute) // asks at minutes 1..20
		if err := ask(l, "alice"); err != nil {
			t.Fatalf("question %d: %v", i+1, err)
		}
	}
	// The clock is at minute 20; the first question (minute 1) expires at
	// minute 61. One nanosecond before that it is still full.
	clk.t = clk.t.Add(time.Hour + time.Minute - 20*time.Minute - time.Nanosecond)
	if err := ask(l, "alice"); !errors.Is(err, ErrUserLimit) {
		t.Fatalf("before the first question expired: %v, want ErrUserLimit", err)
	}
	// At exactly one hour after the first question, one slot is free.
	clk.t = clk.t.Add(time.Nanosecond)
	if err := ask(l, "alice"); err != nil {
		t.Fatalf("after one hour: %v, want nil", err)
	}
	if err := ask(l, "alice"); !errors.Is(err, ErrUserLimit) {
		t.Fatalf("second question in the same instant: %v, want ErrUserLimit", err)
	}
}

// TestUserBusyWhileInFlight: a second question while one runs is refused
// with ErrUserBusy and is possible again after release.
func TestUserBusyWhileInFlight(t *testing.T) {
	l := New(newClock().now)
	release, err := l.Acquire("alice")
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if _, err := l.Acquire("alice"); !errors.Is(err, ErrUserBusy) {
		t.Fatalf("second Acquire while in flight: %v, want ErrUserBusy", err)
	}
	release()
	if err := ask(l, "alice"); err != nil {
		t.Fatalf("Acquire after release: %v, want nil", err)
	}
}

// TestReleaseIsIdempotent: a second call of an old release must not free a
// slot that a newer question holds.
func TestReleaseIsIdempotent(t *testing.T) {
	l := New(newClock().now)
	release, err := l.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	release()
	release()
	second, err := l.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	release() // stale release, must have no effect
	if _, err := l.Acquire("alice"); !errors.Is(err, ErrUserBusy) {
		t.Fatalf("stale release freed the second question's slot: %v, want ErrUserBusy", err)
	}
	second()
}

// TestBusyAttemptDoesNotCount: a refused ErrUserBusy attempt is not counted
// against the 20 per hour. With 18 counted questions and 5 refused busy
// attempts, the 20th question must still be allowed.
func TestBusyAttemptDoesNotCount(t *testing.T) {
	l := New(newClock().now)
	for i := 0; i < PerUserPerHour-2; i++ {
		if err := ask(l, "alice"); err != nil {
			t.Fatalf("question %d: %v", i+1, err)
		}
	}
	release, err := l.Acquire("alice")
	if err != nil {
		t.Fatalf("question 19: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Acquire("alice"); !errors.Is(err, ErrUserBusy) {
			t.Fatalf("busy attempt %d: %v, want ErrUserBusy", i+1, err)
		}
	}
	release()
	if err := ask(l, "alice"); err != nil {
		t.Fatalf("question 20 after busy attempts: %v, want nil", err)
	}
	if err := ask(l, "alice"); !errors.Is(err, ErrUserLimit) {
		t.Fatalf("question 21: %v, want ErrUserLimit", err)
	}
}

// TestAbortedQuestionFreesSlot: a question that fails or panics after
// Acquire still frees the in-flight slot through its release.
func TestAbortedQuestionFreesSlot(t *testing.T) {
	l := New(newClock().now)
	failed := func() error {
		release, err := l.Acquire("alice")
		if err != nil {
			return err
		}
		defer release()
		return errors.New("llm call failed")
	}
	if err := failed(); err == nil {
		t.Fatal("failing question returned nil")
	}
	panicked := func() {
		defer func() { _ = recover() }()
		release, err := l.Acquire("alice")
		if err != nil {
			t.Fatalf("Acquire after failure: %v", err)
		}
		defer release()
		panic("request cancelled")
	}
	panicked()
	if err := ask(l, "alice"); err != nil {
		t.Fatalf("Acquire after aborted questions: %v, want nil", err)
	}
}

// TestFailedQuestionCountsAgainstLimit: a question whose LLM call failed
// still counts, because it may have triggered the call.
func TestFailedQuestionCountsAgainstLimit(t *testing.T) {
	l := New(newClock().now)
	for i := 0; i < PerUserPerHour; i++ {
		release, err := l.Acquire("alice")
		if err != nil {
			t.Fatalf("question %d: %v", i+1, err)
		}
		release() // the question failed afterwards; it still counts
	}
	if err := ask(l, "alice"); !errors.Is(err, ErrUserLimit) {
		t.Fatalf("question 21 after failed questions: %v, want ErrUserLimit", err)
	}
}

// TestGlobalLimitAcrossUsers: 300 questions from many users pass; the 301st
// is refused with ErrGlobalLimit, also for a new user. The day window
// reopens 24 hours after the first question.
func TestGlobalLimitAcrossUsers(t *testing.T) {
	clk := newClock()
	l := New(clk.now)
	for u := 0; u < 100; u++ {
		user := string(rune('a'+u/26)) + string(rune('a'+u%26))
		for i := 0; i < 3; i++ {
			if err := ask(l, user); err != nil {
				t.Fatalf("user %s question %d: %v", user, i+1, err)
			}
		}
	}
	if err := ask(l, "newcomer"); !errors.Is(err, ErrGlobalLimit) {
		t.Fatalf("301st question (new user): %v, want ErrGlobalLimit", err)
	}
	if err := ask(l, "aa"); !errors.Is(err, ErrGlobalLimit) {
		t.Fatalf("301st question (known user): %v, want ErrGlobalLimit", err)
	}
	clk.t = clk.t.Add(24*time.Hour - time.Nanosecond)
	if err := ask(l, "newcomer"); !errors.Is(err, ErrGlobalLimit) {
		t.Fatalf("just before 24 h: %v, want ErrGlobalLimit", err)
	}
	clk.t = clk.t.Add(time.Nanosecond)
	if err := ask(l, "newcomer"); err != nil {
		t.Fatalf("after 24 h: %v, want nil", err)
	}
}

// TestRefusedQuestionsDoNotCountGlobally: questions refused by the user
// limit or ErrUserBusy must not use up the global budget.
func TestRefusedQuestionsDoNotCountGlobally(t *testing.T) {
	l := New(newClock().now)
	release, err := l.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()
	for i := 0; i < 1000; i++ {
		if _, err := l.Acquire("alice"); !errors.Is(err, ErrUserBusy) {
			t.Fatalf("attempt %d: %v, want ErrUserBusy", i, err)
		}
	}
	// 299 more questions from other users must still fit (alice's one counts).
	for u := 0; u < 299; u++ {
		user := "u" + string(rune('a'+u/26)) + string(rune('a'+u%26))
		if err := ask(l, user); err != nil {
			t.Fatalf("user %s: %v, want nil", user, err)
		}
	}
	if err := ask(l, "last"); !errors.Is(err, ErrGlobalLimit) {
		t.Fatalf("301st question: %v, want ErrGlobalLimit", err)
	}
}

// TestClockBackwardsNeverExceedsLimit: a clock that jumps back must not
// reopen a window; entries stamped after the clock are still counted.
func TestClockBackwardsNeverExceedsLimit(t *testing.T) {
	clk := newClock()
	l := New(clk.now)
	start := clk.t
	for i := 0; i < PerUserPerHour; i++ {
		if err := ask(l, "alice"); err != nil {
			t.Fatalf("question %d: %v", i+1, err)
		}
	}
	clk.t = start.Add(-2 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := ask(l, "alice"); !errors.Is(err, ErrUserLimit) {
			t.Fatalf("after clock jump back, question %d: %v, want ErrUserLimit", i+1, err)
		}
	}
	// Global: 280 more from other users, then the clock goes back again.
	for u := 0; u < 280; u++ {
		user := "g" + string(rune('a'+u/26)) + string(rune('a'+u%26))
		if err := ask(l, user); err != nil {
			t.Fatalf("user %s: %v", user, err)
		}
	}
	clk.t = start.Add(-24 * time.Hour)
	if err := ask(l, "late"); !errors.Is(err, ErrGlobalLimit) {
		t.Fatalf("after global clock jump back: %v, want ErrGlobalLimit", err)
	}
}

// TestEmptyUserRejected: an empty user name is refused and nothing counts.
func TestEmptyUserRejected(t *testing.T) {
	l := New(newClock().now)
	if _, err := l.Acquire(""); !errors.Is(err, ErrEmptyUser) {
		t.Fatalf("Acquire(\"\"): %v, want ErrEmptyUser", err)
	}
	if len(l.global) != 0 || len(l.users) != 0 {
		t.Fatalf("empty user left state behind: global=%d users=%d", len(l.global), len(l.users))
	}
}

// TestTrackedUsersCapFailsClosed: when the table of tracked users is full
// and no entry can be removed, a new user is refused with ErrUserTableFull;
// idle expired entries are removed and the new user is admitted.
func TestTrackedUsersCapFailsClosed(t *testing.T) {
	clk := newClock()
	l := New(clk.now)
	l.maxUsers = 3
	holds := make([]func(), 0, 3)
	for _, user := range []string{"a", "b", "c"} {
		release, err := l.Acquire(user)
		if err != nil {
			t.Fatalf("Acquire(%s): %v", user, err)
		}
		holds = append(holds, release)
	}
	if _, err := l.Acquire("d"); !errors.Is(err, ErrUserTableFull) {
		t.Fatalf("fourth user with full table: %v, want ErrUserTableFull", err)
	}
	// Known users keep working: a's second question is busy, not table full.
	if _, err := l.Acquire("a"); !errors.Is(err, ErrUserBusy) {
		t.Fatalf("known user in flight: %v, want ErrUserBusy", err)
	}
	for _, release := range holds {
		release()
	}
	clk.t = clk.t.Add(time.Hour)
	if err := ask(l, "d"); err != nil {
		t.Fatalf("fourth user after expiry: %v, want nil", err)
	}
	if len(l.users) > 3 {
		t.Fatalf("tracked users = %d, want at most 3", len(l.users))
	}
}

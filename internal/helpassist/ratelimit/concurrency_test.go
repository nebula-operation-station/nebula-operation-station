// SPDX-License-Identifier: AGPL-3.0-or-later

package ratelimit

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSameUserNeverTwoInFlightAndNeverOverHourly: many goroutines ask as
// one user. At most one question is in flight at any time, and exactly
// PerUserPerHour are accepted under a fixed clock.
func TestSameUserNeverTwoInFlightAndNeverOverHourly(t *testing.T) {
	l := New(newClock().now)
	var inFlight, maxInFlight, accepted atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 200; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				release, err := l.Acquire("alice")
				if errors.Is(err, ErrUserBusy) {
					runtime.Gosched()
					continue
				}
				if err != nil {
					if !errors.Is(err, ErrUserLimit) {
						t.Errorf("unexpected error: %v", err)
					}
					return
				}
				n := inFlight.Add(1)
				for {
					m := maxInFlight.Load()
					if n <= m || maxInFlight.CompareAndSwap(m, n) {
						break
					}
				}
				accepted.Add(1)
				runtime.Gosched()
				inFlight.Add(-1)
				release()
				return
			}
		}()
	}
	wg.Wait()
	if got := maxInFlight.Load(); got != PerUserInFlight {
		t.Fatalf("max in flight for one user = %d, want %d", got, PerUserInFlight)
	}
	if got := accepted.Load(); got != PerUserPerHour {
		t.Fatalf("accepted = %d, want exactly %d", got, PerUserPerHour)
	}
}

// TestManyUsersNeverOverGlobalDay: many users ask concurrently. Exactly
// GlobalPerDay are accepted, and no user gets more than PerUserPerHour.
func TestManyUsersNeverOverGlobalDay(t *testing.T) {
	l := New(newClock().now)
	const users = 60
	const perUser = 20
	var accepted atomic.Int64
	perUserAccepted := make([]atomic.Int64, users)
	var wg sync.WaitGroup
	for u := 0; u < users; u++ {
		user := fmt.Sprintf("user-%02d", u)
		for g := 0; g < perUser; g++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				for {
					release, err := l.Acquire(user)
					if errors.Is(err, ErrUserBusy) {
						runtime.Gosched()
						continue
					}
					if err != nil {
						if !errors.Is(err, ErrUserLimit) && !errors.Is(err, ErrGlobalLimit) {
							t.Errorf("unexpected error: %v", err)
						}
						return
					}
					accepted.Add(1)
					perUserAccepted[idx].Add(1)
					runtime.Gosched()
					release()
					return
				}
			}(u)
		}
	}
	wg.Wait()
	if got := accepted.Load(); got != GlobalPerDay {
		t.Fatalf("accepted = %d, want exactly %d", got, GlobalPerDay)
	}
	for u := range perUserAccepted {
		if got := perUserAccepted[u].Load(); got > PerUserPerHour {
			t.Fatalf("user %d accepted %d, want at most %d", u, got, PerUserPerHour)
		}
	}
}

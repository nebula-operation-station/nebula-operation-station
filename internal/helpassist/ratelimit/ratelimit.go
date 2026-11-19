// SPDX-License-Identifier: AGPL-3.0-or-later

package ratelimit

import (
	"errors"
	"sync"
	"time"
)

// Limits of ADR 0014 D5 and Q9. Changing one changes the documented
// behaviour; update the ADR first.
const (
	// PerUserPerHour is the number of questions a user may ask in any
	// sliding one-hour window.
	PerUserPerHour = 20
	// PerUserInFlight is the number of questions a user may have running at
	// the same time.
	PerUserInFlight = 1
	// GlobalPerDay is the number of questions the installation may accept in
	// any sliding 24-hour window.
	GlobalPerDay = 300
	// MaxTrackedUsers caps the number of users whose state is kept in
	// memory. Idle users whose windows have expired are removed first.
	MaxTrackedUsers = 1024
)

// userWindow and globalWindow are the sliding windows of the limits above.
const (
	userWindow   = time.Hour
	globalWindow = 24 * time.Hour
)

// Sentinel errors. Callers check them with errors.Is.
var (
	// ErrEmptyUser is returned for an empty user name.
	ErrEmptyUser = errors.New("ratelimit: empty user")
	// ErrUserBusy is returned when the user already has a question running.
	ErrUserBusy = errors.New("ratelimit: a question of this user is already running")
	// ErrUserLimit is returned when the user has used PerUserPerHour questions
	// in the last hour.
	ErrUserLimit = errors.New("ratelimit: user limit of questions per hour reached")
	// ErrGlobalLimit is returned when GlobalPerDay questions were accepted in
	// the last 24 hours.
	ErrGlobalLimit = errors.New("ratelimit: global limit of questions per day reached")
	// ErrUserTableFull is returned for a new user when MaxTrackedUsers users
	// are tracked and none can be removed.
	ErrUserTableFull = errors.New("ratelimit: too many users are tracked")
)

// Limiter enforces the question limits. It is safe for concurrent use. The
// zero value is not usable; create one with New.
type Limiter struct {
	mu       sync.Mutex
	now      func() time.Time
	maxUsers int
	// global holds the accept times of questions in the last globalWindow.
	global []time.Time
	// users holds the state of every tracked user.
	users map[string]*userState
}

// userState is one user's in-flight count and accept times in the last
// userWindow.
type userState struct {
	inFlight int
	asked    []time.Time
}

// New returns a Limiter that reads the time from now. A nil now means
// time.Now.
func New(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		now:      now,
		maxUsers: MaxTrackedUsers,
		users:    make(map[string]*userState),
	}
}

// Acquire asks for permission to run one question of user. On success it
// counts the question and returns a release function that must be called
// when the question ends, on every path. Release is idempotent. On error no
// question is counted and the returned release is nil.
func (l *Limiter) Acquire(user string) (func(), error) {
	if user == "" {
		return nil, ErrEmptyUser
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	l.global = pruneTimes(l.global, now, globalWindow)
	if len(l.global) >= GlobalPerDay {
		return nil, ErrGlobalLimit
	}

	st, known := l.users[user]
	if known {
		if st.inFlight >= PerUserInFlight {
			return nil, ErrUserBusy
		}
		st.asked = pruneTimes(st.asked, now, userWindow)
		if len(st.asked) >= PerUserPerHour {
			return nil, ErrUserLimit
		}
	} else {
		if len(l.users) >= l.maxUsers {
			l.sweepIdle(now)
			if len(l.users) >= l.maxUsers {
				return nil, ErrUserTableFull
			}
		}
		st = &userState{}
		l.users[user] = st
	}

	st.inFlight++
	st.asked = append(st.asked, now)
	l.global = append(l.global, now)

	released := false
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		released = true
		st.inFlight--
	}, nil
}

// sweepIdle removes users with no question in flight and no accept time in
// the user window. The caller holds l.mu.
func (l *Limiter) sweepIdle(now time.Time) {
	for user, st := range l.users {
		st.asked = pruneTimes(st.asked, now, userWindow)
		if st.inFlight == 0 && len(st.asked) == 0 {
			delete(l.users, user)
		}
	}
}

// pruneTimes keeps the times that are still inside window at now. A time
// later than now (the clock went back) is kept. It reuses the slice storage.
func pruneTimes(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	return kept
}

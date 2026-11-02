// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session defines the display contract for the privileged approval
// session in the web UI (ADR 0007, E20).
//
// The page topbar shows the executor-reported session state: the remaining
// time while a session is active, an expired state once it is gone, and a
// single Extend action that opens or extends the session with one fresh
// WebAuthn user-verification assertion.
//
// This package is the source of truth for how the browser maps the poll
// response of GET /privileged/session onto those display states. The client
// implementation lives in web/static/webauthn.js and mirrors the functions
// here one-to-one; the tests in this package pin down the semantics:
//
//   - the remaining time is derived from the executor-reported expiry only;
//   - a session that was active and is now gone is displayed as expired,
//     and the same single assertion opens a new session;
//   - no amount of browsing activity (repeated polls) can renew or extend
//     a session: the state machine is pure and only the executor-reported
//     poll and the clock decide the state;
//   - at most one assertion flow may be in flight, so one click extends
//     the session exactly once and extensions never accumulate;
//   - an unreachable executor fails closed to an unknown state with no
//     action offered.
package session

import (
	"fmt"
	"time"
)

// LowThreshold is the remaining time at or below which the display is
// highlighted as running out.
const LowThreshold = time.Minute

// Poll mirrors the JSON response of GET /privileged/session
// (internal/web/ui/privileged_session.go).
type Poll struct {
	// Active reports whether the executor has an open privileged session.
	Active bool `json:"active"`
	// Available reports whether the executor could be reached at all.
	Available bool `json:"available"`
	// ExpiryUnix is the executor-reported expiry of an active session in
	// seconds since the Unix epoch. Zero when the session is not active.
	ExpiryUnix int64 `json:"expiry_unix"`
}

// State is a display state of the privileged session in the web UI.
type State int

// The display states of the privileged session.
const (
	// StateUnknown: the executor could not be reached. The display shows
	// that the session state is unknown and offers no action (fail
	// closed).
	StateUnknown State = iota
	// StateNone: no session is open and none was open before.
	StateNone
	// StateActive: a session is open; the display shows the remaining
	// time and the Extend action.
	StateActive
	// StateExpired: a session was open and is now gone. The display shows
	// the expired state; the same single assertion opens a new session.
	StateExpired
)

// String returns the stable name of the state. The client uses it as the
// data-state attribute of the display element.
func (s State) String() string {
	switch s {
	case StateNone:
		return "none"
	case StateActive:
		return "active"
	case StateExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// Next returns the display state to show after observing the poll p at
// time now, given the previously displayed state prev.
//
// The function is pure: it derives the display state from the
// executor-reported poll and the clock only. Repeated polls caused by
// browsing activity can never move a session back from expired to active
// or extend its expiry — only a poll that reports an active session with
// a future expiry can do that, and such a poll exists only after a fresh
// assertion was completed.
func Next(prev State, p Poll, now time.Time) State {
	if !p.Available {
		return StateUnknown
	}
	if p.Active {
		// Fail closed: an active session without a verifiable future
		// expiry is displayed as expired, never as active.
		if p.ExpiryUnix <= 0 || !now.Before(time.Unix(p.ExpiryUnix, 0)) {
			return StateExpired
		}
		return StateActive
	}
	if prev == StateActive || prev == StateExpired {
		return StateExpired
	}
	return StateNone
}

// Remaining returns the remaining time of the session reported by the poll
// p at time now, clamped to zero. It is derived from the executor-reported
// expiry only; a poll never changes the value it reports.
func Remaining(p Poll, now time.Time) time.Duration {
	if !p.Available || !p.Active || p.ExpiryUnix <= 0 {
		return 0
	}
	d := time.Unix(p.ExpiryUnix, 0).Sub(now)
	if d < 0 {
		d = 0
	}
	return d
}

// FormatRemaining renders a remaining time for the display: "1h 04m" for
// an hour or more, "12m 09s" for a minute or more, "45s" below that.
// Negative durations render as "0s".
func FormatRemaining(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

// CanExtend reports whether the Extend action is offered in the display
// state s. An active session is extended and an expired session is opened
// again with one fresh WebAuthn assertion. A session that was never opened
// is opened from the dashboard, and an unreachable executor offers no
// action (fail closed).
func CanExtend(s State) bool {
	return s == StateActive || s == StateExpired
}

// Extending reports whether a new extend flow may be started in the display
// state s while inFlight assertion flows are in progress. At most one flow
// runs at a time: one click extends the session exactly once, and a second
// click while the first is running starts nothing.
func Extending(s State, inFlight bool) bool {
	return !inFlight && CanExtend(s)
}

// StateLabel returns the short label shown for the display state s.
func StateLabel(s State) string {
	switch s {
	case StateActive:
		return "Session"
	case StateExpired:
		return "Session expired"
	case StateNone:
		return "No session"
	default:
		return "Session unavailable"
	}
}

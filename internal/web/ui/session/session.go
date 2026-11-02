// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session computes the display of the privileged approval session
// in the web UI (ADR 0007, E20).
//
// The page topbar shows the executor-reported session state: the remaining
// time while a session is active, an expired state once it is gone, and a
// single Extend action that opens or extends the session with one fresh
// WebAuthn user-verification assertion.
//
// The server is the source of truth for the display: GET /privileged/session
// (internal/web/ui/privileged_session.go) runs Display on every poll and
// sends the resulting View. The browser (web/static/nav.js) only
// renders that View, counts the reported remaining seconds down and polls
// again; it derives no state of its own. The properties pinned down here:
//
//   - the remaining time is derived from the executor-reported expiry only;
//   - a session that was active and is now gone is displayed as expired,
//     and the same single assertion opens a new session;
//   - no amount of browsing activity (repeated polls) can renew or extend
//     a session: Display is pure and only the executor-reported state and
//     the clock decide it;
//   - an unreachable executor fails closed to an unknown state with no
//     action offered.
package session

import (
	"time"
)

// LowThreshold is the remaining time at or below which the display is
// highlighted as running out.
const LowThreshold = time.Minute

// Poll is the executor-reported session status a display is computed from.
type Poll struct {
	// Active reports whether the executor has an open privileged session.
	Active bool
	// Available reports whether the executor could be reached at all.
	Available bool
	// ExpiryUnix is the executor-reported expiry of an active session in
	// seconds since the Unix epoch. Zero when the session is not active.
	ExpiryUnix int64
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
// data-state attribute of the display element and sends it back as the
// prev query parameter of the next poll.
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

// ParseState returns the state named s (see State.String). Anything else,
// including the empty string, is StateUnknown.
func ParseState(s string) State {
	switch s {
	case "none":
		return StateNone
	case "active":
		return StateActive
	case "expired":
		return StateExpired
	default:
		return StateUnknown
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

// CanExtend reports whether the Extend action is offered in the display
// state s. An active session is extended and an expired session is opened
// again with one fresh WebAuthn assertion. A session that was never opened
// is opened from the dashboard, and an unreachable executor offers no
// action (fail closed).
func CanExtend(s State) bool {
	return s == StateActive || s == StateExpired
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

// View is the computed display the poll endpoint sends to the browser.
// The client renders it as is.
type View struct {
	// State is the display state name (State.String).
	State string `json:"state"`
	// Label is the text shown for the state (StateLabel).
	Label string `json:"label"`
	// RemainingSeconds is the remaining time of an active session, rounded
	// up to whole seconds so an active session always reports at least 1;
	// zero in every other state. The client counts it down locally and
	// polls again when it reaches zero.
	RemainingSeconds int64 `json:"remaining_seconds"`
	// Extendable reports whether the Extend action is offered (CanExtend).
	Extendable bool `json:"extendable"`
	// LowThresholdSeconds is LowThreshold in seconds: the client highlights
	// the display while the remaining time is at or below it.
	LowThresholdSeconds int64 `json:"low_threshold_seconds"`
}

// Display computes the View for the poll p at time now, given the state
// prev the client displayed before (Next).
func Display(prev State, p Poll, now time.Time) View {
	s := Next(prev, p, now)
	v := View{
		State:               s.String(),
		Label:               StateLabel(s),
		Extendable:          CanExtend(s),
		LowThresholdSeconds: int64(LowThreshold / time.Second),
	}
	if s == StateActive {
		d := Remaining(p, now)
		v.RemainingSeconds = int64((d + time.Second - 1) / time.Second)
	}
	return v
}

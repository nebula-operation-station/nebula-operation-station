// SPDX-License-Identifier: AGPL-3.0-or-later

package opsdigest

import (
	"fmt"
	"time"
)

// TimeOfDay is the configured send time on the local calendar.
type TimeOfDay struct {
	Hour   int // 0–23
	Minute int // 0–59
}

// valid reports whether the time of day is in range.
func (t TimeOfDay) valid() bool {
	return t.Hour >= 0 && t.Hour <= 23 && t.Minute >= 0 && t.Minute <= 59
}

// Due reports whether the digest should be sent at now.
//
// Rules:
//   - At most one digest per calendar day in loc.
//   - A digest is due once the configured time has passed on the current day.
//   - If the server was down at the configured time, the missed digest is
//     sent once when it comes back. Several missed days are one catch-up, never
//     one per day.
//   - A digest sent for a slot counts; the next slot is the next day.
//   - With no record of an earlier send (lastSent is zero), the first digest
//     is due at today's slot. Days before the first start are not caught up.
//
// The caller stores the time of the last successful send and passes it in.
// now is injected so tests and the daemon agree on the clock. A time that does
// not exist on a DST-change day is resolved by time.Date; the rules above still
// hold for it.
func Due(lastSent time.Time, at TimeOfDay, now time.Time, loc *time.Location) (bool, error) {
	if loc == nil {
		return false, ErrNoLocation
	}
	if !at.valid() {
		return false, fmt.Errorf("send time %02d:%02d: %w", at.Hour, at.Minute, ErrInvalidTime)
	}
	local := now.In(loc)
	y, m, d := local.Date()
	today := time.Date(y, m, d, at.Hour, at.Minute, 0, 0, loc)

	if lastSent.IsZero() {
		return !now.Before(today), nil
	}

	// The most recent slot that is not after now.
	slot := today
	if now.Before(today) {
		slot = time.Date(y, m, d-1, at.Hour, at.Minute, 0, 0, loc)
	}
	if !lastSent.Before(slot) {
		return false, nil // already sent for this slot (or a later send)
	}
	ly, lm, ld := lastSent.In(loc).Date()
	if ly == y && lm == m && ld == d {
		return false, nil // one digest per calendar day
	}
	return true, nil
}

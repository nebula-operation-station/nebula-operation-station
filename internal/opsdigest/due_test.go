// SPDX-License-Identifier: AGPL-3.0-or-later

package opsdigest

import (
	"errors"
	"testing"
	"time"
	_ "time/tzdata" // zone data for tests, independent of the host
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return loc
}

func at(t *testing.T, loc *time.Location, y int, m time.Month, d, h, min int) time.Time {
	t.Helper()
	return time.Date(y, m, d, h, min, 0, 0, loc)
}

func TestDueTable(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	slot := TimeOfDay{Hour: 8, Minute: 0}
	cases := []struct {
		name     string
		lastSent time.Time
		now      time.Time
		want     bool
	}{
		{
			name:     "never sent, before today's slot",
			lastSent: time.Time{},
			now:      at(t, berlin, 2026, 11, 17, 7, 59),
			want:     false,
		},
		{
			name:     "never sent, at today's slot",
			lastSent: time.Time{},
			now:      at(t, berlin, 2026, 11, 17, 8, 0),
			want:     true,
		},
		{
			name:     "sent yesterday, before today's slot",
			lastSent: at(t, berlin, 2026, 11, 16, 8, 0),
			now:      at(t, berlin, 2026, 11, 17, 7, 59),
			want:     false,
		},
		{
			name:     "sent yesterday, at today's slot",
			lastSent: at(t, berlin, 2026, 11, 16, 8, 0),
			now:      at(t, berlin, 2026, 11, 17, 8, 0),
			want:     true,
		},
		{
			name:     "sent today already, later in the day",
			lastSent: at(t, berlin, 2026, 11, 17, 8, 0),
			now:      at(t, berlin, 2026, 11, 17, 23, 59),
			want:     false,
		},
		{
			name:     "outage over the slot, recovered before today's slot: catch up once",
			lastSent: at(t, berlin, 2026, 11, 13, 8, 0),
			now:      at(t, berlin, 2026, 11, 17, 7, 0),
			want:     true,
		},
		{
			name:     "outage over the slot, recovered after today's slot",
			lastSent: at(t, berlin, 2026, 11, 13, 8, 0),
			now:      at(t, berlin, 2026, 11, 17, 10, 0),
			want:     true,
		},
		{
			name:     "catch-up already sent today, no second digest",
			lastSent: at(t, berlin, 2026, 11, 17, 7, 5),
			now:      at(t, berlin, 2026, 11, 17, 8, 0),
			want:     false,
		},
		{
			name:     "catch-up already sent today, next day before slot",
			lastSent: at(t, berlin, 2026, 11, 17, 10, 0),
			now:      at(t, berlin, 2026, 11, 18, 7, 59),
			want:     false,
		},
		{
			name:     "next day at slot after catch-up",
			lastSent: at(t, berlin, 2026, 11, 17, 10, 0),
			now:      at(t, berlin, 2026, 11, 18, 8, 0),
			want:     true,
		},
		{
			name:     "clock ahead of stored send (future timestamp) does not resend",
			lastSent: at(t, berlin, 2026, 11, 17, 9, 0),
			now:      at(t, berlin, 2026, 11, 17, 8, 30),
			want:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Due(tc.lastSent, slot, tc.now, berlin)
			if err != nil {
				t.Fatalf("Due: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Due(last=%v, now=%v) = %v, want %v", tc.lastSent, tc.now, got, tc.want)
			}
		})
	}
}

func TestDueRejectsBadInput(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	now := at(t, berlin, 2026, 11, 17, 9, 0)
	if _, err := Due(time.Time{}, TimeOfDay{Hour: 24}, now, berlin); !errors.Is(err, ErrInvalidTime) {
		t.Errorf("hour 24: want ErrInvalidTime, got %v", err)
	}
	if _, err := Due(time.Time{}, TimeOfDay{Minute: 60}, now, berlin); !errors.Is(err, ErrInvalidTime) {
		t.Errorf("minute 60: want ErrInvalidTime, got %v", err)
	}
	if _, err := Due(time.Time{}, TimeOfDay{Hour: 8}, now, nil); !errors.Is(err, ErrNoLocation) {
		t.Errorf("nil location: want ErrNoLocation, got %v", err)
	}
}

// TestDueAtMostOncePerDayAcrossDST walks through minute by minute, the
// days around both DST changes in Berlin, with a "sender" that records a
// send whenever Due says yes. Every calendar day must get exactly one
// digest, including the day the clock jumps and the day it repeats.
func TestDueAtMostOncePerDayAcrossDST(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	slots := []TimeOfDay{{Hour: 2, Minute: 30}, {Hour: 8, Minute: 0}, {Hour: 3, Minute: 15}}
	for _, slot := range slots {
		var lastSent time.Time
		sendsPerDay := map[string]int{}
		start := at(t, berlin, 2026, 3, 27, 0, 0)
		end := at(t, berlin, 2026, 11, 2, 0, 0) // covers both transitions
		for now := start; now.Before(end); now = now.Add(time.Minute) {
			due, err := Due(lastSent, slot, now, berlin)
			if err != nil {
				t.Fatalf("slot %v at %v: %v", slot, now, err)
			}
			if due {
				lastSent = now
				sendsPerDay[now.In(berlin).Format("2006-01-02")]++
			}
		}
		for day, n := range sendsPerDay {
			if n != 1 {
				t.Errorf("slot %v: %s got %d digests, want 1", slot, day, n)
			}
		}
		// 2026-03-27 up to but excluding 2026-11-02: 220 calendar days.
		if got, want := len(sendsPerDay), 220; got != want {
			t.Errorf("slot %v: digests on %d days, want %d", slot, got, want)
		}
	}
}

// TestDueSpringGapSlot checks a configured time that does not exist on the
// day the clock jumps (02:30 on 2026-03-29 in Berlin). The digest still
// goes out that day, once, and never before 03:00 local.
func TestDueSpringGapSlot(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	slot := TimeOfDay{Hour: 2, Minute: 30}
	lastSent := at(t, berlin, 2026, 3, 28, 2, 30)

	before := time.Date(2026, 3, 29, 1, 59, 0, 0, berlin)
	if due, err := Due(lastSent, slot, before, berlin); err != nil || due {
		t.Fatalf("01:59 on gap day: due=%v err=%v, want false", due, err)
	}
	after := time.Date(2026, 3, 29, 4, 0, 0, 0, berlin)
	due, err := Due(lastSent, slot, after, berlin)
	if err != nil || !due {
		t.Fatalf("04:00 on gap day: due=%v err=%v, want true", due, err)
	}
	if due, _ := Due(after, slot, after.Add(time.Hour), berlin); due {
		t.Fatal("second digest on the gap day")
	}
}

// TestDueFallBackSlotSentOnce checks a time that occurs twice on the day
// the clock goes back (02:30 on 2026-10-25 in Berlin). It is sent once.
func TestDueFallBackSlotSentOnce(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	slot := TimeOfDay{Hour: 2, Minute: 30}
	lastSent := at(t, berlin, 2026, 10, 24, 2, 30)
	now := time.Date(2026, 10, 25, 4, 0, 0, 0, berlin)
	due, err := Due(lastSent, slot, now, berlin)
	if err != nil || !due {
		t.Fatalf("04:00 on fall-back day: due=%v err=%v, want true", due, err)
	}
	for m := 0; m < 24*60; m += 30 {
		later := now.Add(time.Duration(m) * time.Minute)
		if later.In(berlin).Day() != 25 {
			break
		}
		if due, _ := Due(now, slot, later, berlin); due {
			t.Fatalf("second digest at %v on fall-back day", later)
		}
	}
}

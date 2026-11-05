// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"testing"
	"time"
)

type fixedRetention time.Duration

func (r fixedRetention) Retention() time.Duration { return time.Duration(r) }

func names(ws []QueryWindow) string {
	s := ""
	for i, w := range ws {
		if i > 0 {
			s += ","
		}
		s += w.Name
	}
	return s
}

func TestQueryWindowsFollowTheRetention(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		retention time.Duration
		want, def string
	}{
		{Retention, "1h,24h,7d,21d", "24h"},
		{7 * day, "1h,24h,7d", "24h"},
		{day, "1h,24h", "24h"},
		{12 * time.Hour, "1h", "1h"},
		{time.Hour, "1h", "1h"},
	}
	for _, c := range cases {
		if got := names(QueryWindows(c.retention)); got != c.want {
			t.Errorf("QueryWindows(%s) = %s, want %s", c.retention, got, c.want)
		}
		if got := DefaultQueryWindowFor(c.retention).Name; got != c.def {
			t.Errorf("DefaultQueryWindowFor(%s) = %s, want %s", c.retention, got, c.def)
		}
	}
	if w, ok := LookupQueryWindow("7d", 7*day); !ok || w.Dur != 7*day {
		t.Errorf("7d within 7d: %v %v", w, ok)
	}
	for _, name := range []string{"21d", "30d", "", "7D"} {
		if w, ok := LookupQueryWindow(name, 7*day); ok || w != (QueryWindow{}) {
			t.Errorf("LookupQueryWindow(%q, 7d) = %v %v, want refused", name, w, ok)
		}
	}
}

func TestEffectiveRetention(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		configured time.Duration
		src        any
		want       time.Duration
		ok         bool
	}{
		{0, nil, Retention, true},
		{7 * day, nil, 7 * day, true},
		{0, fixedRetention(3 * day), 3 * day, true},
		{7 * day, fixedRetention(14 * day), 7 * day, true},
		{0, fixedRetention(30 * time.Minute), 0, false},
		{-time.Hour, nil, 0, false},
		{Retention + time.Hour, nil, 0, false},
	}
	for _, c := range cases {
		got, err := EffectiveRetention(c.configured, c.src)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("EffectiveRetention(%s, %v) = %s, %v", c.configured, c.src, got, err)
		}
	}
}

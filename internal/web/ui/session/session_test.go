// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"strings"
	"testing"
	"time"

	templates "github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// testNow is a fixed reference time for the table tests.
var testNow = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func TestNext(t *testing.T) {
	future := testNow.Add(30 * time.Minute).Unix()
	past := testNow.Add(-time.Minute).Unix()
	cases := []struct {
		name string
		prev State
		poll Poll
		now  time.Time
		want State
	}{
		{"unavailable wins over everything", StateActive, Poll{Available: false}, testNow, StateUnknown},
		{"unavailable from none", StateNone, Poll{Available: false}, testNow, StateUnknown},
		{"active with future expiry", StateNone, Poll{Active: true, Available: true, ExpiryUnix: future}, testNow, StateActive},
		{"active at exact expiry is expired", StateNone, Poll{Active: true, Available: true, ExpiryUnix: testNow.Unix()}, testNow, StateExpired},
		{"active past expiry is expired", StateActive, Poll{Active: true, Available: true, ExpiryUnix: past}, testNow, StateExpired},
		{"active without expiry fails closed to expired", StateNone, Poll{Active: true, Available: true}, testNow, StateExpired},
		{"active zero expiry fails closed to expired", StateNone, Poll{Active: true, Available: true, ExpiryUnix: 0}, testNow, StateExpired},
		{"inactive after active is expired", StateActive, Poll{Available: true}, testNow, StateExpired},
		{"inactive after expired stays expired", StateExpired, Poll{Available: true}, testNow, StateExpired},
		{"inactive from unknown is none", StateUnknown, Poll{Available: true}, testNow, StateNone},
		{"inactive from none is none", StateNone, Poll{Available: true}, testNow, StateNone},
		{"new session after expired is active", StateExpired, Poll{Active: true, Available: true, ExpiryUnix: future}, testNow, StateActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Next(tc.prev, tc.poll, tc.now); got != tc.want {
				t.Errorf("Next(%v, %+v, %s) = %v, want %v", tc.prev, tc.poll, tc.now, got, tc.want)
			}
		})
	}
}

// TestNextActivityNeverRenews pins down the no-activity-based-renewal
// property: an unbounded stream of polls (browsing activity) with a fixed
// executor-reported expiry can only follow the clock. The state is active
// exactly while now is before the expiry and expired from the expiry on;
// no number of polls can move it back to active or extend the expiry.
func TestNextActivityNeverRenews(t *testing.T) {
	expiry := testNow.Add(30 * time.Minute).Unix()
	poll := Poll{Active: true, Available: true, ExpiryUnix: expiry}

	state := StateNone
	// Poll every second for 120 s before and 120 s after the expiry.
	for i := -120; i <= 120; i++ {
		now := testNow.Add(time.Duration(i) * time.Second)
		state = Next(state, poll, now)
		want := StateActive
		if !now.Before(time.Unix(expiry, 0)) {
			want = StateExpired
		}
		if state != want {
			t.Fatalf("at now=%s (offset %ds): state = %v, want %v", now, i, state, want)
		}
	}
	// After the expiry the state must stay expired no matter how many
	// further polls arrive.
	for i := 0; i < 1000; i++ {
		state = Next(state, poll, testNow.Add(time.Hour))
		if state != StateExpired {
			t.Fatalf("poll %d after expiry: state = %v, want %v", i, state, StateExpired)
		}
	}
}

func TestParseState(t *testing.T) {
	for _, st := range []State{StateUnknown, StateNone, StateActive, StateExpired} {
		if got := ParseState(st.String()); got != st {
			t.Errorf("ParseState(%q) = %v, want %v", st.String(), got, st)
		}
	}
	// Anything the client might send that is not a state name is unknown.
	for _, in := range []string{"", "ACTIVE", "active ", "loading", "1", strings.Repeat("a", 4096)} {
		if got := ParseState(in); got != StateUnknown {
			t.Errorf("ParseState(%q) = %v, want unknown", in, got)
		}
	}
}

func TestDisplay(t *testing.T) {
	cases := []struct {
		name string
		prev State
		poll Poll
		now  time.Time
		want View
	}{
		{"active", StateNone, Poll{Active: true, Available: true, ExpiryUnix: testNow.Add(90 * time.Second).Unix()}, testNow,
			View{State: "active", Label: "Session", RemainingSeconds: 90, Extendable: true, LowThresholdSeconds: 60}},
		{"active rounds up", StateActive, Poll{Active: true, Available: true, ExpiryUnix: testNow.Add(90 * time.Second).Unix()}, testNow.Add(500 * time.Millisecond),
			View{State: "active", Label: "Session", RemainingSeconds: 90, Extendable: true, LowThresholdSeconds: 60}},
		{"last fraction of a second is still at least 1", StateActive, Poll{Active: true, Available: true, ExpiryUnix: testNow.Unix()}, testNow.Add(-time.Millisecond),
			View{State: "active", Label: "Session", RemainingSeconds: 1, Extendable: true, LowThresholdSeconds: 60}},
		{"expired at expiry", StateActive, Poll{Active: true, Available: true, ExpiryUnix: testNow.Unix()}, testNow,
			View{State: "expired", Label: "Session expired", Extendable: true, LowThresholdSeconds: 60}},
		{"gone after active", StateActive, Poll{Available: true}, testNow,
			View{State: "expired", Label: "Session expired", Extendable: true, LowThresholdSeconds: 60}},
		{"none", StateUnknown, Poll{Available: true}, testNow,
			View{State: "none", Label: "No session", LowThresholdSeconds: 60}},
		{"unavailable", StateActive, Poll{Active: true, ExpiryUnix: testNow.Add(time.Hour).Unix()}, testNow,
			View{State: "unknown", Label: "Session unavailable", LowThresholdSeconds: 60}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Display(tc.prev, tc.poll, tc.now); got != tc.want {
				t.Errorf("Display = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestDisplayActivityNeverRenews: polling Display with a fixed
// executor-reported expiry only ever counts down; the remaining time never
// grows and nothing but a new expiry from the executor moves it back up.
func TestDisplayActivityNeverRenews(t *testing.T) {
	poll := Poll{Active: true, Available: true, ExpiryUnix: testNow.Add(5 * time.Minute).Unix()}
	prev := StateNone
	last := int64(1 << 62)
	for i := 0; i < 2000; i++ {
		now := testNow.Add(time.Duration(i) * 250 * time.Millisecond)
		v := Display(prev, poll, now)
		if v.RemainingSeconds > last {
			t.Fatalf("poll %d: remaining grew from %d to %d", i, last, v.RemainingSeconds)
		}
		last = v.RemainingSeconds
		prev = ParseState(v.State)
	}
	if prev != StateExpired || last != 0 {
		t.Fatalf("after the expiry: state %v remaining %d, want expired 0", prev, last)
	}
}

func TestRemaining(t *testing.T) {
	cases := []struct {
		name string
		poll Poll
		now  time.Time
		want time.Duration
	}{
		{"active", Poll{Active: true, Available: true, ExpiryUnix: testNow.Add(90 * time.Second).Unix()}, testNow, 90 * time.Second},
		{"inactive is zero", Poll{Available: true}, testNow, 0},
		{"unavailable is zero", Poll{Active: true, ExpiryUnix: testNow.Add(time.Minute).Unix()}, testNow, 0},
		{"past expiry clamps to zero", Poll{Active: true, Available: true, ExpiryUnix: testNow.Add(-time.Minute).Unix()}, testNow, 0},
		{"zero expiry is zero", Poll{Active: true, Available: true}, testNow, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Remaining(tc.poll, tc.now); got != tc.want {
				t.Errorf("Remaining = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanExtend(t *testing.T) {
	cases := []struct {
		state State
		want  bool
	}{
		{StateActive, true},
		{StateExpired, true},
		{StateNone, false},
		{StateUnknown, false},
	}
	for _, tc := range cases {
		if got := CanExtend(tc.state); got != tc.want {
			t.Errorf("CanExtend(%v) = %v, want %v", tc.state, got, tc.want)
		}
	}
}

func TestStateLabel(t *testing.T) {
	cases := []struct {
		state State
		want  string
	}{
		{StateActive, "Session"},
		{StateExpired, "Session expired"},
		{StateNone, "No session"},
		{StateUnknown, "Session unavailable"},
	}
	for _, tc := range cases {
		if got := StateLabel(tc.state); got != tc.want {
			t.Errorf("StateLabel(%v) = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestStateString(t *testing.T) {
	cases := []struct {
		state State
		want  string
	}{
		{StateUnknown, "unknown"},
		{StateNone, "none"},
		{StateActive, "active"},
		{StateExpired, "expired"},
	}
	for _, tc := range cases {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("State(%v).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// TestLayoutSessionDisplayCSPClean verifies the layout carries the session
// display elements the display module wires up, and that it stays clean
// under the strict Content-Security-Policy: no inline event handlers, no
// inline script, no style attributes. The display is driven entirely by
// the external webauthn.js asset.
func TestLayoutSessionDisplayCSPClean(t *testing.T) {
	raw, err := templates.FS.ReadFile("layout.html")
	if err != nil {
		t.Fatalf("read layout.html: %v", err)
	}
	s := string(raw)

	for _, want := range []string{
		`id="session-display"`,
		`id="session-state"`,
		`id="session-time"`,
		`id="session-error"`,
		`id="session-extend"`,
		`type="button"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("layout.html missing %s", want)
		}
	}

	// The extend control must be a plain button, never a form submit:
	// the session flow is the explicit begin/finish assertion pair.
	i := strings.Index(s, `id="session-extend"`)
	if i < 0 {
		t.Fatal("layout.html has no session-extend element")
	}
	tag := s[strings.LastIndex(s[:i], "<button") : i+len(`id="session-extend"`)]
	if !strings.Contains(tag, `type="button"`) {
		t.Errorf("session-extend element must be type=button, got: %s", tag)
	}

	lower := strings.ToLower(s)
	for _, bad := range []string{
		"onclick=", "onload=", "onerror=", "onsubmit=", "onchange=",
		"style=", "javascript:",
	} {
		if strings.Contains(lower, bad) {
			t.Errorf("layout.html contains %q, which the strict CSP forbids", bad)
		}
	}
	// Every script tag in the layout must reference an external file.
	for _, line := range strings.Split(s, "\n") {
		tl := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(tl, "<script") && !strings.Contains(tl, "src=") {
			t.Errorf("layout.html has an inline script tag: %s", line)
		}
	}
}

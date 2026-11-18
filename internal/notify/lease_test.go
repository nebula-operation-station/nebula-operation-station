// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

var leaseAt = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)

func TestLeaseExpiringEventIsTemplatedAndLinked(t *testing.T) {
	e, err := NewLeaseExpiring("https://nebula.example.org/", LeaseExpiry{
		GrantID:   "lease-7",
		GrantName: "Nightly package check",
		Threshold: 7 * 24 * time.Hour,
		ExpiresAt: leaseAt.Add(6*24*time.Hour + 5*time.Hour),
		At:        leaseAt,
	})
	if err != nil {
		t.Fatalf("NewLeaseExpiring: %v", err)
	}
	if e.Kind != KindLeaseExpiring {
		t.Errorf("kind = %q, want %q", e.Kind, KindLeaseExpiring)
	}
	text := e.Text()
	for _, want := range []string{"Nightly package check", "6 days left", "https://nebula.example.org/leases/lease-7"} {
		if !strings.Contains(text, want) {
			t.Errorf("text %q lacks %q", text, want)
		}
	}
	if n := strings.Count(text, "https://"); n != 1 {
		t.Errorf("text has %d links, want exactly 1: %q", n, text)
	}
}

func TestLeaseExpiringShortWindowShowsHours(t *testing.T) {
	e, err := NewLeaseExpiring("https://nebula.example.org", LeaseExpiry{
		GrantID: "lease-7", GrantName: "x", Threshold: 24 * time.Hour,
		ExpiresAt: leaseAt.Add(3 * time.Hour), At: leaseAt,
	})
	if err != nil {
		t.Fatalf("NewLeaseExpiring: %v", err)
	}
	if !strings.Contains(e.Text(), "3 hours left") {
		t.Errorf("text %q lacks the remaining hours", e.Text())
	}
}

func TestLeaseEventsRejectBadInput(t *testing.T) {
	good := LeaseExpiry{GrantID: "lease-7", GrantName: "x", Threshold: 24 * time.Hour, ExpiresAt: leaseAt.Add(time.Hour), At: leaseAt}
	tests := []struct {
		name string
		base string
		x    LeaseExpiry
	}{
		{"base without scheme", "nebula.example.org", good},
		{"base with userinfo", "https://user:pw@nebula.example.org", good},
		{"base with path", "https://nebula.example.org/ui", good},
		{"base with query", "https://nebula.example.org/?a=1", good},
		{"ftp base", "ftp://nebula.example.org", good},
		{"id with slash", "https://nebula.example.org", withID(good, "a/b")},
		{"id with dots only", "https://nebula.example.org", withID(good, "..")},
		{"id with space", "https://nebula.example.org", withID(good, "a b")},
		{"empty id", "https://nebula.example.org", withID(good, "")},
		{"no expiry time", "https://nebula.example.org", withExpiry(good, time.Time{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewLeaseExpiring(tt.base, tt.x); !errors.Is(err, ErrInvalidLeaseEvent) {
				t.Fatalf("NewLeaseExpiring error = %v, want ErrInvalidLeaseEvent", err)
			}
		})
	}
}

func withID(x LeaseExpiry, id string) LeaseExpiry { x.GrantID = id; return x }

func withExpiry(x LeaseExpiry, at time.Time) LeaseExpiry { x.ExpiresAt = at; return x }

func TestLeaseNameIsPlainTextOneLine(t *testing.T) {
	e, err := NewLeaseExpiring("https://nebula.example.org", LeaseExpiry{
		GrantID: "lease-7", GrantName: "evil\nState: ok‮X [link](https://x.example)",
		Threshold: 24 * time.Hour, ExpiresAt: leaseAt.Add(time.Hour), At: leaseAt,
	})
	if err != nil {
		t.Fatalf("NewLeaseExpiring: %v", err)
	}
	if strings.Contains(e.Text(), "‮") {
		t.Errorf("bidi control survived in the name: %q", e.Text())
	}
	// Title, State, Reason, Details and time: one line each, the name never
	// adds a line.
	if n := strings.Count(e.Text(), "\n"); n != 4 {
		t.Errorf("text has %d newlines, want 4: %q", n, e.Text())
	}
}

func TestLeaseRunFailedEventNamesActionAndHost(t *testing.T) {
	e, err := NewLeaseRunFailed("https://nebula.example.org", LeaseRunFailure{
		GrantID: "lease-9", GrantName: "Checks", Action: "os.updates.list", HostLabel: "pve-01", At: leaseAt,
	})
	if err != nil {
		t.Fatalf("NewLeaseRunFailed: %v", err)
	}
	if e.Kind != KindLeaseRunFailed {
		t.Errorf("kind = %q", e.Kind)
	}
	text := e.Text()
	for _, want := range []string{"os.updates.list", "pve-01", "Checks", "https://nebula.example.org/leases/lease-9"} {
		if !strings.Contains(text, want) {
			t.Errorf("text %q lacks %q", text, want)
		}
	}
}

func TestLeaseRunFailedRejectsEmptyAction(t *testing.T) {
	_, err := NewLeaseRunFailed("https://nebula.example.org", LeaseRunFailure{GrantID: "lease-9", HostLabel: "h", At: leaseAt})
	if !errors.Is(err, ErrInvalidLeaseEvent) {
		t.Fatalf("error = %v, want ErrInvalidLeaseEvent", err)
	}
}

func TestLeaseEventsHaveLogCodes(t *testing.T) {
	cases := map[string]struct {
		kind  notifylog.KindCode
		state notifylog.StateCode
	}{
		KindLeaseExpiring:  {notifylog.KindLeaseExpiring, notifylog.StateExpiring},
		KindLeaseRunFailed: {notifylog.KindLeaseRunFailed, notifylog.StateFailed},
	}
	for kind, want := range cases {
		k, s, ok := logEntry(Event{Kind: kind})
		if !ok || k != want.kind || s != want.state {
			t.Errorf("logEntry(%s) = %q, %q, %v; want %q, %q", kind, k, s, ok, want.kind, want.state)
		}
	}
}

func TestDailyDigestEventCarriesTheText(t *testing.T) {
	const body = "NOS daily digest\nOpen updates: 3\nSee https://nebula.example.org"
	e, err := NewDailyDigest(body, leaseAt)
	if err != nil {
		t.Fatalf("NewDailyDigest: %v", err)
	}
	if got := e.Text(); got != body {
		t.Errorf("Text() = %q, want the digest text unchanged", got)
	}
	if e.Title() != "Nebula: daily digest" {
		t.Errorf("Title() = %q", e.Title())
	}
	if k, s, ok := logEntry(e); !ok || k != notifylog.KindDigest || s != notifylog.StateSummary {
		t.Errorf("logEntry = %q, %q, %v; want the digest code", k, s, ok)
	}
}

func TestDailyDigestEventRejectsBadText(t *testing.T) {
	for name, body := range map[string]string{
		"empty":     "",
		"too long":  strings.Repeat("a", MaxDailyDigestBytes+1),
		"bad utf-8": "ok\xff",
		"control":   "ok\x07",
	} {
		if _, err := NewDailyDigest(body, leaseAt); !errors.Is(err, ErrInvalidLeaseEvent) {
			t.Errorf("%s: error = %v, want ErrInvalidLeaseEvent", name, err)
		}
	}
}

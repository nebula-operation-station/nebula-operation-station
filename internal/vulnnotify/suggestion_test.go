// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// suggEvent is a suggestion message as notify.SuggestionTemplate builds it.
func suggEvent(t *testing.T, key string, noteID int64, at time.Time) notify.Event {
	t.Helper()
	tpl, err := notify.NewSuggestionTemplate("https://nos.example.net")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := tpl.Event(notify.SuggestionEvent{Key: key, Host: "web-02", Tier: "high", NoteID: noteID}, at)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// countKind counts the delivered events of kind.
func countKind(s *sink, kind string) int {
	n := 0
	for _, e := range s.es {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// fillHourlyLimit delivers MaxPerHour vuln.kev_new messages.
func fillHourlyLimit(t *testing.T, n *Notifier) {
	t.Helper()
	var fs []vulnstore.Finding
	for i := 1; i <= MaxPerHour; i++ {
		fs = append(fs, finding(byte(i), 1, vulnstore.TierHigh, true))
	}
	if got := n.Findings(context.Background(), fs); got != MaxPerHour {
		t.Fatalf("filled limit with %d messages, want %d", got, MaxPerHour)
	}
}

// TestSuggestionOncePerEpisodeKey: a second suggestion for the same episode
// key is not sent again.
func TestSuggestionOncePerEpisodeKey(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	ev := suggEvent(t, "web-02/os|high", 1, c.Now())
	if got := n.Suggestion(ctx, "web-02/os|high", ev); got != 1 {
		t.Fatalf("first suggestion sent %d, want 1", got)
	}
	if got := n.Suggestion(ctx, "web-02/os|high", suggEvent(t, "web-02/os|high", 2, c.Now())); got != 0 {
		t.Fatalf("second suggestion for the same episode sent %d, want 0", got)
	}
	if got := countKind(s, notify.KindOpsSuggestion); got != 1 {
		t.Fatalf("delivered %d suggestions, want 1", got)
	}
}

// TestSuggestionSharesHourlyLimitAndDigest: a suggestion over MaxPerHour is
// held, counted into the hourly digest and not sent later (ADR 0016 D10).
func TestSuggestionSharesHourlyLimitAndDigest(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	fillHourlyLimit(t, n)
	if got := n.Suggestion(ctx, "web-02/os|high", suggEvent(t, "web-02/os|high", 1, c.Now())); got != 0 {
		t.Fatalf("suggestion over the limit sent %d, want 0 (held)", got)
	}
	if got := countKind(s, notify.KindOpsSuggestion); got != 0 {
		t.Fatalf("delivered %d suggestions over the limit, want 0", got)
	}
	// The held episode is remembered: it is not sent later.
	c.Add(RateWindow)
	n.Flush(ctx)
	if got := countKind(s, notify.KindOpsSuggestion); got != 0 {
		t.Fatalf("held suggestion sent by a later Flush (%d), want none", got)
	}
	var digest *notify.Event
	for i := range s.es {
		if s.es[i].Kind == KindDigest {
			digest = &s.es[i]
		}
	}
	if digest == nil {
		t.Fatalf("no digest after the held suggestion; delivered %v", s.kinds())
	}
	if !strings.Contains(digest.Reason, notify.KindOpsSuggestion+": 1") {
		t.Fatalf("digest %q does not count the held suggestion", digest.Reason)
	}
	if keys := n.SuggestionKeys(); len(keys) != 1 || keys[0] != "web-02/os|high" {
		t.Fatalf("SuggestionKeys = %v, want the held episode", keys)
	}
}

// TestSuggestionUndeliveredIsRetriedByFlush: a suggestion no provider accepts
// is not remembered, and the next Flush sends it.
func TestSuggestionUndeliveredIsRetriedByFlush(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	s.setDown(true)
	if got := n.Suggestion(ctx, "web-02/os|high", suggEvent(t, "web-02/os|high", 1, c.Now())); got != 0 {
		t.Fatalf("undelivered suggestion reported %d, want 0", got)
	}
	if keys := n.SuggestionKeys(); len(keys) != 0 {
		t.Fatalf("undelivered episode remembered: %v", keys)
	}
	s.setDown(false)
	if got := n.Flush(ctx); got != 1 {
		t.Fatalf("Flush delivered %d, want the queued suggestion", got)
	}
	if got := countKind(s, notify.KindOpsSuggestion); got != 1 {
		t.Fatalf("delivered %d suggestions, want 1", got)
	}
}

// TestSuggestionForgetEndsEpisode: after ForgetSuggestions the same key sends
// again; keys that were not remembered are ignored.
func TestSuggestionForgetEndsEpisode(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	n.Suggestion(ctx, "web-02/os|high", suggEvent(t, "web-02/os|high", 1, c.Now()))
	n.ForgetSuggestions([]string{"web-02/os|high", "never-seen|high"})
	if keys := n.SuggestionKeys(); len(keys) != 0 {
		t.Fatalf("remembered keys after Forget = %v, want none", keys)
	}
	if got := n.Suggestion(ctx, "web-02/os|high", suggEvent(t, "web-02/os|high", 2, c.Now())); got != 1 {
		t.Fatalf("suggestion after the episode ended sent %d, want 1", got)
	}
	if got := countKind(s, notify.KindOpsSuggestion); got != 2 {
		t.Fatalf("delivered %d suggestions, want 2", got)
	}
}

// TestSuggestionRestoredEpisodeIsNotSent: episodes restored after a restart
// are not sent again; unusable restored keys are ignored.
func TestSuggestionRestoredEpisodeIsNotSent(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	n.RestoreSuggestions([]string{"web-02/os|high", "", "bad key|high"})
	if got := n.Suggestion(ctx, "web-02/os|high", suggEvent(t, "web-02/os|high", 1, c.Now())); got != 0 {
		t.Fatalf("restored episode sent %d, want 0", got)
	}
	if keys := n.SuggestionKeys(); len(keys) != 1 {
		t.Fatalf("SuggestionKeys = %v, want the one usable key", keys)
	}
	if got := countKind(s, notify.KindOpsSuggestion); got != 0 {
		t.Fatalf("delivered %d suggestions, want 0", got)
	}
}

// TestSuggestionRefusesOtherKindsAndKeys: only opsagent.suggestion_new with a
// valid key is accepted; a vuln message or an empty key sends nothing.
func TestSuggestionRefusesOtherKindsAndKeys(t *testing.T) {
	ctx := context.Background()
	n, s, c := newTest(t)
	vuln := notify.Event{Kind: KindKEVNew, Time: c.Now()}
	if got := n.Suggestion(ctx, "web-02/os|high", vuln); got != 0 {
		t.Fatalf("vuln kind through Suggestion sent %d", got)
	}
	ev := suggEvent(t, "web-02/os|high", 1, c.Now())
	if got := n.Suggestion(ctx, "", ev); got != 0 {
		t.Fatalf("empty key sent %d", got)
	}
	if len(s.es) != 0 {
		t.Fatalf("delivered %v, want nothing", s.kinds())
	}
}

// TestSuggestionDoesNotEvictVulnMarks: the suggestion marks have their own
// bound, so they never push out a vuln.* de-duplication mark.
func TestSuggestionDoesNotEvictVulnMarks(t *testing.T) {
	n, _, _ := newTest(t)
	fe := findingEvent{key: finding(1, 1, vulnstore.TierHigh, true).Key, kind: KindKEVNew}
	n.markNotified(fe, 1)
	for i := 0; i < MaxTrackedSuggestionKeys+5; i++ {
		n.markSuggested("web-02/os" + strconv.Itoa(i) + "|high")
	}
	if _, ok := n.notified[fe]; !ok {
		t.Fatal("vuln.kev_new mark evicted by suggestion marks")
	}
	if len(n.suggested) > MaxTrackedSuggestionKeys {
		t.Fatalf("suggestion marks %d exceed the bound %d", len(n.suggested), MaxTrackedSuggestionKeys)
	}
}

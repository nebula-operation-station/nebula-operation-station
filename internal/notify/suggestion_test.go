// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// suggRec is a provider that records the events it accepts.
type suggRec struct {
	mu   sync.Mutex
	got  []Event
	fail bool
}

func (s *suggRec) Name() string { return "rec" }

func (s *suggRec) Send(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("provider down")
	}
	s.got = append(s.got, e)
	return nil
}

func (s *suggRec) events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.got...)
}

func newSuggestionFixture(t *testing.T, rec *suggRec, now *time.Time) *SuggestionGate {
	t.Helper()
	n := NewWithSenders(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, rec)
	g, err := NewSuggestionGate(n, testNOSBase, func() time.Time { return *now })
	if err != nil {
		t.Fatalf("NewSuggestionGate: %v", err)
	}
	return g
}

func suggEvent(key string, noteID int64, tier string, english bool) SuggestionEvent {
	return SuggestionEvent{Key: key, Host: "web-02", Tier: tier, English: english, NoteID: noteID}
}

// TestSuggestionMediumTierSendsNothing: a note whose group is at medium is
// not a suggestion event (ADR 0016 D10): nothing is sent or remembered.
func TestSuggestionMediumTierSendsNothing(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	for _, tier := range []string{"medium", "low", "", "CRITICAL", "info"} {
		if _, err := g.Submit(context.Background(), suggEvent("g1|"+tier, 1, tier, false)); !errors.Is(err, ErrInvalidSuggestion) {
			t.Errorf("tier %q: err %v, want ErrInvalidSuggestion", tier, err)
		}
	}
	if got := rec.events(); len(got) != 0 {
		t.Fatalf("sent %d events for non-critical tiers, want 0", len(got))
	}
	if keys := g.Keys(); len(keys) != 0 {
		t.Fatalf("remembered keys %v for refused tiers", keys)
	}
}

// TestSuggestionOncePerGroupAndTier: a second note of the same group at the
// same tier is not sent again; a different tier is a new episode.
func TestSuggestionOncePerGroupAndTier(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	ctx := context.Background()
	if d, err := g.Submit(ctx, suggEvent("web-02/os|high", 1, "high", false)); err != nil || d != DecisionSent {
		t.Fatalf("first note: %v %v, want DecisionSent", d, err)
	}
	if d, err := g.Submit(ctx, suggEvent("web-02/os|high", 2, "high", false)); err != nil || d != DecisionDuplicate {
		t.Fatalf("second note same group and tier: %v %v, want DecisionDuplicate", d, err)
	}
	if d, err := g.Submit(ctx, suggEvent("web-02/os|critical", 3, "critical", false)); err != nil || d != DecisionSent {
		t.Fatalf("same group, new tier: %v %v, want DecisionSent", d, err)
	}
	if got := len(rec.events()); got != 2 {
		t.Fatalf("sent %d events, want 2", got)
	}
}

// TestSuggestionForgetEndsEpisode: after Forget the episode is over, so the
// same group and tier sends again; keys that were not remembered are ignored.
func TestSuggestionForgetEndsEpisode(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	ctx := context.Background()
	if d, err := g.Submit(ctx, suggEvent("web-02/os|high", 1, "high", false)); err != nil || d != DecisionSent {
		t.Fatalf("first high note: %v %v, want DecisionSent", d, err)
	}
	g.Forget([]string{"web-02/os|high", "never-seen|high"})
	if keys := g.Keys(); len(keys) != 0 {
		t.Fatalf("remembered keys after Forget = %v, want none", keys)
	}
	if d, err := g.Submit(ctx, suggEvent("web-02/os|high", 2, "high", false)); err != nil || d != DecisionSent {
		t.Fatalf("high note after the episode ended: %v %v, want DecisionSent", d, err)
	}
	if got := len(rec.events()); got != 2 {
		t.Fatalf("sent %d events, want 2", got)
	}
}

// TestSuggestionTextIsFixedTemplate: the text is the fixed template with the
// host label, the tier and the NOS link; nothing else is in it. The event
// carries no note text, so a marker can only be absent from the message.
func TestSuggestionTextIsFixedTemplate(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	ctx := context.Background()
	if _, err := g.Submit(ctx, suggEvent("a|high", 7, "high", false)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Submit(ctx, SuggestionEvent{Key: "b|critical", Host: "Keller Server", Tier: "critical", English: true, NoteID: 8}); err != nil {
		t.Fatal(err)
	}
	got := rec.events()
	if len(got) != 2 {
		t.Fatalf("sent %d events, want 2", len(got))
	}
	wantDE := "Neuer Fix-Vorschlag für web-02, Tier high\nDetails: " + testNOSBase + "/assistant/ops/notes/7\n2026-11-18T10:00:00Z"
	if got[0].Text() != wantDE {
		t.Errorf("de text:\n%q\nwant:\n%q", got[0].Text(), wantDE)
	}
	wantEN := "New fix suggestion for Keller Server, tier critical\nDetails: " + testNOSBase + "/assistant/ops/notes/8\n2026-11-18T10:00:00Z"
	if got[1].Text() != wantEN {
		t.Errorf("en text:\n%q\nwant:\n%q", got[1].Text(), wantEN)
	}
	if got[0].Title() != "Neuer Fix-Vorschlag für web-02, Tier high" {
		t.Errorf("title %q", got[0].Title())
	}
	if got[0].Kind != KindOpsSuggestion || got[0].State != "" || got[0].Reason != "" || got[0].Host != "" {
		t.Errorf("event carries fields beyond the template: %+v", got[0])
	}
}

// TestSuggestionHostLabelIsPlainText: a label with markup or a domain-like
// text is reduced like every integrity label, so no link or mention is formed.
func TestSuggestionHostLabelIsPlainText(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	_, err := g.Submit(context.Background(), SuggestionEvent{Key: "x|high", Host: "[a](http://evil.example)@all\n", Tier: "high", NoteID: 3})
	if err != nil {
		t.Fatal(err)
	}
	text := rec.events()[0].Text()
	if strings.ContainsAny(strings.SplitN(text, "\n", 2)[0], "[]()@.:/\n") {
		t.Errorf("title keeps markup: %q", text)
	}
}

// TestSuggestionNoLinkOutsideNOSBase: the link is built from the configured
// NOS base only; an invalid base is refused at construction.
func TestSuggestionNoLinkOutsideNOSBase(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	for _, base := range []string{"", "ftp://nos.example.net", "https://user@nos.example.net", "https://nos.example.net?x=1", "nos.example.net"} {
		if _, err := NewSuggestionGate(NewWithSenders(nil, nil), base, func() time.Time { return now }); !errors.Is(err, ErrInvalidNOSBase) {
			t.Errorf("base %q: err %v, want ErrInvalidNOSBase", base, err)
		}
	}
}

// TestSuggestionHourlyLimitHolds: past MaxSuggestionsPerHour in one hour a
// suggestion is held, not sent, and the limit resets after the window.
func TestSuggestionHourlyLimitHolds(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	ctx := context.Background()
	for i := 0; i < MaxSuggestionsPerHour; i++ {
		if d, err := g.Submit(ctx, suggEvent("g"+string(rune('a'+i))+"|high", int64(i+1), "high", false)); err != nil || d != DecisionSent {
			t.Fatalf("send %d: %v %v", i, d, err)
		}
	}
	if d, err := g.Submit(ctx, suggEvent("late|high", 99, "high", false)); err != nil || d != DecisionHeld {
		t.Fatalf("over the limit: %v %v, want DecisionHeld", d, err)
	}
	if got := len(rec.events()); got != MaxSuggestionsPerHour {
		t.Fatalf("sent %d, want %d", got, MaxSuggestionsPerHour)
	}
	now = now.Add(SuggestionWindow)
	if d, err := g.Submit(ctx, suggEvent("after|high", 100, "high", false)); err != nil || d != DecisionSent {
		t.Fatalf("after the window: %v %v, want DecisionSent", d, err)
	}
}

// TestSuggestionUndeliveredIsNotRemembered: when no provider accepts the
// message, its key is not recorded and the slot is given back.
func TestSuggestionUndeliveredIsNotRemembered(t *testing.T) {
	rec := &suggRec{fail: true}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	ctx := context.Background()
	if d, err := g.Submit(ctx, suggEvent("u|high", 1, "high", false)); err != nil || d != DecisionUndelivered {
		t.Fatalf("down provider: %v %v, want DecisionUndelivered", d, err)
	}
	if keys := g.Keys(); len(keys) != 0 {
		t.Fatalf("undelivered key remembered: %v", keys)
	}
	rec.mu.Lock()
	rec.fail = false
	rec.mu.Unlock()
	if d, err := g.Submit(ctx, suggEvent("u|high", 1, "high", false)); err != nil || d != DecisionSent {
		t.Fatalf("retry after recovery: %v %v, want DecisionSent", d, err)
	}
}

// TestSuggestionStateSurvivesRestore: the keys of a gate can be handed to a
// new gate, which then does not send them again (durable state).
func TestSuggestionStateSurvivesRestore(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	if _, err := g.Submit(context.Background(), suggEvent("k|high", 1, "high", false)); err != nil {
		t.Fatal(err)
	}
	keys := g.Keys()
	if len(keys) != 1 || keys[0] != "k|high" {
		t.Fatalf("keys %v, want [k|high]", keys)
	}
	g2 := newSuggestionFixture(t, rec, &now)
	g2.Restore(keys)
	if d, err := g2.Submit(context.Background(), suggEvent("k|high", 2, "high", false)); err != nil || d != DecisionDuplicate {
		t.Fatalf("after restore: %v %v, want DecisionDuplicate", d, err)
	}
	if got := len(rec.events()); got != 1 {
		t.Fatalf("sent %d events, want 1", got)
	}
}

// TestSuggestionRefusesBadInput: an empty or oversized key, an empty NOS
// note ID and a key with control characters are refused without a send.
func TestSuggestionRefusesBadInput(t *testing.T) {
	rec := &suggRec{}
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	g := newSuggestionFixture(t, rec, &now)
	long := strings.Repeat("k", maxSuggestionKey+1)
	for name, ev := range map[string]SuggestionEvent{
		"empty key":    suggEvent("", 1, "high", false),
		"long key":     suggEvent(long, 1, "high", false),
		"control key":  suggEvent("a\nb|high", 1, "high", false),
		"zero note id": suggEvent("z|high", 0, "high", false),
	} {
		if _, err := g.Submit(context.Background(), ev); !errors.Is(err, ErrInvalidSuggestion) {
			t.Errorf("%s: err %v, want ErrInvalidSuggestion", name, err)
		}
	}
	if got := rec.events(); len(got) != 0 {
		t.Fatalf("sent %d events for refused input", len(got))
	}
}

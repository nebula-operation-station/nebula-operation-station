// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func suggTemplate(t *testing.T) *SuggestionTemplate {
	t.Helper()
	tpl, err := NewSuggestionTemplate(testNOSBase)
	if err != nil {
		t.Fatalf("NewSuggestionTemplate: %v", err)
	}
	return tpl
}

func suggEvent(key string, noteID int64, tier string, english bool) SuggestionEvent {
	return SuggestionEvent{Key: key, Host: "web-02", Tier: tier, English: english, NoteID: noteID}
}

// TestSuggestionRefusesNonSuggestionTiers: a group at medium, low, an unknown
// tier or an upper-case tier is never a suggestion event (ADR 0016 D10).
func TestSuggestionRefusesNonSuggestionTiers(t *testing.T) {
	tpl := suggTemplate(t)
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	for _, tier := range []string{"medium", "low", "", "CRITICAL", "info"} {
		if _, err := tpl.Event(suggEvent("g1|"+tier, 1, tier, false), now); !errors.Is(err, ErrInvalidSuggestion) {
			t.Errorf("tier %q: err %v, want ErrInvalidSuggestion", tier, err)
		}
	}
}

// TestSuggestionRefusesBadInput: an empty or non-printable key, a non-positive
// note ID and an overlong key are refused before a message exists.
func TestSuggestionRefusesBadInput(t *testing.T) {
	tpl := suggTemplate(t)
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	long := strings.Repeat("k", maxSuggestionKey+1)
	cases := map[string]SuggestionEvent{
		"empty key":     suggEvent("", 1, "high", false),
		"control key":   suggEvent("a\nb|high", 1, "high", false),
		"space in key":  suggEvent("a b|high", 1, "high", false),
		"overlong key":  suggEvent(long, 1, "high", false),
		"zero note ID":  suggEvent("a|high", 0, "high", false),
		"negative note": suggEvent("a|high", -3, "high", false),
	}
	for name, ev := range cases {
		if _, err := tpl.Event(ev, now); !errors.Is(err, ErrInvalidSuggestion) {
			t.Errorf("%s: err %v, want ErrInvalidSuggestion", name, err)
		}
	}
	if ValidSuggestionKey("a|high") != true || ValidSuggestionKey("") {
		t.Fatal("ValidSuggestionKey disagrees with the key rules")
	}
}

// TestSuggestionTextIsFixedTemplate: the text is the fixed template with the
// host label, the tier and the NOS link; nothing else is in it.
func TestSuggestionTextIsFixedTemplate(t *testing.T) {
	tpl := suggTemplate(t)
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	de, err := tpl.Event(suggEvent("a|high", 7, "high", false), now)
	if err != nil {
		t.Fatal(err)
	}
	en, err := tpl.Event(SuggestionEvent{Key: "b|critical", Host: "Keller Server", Tier: "critical", English: true, NoteID: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	wantDE := "Neuer Fix-Vorschlag für web-02, Tier high\nDetails: " + testNOSBase + "/assistant/ops/notes/7\n2026-11-18T10:00:00Z"
	wantEN := "New fix suggestion for Keller Server, tier critical\nDetails: " + testNOSBase + "/assistant/ops/notes/8\n2026-11-18T10:00:00Z"
	if got := de.Text(); got != wantDE {
		t.Errorf("German text:\n got %q\nwant %q", got, wantDE)
	}
	if got := en.Text(); got != wantEN {
		t.Errorf("English text:\n got %q\nwant %q", got, wantEN)
	}
	if de.Kind != KindOpsSuggestion {
		t.Errorf("kind %q, want %q", de.Kind, KindOpsSuggestion)
	}
}

// TestSuggestionHostLabelIsPlainText: a host label with control or bidi
// characters is reduced to plain text before it is part of the message.
func TestSuggestionHostLabelIsPlainText(t *testing.T) {
	tpl := suggTemplate(t)
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	ev, err := tpl.Event(SuggestionEvent{Key: "c|high", Host: "web\x07‮02", Tier: "high", NoteID: 3}, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(ev.Text(), "\x07‮") {
		t.Fatalf("control or bidi character in text %q", ev.Text())
	}
}

// TestSuggestionNOSBaseIsRequired: a base that is not usable is refused at
// construction, and the error does not echo it.
func TestSuggestionNOSBaseIsRequired(t *testing.T) {
	for _, base := range []string{"", "nos.example.net", "http://nos.example.net/x?y=1"} {
		if _, err := NewSuggestionTemplate(base); err == nil {
			t.Errorf("base %q accepted, want an error", base)
		} else if base != "" && strings.Contains(err.Error(), base) {
			t.Errorf("error %q echoes the base", err)
		}
	}
}

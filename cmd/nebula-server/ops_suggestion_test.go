// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// suggSender records the notification events it accepts.
type suggSender struct {
	mu  sync.Mutex
	got []notify.Event
}

func (s *suggSender) Name() string { return "rec" }

func (s *suggSender) Send(_ context.Context, e notify.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, e)
	return nil
}

func (s *suggSender) texts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.got {
		out = append(out, e.Text())
	}
	return out
}

const suggTestBase = "https://nos.example.net"

// suggFixture returns the suggestions of one server with the agent on or off,
// the recorder and the data directory (the state file lives there).
func suggFixture(t *testing.T, dataDir string, enabled bool) (*opsSuggestEvents, *suggSender) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dataDir, opsNotesDir), 0o700); err != nil {
		t.Fatal(err)
	}
	rec := &suggSender{}
	n := notify.NewWithSenders(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, rec)
	st := &fakeTriggerSettings{row: opsconfig.Row{Settings: opsconfig.Settings{Enabled: enabled}}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newOpsSuggestions(st, dataDir, suggTestBase, n, log), rec
}

// suggNote returns an accepted note of kind for group ref whose snapshot has
// the given tiers. marker is note text: it must never reach a message.
func suggNote(t *testing.T, id int64, kind opsnotes.Kind, ref string, tiers []opsfacts.Tier, marker string) opsnotes.Note {
	t.Helper()
	p := opsfacts.LabProjection{Host: opsfacts.LabHost{Label: "web-02"}}
	for _, tier := range tiers {
		p.Findings = append(p.Findings, opsfacts.LabFinding{Tier: tier})
	}
	snap, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return opsnotes.Note{ID: id, Kind: kind, Ref: ref, Snapshot: string(snap),
		Body: opsnotes.Body{Summary: marker, Urgency: marker}}
}

// accept runs the hook for n and waits for its background work.
func accept(s *opsSuggestEvents, n opsnotes.Note) {
	s.NoteAccepted(n)
	s.bg.Wait()
}

// TestSuggestionSentOnceForHighFixNote: an accepted fix note at tier high sends
// one suggestion; a second note of the same group at high sends nothing.
func TestSuggestionSentOnceForHighFixNote(t *testing.T) {
	s, rec := suggFixture(t, t.TempDir(), true)
	accept(s, suggNote(t, 1, opsnotes.KindFix, "group-a", []opsfacts.Tier{opsfacts.TierHigh}, ""))
	accept(s, suggNote(t, 2, opsnotes.KindFix, "group-a", []opsfacts.Tier{opsfacts.TierHigh}, ""))
	got := rec.texts()
	if len(got) != 1 {
		t.Fatalf("sent %d suggestions, want 1: %q", len(got), got)
	}
	want := "Neuer Fix-Vorschlag für web-02, Tier high\nDetails: " + suggTestBase + "/assistant/ops/notes/1\n"
	if !strings.HasPrefix(got[0], want) {
		t.Fatalf("text = %q, want prefix %q", got[0], want)
	}
}

// TestSuggestionNotForMediumOrOtherKinds: a group at medium, and any note that
// is not a fix note, sends nothing.
func TestSuggestionNotForMediumOrOtherKinds(t *testing.T) {
	s, rec := suggFixture(t, t.TempDir(), true)
	accept(s, suggNote(t, 1, opsnotes.KindFix, "group-m", []opsfacts.Tier{opsfacts.TierMedium}, ""))
	accept(s, suggNote(t, 2, opsnotes.KindSummary, "group-h", []opsfacts.Tier{opsfacts.TierHigh}, ""))
	if got := rec.texts(); len(got) != 0 {
		t.Fatalf("sent %q, want nothing", got)
	}
}

// TestSuggestionTextHoldsNoNoteText: a note with a marker in its body and
// summary sends a message without the marker.
func TestSuggestionTextHoldsNoNoteText(t *testing.T) {
	const marker = "ZZ-NOTE-MARKER-7f3a"
	s, rec := suggFixture(t, t.TempDir(), true)
	accept(s, suggNote(t, 3, opsnotes.KindFix, "group-t", []opsfacts.Tier{opsfacts.TierCritical}, marker))
	got := rec.texts()
	if len(got) != 1 {
		t.Fatalf("sent %d, want 1", len(got))
	}
	if strings.Contains(got[0], marker) {
		t.Fatalf("message carries note text: %q", got[0])
	}
}

// TestSuggestionOffAgentSendsNothing: with the ops agent off no suggestion is
// sent.
func TestSuggestionOffAgentSendsNothing(t *testing.T) {
	s, rec := suggFixture(t, t.TempDir(), false)
	accept(s, suggNote(t, 1, opsnotes.KindFix, "group-o", []opsfacts.Tier{opsfacts.TierHigh}, ""))
	if got := rec.texts(); len(got) != 0 {
		t.Fatalf("sent %q with the agent off", got)
	}
}

// TestSuggestionEpisodeEndsOnLowerTier: an episode (group, tier) ends when an
// accepted note of the group has a lower top tier, so a later return to the
// tier is a new episode. The episode above the new tier ends, the one below
// does not change what is sent.
func TestSuggestionEpisodeEndsOnLowerTier(t *testing.T) {
	dir := t.TempDir()
	s, rec := suggFixture(t, dir, true)
	high := []opsfacts.Tier{opsfacts.TierHigh}
	crit := []opsfacts.Tier{opsfacts.TierCritical}
	med := []opsfacts.Tier{opsfacts.TierMedium}
	accept(s, suggNote(t, 1, opsnotes.KindFix, "g", high, ""))
	accept(s, suggNote(t, 2, opsnotes.KindFix, "g", med, ""))  // episode high ends
	accept(s, suggNote(t, 3, opsnotes.KindFix, "g", high, "")) // new episode: sent again
	accept(s, suggNote(t, 4, opsnotes.KindFix, "g", crit, "")) // critical: new episode
	accept(s, suggNote(t, 5, opsnotes.KindFix, "g", high, "")) // critical ends; high (step 3) still open
	accept(s, suggNote(t, 6, opsnotes.KindFix, "g", crit, "")) // critical again: new episode
	if got := len(rec.texts()); got != 4 {
		t.Fatalf("sent %d suggestions, want 4 (high, high again, critical, critical again)", got)
	}
	// The remembered episodes survive a restart: the high episode of step 3 is
	// still open, so a note at high is not sent again.
	s2, rec2 := suggFixture(t, dir, true)
	accept(s2, suggNote(t, 7, opsnotes.KindFix, "g", high, ""))
	if got := rec2.texts(); len(got) != 0 {
		t.Fatalf("after restart sent %q for an episode already sent", got)
	}
}

// TestSuggestionOtherGroupsAreSeparate: two groups at high each get one
// suggestion.
func TestSuggestionOtherGroupsAreSeparate(t *testing.T) {
	s, rec := suggFixture(t, t.TempDir(), true)
	high := []opsfacts.Tier{opsfacts.TierHigh}
	accept(s, suggNote(t, 1, opsnotes.KindFix, "g1", high, ""))
	accept(s, suggNote(t, 2, opsnotes.KindFix, "g2", high, ""))
	if got := len(rec.texts()); got != 2 {
		t.Fatalf("sent %d, want 2", got)
	}
}

// TestSuggestionStateHoldsNoGroupRef: the state file keeps hashed group keys,
// never the group reference itself.
func TestSuggestionStateHoldsNoGroupRef(t *testing.T) {
	const ref = "host-secret-group-ref"
	dir := t.TempDir()
	s, _ := suggFixture(t, dir, true)
	accept(s, suggNote(t, 1, opsnotes.KindFix, ref, []opsfacts.Tier{opsfacts.TierHigh}, ""))
	data, err := os.ReadFile(s.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), ref) {
		t.Fatalf("state file holds the group ref: %s", data)
	}
}

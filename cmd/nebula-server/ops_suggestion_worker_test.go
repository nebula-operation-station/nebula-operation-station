// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// TestSuggestionHeldEpisodeSurvivesRestart: an episode held by the hourly limit
// is saved with the state, so after a restart it is not sent after all (ADR
// 0016 D10: a held suggestion is not sent later).
func TestSuggestionHeldEpisodeSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, rec := suggFixture(t, dir, true)
	high := []opsfacts.Tier{opsfacts.TierHigh}
	// MaxPerHour (10) suggestions use up the hourly limit.
	for i := 0; i < 10; i++ {
		accept(s, suggNote(t, int64(i+1), opsnotes.KindFix, fmt.Sprintf("g%d", i), high, ""))
	}
	accept(s, suggNote(t, 100, opsnotes.KindFix, "held", high, ""))
	if got := len(rec.texts()); got != 10 {
		t.Fatalf("sent %d suggestions before the limit, want 10", got)
	}
	s2, rec2 := suggFixture(t, dir, true)
	accept(s2, suggNote(t, 101, opsnotes.KindFix, "held", high, ""))
	if got := rec2.texts(); len(got) != 0 {
		t.Fatalf("held episode sent after a restart: %q", got)
	}
}

// TestSuggestionQueueIsBounded: accepted notes beyond the queue bound are not
// handled and never block the API hook.
func TestSuggestionQueueIsBounded(t *testing.T) {
	s, _ := suggFixture(t, t.TempDir(), true)
	var notes []opsnotes.Note
	for i := 0; i < opsSuggestionQueue+5; i++ {
		notes = append(notes, suggNote(t, int64(i+1), opsnotes.KindFix, fmt.Sprintf("q%d", i), []opsfacts.Tier{opsfacts.TierHigh}, ""))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, n := range notes {
			s.NoteAccepted(n)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("NoteAccepted blocked on a full queue")
	}
	if got := len(s.queue); got != opsSuggestionQueue {
		t.Fatalf("queued %d notes, want the bound %d", got, opsSuggestionQueue)
	}
}

// TestSuggestionWorkerStopsAtShutdown: the worker returns when the server's
// context is done, so no goroutine outlives the shutdown.
func TestSuggestionWorkerStopsAtShutdown(t *testing.T) {
	s, _ := suggFixture(t, t.TempDir(), true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker still running after the context was cancelled")
	}
}

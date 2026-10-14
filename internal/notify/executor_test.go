// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

func TestExecutorWatcherNotifiesLockAfterRestartOnly(t *testing.T) {
	rec := &recorder{}
	var unlocked bool
	var down error
	w := &ExecutorWatcher{Notifier: NewWithSenders(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, rec),
		Unlocked: func(context.Context) (bool, error) { return unlocked, down },
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	steps := []struct {
		name     string
		unlocked bool
		down     bool
		notify   bool
	}{
		{"server starts, executor locked", false, false, true},
		{"still locked: no repeat", false, false, false},
		{"admin unlocks", true, false, false},
		{"deliberate lock while reachable", false, false, false},
		{"unlocked again", true, false, false},
		{"executor restarts (unreachable)", false, true, false},
		{"back, locked", false, false, true},
		{"still locked", false, false, false},
	}
	for _, s := range steps {
		unlocked, down = s.unlocked, nil
		if s.down {
			down = errors.New("connection refused")
		}
		if got := w.Poll(ctx); got != s.notify {
			t.Fatalf("%s: notified %v", s.name, got)
		}
	}
	if len(rec.events) != 2 || rec.events[0].Kind != KindExecutorLocked || rec.events[0].Title() != "Nebula: executor is locked" {
		t.Fatalf("%+v", rec.events)
	}
}

func TestExecutionEventTitle(t *testing.T) {
	e := Event{Kind: KindExecution, State: "WARNING", ExecutionID: "x", Reason: "core.facts: 1 of 2 hosts failed: db (script_failed)"}
	if e.Title() != "Nebula: operation finished with WARNING" {
		t.Fatal(e.Title())
	}
}

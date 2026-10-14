// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"log/slog"
	"time"
)

// ExecutorWatcher notifies when the executor is found locked after it was
// unreachable (an executor restart: keys and vault are locked again) or
// when the server starts and finds it locked (spec 13: runs wait until
// `nebula unlock`). A lock while the executor stays reachable is a
// deliberate Lock from the dashboard or the CLI and is not notified.
type ExecutorWatcher struct {
	Notifier *Notifier
	// Unlocked reports the executor's state (server role GetStatus).
	Unlocked func(ctx context.Context) (bool, error)
	Interval time.Duration
	Log      *slog.Logger
	Now      func() time.Time

	// seen is the last observation: "", "unreachable", "locked", "unlocked".
	seen string
}

// Run polls until ctx ends.
func (w *ExecutorWatcher) Run(ctx context.Context) {
	if !w.Notifier.Enabled() {
		return
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		w.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll checks once and reports whether it sent a notification.
func (w *ExecutorWatcher) Poll(ctx context.Context) bool {
	unlocked, err := w.Unlocked(ctx)
	if err != nil {
		if ctx.Err() == nil && w.seen != "unreachable" {
			w.Log.Warn("executor watcher", "error", err.Error())
		}
		w.seen = "unreachable"
		return false
	}
	prev := w.seen
	if unlocked {
		w.seen = "unlocked"
		return false
	}
	w.seen = "locked"
	if prev != "" && prev != "unreachable" {
		return false
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	w.Notifier.Notify(ctx, Event{Kind: KindExecutorLocked, State: "LOCKED", Time: now(),
		Reason: "the executor is locked (restarted?); operations wait until an admin runs `nebula unlock` on the executor host"})
	return true
}

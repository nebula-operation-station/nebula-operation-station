// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
)

// countingSender is a provider that accepts every notification.
type countingSender struct{ sent int }

func (c *countingSender) Name() string { return "ntfy" }

func (c *countingSender) Send(context.Context, notify.Event) error {
	c.sent++
	return nil
}

// TestBrokenNotifyLogDoesNotStopNotifications: when the notification log cannot
// be attached, attachNotifyLog reports the error, and the notifier still
// sends. A log error never blocks a notification (ADR 0016 D10).
func TestBrokenNotifyLogDoesNotStopNotifications(t *testing.T) {
	sender := &countingSender{}
	n := notify.NewWithSenders(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, sender)
	store, err := attachNotifyLog(n, nil, time.Now)
	if err == nil || store != nil {
		t.Fatalf("attachNotifyLog(nil database) = %v, %v; want an error and no store", store, err)
	}
	ev := notify.Event{Kind: notify.KindTest, Reason: "still works", Time: time.Unix(1791960000, 0)}
	if got := n.Notify(context.Background(), ev); got != 1 {
		t.Fatalf("Notify = %d, want 1", got)
	}
	if sender.sent != 1 {
		t.Fatalf("sender called %d times, want 1", sender.sent)
	}
}

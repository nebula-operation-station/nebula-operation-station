// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// TestNotifyDecisionsReachTheLog: a notification the server sends is recorded
// in the notification log that attachNotifyLog wires into the notifier.
func TestNotifyDecisionsReachTheLog(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := notify.New(serverconfig.Notifications{Webhook: &serverconfig.WebhookConfig{URL: srv.URL + "/hook", Secret: "0123456789abcdef0123456789abcdef"}}, nil, quiet)

	now := time.Unix(1791960000, 0)
	store, err := attachNotifyLog(n, db, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	gate, err := notify.NewIntegrityGate(n, "https://nos.example.net", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ev := notify.IntegrityEvent{Kind: notify.IntegrityHostChange, Host: "web01", Class: "pkg_hash", Severity: notify.SeverityHigh, Count: 1}
	if d, err := gate.Submit(context.Background(), ev, notify.NewIntegrityKey("web01", "pkg_hash", "/etc/x")); err != nil || d != notify.DecisionSent {
		t.Fatalf("Submit = %v, %v; want DecisionSent", d, err)
	}
	// The write runs beside the send; wait for it before reading the log.
	if err := n.FlushRecords(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Outcome != notifylog.OutcomeSent || entries[0].Host != "web01" {
		t.Fatalf("log entries %+v; want one sent entry for web01", entries)
	}
}

// TestPruneNotifyLogUsesInjectedClock: entries older than the retention period
// on the store's clock are removed by one prune pass, newer ones are kept.
func TestPruneNotifyLogUsesInjectedClock(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Unix(1791960000, 0)
	clock := func() time.Time { return now }
	store, err := notifylog.New(db, clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rec := notifylog.Record{Kind: notifylog.KindDigest, State: notifylog.StateSummary, Outcome: notifylog.OutcomeSent}
	if _, err := store.Append(ctx, rec); err != nil {
		t.Fatal(err)
	}
	now = now.Add(notifylog.Retention + time.Second)
	if _, err := store.Append(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// The first append is older than Retention now; the prune pass drops it.
	if removed := pruneNotifyLogOnce(ctx, store, slog.New(slog.NewTextHandler(io.Discard, nil))); removed != 1 {
		t.Fatalf("prune removed %d entries, want 1", removed)
	}
	entries, err := store.List(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d entries left, want 1", len(entries))
	}
}

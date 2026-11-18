// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

// notifyLogPruneInterval is how often entries past the retention period are
// removed from the notification log (ADR 0016 D10).
const notifyLogPruneInterval = time.Hour

// attachNotifyLog opens the notification log on db and makes n record every
// sent, held and failed notification in it. now is the clock the log uses;
// nil means time.Now. The returned store is the one to prune.
func attachNotifyLog(n *notify.Notifier, db *sql.DB, now func() time.Time) (*notifylog.Store, error) {
	store, err := notifylog.New(db, now)
	if err != nil {
		return nil, fmt.Errorf("open notification log: %w", err)
	}
	n.SetRecorder(store)
	return store, nil
}

// pruneNotifyLogOnce removes expired entries and returns how many were
// removed. A failure is logged and reported as zero; it affects nothing else.
func pruneNotifyLogOnce(ctx context.Context, s *notifylog.Store, log *slog.Logger) int64 {
	n, err := s.Prune(ctx)
	if err != nil {
		log.Error("prune notification log", "error", err)
		return 0
	}
	if n > 0 {
		log.Info("pruned notification log", "count", n)
	}
	return n
}

// pruneNotifyLog prunes the notification log every notifyLogPruneInterval
// until ctx ends.
func pruneNotifyLog(ctx context.Context, s *notifylog.Store, log *slog.Logger) {
	t := time.NewTicker(notifyLogPruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pruneNotifyLogOnce(ctx, s, log)
		}
	}
}

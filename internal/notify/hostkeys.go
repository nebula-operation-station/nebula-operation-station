// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// HostKeyWatcher polls the executor's pins and notifies once per host key
// mismatch block (spec 08 and 13: always sent, cannot be muted). What was
// notified is kept in server.db (migration 0004), so a restart does not
// repeat it; a block whose notification failed on every provider is
// retried on the next poll.
type HostKeyWatcher struct {
	Notifier *Notifier
	// List returns the executor's pins (server role ListHostKeys).
	List     func(ctx context.Context) ([]*pb.HostKeyPin, error)
	DB       *sql.DB
	Interval time.Duration
	Log      *slog.Logger
	Now      func() time.Time
}

// Run polls until ctx ends.
func (w *HostKeyWatcher) Run(ctx context.Context) {
	if !w.Notifier.Enabled() {
		return
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		if err := w.Poll(ctx); err != nil && ctx.Err() == nil {
			w.Log.Warn("host key watcher", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll checks once.
func (w *HostKeyWatcher) Poll(ctx context.Context) error {
	pins, err := w.List(ctx)
	if err != nil {
		return fmt.Errorf("list host keys: %w", err)
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	blocked := map[string]bool{}
	for _, p := range pins {
		if !p.GetBlocked() {
			continue
		}
		blocked[p.GetHostId()] = true
		done, err := w.delivered(ctx, p.GetHostId(), p.GetBlockedAtUnix())
		if err != nil {
			return err
		}
		missing := false
		for _, name := range w.Notifier.Providers() {
			missing = missing || !done[name]
		}
		if !missing {
			continue
		}
		fp := p.GetBlockedFingerprint()
		if fp == "" {
			fp = "no key of the pinned type"
		}
		e := Event{Kind: KindHostKeyMismatch, Host: p.GetHostId(), State: "BLOCKED",
			Reason: fmt.Sprintf("%s presented %s instead of the pinned %s. Nebula does not connect until the key is re-pinned.",
				p.GetBlockedEndpoint(), fp, p.GetFingerprint()),
			Time: time.Unix(p.GetBlockedAtUnix(), 0)}
		// Providers that failed are retried on the next poll, each until it
		// accepts the block (spec 13: always sent).
		for _, name := range w.Notifier.NotifyProviders(ctx, e, func(n string) bool { return done[n] }) {
			if _, err := w.DB.ExecContext(ctx, `INSERT OR IGNORE INTO notified_host_key_blocks (host_id, blocked_at, provider, notified_at) VALUES (?, ?, ?, ?)`,
				p.GetHostId(), p.GetBlockedAtUnix(), name, now().Unix()); err != nil {
				return fmt.Errorf("record notified block: %w", err)
			}
		}
	}
	// Forget hosts that are no longer blocked, so a new block notifies.
	rows, err := w.DB.QueryContext(ctx, `SELECT DISTINCT host_id FROM notified_host_key_blocks`)
	if err != nil {
		return fmt.Errorf("read notified blocks: %w", err)
	}
	var stale []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !blocked[id] {
			stale = append(stale, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range stale {
		if _, err := w.DB.ExecContext(ctx, `DELETE FROM notified_host_key_blocks WHERE host_id = ?`, id); err != nil {
			return fmt.Errorf("forget block: %w", err)
		}
	}
	return nil
}

// delivered returns the providers that already accepted a block.
func (w *HostKeyWatcher) delivered(ctx context.Context, host string, blockedAt int64) (map[string]bool, error) {
	rows, err := w.DB.QueryContext(ctx, `SELECT provider FROM notified_host_key_blocks WHERE host_id = ? AND blocked_at = ?`, host, blockedAt)
	if err != nil {
		return nil, fmt.Errorf("read notified blocks: %w", err)
	}
	defer rows.Close()
	done := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read notified blocks: %w", err)
		}
		done[name] = true
	}
	return done, rows.Err()
}

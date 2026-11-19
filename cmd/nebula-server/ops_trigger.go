// SPDX-License-Identifier: AGPL-3.0-or-later

// Ops agent trigger of the server (ADR 0016 D3): the server touches a trigger
// file when a finding newly enters tier critical or high, and systemd's path
// unit starts the agent. The trigger file holds no data; the touch replaces it
// by rename inside the server's own state directory and touches nothing else.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
)

// Ops agent trigger constants.
const (
	// opsTriggerPath is the trigger file the ops agent's path unit watches
	// (deploy/systemd/nebula-ops-agent.path). It lies in the server's own
	// StateDirectory (nebula/server in nebula-server.service), the only
	// directory the server may write under ProtectSystem=strict, so the
	// server needs no extra write path (ADR 0016 amendment 2026-11-19;
	// previously /var/lib/nebula/opsagent/trigger, which the server could
	// not write). The agent never reads it: /var/lib/nebula is in its
	// InaccessiblePaths.
	opsTriggerPath = "/var/lib/nebula/server/ops-trigger"
	// opsTriggerInterval is the least time between two touches of the trigger.
	opsTriggerInterval = time.Minute
	// opsTriggerSettingsTimeout bounds the settings read before a touch.
	opsTriggerSettingsTimeout = 5 * time.Second
)

// opsSettingsReader is the part of the ops settings store the trigger reads.
// *opsconfig.Store implements it.
type opsSettingsReader interface {
	Get(ctx context.Context) (opsconfig.Row, error)
}

// opsTrigger touches the ops agent's trigger file. It touches nothing while
// the agent is off, and at most once per opsTriggerInterval.
type opsTrigger struct {
	settings opsSettingsReader
	path     string
	now      func() time.Time
	log      *slog.Logger

	mu        sync.Mutex // guards touched and lastTouch
	touched   bool
	lastTouch time.Time
}

// wireOpsTrigger returns the trigger on the server's database, reading the
// ops settings from db, with the real trigger path and clock. Call it only
// when the ops token is configured.
func wireOpsTrigger(db *sql.DB, log *slog.Logger) (*opsTrigger, error) {
	st, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ops agent trigger: %w", err)
	}
	return newOpsTrigger(st, opsTriggerPath, time.Now, log), nil
}

// newOpsTrigger returns a trigger that writes path, using settings and now.
func newOpsTrigger(settings opsSettingsReader, path string, now func() time.Time, log *slog.Logger) *opsTrigger {
	if now == nil {
		now = time.Now
	}
	return &opsTrigger{settings: settings, path: path, now: now, log: log}
}

// Touch is the trigger callback of internal/vulnnotify. It returns true when
// the trigger file was touched. It returns false when the touch did not happen
// (a settings read failed, the agent is off, the once-per-minute throttle holds
// it, or the file could not be touched); the notifier then keeps the trigger
// pending and calls Touch again on its next tick, so the episode is not lost.
// A failure is logged and never changes the findings upload or the messages.
func (t *opsTrigger) Touch() bool {
	ctx, cancel := context.WithTimeout(context.Background(), opsTriggerSettingsTimeout)
	defer cancel()
	row, err := t.settings.Get(ctx)
	if err != nil {
		t.log.Error("ops agent trigger: read settings", "error", err)
		return false
	}
	if !row.Enabled {
		return false
	}
	t.mu.Lock()
	now := t.now()
	if t.touched && now.Sub(t.lastTouch) < opsTriggerInterval {
		t.mu.Unlock()
		return false
	}
	t.touched, t.lastTouch = true, now
	t.mu.Unlock()
	if err := touchTrigger(t.path); err != nil {
		t.log.Warn("ops agent trigger not touched", "error", err)
		return false
	}
	return true
}

// touchTrigger replaces the trigger file atomically: it creates an empty
// temporary file with mode 0600 in the same directory and renames it over
// path. The path unit (PathChanged=) sees the new file appear, or the old
// inode lose its link. The content is empty and has no meaning. A symlink or
// any other file at path is replaced, never written through. On failure the
// temporary file is removed.
func touchTrigger(path string) (err error) {
	dir, base := filepath.Split(path)
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create trigger: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	// CreateTemp already uses 0600; Chmod makes the mode independent of it.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod trigger: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close trigger: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename trigger: %w", err)
	}
	return nil
}

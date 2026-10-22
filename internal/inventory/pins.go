// SPDX-License-Identifier: AGPL-3.0-or-later
// Pins: the catalog actions an admin pins to a host, so the host page and
// the inventory can run them in one step (spec 12, job ui5). Pinning
// changes no risk and no approval; only catalog actions may be pinned,
// which the UI layer validates against the catalog before calling here.
package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PinnedAction is a catalog action pinned to a host, in the order the
// admin chose (Position is 0-based).
type PinnedAction struct {
	ActionID string
	Position int
}

// ListPinnedActions returns the actions pinned to the host with the given
// ID, in position order. A host without pins returns an empty slice.
func (s *Store) ListPinnedActions(ctx context.Context, hostID string) ([]PinnedAction, error) {
	var hid int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM hosts WHERE name = ?`, hostID).Scan(&hid); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("inventory: list pins for %s: %w", hostID, ErrHostNotFound)
		}
		return nil, fmt.Errorf("inventory: list pins for %s: %w", hostID, err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT action_id, position FROM host_pinned_actions WHERE host_id = ? ORDER BY position`, hid)
	if err != nil {
		return nil, fmt.Errorf("inventory: list pins for %s: %w", hostID, err)
	}
	defer rows.Close()
	var out []PinnedAction
	for rows.Next() {
		var p PinnedAction
		if err := rows.Scan(&p.ActionID, &p.Position); err != nil {
			return nil, fmt.Errorf("inventory: list pins for %s: %w", hostID, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetPinnedActions replaces the pins of the host with the given ID by the
// given ordered list of action IDs (positions are renumbered 0..n-1). An
// empty list removes all pins. Duplicate action IDs are rejected.
func (s *Store) SetPinnedActions(ctx context.Context, hostID string, actionIDs []string, by string) error {
	seen := make(map[string]bool, len(actionIDs))
	for _, a := range actionIDs {
		if seen[a] {
			return fmt.Errorf("inventory: set pins for %s: duplicate action %s", hostID, a)
		}
		seen[a] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("inventory: set pins for %s: begin: %w", hostID, err)
	}
	defer tx.Rollback()
	var hid int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE name = ?`, hostID).Scan(&hid); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("inventory: set pins for %s: %w", hostID, ErrHostNotFound)
		}
		return fmt.Errorf("inventory: set pins for %s: %w", hostID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_pinned_actions WHERE host_id = ?`, hid); err != nil {
		return fmt.Errorf("inventory: set pins for %s: clear: %w", hostID, err)
	}
	ts := s.now().UTC().Format(time.RFC3339)
	for i, a := range actionIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO host_pinned_actions (host_id, action_id, position, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
			hid, a, i, by, ts); err != nil {
			return fmt.Errorf("inventory: set pins for %s: insert %s: %w", hostID, a, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("inventory: set pins for %s: commit: %w", hostID, err)
	}
	return nil
}

// AddPinnedAction pins one action to the host with the given ID at the end
// of its pin list. A pin that already exists is left in place (no error),
// so pinning the same action twice is a no-op.
func (s *Store) AddPinnedAction(ctx context.Context, hostID, actionID, by string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("inventory: pin %s to %s: begin: %w", actionID, hostID, err)
	}
	defer tx.Rollback()
	var hid int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE name = ?`, hostID).Scan(&hid); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("inventory: pin %s to %s: %w", actionID, hostID, ErrHostNotFound)
		}
		return fmt.Errorf("inventory: pin %s to %s: %w", actionID, hostID, err)
	}
	var position int
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(position), -1) + 1 FROM host_pinned_actions WHERE host_id = ?`, hid).Scan(&position)
	if err != nil {
		return fmt.Errorf("inventory: pin %s to %s: %w", actionID, hostID, err)
	}
	ts := s.now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO host_pinned_actions (host_id, action_id, position, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		hid, actionID, position, by, ts); err != nil {
		return fmt.Errorf("inventory: pin %s to %s: %w", actionID, hostID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("inventory: pin %s to %s: commit: %w", actionID, hostID, err)
	}
	return nil
}

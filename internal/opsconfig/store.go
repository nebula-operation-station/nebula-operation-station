// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Auditor runs a change in a write transaction together with its audit
// entries: fn writes the change through tx and the entry through appendLine,
// and the auditor commits both or neither. The server passes its audit log,
// the same contract as the vulnerability agent settings (vulnstore).
type Auditor interface {
	WithTx(ctx context.Context, fn func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error) error
}

// Store reads and saves the ops agent settings row.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// actorRe is the admin name pattern of the audit entries.
var actorRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)

// NewStore returns a store on db, which must carry the serverdb schema
// (migration 0046). now defaults to time.Now.
func NewStore(db *sql.DB, now func() time.Time) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("opsconfig: new store: db is required: %w", ErrInvalidInput)
	}
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// readRow reads the settings row; a missing row (not possible after
// migration 0046) reads as the defaults at version 0.
func readRow(ctx context.Context, q querier) (Row, error) {
	var (
		r                       Row
		enabled, allowPlainHTTP int64
		updatedAt               int64
	)
	err := q.QueryRowContext(ctx, `SELECT enabled, base_url, model, allow_plain_http, data_class,
		operator_instructions, language, updated_by, updated_at, version
		FROM ops_agent_config WHERE id = 1`).
		Scan(&enabled, &r.BaseURL, &r.Model, &allowPlainHTTP, &r.DataClass,
			&r.Instructions, &r.Language, &r.UpdatedBy, &updatedAt, &r.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return Row{Settings: Default()}, nil
	}
	if err != nil {
		return Row{}, fmt.Errorf("opsconfig: read settings: %w", err)
	}
	r.Enabled = enabled == 1
	r.AllowPlainHTTP = allowPlainHTTP == 1
	if updatedAt != 0 {
		r.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	}
	return r, nil
}

// Get returns the stored row, or the defaults at version 0 before any save.
func (s *Store) Get(ctx context.Context) (Row, error) {
	return readRow(ctx, s.db)
}

// Save validates next and stores it, provided the stored row still has
// baseVersion; otherwise it returns ErrStale and changes nothing. The change
// and its AuditOpsAgentSettingsChanged entry (the Diff fields, the actor and
// both versions) commit in one transaction. actor is the admin, who has
// already passed the role check and the fresh assertion.
func (s *Store) Save(ctx context.Context, actor string, next Settings, baseVersion int64, audit Auditor) (Row, error) {
	if audit == nil {
		return Row{}, fmt.Errorf("opsconfig: save: auditor is required: %w", ErrInvalidInput)
	}
	if !actorRe.MatchString(actor) {
		return Row{}, fmt.Errorf("opsconfig: save: actor: %w", ErrInvalidInput)
	}
	if baseVersion < 0 {
		return Row{}, fmt.Errorf("opsconfig: save: base version: %w", ErrInvalidInput)
	}
	if err := next.Validate(); err != nil {
		return Row{}, fmt.Errorf("opsconfig: save: %w", err)
	}
	var cur Row
	err := audit.WithTx(ctx, func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error {
		old, err := readRow(ctx, tx)
		if err != nil {
			return err
		}
		if old.Version != baseVersion {
			return fmt.Errorf("base version %d, stored %d: %w", baseVersion, old.Version, ErrStale)
		}
		now := s.now().UTC()
		// The version check is repeated in the WHERE clause, so a row that
		// changed after the read cannot be overwritten.
		res, err := tx.ExecContext(ctx, `UPDATE ops_agent_config SET enabled = ?, base_url = ?, model = ?,
			allow_plain_http = ?, data_class = ?, operator_instructions = ?, language = ?,
			updated_by = ?, updated_at = ?, version = version + 1
			WHERE id = 1 AND version = ?`,
			boolInt(next.Enabled), next.BaseURL, next.Model, boolInt(next.AllowPlainHTTP),
			next.DataClass, next.Instructions, next.Language, actor, now.Unix(), baseVersion)
		if err != nil {
			return fmt.Errorf("opsconfig: write settings: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("opsconfig: write settings: %w", err)
		} else if n != 1 {
			return fmt.Errorf("opsconfig: settings row not at base version %d: %w", baseVersion, ErrStale)
		}
		cur = Row{Settings: next, Version: baseVersion + 1, UpdatedBy: actor, UpdatedAt: now}
		attrs := Diff(old.Settings, next)
		attrs["actor"] = actor
		attrs["old_version"] = strconv.FormatInt(old.Version, 10)
		attrs["new_version"] = strconv.FormatInt(cur.Version, 10)
		if err := appendLine(AuditOpsAgentSettingsChanged, attrs); err != nil {
			return fmt.Errorf("opsconfig: audit: %w", err)
		}
		return nil
	})
	if err != nil {
		return Row{}, fmt.Errorf("opsconfig: save: %w", err)
	}
	return cur, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

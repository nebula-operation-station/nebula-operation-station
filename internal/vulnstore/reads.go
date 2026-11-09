// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MaxListFindings bounds one List or RunAlertFindings read.
const MaxListFindings = 200_000

// List returns at most limit findings in key order and whether more
// exist. It is the read behind the findings pages and the admin export.
func (s *Store) List(ctx context.Context, limit int) ([]Finding, bool, error) {
	if limit <= 0 || limit > MaxListFindings {
		return nil, false, fmt.Errorf("vulnstore: list: limit %d: %w", limit, ErrInvalidInput)
	}
	fs, err := queryFindings(ctx, s.db, `SELECT `+findingColumns+` FROM vuln_findings ORDER BY finding_key LIMIT ?`, limit+1)
	if err != nil {
		return nil, false, err
	}
	if len(fs) > limit {
		return fs[:limit], true, nil
	}
	return fs, false, nil
}

// RunAlertFindings returns at most limit open findings that run runID wrote
// last (state_run_seq) and that are KEV-listed or in the critical tier in
// their episode: the candidates for vuln.kev_new and vuln.critical_new
// (ADR 0011 D9). The notifier de-duplicates; this read only bounds the
// input. ErrRunNotFound for an unknown run.
func (s *Store) RunAlertFindings(ctx context.Context, runID string, limit int) ([]Finding, error) {
	if limit <= 0 || limit > MaxListFindings {
		return nil, fmt.Errorf("vulnstore: run alert findings: limit %d: %w", limit, ErrInvalidInput)
	}
	r, err := loadRun(ctx, s.db, runID)
	if err != nil {
		return nil, fmt.Errorf("vulnstore: run alert findings: %w", err)
	}
	return queryFindings(ctx, s.db, `SELECT `+findingColumns+` FROM vuln_findings
		WHERE state = 'open' AND state_run_seq = ?
		AND (episode_kev_date IS NOT NULL OR episode_peak_tier = ? OR json_extract(record, '$.scores.kev') IS NOT NULL)
		ORDER BY finding_key LIMIT ?`, r.seq, int(TierCritical), limit)
}

// FeedState is NOS's view of one listed feed source (D4, D5, D6).
type FeedState struct {
	SourceID string
	MaxAge   time.Duration
	// ContentDate is the high-water mark's content date; zero when no run
	// named the source with a date.
	ContentDate time.Time
	// Stale: undated, or the content date is older than MaxAge.
	Stale bool
	// StaleSince is ContentDate plus MaxAge; zero when undated.
	StaleSince time.Time
	// LastVerdict is the verdict of the latest run naming the source;
	// empty when no run named it.
	LastVerdict SourceStatus
	// Probation after a mark reset, with the pre-reset mark.
	Probation    bool
	PreResetDate time.Time
	PreResetSeq  *int64
}

// FeedStatuses returns the state of every listed source, in source list
// order. The list is NOS's own, so the result is bounded by it.
func (s *Store) FeedStatuses(ctx context.Context) ([]FeedState, error) {
	now := s.now().UTC()
	out := make([]FeedState, 0, len(s.order))
	for _, id := range s.order {
		src := s.sources[id]
		fs := FeedState{SourceID: id, MaxAge: src.MaxAge}
		m, found, err := loadMark(ctx, s.db, id)
		if err != nil {
			return nil, fmt.Errorf("vulnstore: feed status %s: %w", id, err)
		}
		if found {
			if m.date.Valid {
				fs.ContentDate = fromUnix(m.date.Int64)
			}
			fs.Probation = m.probation
			if m.preDate.Valid {
				fs.PreResetDate = fromUnix(m.preDate.Int64)
			}
			if m.preSeq.Valid {
				v := m.preSeq.Int64
				fs.PreResetSeq = &v
			}
		}
		_, st, _, _, named, err := latestNaming(ctx, s.db, id)
		if err != nil {
			return nil, fmt.Errorf("vulnstore: feed status %s: %w", id, err)
		}
		if named {
			fs.LastVerdict = st
		}
		if fs.ContentDate.IsZero() {
			fs.Stale = true
		} else {
			fs.StaleSince = fs.ContentDate.Add(src.MaxAge)
			fs.Stale = now.After(fs.StaleSince) || now.Equal(fs.StaleSince)
		}
		out = append(out, fs)
	}
	return out, nil
}

// LastComplete returns when the last run completed; zero when none did.
func (s *Store) LastComplete(ctx context.Context) (time.Time, error) {
	var at sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(ended_at) FROM vuln_runs WHERE state = 'completed'`).Scan(&at)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, fmt.Errorf("vulnstore: last complete: %w", err)
	}
	if !at.Valid {
		return time.Time{}, nil
	}
	return fromUnix(at.Int64), nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// MaxListFindings bounds one List or RunAlertFindings read.
const MaxListFindings = 200_000

// ListQuery scopes a List read.
type ListQuery struct {
	// VulnID limits the read to one vulnerability ID; empty for all.
	VulnID string
	// Subject limits the read to one subject; nil for all.
	Subject *Subject
	// Limit is the most findings returned, 1 to MaxListFindings.
	Limit int
}

// List returns at most q.Limit findings in key order and whether more
// matched. It is the read behind the findings pages and the admin export.
func (s *Store) List(ctx context.Context, q ListQuery) ([]Finding, bool, error) {
	if q.Limit <= 0 || q.Limit > MaxListFindings {
		return nil, false, fmt.Errorf("vulnstore: list: limit %d: %w", q.Limit, ErrInvalidInput)
	}
	where, args := "1 = 1", []any{}
	if q.VulnID != "" {
		where += ` AND json_extract(record, '$.vuln.id') = ?`
		args = append(args, q.VulnID)
	}
	if q.Subject != nil {
		where += ` AND subject = ?`
		args = append(args, q.Subject.String())
	}
	args = append(args, q.Limit+1)
	fs, err := queryFindings(ctx, s.db, `SELECT `+findingColumns+` FROM vuln_findings WHERE `+where+` ORDER BY finding_key LIMIT ?`, args...)
	if err != nil {
		return nil, false, err
	}
	if len(fs) > q.Limit {
		return fs[:q.Limit], true, nil
	}
	return fs, false, nil
}

// RunAlertFindings returns at most limit open findings that run runID wrote
// last (state_run_seq) and that are KEV-listed or in the critical tier in
// their episode: the candidates for vuln.kev_new and vuln.critical_new
// (ADR 0011 D9). The notifier de-duplicates; this read only bounds the
// input. ErrRunNotFound for an unknown run.
func (s *Store) RunAlertFindings(ctx context.Context, runID string, limit int) ([]Finding, error) {
	return s.RunAlertFindingsAfter(ctx, runID, nil, limit)
}

// RunAlertFindingsAfter is RunAlertFindings starting after the finding key
// after (nil: from the first key), so a caller can page through every
// candidate of a run in key order, limit at a time.
func (s *Store) RunAlertFindingsAfter(ctx context.Context, runID string, after *vulnfinding.Key, limit int) ([]Finding, error) {
	if limit <= 0 || limit > MaxListFindings {
		return nil, fmt.Errorf("vulnstore: run alert findings: limit %d: %w", limit, ErrInvalidInput)
	}
	r, err := loadRun(ctx, s.db, runID)
	if err != nil {
		return nil, fmt.Errorf("vulnstore: run alert findings: %w", err)
	}
	where, args := `state = 'open' AND state_run_seq = ?`, []any{r.seq}
	if after != nil {
		where += ` AND finding_key > ?`
		args = append(args, after[:])
	}
	args = append(args, int(TierCritical), limit)
	return queryFindings(ctx, s.db, `SELECT `+findingColumns+` FROM vuln_findings WHERE `+where+`
		AND (episode_kev_date IS NOT NULL OR episode_peak_tier = ? OR json_extract(record, '$.scores.kev') IS NOT NULL)
		ORDER BY finding_key LIMIT ?`, args...)
}

// MaxSubjectStatuses bounds one SubjectStatuses read.
const MaxSubjectStatuses = 5_000

// subjectStatusChunk is how many subjects one SubjectStatuses query binds
// (below SQLite's bound-parameter limit).
const subjectStatusChunk = 500

// SubjectStatuses is SubjectStatus for up to MaxSubjectStatuses subjects in
// a few bounded queries instead of one per subject. Every requested
// subject is in the result (NotAssessed without a watermark).
func (s *Store) SubjectStatuses(ctx context.Context, subjects []Subject) (map[Subject]SubjectStatus, error) {
	if len(subjects) > MaxSubjectStatuses {
		return nil, fmt.Errorf("vulnstore: subject statuses: %d subjects: %w", len(subjects), ErrInvalidInput)
	}
	now := s.now().UTC()
	out := make(map[Subject]SubjectStatus, len(subjects))
	byKey := make(map[string]Subject, len(subjects))
	for _, subj := range subjects {
		out[subj] = SubjectStatus{Assessment: NotAssessed}
		byKey[subj.String()] = subj
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	for start := 0; start < len(keys); start += subjectStatusChunk {
		chunk := keys[start:min(start+subjectStatusChunk, len(keys))]
		args := make([]any, len(chunk))
		for i, k := range chunk {
			args[i] = k
		}
		rows, err := s.db.QueryContext(ctx, `SELECT subject, completed_at FROM vuln_subject_watermarks WHERE subject IN (?`+
			strings.Repeat(", ?", len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("vulnstore: subject statuses: %w", err)
		}
		for rows.Next() {
			var key string
			var at int64
			if err := rows.Scan(&key, &at); err != nil {
				rows.Close()
				return nil, fmt.Errorf("vulnstore: subject statuses: %w", err)
			}
			subj, ok := byKey[key]
			if !ok {
				continue
			}
			st := SubjectStatus{Assessment: Fresh, LastComplete: fromUnix(at)}
			if now.Sub(st.LastComplete) > StaleAfter {
				st.Assessment = Stale
			}
			out[subj] = st
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("vulnstore: subject statuses: %w", err)
		}
	}
	return out, nil
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
	// Seen: a run named the source or it has a high-water mark. A source
	// never seen is stale (undated) but has never reported, so it is "not
	// yet seen" rather than a feed that stopped (vuln.feed_stale skips it).
	Seen bool
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
// order. The list is NOS's own, so the result is bounded by it. All of it
// is read in one read transaction (one snapshot): a run start committing
// meanwhile must not show a source as named but without its mark (a false
// "stale, undated").
func (s *Store) FeedStatuses(ctx context.Context) ([]FeedState, error) {
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("vulnstore: feed status: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // read-only; nothing to keep
	out := make([]FeedState, 0, len(s.order))
	for _, id := range s.order {
		src := s.sources[id]
		fs := FeedState{SourceID: id, MaxAge: src.MaxAge}
		m, found, err := loadMark(ctx, tx, id)
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
		_, st, _, _, named, err := latestNaming(ctx, tx, id)
		if err != nil {
			return nil, fmt.Errorf("vulnstore: feed status %s: %w", id, err)
		}
		if named {
			fs.LastVerdict = st
		}
		fs.Seen = found || named
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

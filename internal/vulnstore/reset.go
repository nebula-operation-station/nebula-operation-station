// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// MarkResetView is what an admin sees before resetting a source's
// high-water mark (D5): the current mark, the value the latest run that
// named the source regressed reported, and the last accepted snapshot.
type MarkResetView struct {
	SourceID string
	MarkDate time.Time
	MarkSeq  *int64
	// RunID is the latest run that named the source, if its verdict on it
	// was regressed; empty when no run named the source or the latest one
	// did not regress it (nothing to reset to).
	RunID        string
	ReportedDate time.Time
	ReportedSeq  *int64
	// LastAcceptedSnapshot is the snapshot ID of the latest run that
	// accepted the source.
	LastAcceptedSnapshot string
	// Probation and the pre-reset mark that ends it.
	Probation    bool
	PreResetDate time.Time
	PreResetSeq  *int64
}

// MarkResetRequest resets one listed source's mark down to exactly the
// value RunID reported. The caller has checked that the actor is an admin
// with a fresh WebAuthn assertion (Q4); the hermes-vuln token and API
// scopes never reach this method.
type MarkResetRequest struct {
	SourceID    string
	RunID       string
	ContentDate time.Time
	Sequence    *int64
	Admin       string
	// Reason is required: at most MaxHumanReason bytes of valid UTF-8.
	Reason string
}

// MarkReset is an applied reset. ResetMark has already written its
// AuditVulnMarkReset line in the reset's transaction; the caller raises
// the vuln.feed_mark_reset event from it.
type MarkReset struct {
	SourceID     string
	RunID        string
	Admin        string
	Reason       string
	OldDate      time.Time
	OldSeq       *int64
	NewDate      time.Time
	NewSeq       *int64
	PreResetDate time.Time
	PreResetSeq  *int64
	At           time.Time
}

type markRow struct {
	date, seq, preDate, preSeq sql.NullInt64
	probation                  bool
}

func loadMark(ctx context.Context, q queryer, sourceID string) (markRow, bool, error) {
	var m markRow
	var p int
	err := q.QueryRowContext(ctx, `SELECT content_date, sequence, probation, pre_reset_date, pre_reset_sequence FROM vuln_source_marks WHERE source_id = ?`,
		sourceID).Scan(&m.date, &m.seq, &p, &m.preDate, &m.preSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return markRow{}, false, nil
	}
	if err != nil {
		return markRow{}, false, fmt.Errorf("read mark: %w", err)
	}
	m.probation = p == 1
	return m, true, nil
}

// latestNaming returns the latest run (by run_seq) that named the source,
// whatever its verdict, with that verdict and the values it reported. D5
// lets an admin reset only to what this run reported and only if it
// regressed the source: an older regressed run's value could lower the
// mark below data NOS accepted from a later run.
func latestNaming(ctx context.Context, q queryer, sourceID string) (runID string, status SourceStatus, date, seq sql.NullInt64, found bool, err error) {
	var st string
	err = q.QueryRowContext(ctx, `SELECT s.run_id, s.status, s.content_date, s.sequence FROM vuln_run_sources s JOIN vuln_runs r ON r.id = s.run_id
		WHERE s.source_id = ? ORDER BY r.run_seq DESC LIMIT 1`, sourceID).Scan(&runID, &st, &date, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", date, seq, false, nil
	}
	if err != nil {
		return "", "", date, seq, false, fmt.Errorf("latest run naming source: %w", err)
	}
	return runID, SourceStatus(st), date, seq, true, nil
}

func timeOf(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return fromUnix(v.Int64)
}

func ptrOf(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	x := v.Int64
	return &x
}

func nullOf(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

// MarkResetCandidate returns the admin's view of a listed source's mark.
func (s *Store) MarkResetCandidate(ctx context.Context, sourceID string) (MarkResetView, error) {
	if _, listed := s.sources[sourceID]; !listed {
		return MarkResetView{}, fmt.Errorf("vulnstore: mark reset view: source not listed: %w", ErrInvalidInput)
	}
	v := MarkResetView{SourceID: sourceID}
	m, ok, err := loadMark(ctx, s.db, sourceID)
	if err != nil {
		return MarkResetView{}, fmt.Errorf("vulnstore: mark reset view %s: %w", sourceID, err)
	}
	if ok {
		v.MarkDate, v.MarkSeq = timeOf(m.date), ptrOf(m.seq)
		v.Probation, v.PreResetDate, v.PreResetSeq = m.probation, timeOf(m.preDate), ptrOf(m.preSeq)
	}
	runID, status, date, seq, found, err := latestNaming(ctx, s.db, sourceID)
	if err != nil {
		return MarkResetView{}, fmt.Errorf("vulnstore: mark reset view %s: %w", sourceID, err)
	}
	if found && status == SourceRegressed {
		v.RunID, v.ReportedDate, v.ReportedSeq = runID, timeOf(date), ptrOf(seq)
	}
	err = s.db.QueryRowContext(ctx, `SELECT s.snapshot_id FROM vuln_run_sources s JOIN vuln_runs r ON r.id = s.run_id
		WHERE s.source_id = ? AND s.status = 'accepted' ORDER BY r.run_seq DESC LIMIT 1`, sourceID).Scan(&v.LastAcceptedSnapshot)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MarkResetView{}, fmt.Errorf("vulnstore: mark reset view %s: last accepted: %w", sourceID, err)
	}
	return v, nil
}

// ResetMark applies the D5 admin reset of a per-source high-water mark. It
// is refused (ErrResetRefused) unless the source is listed and has a mark,
// RunID is the latest run that named the source and regressed it (a later
// run naming it with any other verdict, accepted included, leaves nothing
// to reset to until a newer run regresses it), the
// requested value equals exactly what that run reported, the value is
// below the mark in at least one component and above it in none, and its
// date is not beyond NOS's clock plus MaxFutureSkew. The source then stays
// on probation until a run names it strictly above the pre-reset mark (a
// second reset during probation keeps the higher pre-reset mark). The reset
// applies to run starts after it; verdicts of runs already started stay.
// The reset and its AuditVulnMarkReset line are written in one transaction
// of audit (required): both or neither.
func (s *Store) ResetMark(ctx context.Context, req MarkResetRequest, audit DecisionAuditor) (MarkReset, error) {
	if audit == nil {
		return MarkReset{}, fmt.Errorf("vulnstore: mark reset: auditor is required: %w", ErrInvalidInput)
	}
	now := s.now().UTC()
	if err := checkActor(req.Admin); err != nil {
		return MarkReset{}, fmt.Errorf("vulnstore: mark reset: %w", err)
	}
	if err := checkReason(req.Reason); err != nil {
		return MarkReset{}, fmt.Errorf("vulnstore: mark reset: %w", err)
	}
	if _, listed := s.sources[req.SourceID]; !listed {
		return MarkReset{}, fmt.Errorf("vulnstore: mark reset: source not listed: %w", ErrResetRefused)
	}
	var out MarkReset
	err := s.decisionTx(ctx, audit, func(tx *sql.Tx, appendLine func(string, map[string]string) error) error {
		var err error
		out, err = s.resetMark(ctx, tx, req, now)
		if err != nil {
			return err
		}
		return appendDecision(appendLine, AuditVulnMarkReset, req.Admin, markResetAttrs(out))
	})
	if err != nil {
		return MarkReset{}, fmt.Errorf("vulnstore: mark reset %s: %w", req.SourceID, err)
	}
	return out, nil
}

// resetMark checks and applies req through tx.
func (s *Store) resetMark(ctx context.Context, tx *sql.Tx, req MarkResetRequest, now time.Time) (MarkReset, error) {
	m, ok, err := loadMark(ctx, tx, req.SourceID)
	if err != nil {
		return MarkReset{}, err
	}
	if !ok || !m.date.Valid {
		return MarkReset{}, fmt.Errorf("no mark: %w", ErrResetRefused)
	}
	runID, status, repDate, repSeq, found, err := latestNaming(ctx, tx, req.SourceID)
	if err != nil {
		return MarkReset{}, err
	}
	if !found || runID != req.RunID {
		return MarkReset{}, fmt.Errorf("not the latest run naming the source: %w", ErrResetRefused)
	}
	if status != SourceRegressed {
		return MarkReset{}, fmt.Errorf("latest run naming the source did not regress it: %w", ErrResetRefused)
	}
	reqSeq := nullOf(req.Sequence)
	if req.ContentDate.IsZero() || !repDate.Valid || unix(req.ContentDate) != repDate.Int64 || reqSeq != repSeq {
		return MarkReset{}, fmt.Errorf("value not reported by that run: %w", ErrResetRefused)
	}
	if req.ContentDate.After(now.Add(MaxFutureSkew)) {
		return MarkReset{}, fmt.Errorf("value in the future: %w", ErrResetRefused)
	}
	newDate := repDate.Int64
	dateAbove := newDate > m.date.Int64
	seqAbove := repSeq.Valid && m.seq.Valid && repSeq.Int64 > m.seq.Int64
	lowers := newDate < m.date.Int64 || m.seq.Valid && (!repSeq.Valid || repSeq.Int64 < m.seq.Int64)
	if dateAbove || seqAbove || !lowers {
		return MarkReset{}, fmt.Errorf("not below the mark: %w", ErrResetRefused)
	}

	// The pre-reset mark probation must pass: the mark just before this
	// reset, or the higher one kept by an earlier reset still in probation.
	preDate, preSeq := m.date, m.seq
	if m.probation {
		preDate = maxNull(preDate, m.preDate)
		preSeq = maxNull(preSeq, m.preSeq)
	}
	n := unix(now)
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_source_marks SET content_date = ?, sequence = ?, probation = 1,
		pre_reset_date = ?, pre_reset_sequence = ?, updated_at = ? WHERE source_id = ?`,
		newDate, repSeq, preDate, preSeq, n, req.SourceID); err != nil {
		return MarkReset{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_mark_resets (source_id, run_id, admin, reason, old_date, old_sequence,
		new_date, new_sequence, pre_reset_date, pre_reset_sequence, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.SourceID, runID, req.Admin, req.Reason, m.date, m.seq, newDate, repSeq, preDate, preSeq, n); err != nil {
		return MarkReset{}, fmt.Errorf("record: %w", err)
	}
	return MarkReset{
		SourceID: req.SourceID, RunID: runID, Admin: req.Admin, Reason: req.Reason,
		OldDate: timeOf(m.date), OldSeq: ptrOf(m.seq),
		NewDate: fromUnix(newDate), NewSeq: ptrOf(repSeq),
		PreResetDate: timeOf(preDate), PreResetSeq: ptrOf(preSeq),
		At: fromUnix(n),
	}, nil
}

// markResetAttrs are the audit attributes of an applied reset.
func markResetAttrs(r MarkReset) map[string]string {
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339)
	}
	seq := func(p *int64) string {
		if p == nil {
			return ""
		}
		return strconv.FormatInt(*p, 10)
	}
	return map[string]string{
		"source_id":          r.SourceID,
		"run_id":             r.RunID,
		"reason":             r.Reason,
		"old_date":           ts(r.OldDate),
		"old_sequence":       seq(r.OldSeq),
		"new_date":           ts(r.NewDate),
		"new_sequence":       seq(r.NewSeq),
		"pre_reset_date":     ts(r.PreResetDate),
		"pre_reset_sequence": seq(r.PreResetSeq),
	}
}

func maxNull(a, b sql.NullInt64) sql.NullInt64 {
	switch {
	case !a.Valid:
		return b
	case !b.Valid:
		return a
	case b.Int64 > a.Int64:
		return b
	}
	return a
}

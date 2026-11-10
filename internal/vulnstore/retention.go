// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PruneResult counts what Prune removed.
type PruneResult struct {
	// ResumedRuns: runs left completing that Prune finished.
	ResumedRuns       int
	AbortedRuns       int
	DeletedFindings   int
	ClearedAssessment int
	DeletedRuns       int
	DeletedHistory    int
}

// Prune applies the D6 retention (Q3): fixed findings are deleted 365 days
// after closing, the assessment text of closed findings is removed after
// 90 days, and run records (with their sources, batches, coverage and
// holds) are deleted 90 days after they ended. Open, accepted_risk and
// false_positive findings are kept while the subject exists; they leave
// only through closure path 3 and then the fixed retention. Runs left
// completing are finished (ResumeCompleting) and runs past their time
// limit are aborted first; a run that fails to finish does not stop the
// retention, its error is returned with the result.
//
// Prune is the periodic sweep, one call for all of it. The store does not
// call it by itself and has no timer; cmd/nebula-server calls it every 15
// minutes with a 10 minute deadline and logs an error with the counts.
// The caller must:
//
//   - call it at a fixed interval well below MaxRunDuration (an hour or
//     less), so a run its client left completing is finished within one
//     interval, and a forgotten run is aborted within one interval after
//     its time limit;
//   - not overlap calls on purpose (concurrent calls are safe: the second
//     waits for the first and then finds little left to do);
//   - pass a context with a deadline: resuming completing runs can take
//     minutes and holds the store's complete lock, so a client Complete
//     for another run waits behind it; a context that ends stops the
//     sweep between apply transactions and leaves the run completing for
//     the next call (TestSweepDeadlineLeavesCompletingRunResumable);
//   - treat an error as "retry at the next interval" (log it with the
//     counts of the result, which are valid with it).
func (s *Store) Prune(ctx context.Context) (PruneResult, error) {
	var res PruneResult
	resumed, rerr := s.ResumeCompleting(ctx)
	res.ResumedRuns = resumed
	n, err := s.abortExpiredRuns(ctx)
	if err != nil {
		return res, errors.Join(err, rerr)
	}
	res.AbortedRuns = n
	res, err = s.prune(ctx, res)
	return res, errors.Join(err, rerr)
}

// prune applies the retention steps of Prune in one write transaction.
func (s *Store) prune(ctx context.Context, res PruneResult) (PruneResult, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return res, fmt.Errorf("vulnstore: prune: %w", err)
	}
	defer tx.Rollback()
	steps := []struct {
		dst   *int
		query string
		arg   int64
	}{
		{&res.DeletedFindings, `DELETE FROM vuln_findings WHERE state = 'fixed' AND closed_at <= ?`, unix(now.Add(-RetainFixed))},
		{&res.ClearedAssessment, `UPDATE vuln_findings SET assessment = NULL WHERE state = 'fixed' AND closed_at <= ? AND assessment IS NOT NULL`,
			unix(now.Add(-RetainClosedAssessment))},
		{&res.DeletedRuns, `DELETE FROM vuln_runs WHERE state <> 'running' AND ended_at <= ?`, unix(now.Add(-RetainRuns))},
		// History older than the fixed retention: far past the guard
		// window, which reads only the last WindowGuardSpan.
		{&res.DeletedHistory, `DELETE FROM vuln_finding_history WHERE at <= ?`, unix(now.Add(-RetainFixed))},
	}
	for _, st := range steps {
		r, err := tx.ExecContext(ctx, st.query, st.arg)
		if err != nil {
			return res, fmt.Errorf("vulnstore: prune: %w", err)
		}
		k, _ := r.RowsAffected()
		*st.dst = int(k)
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("vulnstore: prune: commit: %w", err)
	}
	return res, nil
}

// Assessment is a subject's assessment status (D6 staleness).
type Assessment int

// Assessment statuses. None of them means "0 findings" or green.
const (
	// NotAssessed: no complete run ever covered the subject.
	NotAssessed Assessment = iota + 1
	// Stale: the last complete run is older than StaleAfter.
	Stale
	// Fresh: a complete run covered the subject within StaleAfter.
	Fresh
)

// SubjectStatus is the staleness of one subject.
type SubjectStatus struct {
	Assessment Assessment
	// LastComplete is when the last complete run covering the subject
	// completed ("stale since" = LastComplete + StaleAfter).
	LastComplete time.Time
}

// SubjectStatus returns whether the subject was assessed and how fresh.
func (s *Store) SubjectStatus(ctx context.Context, subj Subject) (SubjectStatus, error) {
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT completed_at FROM vuln_subject_watermarks WHERE subject = ?`, subj.String()).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return SubjectStatus{Assessment: NotAssessed}, nil
	}
	if err != nil {
		return SubjectStatus{}, fmt.Errorf("vulnstore: subject status: %w", err)
	}
	st := SubjectStatus{Assessment: Fresh, LastComplete: fromUnix(at)}
	if s.now().UTC().Sub(st.LastComplete) > StaleAfter {
		st.Assessment = Stale
	}
	return st, nil
}

// HermesOffline reports whether no run completed within StaleAfter (D6:
// one notification, raised by the caller). last is zero when no run ever
// completed.
func (s *Store) HermesOffline(ctx context.Context) (offline bool, last time.Time, err error) {
	var at sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(ended_at) FROM vuln_runs WHERE state = 'completed'`).Scan(&at); err != nil {
		return false, time.Time{}, fmt.Errorf("vulnstore: hermes offline: %w", err)
	}
	if !at.Valid {
		return true, time.Time{}, nil
	}
	last = fromUnix(at.Int64)
	return s.now().UTC().Sub(last) > StaleAfter, last, nil
}

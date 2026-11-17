// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"context"
	"fmt"
)

// PruneResult counts what Prune did.
type PruneResult struct {
	// AbortedRuns: running runs past MaxRunDuration that Prune aborted.
	AbortedRuns int
	// ClearedRecords: resolved findings whose record text was cleared.
	ClearedRecords int
	// DeletedFindings: resolved findings past RetainResolved.
	DeletedFindings int
	// DeletedRuns: finished runs past RetainRuns.
	DeletedRuns int
}

// Prune applies the retention of D9 (ADR 0011 D6 pattern): overdue runs are
// aborted; record text of resolved findings is cleared 90 days after
// closing; resolved findings are deleted 365 days after closing; finished
// runs are deleted 90 days after they ended. Open, expected_pending and
// accepted findings are kept. The store has no timer: the caller runs Prune
// periodically, with a context that has a deadline.
func (s *Store) Prune(ctx context.Context) (PruneResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	nowUnix := unix(now)
	tx, err := s.writeTx(ctx)
	if err != nil {
		return PruneResult{}, err
	}
	defer tx.Rollback()
	var res PruneResult
	steps := []struct {
		dst   *int
		query string
		args  []any
	}{
		{&res.AbortedRuns, `UPDATE integrity_runs SET state = 'aborted', ended_at = ? WHERE state = 'running' AND started_at < ?`,
			[]any{nowUnix, cutoff(nowUnix)}},
		{&res.ClearedRecords, `UPDATE integrity_findings SET old_record = '', new_record = ''
			WHERE state = 'resolved' AND closed_at <= ? AND (old_record <> '' OR new_record <> '')`,
			[]any{unix(now.Add(-RetainRecords))}},
		{&res.DeletedFindings, `DELETE FROM integrity_findings WHERE state = 'resolved' AND closed_at <= ?`,
			[]any{unix(now.Add(-RetainResolved))}},
		{&res.DeletedRuns, `DELETE FROM integrity_runs WHERE state <> 'running' AND ended_at <= ?`,
			[]any{unix(now.Add(-RetainRuns))}},
	}
	for _, st := range steps {
		r, err := tx.ExecContext(ctx, st.query, st.args...)
		if err != nil {
			return PruneResult{}, fmt.Errorf("integritystore: prune: %w", err)
		}
		k, _ := r.RowsAffected()
		*st.dst = int(k)
	}
	if err := tx.Commit(); err != nil {
		return PruneResult{}, fmt.Errorf("integritystore: prune: commit: %w", err)
	}
	return res, nil
}

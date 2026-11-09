// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// HistoryEvent is one entry kind of a finding's history.
type HistoryEvent string

// History events. Opened, reopened, closed, human_set and human_reopened
// are state changes; kev_dropped and tier_fell record a drop an applied
// record made inside an episode (D5 episode high-water marks).
const (
	EventOpened        HistoryEvent = "opened"
	EventReopened      HistoryEvent = "reopened"
	EventClosed        HistoryEvent = "closed"
	EventHumanSet      HistoryEvent = "human_set"
	EventHumanReopened HistoryEvent = "human_reopened"
	EventKEVDropped    HistoryEvent = "kev_dropped"
	EventTierFell      HistoryEvent = "tier_fell"
)

// HistoryEntry is one row of a finding's history.
type HistoryEntry struct {
	Event HistoryEvent
	At    time.Time
	// RunSeq is the run that caused it; 0 for NOS's own or admin actions.
	RunSeq int64
	// ClosedBy is set for EventClosed.
	ClosedBy ClosedBy
}

// stateChange returns (was_open, is_open) of a state change event; ok is
// false for drop events.
func stateChange(ev HistoryEvent, wasOpen bool) (was, is int, ok bool) {
	switch ev {
	case EventOpened, EventReopened, EventHumanReopened:
		return 0, 1, true
	case EventClosed:
		return boolInt(wasOpen), 0, true
	case EventHumanSet:
		return 1, 0, true
	}
	return 0, 0, false
}

// logHistory appends one history row. wasOpen matters only for
// EventClosed (subject removal also closes human states). runSeq 0 is
// stored as NULL.
func logHistory(ctx context.Context, tx *sql.Tx, key vulnfinding.Key, subject string, at int64, runSeq int64, ev HistoryEvent, wasOpen bool, by ClosedBy) error {
	var was, is, rs, cb any
	if w, i, ok := stateChange(ev, wasOpen); ok {
		was, is = w, i
	}
	if runSeq > 0 {
		rs = runSeq
	}
	if ev == EventClosed {
		cb = string(by)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_finding_history (finding_key, subject, at, run_seq, event, was_open, is_open, closed_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, key[:], subject, at, rs, string(ev), was, is, cb); err != nil {
		return fmt.Errorf("history %s: %w", ev, err)
	}
	return nil
}

// History returns a finding's history, oldest first.
func (s *Store) History(ctx context.Context, key vulnfinding.Key) ([]HistoryEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event, at, run_seq, closed_by FROM vuln_finding_history WHERE finding_key = ? ORDER BY id`, key[:])
	if err != nil {
		return nil, fmt.Errorf("vulnstore: history: %w", err)
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var ev string
		var at int64
		var rs sql.NullInt64
		var by sql.NullString
		if err := rows.Scan(&ev, &at, &rs, &by); err != nil {
			return nil, fmt.Errorf("vulnstore: history: %w", err)
		}
		out = append(out, HistoryEntry{Event: HistoryEvent(ev), At: fromUnix(at), RunSeq: rs.Int64, ClosedBy: ClosedBy(by.String)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnstore: history: %w", err)
	}
	return out, nil
}

// windowView is the window guard's view of one subject (D5): its
// baseline (findings open at the window start) and the baseline findings
// whose unevidenced closure was already applied inside the window.
type windowView struct {
	base    int
	applied map[vulnfinding.Key]bool
	// firstWasOpen holds, per finding with a state change inside the
	// window, whether its first such change left 'open'.
	firstWasOpen map[vulnfinding.Key]bool
}

// inBaseline reports whether a finding that is open now was open at the
// window start.
func (w windowView) inBaseline(k vulnfinding.Key) bool {
	was, changed := w.firstWasOpen[k]
	return !changed || was
}

// loadWindow builds the window view of subject for a window starting at
// winStart. It reads the persisted history, so re-opening and re-closing a
// finding inside the window neither removes it from the baseline nor
// uncounts its earlier closure.
func loadWindow(ctx context.Context, q queryer, subject string, winStart int64) (windowView, error) {
	w := windowView{applied: map[vulnfinding.Key]bool{}, firstWasOpen: map[vulnfinding.Key]bool{}}
	rows, err := q.QueryContext(ctx, `SELECT finding_key, was_open, closed_by FROM vuln_finding_history
		WHERE subject = ? AND at > ? AND was_open IS NOT NULL ORDER BY id`, subject, winStart)
	if err != nil {
		return w, fmt.Errorf("window history: %w", err)
	}
	defer rows.Close()
	unevidenced := map[vulnfinding.Key]bool{}
	for rows.Next() {
		var kb []byte
		var was int
		var by sql.NullString
		if err := rows.Scan(&kb, &was, &by); err != nil {
			return w, fmt.Errorf("window history: %w", err)
		}
		var k vulnfinding.Key
		if len(kb) != len(k) {
			return w, fmt.Errorf("window history: key length %d", len(kb))
		}
		copy(k[:], kb)
		if _, seen := w.firstWasOpen[k]; !seen {
			w.firstWasOpen[k] = was == 1
		}
		if ClosedBy(by.String) == ClosedByHermesUnconfirmed || ClosedBy(by.String) == ClosedByAdminConfirmed {
			unevidenced[k] = true
		}
	}
	if err := rows.Err(); err != nil {
		return w, fmt.Errorf("window history: %w", err)
	}
	for k, was := range w.firstWasOpen {
		if was {
			w.base++
			if unevidenced[k] {
				w.applied[k] = true
			}
		}
	}
	var untouched int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM vuln_findings f WHERE f.subject = ? AND f.state = 'open'
		AND NOT EXISTS (SELECT 1 FROM vuln_finding_history h WHERE h.finding_key = f.finding_key AND h.at > ? AND h.was_open IS NOT NULL)`,
		subject, winStart).Scan(&untouched); err != nil {
		return w, fmt.Errorf("window baseline: %w", err)
	}
	w.base += untouched
	return w, nil
}

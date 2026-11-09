// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// HoldReason says why a run closure was held for an admin.
type HoldReason string

// Hold reasons.
const (
	HoldContradicted   HoldReason = "contradicted"
	HoldKEVOrCritical  HoldReason = "kev_or_critical"
	HoldRunGuard       HoldReason = "run_guard"
	HoldWindowGuard    HoldReason = "window_guard"
	HoldClassifyFailed HoldReason = "classify_failed"
	// HoldProbation: a basis source is on probation after a mark reset.
	HoldProbation HoldReason = "probation"
)

// Completion reports what completing a run did. It holds counts only.
type Completion struct {
	// ClosedEvidenced: closed as fixed by nos_inventory (path 4).
	ClosedEvidenced int `json:"closed_evidenced"`
	// ClosedUnconfirmed: closed as fixed by hermes_unconfirmed (path 5).
	ClosedUnconfirmed int `json:"closed_unconfirmed"`
	// Held: closures held for an admin, by reason.
	Held map[HoldReason]int `json:"held,omitempty"`
	// NotRequested: omitted or not_affected findings whose closure this
	// run cannot request: a basis source not accepted, stale or undated
	// (path 5d). Not held and not counted by the guards.
	NotRequested int `json:"not_requested"`
	// BlockedRejected: closures blocked by a rejected record of the key.
	BlockedRejected int `json:"blocked_rejected"`
	// SubjectsBelowWatermark: covered subjects a newer complete run
	// already covered; this run closed nothing there.
	SubjectsBelowWatermark int `json:"subjects_below_watermark"`
	// Superseded: closures dropped because the finding changed meanwhile.
	Superseded int `json:"superseded"`
	// BatchRejected: a batch was rejected as a whole; no closures at all.
	BatchRejected bool `json:"batch_rejected"`
	// RunGuard and WindowGuard report a tripped guard.
	RunGuard    bool `json:"run_guard"`
	WindowGuard bool `json:"window_guard"`
}

// candidate is one requested run closure.
type candidate struct {
	f      Finding
	class  Class
	hold   HoldReason
	inWin  bool // in the window baseline and not yet counted as applied
	counts bool // unevidenced: counted by the guards
}

// subjectPlan is the closure plan of one covered subject.
type subjectPlan struct {
	subject string
	scope   int // run guard scope
	base    int // window guard baseline: open at the window start
	applied int // baseline findings with an unevidenced closure applied in the window
	cands   []candidate
}

// Complete completes a run. Only a completed run requests run closures:
// for each subject it fully covered, open findings it omitted or reported
// not_affected. Closures are planned, the guards are checked, the closures
// are applied (re-checking each subject's coverage watermark and each
// finding's state_run_seq and revision), the run is marked completed and
// the completion is saved, all in one transaction. A context ending
// part-way therefore rolls everything back: the run stays running and a
// retry plans again from the same state. Once Complete has returned,
// CompletionOf returns the saved completion.
func (s *Store) Complete(ctx context.Context, runID string) (Completion, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.writeTx(ctx)
	if err != nil {
		return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
	}
	defer tx.Rollback()
	run, err := loadRun(ctx, tx, runID)
	if err != nil {
		return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
	}
	if err := s.checkRunning(ctx, tx, run, now); err != nil {
		if errors.Is(err, ErrRunExpired) {
			if cerr := tx.Commit(); cerr != nil {
				return Completion{}, fmt.Errorf("vulnstore: complete: commit abort: %w", cerr)
			}
		}
		return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
	}
	comp := Completion{Held: map[HoldReason]int{}, BatchRejected: run.rejected}
	if !run.rejected {
		plans, err := s.planClosures(ctx, tx, run, now, &comp)
		if err != nil {
			return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
		}
		applyGuards(plans, &comp)
		for _, p := range plans {
			if err := applySubject(ctx, tx, run, p, now, &comp); err != nil {
				return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
			}
		}
	}
	if err := saveCompletion(ctx, tx, run, comp, now); err != nil {
		return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Completion{}, fmt.Errorf("vulnstore: complete: commit: %w", err)
	}
	return comp, nil
}

// CompletionOf returns the saved completion of a completed run that
// tokenID started, so that a retried complete gets the same answer after
// the caller lost its own record of it (restart, eviction). A run of
// another token is ErrRunNotFound; a run that is running, aborted or has
// no saved completion is ErrRunNotRunning.
func (s *Store) CompletionOf(ctx context.Context, runID, tokenID string) (Completion, error) {
	run, err := loadRun(ctx, s.db, runID)
	if err != nil {
		return Completion{}, fmt.Errorf("vulnstore: completion: %w", err)
	}
	if run.tokenID != tokenID {
		return Completion{}, fmt.Errorf("vulnstore: completion: %w", ErrRunNotFound)
	}
	rep := parseReport(run.reportRaw)
	if run.state != "completed" || rep.Completion == nil {
		return Completion{}, fmt.Errorf("vulnstore: completion: %w", ErrRunNotRunning)
	}
	c := *rep.Completion
	if c.Held == nil {
		c.Held = map[HoldReason]int{}
	}
	return c, nil
}

// saveCompletion marks the run completed and saves the completion in its
// report, inside the caller's transaction.
func saveCompletion(ctx context.Context, tx *sql.Tx, run runRow, comp Completion, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_runs SET state = 'completed', ended_at = ?, superseded = superseded + ? WHERE id = ?`,
		unix(now), comp.Superseded, run.id); err != nil {
		return fmt.Errorf("mark completed: %w", err)
	}
	rep := parseReport(run.reportRaw)
	rep.Completion = &comp
	return saveReport(ctx, tx, run.id, rep)
}

// planClosures reads, per covered subject at or above its watermark, the
// requested closures and classifies them. It writes nothing.
func (s *Store) planClosures(ctx context.Context, tx *sql.Tx, run runRow, now time.Time, comp *Completion) ([]*subjectPlan, error) {
	sources, err := loadRunSources(ctx, tx, run.id)
	if err != nil {
		return nil, err
	}
	subjects, err := stringColumn(ctx, tx, `SELECT subject FROM vuln_run_subjects WHERE run_id = ? ORDER BY subject`, run.id)
	if err != nil {
		return nil, fmt.Errorf("covered subjects: %w", err)
	}
	winStart := unix(now.Add(-WindowGuardSpan))
	var plans []*subjectPlan
	for _, subj := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wm, err := watermark(ctx, tx, subj)
		if err != nil {
			return nil, err
		}
		if wm > run.seq {
			comp.SubjectsBelowWatermark++
			continue
		}
		p := &subjectPlan{subject: subj}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vuln_findings WHERE subject = ? AND state = 'open'
			AND state_run_seq <= ? AND episode_opened_at <= ? AND episode_opened_run_seq <> ?`,
			subj, run.seq, unix(run.started), run.seq).Scan(&p.scope); err != nil {
			return nil, fmt.Errorf("run guard scope: %w", err)
		}
		win, err := loadWindow(ctx, tx, subj, winStart)
		if err != nil {
			return nil, err
		}
		p.base, p.applied = win.base, len(win.applied)
		open, err := queryFindings(ctx, tx, `SELECT `+findingColumns+` FROM vuln_findings
			WHERE subject = ? AND state = 'open' AND state_run_seq <= ? ORDER BY finding_key`, subj, run.seq)
		if err != nil {
			return nil, err
		}
		for _, f := range open {
			c, ok, err := s.planOne(ctx, tx, run, sources, f, comp)
			if err != nil {
				return nil, err
			}
			if ok {
				// Counted by the window guard only when the finding is in
				// the baseline and not already counted as applied.
				c.inWin = win.inBaseline(f.Key) && !win.applied[f.Key]
				p.cands = append(p.cands, c)
			}
		}
		plans = append(plans, p)
	}
	return plans, nil
}

// planOne decides whether the run requests the closure of f and how it is
// classified (D5 closure classes and paths 4 and 5).
func (s *Store) planOne(ctx context.Context, tx *sql.Tx, run runRow, sources map[string]runSourceInfo, f Finding, comp *Completion) (candidate, bool, error) {
	var notAffected int
	err := tx.QueryRowContext(ctx, `SELECT not_affected FROM vuln_run_reported WHERE run_id = ? AND finding_key = ?`, run.id, f.Key[:]).Scan(&notAffected)
	switch {
	case err == nil && notAffected == 0:
		return candidate{}, false, nil // reported again: no closure
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return candidate{}, false, fmt.Errorf("reported: %w", err)
	}
	// Omitted, or reported not_affected: a closure request.
	var rejected int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vuln_run_rejected WHERE run_id = ? AND finding_key = ?`, run.id, f.Key[:]).Scan(&rejected); err != nil {
		return candidate{}, false, fmt.Errorf("rejected: %w", err)
	}
	if rejected > 0 {
		comp.BlockedRejected++ // precondition e, also for path 4
		return candidate{}, false, nil
	}
	class, cerr := s.classify.Classify(ctx, f)
	if cerr == nil && class == ClassEvidenced {
		return candidate{f: f, class: ClassEvidenced}, true, nil // path 4
	}
	if !basisCovered(f.Record, sources) {
		comp.NotRequested++ // precondition d: not requested, not held, not counted
		return candidate{}, false, nil
	}
	c := candidate{f: f, class: class, counts: true}
	switch {
	case cerr != nil:
		c.hold = HoldClassifyFailed
	case class == ClassContradicted:
		c.hold = HoldContradicted
	case class == ClassUnconfirmed || class == ClassUnconfirmedUnchanged:
		if f.EpisodeKEV() || f.EpisodePeakTier >= TierCritical {
			c.hold = HoldKEVOrCritical
		}
	default:
		c.hold = HoldClassifyFailed
	}
	if c.hold == "" && onProbation(f.Record, sources) {
		c.hold = HoldProbation // precondition 5g: held whatever the guards say
	}
	return c, true, nil
}

// onProbation: a basis source of the finding is on probation after a mark
// reset in this run.
func onProbation(r vulnfinding.Record, sources map[string]runSourceInfo) bool {
	for _, bs := range r.Evidence.BasisSources {
		if sources[bs.SourceID].probation {
			return true
		}
	}
	return false
}

// basisCovered: every basis source of the finding is named by the run,
// accepted (not regressed, invalid, unknown or undated) and not stale
// (path 5d).
func basisCovered(r vulnfinding.Record, sources map[string]runSourceInfo) bool {
	if len(r.Evidence.BasisSources) == 0 {
		return false
	}
	for _, bs := range r.Evidence.BasisSources {
		info, ok := sources[bs.SourceID]
		if !ok || info.status != SourceAccepted || info.stale {
			return false
		}
	}
	return true
}

// applyGuards checks the run guard and the window guard and holds every
// unevidenced closure of the run when either trips (D5).
func applyGuards(plans []*subjectPlan, comp *Completion) {
	var scope, total, base, applied, winOwn int
	for _, p := range plans {
		var n, w int
		for _, c := range p.cands {
			if c.counts {
				n++
				if c.inWin {
					w++
				}
			}
		}
		scope += p.scope
		total += n
		base += p.base
		applied += p.applied
		winOwn += w
		if trips(n, p.scope, guardMinSubject) {
			comp.RunGuard = true
		}
		if trips(p.applied+w, p.base, guardMinSubject) {
			comp.WindowGuard = true
		}
	}
	if trips(total, scope, guardMinTotal) {
		comp.RunGuard = true
	}
	if trips(applied+winOwn, base, guardMinTotal) {
		comp.WindowGuard = true
	}
	if !comp.RunGuard && !comp.WindowGuard {
		return
	}
	reason := HoldRunGuard
	if !comp.RunGuard {
		reason = HoldWindowGuard
	}
	for _, p := range plans {
		for i := range p.cands {
			if p.cands[i].counts && p.cands[i].hold == "" {
				p.cands[i].hold = reason
			}
		}
	}
}

// trips: count exceeds half of base and is at least floor.
func trips(count, base, floor int) bool {
	return count >= floor && 2*count > base
}

// applySubject applies one subject's plan inside the caller's transaction:
// it re-checks the watermark, moves it to the run, drops holds of older
// runs on the subject (superseded, path 7), then closes or holds each
// candidate if the finding is unchanged since planning.
func applySubject(ctx context.Context, tx *sql.Tx, run runRow, p *subjectPlan, now time.Time, comp *Completion) error {
	wm, err := watermark(ctx, tx, p.subject)
	if err != nil {
		return err
	}
	if wm > run.seq {
		comp.SubjectsBelowWatermark++
		return nil
	}
	n := unix(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_subject_watermarks (subject, run_seq, completed_at) VALUES (?, ?, ?)
		ON CONFLICT (subject) DO UPDATE SET run_seq = excluded.run_seq, completed_at = excluded.completed_at`, p.subject, run.seq, n); err != nil {
		return fmt.Errorf("watermark: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE subject = ? AND run_seq < ?`, p.subject, run.seq); err != nil {
		return fmt.Errorf("drop superseded holds: %w", err)
	}
	sort.Slice(p.cands, func(i, j int) bool { return string(p.cands[i].f.Key[:]) < string(p.cands[j].f.Key[:]) })
	for _, c := range p.cands {
		if c.hold != "" {
			res, err := tx.ExecContext(ctx, `INSERT INTO vuln_held_closures (run_id, finding_key, run_seq, subject, reason, finding_rev, created_at)
				SELECT ?, finding_key, ?, subject, ?, rev, ? FROM vuln_findings
				WHERE finding_key = ? AND state = 'open' AND state_run_seq <= ? AND rev = ?
				ON CONFLICT (run_id, finding_key) DO NOTHING`,
				run.id, run.seq, string(c.hold), n, c.f.Key[:], run.seq, c.f.Rev)
			if err != nil {
				return fmt.Errorf("hold: %w", err)
			}
			if k, _ := res.RowsAffected(); k == 1 {
				comp.Held[c.hold]++
			} else {
				comp.Superseded++
			}
			continue
		}
		by, note := ClosedByHermesUnconfirmed, ""
		switch c.class {
		case ClassEvidenced:
			by = ClosedByNOSInventory
		case ClassUnconfirmedUnchanged:
			note = NoteVersionUnchanged
		}
		res, err := tx.ExecContext(ctx, `UPDATE vuln_findings SET state = 'fixed', closed_by = ?, closed_note = ?, closed_at = ?,
			state_run_seq = ?, rev = rev + 1, updated_at = ?
			WHERE finding_key = ? AND state = 'open' AND state_run_seq <= ? AND rev = ?`,
			string(by), note, n, run.seq, n, c.f.Key[:], run.seq, c.f.Rev)
		if err != nil {
			return fmt.Errorf("close: %w", err)
		}
		if k, _ := res.RowsAffected(); k != 1 {
			comp.Superseded++
			continue
		}
		if err := logHistory(ctx, tx, c.f.Key, p.subject, n, run.seq, EventClosed, true, by); err != nil {
			return err
		}
		if by == ClosedByNOSInventory {
			comp.ClosedEvidenced++
		} else {
			comp.ClosedUnconfirmed++
		}
	}
	return nil
}

func watermark(ctx context.Context, q queryer, subject string) (int64, error) {
	var wm int64
	err := q.QueryRowContext(ctx, `SELECT run_seq FROM vuln_subject_watermarks WHERE subject = ?`, subject).Scan(&wm)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("watermark: %w", err)
	}
	return wm, nil
}

func stringColumn(ctx context.Context, q queryer, query string, args ...any) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

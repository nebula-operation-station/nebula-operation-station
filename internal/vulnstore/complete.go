// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
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

// Pacing of the apply phase of a complete. Each apply transaction holds
// the server.db write lock, which every other writer of the shared
// database waits for up to its busy timeout (serverdb.DefaultBusyTimeout,
// 5 s). A waiting writer does not queue: SQLite's busy handler retries
// the lock after growing sleeps, from 228 ms on every 100 ms. So an apply
// transaction is kept short (maxApplyWrites statements: well under a
// second even on a slow disk) and the next one starts only after
// applyPause, longer than one retry interval, so that every waiting
// writer retries while the lock is free. For the largest run (10000
// covered subjects, about 50000 statements) the pauses add about 6 s;
// with open findings on the order of MaxFindingsPerRun about a minute,
// well inside the API's complete budget.
const (
	maxApplyWrites = 1024
	applyPause     = 120 * time.Millisecond
)

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
	scope   int         // run guard scope
	base    int         // window guard baseline: open at the window start
	applied int         // baseline findings with an unevidenced closure applied in the window
	cands   []candidate // sorted by finding key
	// below: a newer complete run had covered the subject at planning.
	below bool
	// resumed: an earlier attempt applied the subject's head (watermark,
	// dropped holds, counts) and its candidates up to the saved key.
	resumed bool
	// Counted into the completion when the subject's head is applied.
	notRequested, blockedRejected int
}

// completeProgress is the durable completing state of a run, saved in its
// report by every apply transaction but the last, which marks the run
// completed instead. The guard decision and the completion time are fixed
// by the attempt that committed the first apply transaction; a retry
// resumes after the cursor and adds to the saved counts.
type completeProgress struct {
	// At is the completion time: closed_at, watermarks and ended_at.
	At int64 `json:"at"`
	// Completion holds the counts of what was applied so far and the
	// guard decision for the whole run.
	Completion Completion `json:"completion"`
	// Subject is the last subject applied: fully (Partial false) or its
	// head and its candidates up to Key (hex; "" for none yet).
	Subject string `json:"subject,omitempty"`
	Partial bool   `json:"partial,omitempty"`
	Key     string `json:"key,omitempty"`
}

// sameCursor reports whether p and q are the same completing state (both
// nil: none).
func (p *completeProgress) sameCursor(q *completeProgress) bool {
	if p == nil || q == nil {
		return p == nil && q == nil
	}
	return p.At == q.At && p.Subject == q.Subject && p.Partial == q.Partial && p.Key == q.Key
}

// Complete completes a run. Only a completed run requests run closures:
// for each subject it fully covered, open findings it omitted or reported
// not_affected.
//
// The closures are planned and classified on a read snapshot, which holds
// no write lock, and the guards are checked on the whole plan. The plan is
// then applied in write transactions of at most maxApplyWrites statements,
// applyPause apart (re-checking each subject's coverage watermark and
// each finding's state_run_seq and revision), so other writers of
// server.db never wait long for the write lock. Each apply transaction saves the run's
// completing state with what it applied; the last one marks the run
// completed and saves the completion instead.
//
// A context ending before the first apply transaction commits changes
// nothing: the run stays running and a retry plans again; a complete that
// fits one apply transaction is therefore all or nothing. A larger
// complete that stops later leaves the run completing: it takes no more
// batches and is not aborted at its time limit, and the next Complete (or
// ResumeComplete) resumes after the last committed transaction with the
// saved guard decision, time and counts, so it ends with the closures and
// the completion an uninterrupted complete would have made. Once Complete
// has returned, CompletionOf returns the saved completion.
func (s *Store) Complete(ctx context.Context, runID string) (Completion, error) {
	s.completeMu.Lock()
	defer s.completeMu.Unlock()
	now := s.now().UTC()
	run, prev, plans, err := s.planComplete(ctx, runID, now)
	if err != nil {
		return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
	}
	comp, err := s.applyComplete(ctx, run, plans, prev, now)
	if err != nil {
		return Completion{}, fmt.Errorf("vulnstore: complete: %w", err)
	}
	return comp, nil
}

// ResumeComplete finishes a run of tokenID that an earlier Complete left
// completing (cancelled, out of time or interrupted by a restart after
// part of its closures committed), for a caller that no longer holds its
// own state of the run. A run of another token is ErrRunNotFound; a run
// that is not completing is ErrRunNotRunning.
func (s *Store) ResumeComplete(ctx context.Context, runID, tokenID string) (Completion, error) {
	run, err := loadRun(ctx, s.db, runID)
	if err != nil {
		return Completion{}, fmt.Errorf("vulnstore: resume complete: %w", err)
	}
	if run.tokenID != tokenID {
		return Completion{}, fmt.Errorf("vulnstore: resume complete: %w", ErrRunNotFound)
	}
	if run.state != "running" || parseReport(run.reportRaw).Completing == nil {
		return Completion{}, fmt.Errorf("vulnstore: resume complete: %w", ErrRunNotRunning)
	}
	return s.Complete(ctx, runID)
}

// CompletionOf returns the saved completion of a completed run that
// tokenID started, so that a retried complete gets the same answer after
// the caller lost its own record of it (restart, eviction). A run of
// another token is ErrRunNotFound; a run that is running, completing,
// aborted or has no saved completion is ErrRunNotRunning.
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

// planComplete loads the run and plans its closures on one read snapshot
// (a deferred transaction that only reads takes no write lock). It
// returns the run, its saved completing state (nil for a first attempt)
// and the plans; on a resume only what is left is planned.
func (s *Store) planComplete(ctx context.Context, runID string, now time.Time) (runRow, *completeProgress, []*subjectPlan, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return runRow{}, nil, nil, fmt.Errorf("begin read: %w", err)
	}
	defer tx.Rollback()
	run, err := loadRun(ctx, tx, runID)
	if err != nil {
		return runRow{}, nil, nil, err
	}
	if run.state != "running" {
		return runRow{}, nil, nil, ErrRunNotRunning
	}
	prev := parseReport(run.reportRaw).Completing
	if prev == nil && now.Sub(run.started) > MaxRunDuration {
		tx.Rollback()
		return runRow{}, nil, nil, s.abortIfExpired(ctx, runID, now)
	}
	var plans []*subjectPlan
	if !run.rejected {
		if plans, err = s.planClosures(ctx, tx, run, now, prev); err != nil {
			return runRow{}, nil, nil, err
		}
	}
	return run, prev, plans, nil
}

// abortIfExpired aborts a run past MaxRunDuration in a write transaction
// and returns ErrRunExpired, or why it did not abort it.
func (s *Store) abortIfExpired(ctx context.Context, runID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	run, err := loadRun(ctx, tx, runID)
	if err != nil {
		return err
	}
	err = s.checkRunning(ctx, tx, run, now)
	switch {
	case errors.Is(err, ErrRunExpired):
		if cerr := tx.Commit(); cerr != nil {
			return fmt.Errorf("commit abort: %w", cerr)
		}
		return err
	case err == nil:
		// Planned on a snapshot that is gone: let the caller retry.
		return fmt.Errorf("run changed while planning: %w", ErrRunNotRunning)
	default:
		return err
	}
}

// applyPos is a position in the plans: plan i, whether its head is
// applied, and its next candidate j.
type applyPos struct {
	i, j int
	head bool
}

// applyComplete applies the plans in bounded write transactions. prev is
// the completing state the plans were made on (nil: first attempt).
func (s *Store) applyComplete(ctx context.Context, run runRow, plans []*subjectPlan, prev *completeProgress, now time.Time) (Completion, error) {
	cur := prev
	if cur == nil {
		cur = &completeProgress{At: unix(now), Completion: Completion{Held: map[HoldReason]int{}, BatchRejected: run.rejected}}
		applyGuards(plans, &cur.Completion)
	}
	holdGuarded(plans, cur.Completion)
	var pos applyPos
	for n := 1; ; n++ {
		next, nextPos, done, err := s.applyChunk(ctx, run, plans, pos, prev, cur)
		if err != nil {
			return Completion{}, err
		}
		if done {
			return next.Completion, nil
		}
		if s.chunkDone != nil {
			s.chunkDone(n)
		}
		prev, cur, pos = next, next, nextPos
		t := time.NewTimer(applyPause)
		select {
		case <-ctx.Done():
			t.Stop()
			return Completion{}, ctx.Err()
		case <-t.C:
		}
	}
}

// checkProgress loads the run inside tx and checks that it is running with
// the completing state want (nil: none) the caller planned on. Otherwise
// another Complete, possibly of another process, moved it on and the
// caller must not apply: ErrRunNotRunning.
func checkProgress(ctx context.Context, tx *sql.Tx, runID string, want *completeProgress) (runRow, error) {
	run, err := loadRun(ctx, tx, runID)
	if err != nil {
		return runRow{}, err
	}
	if run.state != "running" || !parseReport(run.reportRaw).Completing.sameCursor(want) {
		return runRow{}, fmt.Errorf("run moved on by another complete: %w", ErrRunNotRunning)
	}
	return run, nil
}

// applyChunk applies the plans from pos in one write transaction of at
// most about maxApplyWrites statements and saves the completing state
// with it, or marks the run completed when it applied the last plan. It
// returns the saved state and the next position.
func (s *Store) applyChunk(ctx context.Context, run runRow, plans []*subjectPlan, pos applyPos, prev, cur *completeProgress) (*completeProgress, applyPos, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return nil, pos, false, err
	}
	defer tx.Rollback()
	stored, err := checkProgress(ctx, tx, run.id, prev)
	if err != nil {
		return nil, pos, false, err
	}
	at := fromUnix(cur.At)
	comp := cur.Completion
	comp.Held = maps.Clone(cur.Completion.Held)
	if comp.Held == nil {
		comp.Held = map[HoldReason]int{}
	}
	writes := 0
	for pos.i < len(plans) && writes < maxApplyWrites {
		p := plans[pos.i]
		if !pos.head && !p.resumed {
			n, live, err := applyHead(ctx, tx, run, p, at, &comp)
			writes += n
			if err != nil {
				return nil, pos, false, err
			}
			if !live {
				pos = applyPos{i: pos.i + 1}
				continue
			}
		} else {
			// The head was applied by an earlier transaction; a newer run
			// may have covered the subject since.
			wm, err := watermark(ctx, tx, p.subject)
			writes++
			if err != nil {
				return nil, pos, false, err
			}
			if wm > run.seq {
				comp.Superseded += len(p.cands) - pos.j
				pos = applyPos{i: pos.i + 1}
				continue
			}
		}
		pos.head = true
		for pos.j < len(p.cands) && writes < maxApplyWrites {
			n, err := applyCandidate(ctx, tx, run, p.subject, p.cands[pos.j], at, &comp)
			writes += n
			if err != nil {
				return nil, pos, false, err
			}
			pos.j++
		}
		if pos.j == len(p.cands) {
			pos = applyPos{i: pos.i + 1}
		}
	}
	rep := parseReport(stored.reportRaw)
	next := &completeProgress{At: cur.At, Completion: comp}
	done := pos.i == len(plans)
	if done {
		rep.Completing, rep.Completion = nil, &comp
		if _, err := tx.ExecContext(ctx, `UPDATE vuln_runs SET state = 'completed', ended_at = ?, superseded = superseded + ? WHERE id = ?`,
			cur.At, comp.Superseded, run.id); err != nil {
			return nil, pos, false, fmt.Errorf("mark completed: %w", err)
		}
	} else {
		switch p := plans[pos.i]; {
		case pos.head && pos.j > 0:
			next.Subject, next.Partial, next.Key = p.subject, true, hex.EncodeToString(p.cands[pos.j-1].f.Key[:])
		case pos.head && p.resumed:
			next.Subject, next.Partial, next.Key = p.subject, true, cur.Key
		case pos.head:
			next.Subject, next.Partial = p.subject, true
		case pos.i > 0:
			next.Subject = plans[pos.i-1].subject
		default:
			return nil, pos, false, errors.New("apply made no progress")
		}
		rep.Completing = next
	}
	if err := saveReport(ctx, tx, run.id, rep); err != nil {
		return nil, pos, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, pos, false, fmt.Errorf("commit: %w", err)
	}
	return next, pos, done, nil
}

// planClosures reads, per covered subject at or above its watermark, the
// requested closures and classifies them. It writes nothing. On a resume
// (prev not nil) it plans only the subjects after prev's cursor and, for
// a partly applied subject, the candidates after prev's key; the guards
// are not computed again, so it skips their inputs.
func (s *Store) planClosures(ctx context.Context, tx *sql.Tx, run runRow, now time.Time, prev *completeProgress) ([]*subjectPlan, error) {
	sources, err := loadRunSources(ctx, tx, run.id)
	if err != nil {
		return nil, err
	}
	query, args := `SELECT subject FROM vuln_run_subjects WHERE run_id = ? ORDER BY subject`, []any{run.id}
	switch {
	case prev != nil && prev.Partial:
		query, args = `SELECT subject FROM vuln_run_subjects WHERE run_id = ? AND subject >= ? ORDER BY subject`, []any{run.id, prev.Subject}
	case prev != nil && prev.Subject != "":
		query, args = `SELECT subject FROM vuln_run_subjects WHERE run_id = ? AND subject > ? ORDER BY subject`, []any{run.id, prev.Subject}
	}
	subjects, err := stringColumn(ctx, tx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("covered subjects: %w", err)
	}
	winStart := unix(now.Add(-WindowGuardSpan))
	var plans []*subjectPlan
	for _, subj := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := &subjectPlan{subject: subj, resumed: prev != nil && prev.Partial && subj == prev.Subject}
		if !p.resumed {
			wm, err := watermark(ctx, tx, subj)
			if err != nil {
				return nil, err
			}
			if wm > run.seq {
				p.below = true
				plans = append(plans, p)
				continue
			}
		}
		win := windowView{applied: map[vulnfinding.Key]bool{}, firstWasOpen: map[vulnfinding.Key]bool{}}
		if prev == nil {
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vuln_findings WHERE subject = ? AND state = 'open'
				AND state_run_seq <= ? AND episode_opened_at <= ? AND episode_opened_run_seq <> ?`,
				subj, run.seq, unix(run.started), run.seq).Scan(&p.scope); err != nil {
				return nil, fmt.Errorf("run guard scope: %w", err)
			}
			if win, err = loadWindow(ctx, tx, subj, winStart); err != nil {
				return nil, err
			}
			p.base, p.applied = win.base, len(win.applied)
		}
		open, err := queryFindings(ctx, tx, `SELECT `+findingColumns+` FROM vuln_findings
			WHERE subject = ? AND state = 'open' AND state_run_seq <= ? ORDER BY finding_key`, subj, run.seq)
		if err != nil {
			return nil, err
		}
		for _, f := range open {
			if p.resumed && hex.EncodeToString(f.Key[:]) <= prev.Key {
				continue // applied by an earlier attempt
			}
			c, ok, err := s.planOne(ctx, tx, run, sources, f, p)
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
		if p.resumed {
			p.notRequested, p.blockedRejected = 0, 0 // counted with the head
		}
		sort.Slice(p.cands, func(i, j int) bool { return string(p.cands[i].f.Key[:]) < string(p.cands[j].f.Key[:]) })
		plans = append(plans, p)
	}
	return plans, nil
}

// planOne decides whether the run requests the closure of f and how it is
// classified (D5 closure classes and paths 4 and 5).
func (s *Store) planOne(ctx context.Context, tx *sql.Tx, run runRow, sources map[string]runSourceInfo, f Finding, p *subjectPlan) (candidate, bool, error) {
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
		p.blockedRejected++ // precondition e, also for path 4
		return candidate{}, false, nil
	}
	class, cerr := s.classify.Classify(ctx, f)
	if cerr == nil && class == ClassEvidenced {
		return candidate{f: f, class: ClassEvidenced}, true, nil // path 4
	}
	if !basisCovered(f.Record, sources) {
		p.notRequested++ // precondition d: not requested, not held, not counted
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

// applyGuards checks the run guard and the window guard on the whole plan
// and records in comp which tripped (D5).
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
}

// holdGuarded holds every unevidenced closure of the run when a guard
// tripped (D5).
func holdGuarded(plans []*subjectPlan, comp Completion) {
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

// applyHead applies the head of one subject's plan inside the caller's
// transaction: it re-checks the watermark, moves it to the run, drops
// holds of older runs on the subject (superseded, path 7) and counts the
// subject's planning results. live is false when the subject is below its
// watermark and nothing more is applied there. n is the statement count.
func applyHead(ctx context.Context, tx *sql.Tx, run runRow, p *subjectPlan, at time.Time, comp *Completion) (n int, live bool, err error) {
	if p.below {
		comp.SubjectsBelowWatermark++
		return 1, false, nil
	}
	wm, err := watermark(ctx, tx, p.subject)
	if err != nil {
		return 1, false, err
	}
	if wm > run.seq {
		comp.SubjectsBelowWatermark++
		return 1, false, nil
	}
	t := unix(at)
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_subject_watermarks (subject, run_seq, completed_at) VALUES (?, ?, ?)
		ON CONFLICT (subject) DO UPDATE SET run_seq = excluded.run_seq, completed_at = excluded.completed_at`, p.subject, run.seq, t); err != nil {
		return 2, false, fmt.Errorf("watermark: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE subject = ? AND run_seq < ?`, p.subject, run.seq); err != nil {
		return 3, false, fmt.Errorf("drop superseded holds: %w", err)
	}
	comp.NotRequested += p.notRequested
	comp.BlockedRejected += p.blockedRejected
	return 3, true, nil
}

// applyCandidate closes or holds one candidate inside the caller's
// transaction if the finding is unchanged since planning. n is the
// statement count.
func applyCandidate(ctx context.Context, tx *sql.Tx, run runRow, subject string, c candidate, at time.Time, comp *Completion) (int, error) {
	t := unix(at)
	if c.hold != "" {
		res, err := tx.ExecContext(ctx, `INSERT INTO vuln_held_closures (run_id, finding_key, run_seq, subject, reason, finding_rev, created_at)
			SELECT ?, finding_key, ?, subject, ?, rev, ? FROM vuln_findings
			WHERE finding_key = ? AND state = 'open' AND state_run_seq <= ? AND rev = ?
			ON CONFLICT (run_id, finding_key) DO NOTHING`,
			run.id, run.seq, string(c.hold), t, c.f.Key[:], run.seq, c.f.Rev)
		if err != nil {
			return 1, fmt.Errorf("hold: %w", err)
		}
		if k, _ := res.RowsAffected(); k == 1 {
			comp.Held[c.hold]++
		} else {
			comp.Superseded++
		}
		return 1, nil
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
		string(by), note, t, run.seq, t, c.f.Key[:], run.seq, c.f.Rev)
	if err != nil {
		return 1, fmt.Errorf("close: %w", err)
	}
	if k, _ := res.RowsAffected(); k != 1 {
		comp.Superseded++
		return 1, nil
	}
	if err := logHistory(ctx, tx, c.f.Key, subject, t, run.seq, EventClosed, true, by); err != nil {
		return 2, err
	}
	if by == ClosedByNOSInventory {
		comp.ClosedEvidenced++
	} else {
		comp.ClosedUnconfirmed++
	}
	return 2, nil
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

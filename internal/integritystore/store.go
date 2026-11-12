// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// runIDBytes is the random part of a run ID; the ID is its hex form.
const runIDBytes = 16

// cutoff returns the start time before which a running run is overdue.
func cutoff(now int64) int64 { return now - int64(MaxRunDuration/time.Second) }

// BeginRun starts a check run of subj. A subject has at most one running run;
// an overdue run is aborted by the next call, and an in-time one refuses
// the new run with ErrRunActive.
func (s *Store) BeginRun(ctx context.Context, subj Subject) (Run, error) {
	if err := subj.validate(); err != nil {
		return Run{}, err
	}
	id, err := newRunID()
	if err != nil {
		return Run{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := unix(s.now())
	tx, err := s.writeTx(ctx)
	if err != nil {
		return Run{}, err
	}
	defer tx.Rollback()
	var live int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM integrity_runs WHERE subject = ? AND state = 'running' AND started_at >= ?`,
		string(subj), cutoff(now)).Scan(&live); err != nil {
		return Run{}, fmt.Errorf("integritystore: begin run: %w", err)
	}
	if live > 0 {
		return Run{}, fmt.Errorf("subject %s: %w", subj, ErrRunActive)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE integrity_runs SET state = 'aborted', ended_at = ? WHERE subject = ? AND state = 'running'`,
		now, string(subj)); err != nil {
		return Run{}, fmt.Errorf("integritystore: begin run: abort overdue: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO integrity_runs (id, subject, state, dropped, started_at) VALUES (?, ?, 'running', 0, ?)`,
		id, string(subj), now); err != nil {
		return Run{}, fmt.Errorf("integritystore: begin run: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("integritystore: begin run: commit: %w", err)
	}
	return Run{ID: id, Subject: subj}, nil
}

// newRunID returns a random 32-character hex run ID.
func newRunID() (string, error) {
	var b [runIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("integritystore: run id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// runRow is a stored run.
type runRow struct {
	subject   Subject
	state     string
	startedAt int64
}

// loadRun reads a run inside tx. A run past its time limit is reported as
// expired by runAccessible, which also aborts it.
func loadRun(ctx context.Context, tx *sql.Tx, runID string) (runRow, error) {
	var r runRow
	var subj string
	err := tx.QueryRowContext(ctx,
		`SELECT subject, state, started_at FROM integrity_runs WHERE id = ?`, runID).
		Scan(&subj, &r.state, &r.startedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return runRow{}, fmt.Errorf("run %s: %w", runID, ErrRunNotFound)
	}
	if err != nil {
		return runRow{}, fmt.Errorf("integritystore: load run: %w", err)
	}
	r.subject = Subject(subj)
	return r, nil
}

// runAccessible checks that a loaded run is running and in time. An
// overdue run is aborted; the caller must commit tx (it returns ErrRunExpired
// so that the abort is committed by the caller on that error path).
func runAccessible(ctx context.Context, tx *sql.Tx, runID string, r runRow, now int64) error {
	if r.state != "running" {
		return fmt.Errorf("run %s: %w", runID, ErrRunNotRunning)
	}
	if r.startedAt < cutoff(now) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE integrity_runs SET state = 'aborted', ended_at = ? WHERE id = ?`, now, runID); err != nil {
			return fmt.Errorf("integritystore: abort run: %w", err)
		}
		return ErrRunExpired
	}
	return nil
}

// Record stores the observations of a running run. It returns counts; see
// Result. A batch over MaxObservationsPerBatch, or with an unknown class, is
// refused whole with an error, and the run is marked as dropped by every
// observation of the batch, so Finish cannot close findings on it. An
// expired run is aborted and returns ErrRunExpired.
func (s *Store) Record(ctx context.Context, runID string, obs []Observation) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := unix(s.now())
	tx, err := s.writeTx(ctx)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()
	run, err := loadRun(ctx, tx, runID)
	if err != nil {
		return Result{}, err
	}
	if err := runAccessible(ctx, tx, runID, run, now); err != nil {
		if errors.Is(err, ErrRunExpired) {
			if cerr := tx.Commit(); cerr != nil {
				return Result{}, fmt.Errorf("integritystore: abort run: commit: %w", cerr)
			}
		}
		return Result{}, err
	}
	if err := checkBatch(obs); err != nil {
		if _, uerr := tx.ExecContext(ctx,
			`UPDATE integrity_runs SET dropped = dropped + ? WHERE id = ?`, len(obs), runID); uerr != nil {
			return Result{}, fmt.Errorf("integritystore: record: refused batch: %w", uerr)
		}
		if cerr := tx.Commit(); cerr != nil {
			return Result{}, fmt.Errorf("integritystore: record: refused batch: commit: %w", cerr)
		}
		return Result{}, err
	}

	var res Result
	uniq, dropped := dedupeBatch(obs, &res)
	n, err := countActive(ctx, tx, run.subject)
	if err != nil {
		return Result{}, err
	}
	for _, o := range uniq {
		if err := s.recordOne(ctx, tx, run, runID, o, now, &n, &res, &dropped); err != nil {
			return Result{}, err
		}
	}
	if dropped > 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE integrity_runs SET dropped = dropped + ? WHERE id = ?`, dropped, runID); err != nil {
			return Result{}, fmt.Errorf("integritystore: record: dropped: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Result{}, fmt.Errorf("integritystore: record: commit: %w", err)
	}
	return res, nil
}

// dedupeBatch drops observations whose path is invalid and merges repeated
// keys (the later one wins). It returns the observations to store and the
// number of observations that were dropped as invalid.
func dedupeBatch(obs []Observation, res *Result) ([]Observation, int64) {
	var dropped int64
	index := make(map[string]int, len(obs))
	out := make([]Observation, 0, len(obs))
	for _, o := range obs {
		if !pathOK(o.Path) {
			res.PathRejected++
			dropped++
			continue
		}
		k := string(o.Class) + "\x00" + string(o.Path)
		if i, ok := index[k]; ok {
			out[i] = o
			res.Duplicates++
			continue
		}
		index[k] = len(out)
		out = append(out, o)
	}
	return out, dropped
}

// checkBatch refuses a batch over the observation limit or with an unknown
// class.
func checkBatch(obs []Observation) error {
	if len(obs) > MaxObservationsPerBatch {
		return fmt.Errorf("integritystore: record %d observations: %w", len(obs), ErrBatchTooLarge)
	}
	for _, o := range obs {
		if _, err := o.Class.Severity(); err != nil {
			return fmt.Errorf("integritystore: record: %w", err)
		}
	}
	return nil
}

// limitFor returns the number of active findings (open or expected_pending)
// that a new or reopened finding of severity sev may see before it is
// refused. Critical findings may use the whole MaxFindingsPerSubject; lower
// severities leave ReservedCriticalSlots free for critical ones.
func limitFor(sev Severity) int {
	if sev == SeverityCritical {
		return MaxFindingsPerSubject
	}
	return MaxFindingsPerSubject - ReservedCriticalSlots
}

// countActive counts the findings of subj that count against the limit:
// open and expected_pending ones.
func countActive(ctx context.Context, tx *sql.Tx, subj Subject) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM integrity_findings WHERE subject = ? AND state IN ('open', 'expected_pending')`,
		string(subj)).Scan(&n); err != nil {
		return 0, fmt.Errorf("integritystore: count findings: %w", err)
	}
	return n, nil
}

// findingRow is the stored state of a finding that recordOne decides on.
type findingRow struct {
	state          State
	oldRec, newRec string
	basisOld       sql.NullString
	basisNew       sql.NullString
	expiresAt      sql.NullInt64
}

// recordOne writes one observation of a run inside tx.
func (s *Store) recordOne(ctx context.Context, tx *sql.Tx, run runRow, runID string, o Observation, now int64, n *int, res *Result, dropped *int64) error {
	subj := string(run.subject)
	oldRec, newRec := o.OldRecord, o.NewRecord
	if !recordOK(oldRec) {
		oldRec = ""
		res.RecordsDropped++
	}
	if !recordOK(newRec) {
		newRec = ""
		res.RecordsDropped++
	}
	sev, err := o.Class.Severity()
	if err != nil {
		return err
	}
	var cur findingRow
	err = tx.QueryRowContext(ctx,
		`SELECT state, old_record, new_record, basis_old_record, basis_new_record, expires_at
		FROM integrity_findings WHERE subject = ? AND class = ? AND path = ?`,
		subj, string(o.Class), o.Path).Scan(&cur.state, &cur.oldRec, &cur.newRec,
		&cur.basisOld, &cur.basisNew, &cur.expiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if *n >= limitFor(sev) {
			res.OverLimit++
			*dropped++
			return nil
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO integrity_findings (
				subject, class, severity, path, path_display, old_record, new_record, state,
				first_seen_at, last_seen_at, opened_run_id, last_run_id, state_run_id, state_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)`,
			subj, string(o.Class), string(sev), o.Path, EscapePath(o.Path), oldRec, newRec,
			now, now, runID, runID, runID, now); err != nil {
			return fmt.Errorf("integritystore: insert finding: %w", err)
		}
		*n++
		res.Inserted++
		return nil
	case err != nil:
		return fmt.Errorf("integritystore: read finding: %w", err)
	}

	switch cur.state {
	case StateResolved:
		if *n >= limitFor(sev) {
			res.OverLimit++
			*dropped++
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE integrity_findings SET
				old_record = ?, new_record = ?, state = 'open', first_seen_at = ?, last_seen_at = ?,
				opened_run_id = ?, last_run_id = ?, closed_run_id = NULL, closed_at = NULL,
				state_run_id = ?, state_by = NULL, state_at = ?
			WHERE subject = ? AND class = ? AND path = ?`,
			oldRec, newRec, now, now, runID, runID, runID, now,
			subj, string(o.Class), o.Path); err != nil {
			return fmt.Errorf("integritystore: reopen finding: %w", err)
		}
		*n++
		res.Reopened++
		return nil
	case StateAccepted, StateExpectedPending:
		// A human or expected state holds only for the records it was
		// decided for, and an accepted one only until it expires (ADR 0011
		// D6). Otherwise the finding reopens as open.
		expired := cur.state == StateAccepted && cur.expiresAt.Valid && now >= cur.expiresAt.Int64
		same := cur.basisOld.Valid && cur.basisNew.Valid &&
			cur.basisOld.String == oldRec && cur.basisNew.String == newRec
		if !expired && same {
			break
		}
		if _, err := tx.ExecContext(ctx, `UPDATE integrity_findings SET
				old_record = ?, new_record = ?, state = 'open', last_seen_at = ?, last_run_id = ?,
				state_run_id = ?, state_by = NULL, state_at = ?,
				basis_old_record = NULL, basis_new_record = NULL, expires_at = NULL
			WHERE subject = ? AND class = ? AND path = ?`,
			oldRec, newRec, now, runID, runID, now,
			subj, string(o.Class), o.Path); err != nil {
			return fmt.Errorf("integritystore: reopen human state: %w", err)
		}
		if cur.state == StateAccepted {
			// An accepted finding is not counted against the limit; reopened
			// it is.
			*n++
		}
		res.Reopened++
		return nil
	}

	if _, err := tx.ExecContext(ctx, `UPDATE integrity_findings SET
			old_record = ?, new_record = ?, last_seen_at = ?, last_run_id = ?
		WHERE subject = ? AND class = ? AND path = ?`,
		oldRec, newRec, now, runID, subj, string(o.Class), o.Path); err != nil {
		return fmt.Errorf("integritystore: update finding: %w", err)
	}
	res.Updated++
	return nil
}

// Finish ends a running run. Only a complete run that dropped nothing
// resolves findings: it resolves every unresolved finding of its subject that
// it did not see. Any other run closes nothing and ends as incomplete.
// An overdue run is aborted and returns ErrRunExpired.
func (s *Store) Finish(ctx context.Context, runID string, complete bool) (FinishResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := unix(s.now())
	tx, err := s.writeTx(ctx)
	if err != nil {
		return FinishResult{}, err
	}
	defer tx.Rollback()
	run, err := loadRun(ctx, tx, runID)
	if err != nil {
		return FinishResult{}, err
	}
	if err := runAccessible(ctx, tx, runID, run, now); err != nil {
		if errors.Is(err, ErrRunExpired) {
			if cerr := tx.Commit(); cerr != nil {
				return FinishResult{}, fmt.Errorf("integritystore: abort run: commit: %w", cerr)
			}
		}
		return FinishResult{}, err
	}
	var dropped int64
	if err := tx.QueryRowContext(ctx, `SELECT dropped FROM integrity_runs WHERE id = ?`, runID).Scan(&dropped); err != nil {
		return FinishResult{}, fmt.Errorf("integritystore: finish: dropped: %w", err)
	}
	res := FinishResult{Outcome: OutcomeIncomplete, Dropped: int(dropped)}
	if complete && dropped == 0 {
		res.Outcome = OutcomeComplete
		r, err := tx.ExecContext(ctx, `UPDATE integrity_findings SET
				state = 'resolved', closed_run_id = ?, closed_at = ?, state_run_id = ?, state_at = ?,
				basis_old_record = NULL, basis_new_record = NULL, expires_at = NULL
			WHERE subject = ? AND state <> 'resolved' AND last_run_id <> ?`,
			runID, now, runID, now, string(run.subject), runID)
		if err != nil {
			return FinishResult{}, fmt.Errorf("integritystore: finish: resolve: %w", err)
		}
		k, _ := r.RowsAffected()
		res.Closed = int(k)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE integrity_runs SET state = ?, ended_at = ? WHERE id = ?`,
		string(res.Outcome), now, runID); err != nil {
		return FinishResult{}, fmt.Errorf("integritystore: finish: end run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return FinishResult{}, fmt.Errorf("integritystore: finish: commit: %w", err)
	}
	return res, nil
}

// MarkExpectedPending moves an open finding to expected_pending, on the
// running run of its subject: a verified expected change from a NOS job.
// It only records the state; it changes nothing on the host.
func (s *Store) MarkExpectedPending(ctx context.Context, runID string, key Key) error {
	return s.transition(ctx, runID, key, StateOpen, StateExpectedPending)
}

// ClearExpectedPending moves an expected_pending finding back to open, on
// the running run of its subject.
func (s *Store) ClearExpectedPending(ctx context.Context, runID string, key Key) error {
	return s.transition(ctx, runID, key, StateExpectedPending, StateOpen)
}

// transition changes the state of one finding from one state to another on
// a running run of the finding's subject.
func (s *Store) transition(ctx context.Context, runID string, key Key, from, to State) error {
	if err := key.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := unix(s.now())
	tx, err := s.writeTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	run, err := loadRun(ctx, tx, runID)
	if err != nil {
		return err
	}
	if err := runAccessible(ctx, tx, runID, run, now); err != nil {
		if errors.Is(err, ErrRunExpired) {
			if cerr := tx.Commit(); cerr != nil {
				return fmt.Errorf("integritystore: abort run: commit: %w", cerr)
			}
		}
		return err
	}
	if run.subject != key.Subject {
		return fmt.Errorf("finding of another subject than run %s: %w", runID, ErrInvalidInput)
	}
	cur, err := readState(ctx, tx, key)
	if err != nil {
		return err
	}
	if cur != from {
		return fmt.Errorf("state %s, want %s: %w", cur, from, ErrWrongState)
	}
	// Entering expected_pending binds the state to the current records;
	// leaving it drops the binding.
	basis := `basis_old_record = NULL, basis_new_record = NULL`
	if to == StateExpectedPending {
		basis = `basis_old_record = old_record, basis_new_record = new_record`
	}
	if _, err := tx.ExecContext(ctx, `UPDATE integrity_findings SET state = ?, state_run_id = ?, state_at = ?, `+basis+`
		WHERE subject = ? AND class = ? AND path = ?`,
		string(to), runID, now, string(key.Subject), string(key.Class), key.Path); err != nil {
		return fmt.Errorf("integritystore: transition: %w", err)
	}
	return tx.Commit()
}

// readState returns the state of a finding inside tx.
func readState(ctx context.Context, tx *sql.Tx, key Key) (State, error) {
	var st string
	err := tx.QueryRowContext(ctx, `SELECT state FROM integrity_findings WHERE subject = ? AND class = ? AND path = ?`,
		string(key.Subject), string(key.Class), key.Path).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrFindingNotFound
	}
	if err != nil {
		return "", fmt.Errorf("integritystore: read state: %w", err)
	}
	return State(st), nil
}

// Accept records an admin's acceptance of an open or expected_pending
// finding. actor is the admin name; it is required. The acceptance is bound
// to the records the finding has now, and it expires after AcceptValidity:
// a different record, or the expiry, reopens the finding at its next run. The
// caller authenticates the admin and audits the change.
func (s *Store) Accept(ctx context.Context, key Key, actor string) error {
	if err := key.validate(); err != nil {
		return err
	}
	if actor == "" || len(actor) > MaxActorBytes || !utf8.ValidString(actor) {
		return fmt.Errorf("actor: %w", ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := unix(s.now())
	tx, err := s.writeTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	cur, err := readState(ctx, tx, key)
	if err != nil {
		return err
	}
	if cur != StateOpen && cur != StateExpectedPending {
		return fmt.Errorf("state %s: %w", cur, ErrWrongState)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE integrity_findings SET state = 'accepted', state_by = ?,
		state_run_id = NULL, state_at = ?, basis_old_record = old_record, basis_new_record = new_record,
		expires_at = ? WHERE subject = ? AND class = ? AND path = ?`,
		actor, now, now+int64(AcceptValidity/time.Second), string(key.Subject), string(key.Class), key.Path); err != nil {
		return fmt.Errorf("integritystore: accept: %w", err)
	}
	return tx.Commit()
}

// Get returns the stored finding for key, or ErrFindingNotFound.
func (s *Store) Get(ctx context.Context, key Key) (Finding, error) {
	if err := key.validate(); err != nil {
		return Finding{}, err
	}
	var (
		f                            Finding
		subj, class, sev, st         string
		firstSeen, lastSeen, stateAt int64
		closedRun, stateRun, stateBy sql.NullString
		closedAt, expires            sql.NullInt64
		basisOld, basisNew           sql.NullString
		path                         []byte
	)
	err := s.db.QueryRowContext(ctx, `SELECT subject, class, severity, path, path_display, old_record, new_record,
			state, first_seen_at, last_seen_at, opened_run_id, last_run_id, closed_run_id, closed_at,
			state_run_id, state_by, state_at, basis_old_record, basis_new_record, expires_at
		FROM integrity_findings WHERE subject = ? AND class = ? AND path = ?`,
		string(key.Subject), string(key.Class), key.Path).Scan(
		&subj, &class, &sev, &path, &f.PathDisplay, &f.OldRecord, &f.NewRecord,
		&st, &firstSeen, &lastSeen, &f.OpenedRunID, &f.LastRunID, &closedRun, &closedAt,
		&stateRun, &stateBy, &stateAt, &basisOld, &basisNew, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrFindingNotFound
	}
	if err != nil {
		return Finding{}, fmt.Errorf("integritystore: get: %w", err)
	}
	f.Key = Key{Subject: Subject(subj), Class: Class(class), Path: bytes.Clone(path)}
	f.Severity = Severity(sev)
	f.State = State(st)
	f.FirstSeen = fromUnix(firstSeen)
	f.LastSeen = fromUnix(lastSeen)
	f.StateAt = fromUnix(stateAt)
	f.ClosedRunID = closedRun.String
	if closedAt.Valid {
		f.ClosedAt = fromUnix(closedAt.Int64)
	}
	f.StateRunID = stateRun.String
	f.StateBy = stateBy.String
	f.BasisOldRecord = basisOld.String
	f.BasisNewRecord = basisNew.String
	if expires.Valid {
		f.ExpiresAt = fromUnix(expires.Int64)
	}
	return f, nil
}

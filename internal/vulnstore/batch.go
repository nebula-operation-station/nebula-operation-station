// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Item is one validated record of a batch, with NOS's own label whether it
// could re-check the version (D4 nos_checked).
type Item struct {
	Finding    vulnfinding.Finding
	NOSChecked bool
}

// Batch is one accepted findings batch of a run. The caller parsed and
// validated every record (internal/vulnfinding) and did the NOS re-check
// (D4); records it rejected are passed as keys in Rejected so their
// closure is blocked in this run.
type Batch struct {
	Seq        int64
	BodySHA256 [32]byte
	Items      []Item
	// Rejected are keys of records rejected by validation or re-check.
	Rejected []vulnfinding.Key
	// Covered are subjects whose last part this batch carries (D3
	// last_part): the run fully covered them.
	Covered []Subject
}

// BatchResult reports what a batch did.
type BatchResult struct {
	// Duplicate: the same batch was already accepted; nothing changed.
	Duplicate bool
	Opened    int
	Updated   int
	Reopened  int
	// Superseded: writes dropped because a newer run wrote the finding.
	Superseded int
	// Rejected: records rejected by the store (basis source not named by
	// the run) plus the caller's rejected keys.
	Rejected int
	// ClosureRequests: not_affected records (applied only at complete).
	ClosureRequests int
	// Ignored lists changes a raise-only record could not apply.
	Ignored []IgnoredChange
	// Downgrades counts KEV flags dropped or tiers fallen inside an
	// episode, applied as current values (the caller audits them).
	Downgrades int
}

// RejectBatch records a batch rejected as a whole: the run then requests
// no closures at all. A repeat with the same hash is a no-op.
func (s *Store) RejectBatch(ctx context.Context, runID string, seq int64, bodySHA256 [32]byte) error {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return fmt.Errorf("vulnstore: reject batch: %w", err)
	}
	defer tx.Rollback()
	r, err := loadRun(ctx, tx, runID)
	if err != nil {
		return fmt.Errorf("vulnstore: reject batch: %w", err)
	}
	if err := s.checkRunning(ctx, tx, r, now); err != nil {
		if errors.Is(err, ErrRunExpired) {
			if cerr := tx.Commit(); cerr != nil {
				return fmt.Errorf("vulnstore: reject batch: commit abort: %w", cerr)
			}
		}
		return fmt.Errorf("vulnstore: reject batch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_run_batches (run_id, batch_seq, body_sha256, rejected) VALUES (?, ?, ?, 1)
		ON CONFLICT (run_id, batch_seq) DO UPDATE SET rejected = 1`, runID, seq, bodySHA256[:]); err != nil {
		return fmt.Errorf("vulnstore: reject batch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_runs SET batch_rejected = 1 WHERE id = ?`, runID); err != nil {
		return fmt.Errorf("vulnstore: reject batch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("vulnstore: reject batch: commit: %w", err)
	}
	return nil
}

// SubmitBatch applies one batch: findings upsert by finding_key under the
// write-ordering rule; not_affected records become closure requests for
// complete. Batches are idempotent by (run, Seq) and body hash.
func (s *Store) SubmitBatch(ctx context.Context, runID string, b Batch) (BatchResult, error) {
	if len(b.Items)+len(b.Rejected) > MaxFindingsPerBatch || b.Seq < 0 {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", ErrBatchTooLarge)
	}
	for _, c := range b.Covered {
		if err := c.validate(); err != nil {
			return BatchResult{}, fmt.Errorf("vulnstore: submit batch: covered: %w", err)
		}
	}
	if err := checkItemKeys(b.Items); err != nil {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}
	defer tx.Rollback()

	r, err := loadRun(ctx, tx, runID)
	if err != nil {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}
	if err := s.checkRunning(ctx, tx, r, now); err != nil {
		if errors.Is(err, ErrRunExpired) {
			if cerr := tx.Commit(); cerr != nil {
				return BatchResult{}, fmt.Errorf("vulnstore: submit batch: commit abort: %w", cerr)
			}
		}
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}
	var prev []byte
	err = tx.QueryRowContext(ctx, `SELECT body_sha256 FROM vuln_run_batches WHERE run_id = ? AND batch_seq = ?`, runID, b.Seq).Scan(&prev)
	switch {
	case err == nil:
		if bytes.Equal(prev, b.BodySHA256[:]) {
			return BatchResult{Duplicate: true}, nil
		}
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch %d: %w", b.Seq, ErrBatchConflict)
	case !errors.Is(err, sql.ErrNoRows):
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}
	// Rejected keys count against the run limit too, so a run cannot grow
	// its rejected and batch rows without bound.
	records := len(b.Items) + len(b.Rejected)
	if r.findings+records > MaxFindingsPerRun {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", ErrBatchTooLarge)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_run_batches (run_id, batch_seq, body_sha256, rejected) VALUES (?, ?, ?, 0)`,
		runID, b.Seq, b.BodySHA256[:]); err != nil {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}

	sources, err := loadRunSources(ctx, tx, runID)
	if err != nil {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}
	var res BatchResult
	for _, k := range b.Rejected {
		if err := markRejected(ctx, tx, runID, k); err != nil {
			return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
		}
		res.Rejected++
	}
	for _, it := range b.Items {
		if err := s.applyItem(ctx, tx, r, sources, it, now, &res); err != nil {
			return BatchResult{}, fmt.Errorf("vulnstore: submit batch: finding %s: %w", it.Finding.Key, err)
		}
	}
	for _, c := range b.Covered {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vuln_run_subjects (run_id, subject) VALUES (?, ?)`, runID, c.String()); err != nil {
			return BatchResult{}, fmt.Errorf("vulnstore: submit batch: covered: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_runs SET finding_count = finding_count + ?, superseded = superseded + ? WHERE id = ?`,
		records, res.Superseded, runID); err != nil {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
	}
	if len(res.Ignored) > 0 || res.Downgrades > 0 {
		rep := parseReport(r.reportRaw)
		for _, ig := range res.Ignored {
			if len(rep.Ignored) < MaxIgnoredListed {
				rep.Ignored = append(rep.Ignored, ig)
			}
			rep.IgnoredCount++
		}
		rep.Downgrades += res.Downgrades
		if err := saveReport(ctx, tx, runID, rep); err != nil {
			return BatchResult{}, fmt.Errorf("vulnstore: submit batch: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return BatchResult{}, fmt.Errorf("vulnstore: submit batch: commit: %w", err)
	}
	return res, nil
}

// checkItemKeys re-validates every record and refuses the batch when the
// caller-supplied key is not the NOS-computed key of its record, so a
// caller bug can never write one finding's values under another's key.
func checkItemKeys(items []Item) error {
	for i, it := range items {
		f, err := vulnfinding.Validate(it.Finding.Record)
		if err != nil {
			return fmt.Errorf("items[%d]: record: %w", i, ErrInvalidInput)
		}
		if f.Key != it.Finding.Key {
			return fmt.Errorf("items[%d]: key does not match record: %w", i, ErrInvalidInput)
		}
	}
	return nil
}

// checkStoredSubject refuses a record whose subject differs from the
// stored row's subject column (closures and guards work per subject).
func checkStoredSubject(ctx context.Context, tx *sql.Tx, k vulnfinding.Key, subj Subject) error {
	var stored string
	if err := tx.QueryRowContext(ctx, `SELECT subject FROM vuln_findings WHERE finding_key = ?`, k[:]).Scan(&stored); err != nil {
		return fmt.Errorf("stored subject: %w", err)
	}
	if stored != subj.String() {
		return fmt.Errorf("record subject differs from stored subject: %w", ErrInvalidInput)
	}
	return nil
}

func markRejected(ctx context.Context, tx *sql.Tx, runID string, k vulnfinding.Key) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vuln_run_rejected (run_id, finding_key) VALUES (?, ?)`, runID, k[:])
	return err
}

// markReported records that the run reported the key. A key reported both
// as affected and as not_affected in one run counts as affected.
func markReported(ctx context.Context, tx *sql.Tx, runID string, k vulnfinding.Key, notAffected bool) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO vuln_run_reported (run_id, finding_key, not_affected) VALUES (?, ?, ?)
		ON CONFLICT (run_id, finding_key) DO UPDATE SET not_affected = MIN(not_affected, excluded.not_affected)`,
		runID, k[:], boolInt(notAffected))
	return err
}

// raiseOnly reports whether a record must only raise values: any basis
// source not accepted (regressed, invalid, unknown) or undated (D5).
// ok is false when a basis source was not named by the run at all.
func raiseOnly(rec vulnfinding.Record, sources map[string]runSourceInfo) (raise, ok bool) {
	for _, bs := range rec.Evidence.BasisSources {
		info, named := sources[bs.SourceID]
		if !named {
			return false, false
		}
		if info.status != SourceAccepted {
			raise = true
		}
	}
	return raise, true
}

func (s *Store) applyItem(ctx context.Context, tx *sql.Tx, run runRow, sources map[string]runSourceInfo, it Item, now time.Time, res *BatchResult) error {
	f := it.Finding
	rec := f.Record
	subj := SubjectOf(rec)
	if len(rec.Evidence.BasisSources) == 0 {
		res.Rejected++
		return markRejected(ctx, tx, run.id, f.Key)
	}
	raise, named := raiseOnly(rec, sources)
	if !named {
		// A basis source the run did not name at start: rejected (D5),
		// which also blocks the key's closure in this run.
		res.Rejected++
		return markRejected(ctx, tx, run.id, f.Key)
	}
	if rec.Fix.State == vulnfinding.FixNotAffected {
		if raise {
			// A raise-only source cannot lower a finding, so its
			// not_affected is no closure request (D5). The record still
			// reports the key, so the finding is not omitted either.
			res.Ignored = append(res.Ignored, IgnoredChange{Key: f.Key.String(), Field: "fix"})
			return markReported(ctx, tx, run.id, f.Key, false)
		}
		res.ClosureRequests++
		return markReported(ctx, tx, run.id, f.Key, true)
	}
	if !rec.Fix.State.Opens() {
		res.Rejected++
		return markRejected(ctx, tx, run.id, f.Key)
	}

	cur, err := loadFinding(ctx, tx, f.Key)
	if errors.Is(err, ErrFindingNotFound) {
		if err := markReported(ctx, tx, run.id, f.Key, false); err != nil {
			return err
		}
		res.Opened++
		return s.insertFinding(ctx, tx, run, subj, it, now)
	}
	if err != nil {
		return err
	}
	if err := checkStoredSubject(ctx, tx, f.Key, subj); err != nil {
		return err
	}
	if err := markReported(ctx, tx, run.id, f.Key, false); err != nil {
		return err
	}
	if cur.StateRunSeq > run.seq {
		res.Superseded++
		return nil
	}
	if cur.State == StateFixed {
		res.Reopened++
		return s.reopenFinding(ctx, tx, run, subj, cur, it, now)
	}
	res.Updated++
	return s.updateFinding(ctx, tx, run, subj, cur, it, raise, now, res)
}

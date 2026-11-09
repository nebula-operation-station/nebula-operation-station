// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// DateKind values (D4): the content date comes from the data, from a
// dated companion source ("proxy:<companion>"), or there is none.
const (
	DateKindData      = "data"
	DateKindNone      = "none"
	DateKindProxyPrfx = "proxy:"
)

// SourceStatus is NOS's verdict on a source named at run start (D5).
type SourceStatus string

// Source verdicts.
const (
	// SourceAccepted: listed, dated, at or above its high-water mark.
	SourceAccepted SourceStatus = "accepted"
	// SourceUndated: listed, content date kind none: stale and raise-only.
	SourceUndated SourceStatus = "undated"
	// SourceRegressed: content date or sequence below the mark.
	SourceRegressed SourceStatus = "regressed"
	// SourceInvalid: content date beyond NOS's clock plus MaxFutureSkew.
	SourceInvalid SourceStatus = "invalid"
	// SourceUnknown: not on NOS's source list.
	SourceUnknown SourceStatus = "unknown"
)

// RunSource is one feed source as a run names it at start.
type RunSource struct {
	ID         string
	SnapshotID string
	Integrity  vulnfinding.IntegrityMode
	// DateKind is DateKindData, DateKindNone or "proxy:<companion>".
	DateKind string
	// ContentDate is the source's content date; zero for DateKindNone.
	ContentDate time.Time
	// Sequence is the bundle sequence where the source has one.
	Sequence *int64
}

// StartRequest starts a run.
type StartRequest struct {
	// TokenID identifies the API token (for audit and the per-token limit).
	TokenID string
	// InventoryGeneration is the generation of the inventory snapshot the
	// run used; InventoryAt is when that snapshot was taken.
	InventoryGeneration int64
	InventoryAt         time.Time
	MatcherVersion      string
	Sources             []RunSource
}

// SourceVerdict is NOS's verdict on one named source.
type SourceVerdict struct {
	ID     string
	Status SourceStatus
	// Stale: past the source's maximum snapshot age, or undated.
	Stale bool
	// Probation: accepted, but on probation after a mark reset (D5):
	// raise-only, and unevidenced closures resting on it are held.
	Probation bool
}

// Run is a started run.
type Run struct {
	ID      string
	Seq     int64
	Started time.Time
	// Sources are the verdicts on the listed sources the run named.
	Sources []SourceVerdict
	// UnknownSources lists at most MaxUnknownSourcesShown unknown IDs;
	// UnknownCount counts all of them.
	UnknownSources []string
	UnknownCount   int
}

var (
	snapshotIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$`)
	matcherVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	tokenIDRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// validateStart checks the run start shape. Every failure is
// ErrMalformedRun and the error never quotes a value.
func (s *Store) validateStart(req StartRequest) error {
	if !tokenIDRe.MatchString(req.TokenID) || !matcherVersionRe.MatchString(req.MatcherVersion) || req.InventoryGeneration < 0 {
		return fmt.Errorf("run metadata: %w", ErrMalformedRun)
	}
	if len(req.Sources) == 0 || len(req.Sources) > len(s.sources) {
		return fmt.Errorf("source count %d: %w", len(req.Sources), ErrMalformedRun)
	}
	seen := make(map[string]struct{}, len(req.Sources))
	for i, src := range req.Sources {
		if !sourceIDRe.MatchString(src.ID) {
			return fmt.Errorf("sources[%d].id: %w", i, ErrMalformedRun)
		}
		if _, dup := seen[src.ID]; dup {
			return fmt.Errorf("sources[%d].id repeated: %w", i, ErrMalformedRun)
		}
		seen[src.ID] = struct{}{}
		if !snapshotIDRe.MatchString(src.SnapshotID) {
			return fmt.Errorf("sources[%d].snapshot_id: %w", i, ErrMalformedRun)
		}
		switch src.Integrity {
		case vulnfinding.IntegritySigned, vulnfinding.IntegrityChecksum, vulnfinding.IntegrityNone:
		default:
			return fmt.Errorf("sources[%d].integrity: %w", i, ErrMalformedRun)
		}
		if src.Sequence != nil && *src.Sequence < 0 {
			return fmt.Errorf("sources[%d].sequence: %w", i, ErrMalformedRun)
		}
		switch {
		case src.DateKind == DateKindData:
		case src.DateKind == DateKindNone:
			if !src.ContentDate.IsZero() {
				return fmt.Errorf("sources[%d].content_date with kind none: %w", i, ErrMalformedRun)
			}
			continue
		case strings.HasPrefix(src.DateKind, DateKindProxyPrfx) && sourceIDRe.MatchString(strings.TrimPrefix(src.DateKind, DateKindProxyPrfx)):
		default:
			return fmt.Errorf("sources[%d].date_kind: %w", i, ErrMalformedRun)
		}
		if src.ContentDate.IsZero() {
			return fmt.Errorf("sources[%d].content_date: %w", i, ErrMalformedRun)
		}
	}
	return nil
}

// StartRun starts a run: it assigns the next run_seq, judges every named
// feed source against the source list and its high-water mark, and moves
// the marks of accepted sources up. A regressed or invalid source does not
// reject the run; it only counts as not accepted for this run.
func (s *Store) StartRun(ctx context.Context, req StartRequest) (Run, error) {
	if err := s.validateStart(req); err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: %w", err)
	}
	now := s.now().UTC()
	if req.InventoryAt.IsZero() || now.Sub(req.InventoryAt) > MaxInventoryAge {
		return Run{}, fmt.Errorf("vulnstore: start run: %w", ErrInventoryTooOld)
	}
	id, err := newRunID()
	if err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: %w", err)
	}
	defer tx.Rollback()

	var seq, maxGen int64
	if err := tx.QueryRowContext(ctx, `SELECT next_run_seq, max_inventory_generation FROM vuln_store_state WHERE id = 1`).Scan(&seq, &maxGen); err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: read state: %w", err)
	}
	if req.InventoryGeneration < maxGen {
		return Run{}, fmt.Errorf("vulnstore: start run: generation %d < %d: %w", req.InventoryGeneration, maxGen, ErrInventoryRegressed)
	}
	var running int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vuln_runs WHERE token_id = ? AND state = 'running' AND started_at > ?`,
		req.TokenID, unix(now.Add(-MaxRunDuration))).Scan(&running); err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: count runs: %w", err)
	}
	if running >= MaxRunningPerToken {
		return Run{}, fmt.Errorf("vulnstore: start run: %w", ErrTooManyRuns)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_store_state SET next_run_seq = ?, max_inventory_generation = ? WHERE id = 1`,
		seq+1, max(maxGen, req.InventoryGeneration)); err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: update state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_runs (id, run_seq, token_id, inventory_generation, matcher_version, state, started_at)
		VALUES (?, ?, ?, ?, ?, 'running', ?)`, id, seq, req.TokenID, req.InventoryGeneration, req.MatcherVersion, unix(now)); err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: insert: %w", err)
	}

	run := Run{ID: id, Seq: seq, Started: fromUnix(unix(now))}
	for _, src := range req.Sources {
		v, err := s.judgeSource(ctx, tx, src, now)
		if err != nil {
			return Run{}, fmt.Errorf("vulnstore: start run: %w", err)
		}
		if v.Status == SourceUnknown {
			run.UnknownCount++
			if len(run.UnknownSources) < MaxUnknownSourcesShown {
				run.UnknownSources = append(run.UnknownSources, src.ID)
			}
		} else {
			run.Sources = append(run.Sources, v)
		}
		var cd, sq any
		if !src.ContentDate.IsZero() {
			cd = unix(src.ContentDate)
		}
		if src.Sequence != nil {
			sq = *src.Sequence
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_run_sources (run_id, source_id, snapshot_id, integrity, date_kind, content_date, sequence, status, stale, probation)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, src.ID, src.SnapshotID, string(src.Integrity), src.DateKind, cd, sq, string(v.Status), boolInt(v.Stale),
			boolInt(v.Probation)); err != nil {
			return Run{}, fmt.Errorf("vulnstore: start run: insert source: %w", err)
		}
	}
	rep := runReport{UnknownSources: run.UnknownSources, UnknownCount: run.UnknownCount}
	if err := saveReport(ctx, tx, id, rep); err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("vulnstore: start run: commit: %w", err)
	}
	return run, nil
}

// judgeSource returns the verdict on one source and moves its mark up when
// accepted. An invalid (future) date is never stored as a mark.
func (s *Store) judgeSource(ctx context.Context, tx *sql.Tx, src RunSource, now time.Time) (SourceVerdict, error) {
	spec, listed := s.sources[src.ID]
	if !listed {
		return SourceVerdict{ID: src.ID, Status: SourceUnknown, Stale: true}, nil
	}
	if src.DateKind == DateKindNone {
		return SourceVerdict{ID: src.ID, Status: SourceUndated, Stale: true}, nil
	}
	if src.ContentDate.After(now.Add(MaxFutureSkew)) {
		return SourceVerdict{ID: src.ID, Status: SourceInvalid, Stale: true}, nil
	}
	var markDate, markSeq, preDate, preSeq sql.NullInt64
	var probation int
	err := tx.QueryRowContext(ctx, `SELECT content_date, sequence, probation, pre_reset_date, pre_reset_sequence FROM vuln_source_marks WHERE source_id = ?`,
		src.ID).Scan(&markDate, &markSeq, &probation, &preDate, &preSeq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SourceVerdict{}, fmt.Errorf("read mark %s: %w", src.ID, err)
	}
	cd := unix(src.ContentDate)
	if markDate.Valid && cd < markDate.Int64 || markSeq.Valid && (src.Sequence == nil || *src.Sequence < markSeq.Int64) {
		return SourceVerdict{ID: src.ID, Status: SourceRegressed, Stale: true}, nil
	}
	// After a mark reset the source stays on probation until a run names
	// it strictly above the pre-reset mark, in every component that mark
	// has (D5); meanwhile it is accepted but raise-only and its unevidenced
	// closures are held.
	//
	// Reading of the ADR wording "content date or sequence" (deliberate,
	// stricter): a run passes only if it is strictly above the pre-reset
	// mark in every component that mark has, so for a source with both a
	// date and a sequence the run must pass both. Passing only one would
	// let a replay that advances the date alone (or the sequence alone)
	// end probation without passing data NOS had already accepted.
	onProbation := false
	if probation == 1 {
		passed := (!preDate.Valid || cd > preDate.Int64) &&
			(!preSeq.Valid || src.Sequence != nil && *src.Sequence > preSeq.Int64)
		onProbation = !passed
	}
	newDate := cd
	if markDate.Valid && markDate.Int64 > newDate {
		newDate = markDate.Int64
	}
	var newSeq any
	if src.Sequence != nil {
		newSeq = *src.Sequence
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_source_marks (source_id, content_date, sequence, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (source_id) DO UPDATE SET content_date = excluded.content_date,
			sequence = COALESCE(excluded.sequence, vuln_source_marks.sequence), updated_at = excluded.updated_at`,
		src.ID, newDate, newSeq, unix(now)); err != nil {
		return SourceVerdict{}, fmt.Errorf("update mark %s: %w", src.ID, err)
	}
	if probation == 1 && !onProbation {
		if _, err := tx.ExecContext(ctx, `UPDATE vuln_source_marks SET probation = 0, pre_reset_date = NULL, pre_reset_sequence = NULL
			WHERE source_id = ?`, src.ID); err != nil {
			return SourceVerdict{}, fmt.Errorf("end probation %s: %w", src.ID, err)
		}
	}
	stale := now.Sub(src.ContentDate) > spec.MaxAge
	return SourceVerdict{ID: src.ID, Status: SourceAccepted, Stale: stale, Probation: onProbation}, nil
}

// runSourceInfo is a run's view of one named source.
type runSourceInfo struct {
	status    SourceStatus
	stale     bool
	probation bool
}

func loadRunSources(ctx context.Context, q queryer, runID string) (map[string]runSourceInfo, error) {
	rows, err := q.QueryContext(ctx, `SELECT source_id, status, stale, probation FROM vuln_run_sources WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("load run sources: %w", err)
	}
	defer rows.Close()
	out := make(map[string]runSourceInfo)
	for rows.Next() {
		var id, status string
		var stale, probation int
		if err := rows.Scan(&id, &status, &stale, &probation); err != nil {
			return nil, fmt.Errorf("load run sources: %w", err)
		}
		out[id] = runSourceInfo{status: SourceStatus(status), stale: stale == 1, probation: probation == 1}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load run sources: %w", err)
	}
	return out, nil
}

// runRow is a stored run.
type runRow struct {
	id        string
	seq       int64
	state     string
	started   time.Time
	rejected  bool
	findings  int
	tokenID   string
	reportRaw string
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func loadRun(ctx context.Context, q queryer, id string) (runRow, error) {
	var r runRow
	var started int64
	var rej int
	err := q.QueryRowContext(ctx, `SELECT id, run_seq, state, started_at, batch_rejected, finding_count, token_id, report FROM vuln_runs WHERE id = ?`, id).
		Scan(&r.id, &r.seq, &r.state, &started, &rej, &r.findings, &r.tokenID, &r.reportRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return runRow{}, ErrRunNotFound
	}
	if err != nil {
		return runRow{}, fmt.Errorf("load run: %w", err)
	}
	r.started = fromUnix(started)
	r.rejected = rej == 1
	return r, nil
}

// checkRunning returns ErrRunNotRunning for a run that is not running or
// is completing or, for a run past MaxRunDuration, aborts it and returns
// ErrRunExpired. The abort is committed by the caller's transaction. A
// completing run is never aborted: its closures are partly applied and
// only finishing the complete makes them whole.
func (s *Store) checkRunning(ctx context.Context, tx *sql.Tx, r runRow, now time.Time) error {
	if r.state != "running" || parseReport(r.reportRaw).Completing != nil {
		return ErrRunNotRunning
	}
	if now.Sub(r.started) > MaxRunDuration {
		if _, err := tx.ExecContext(ctx, `UPDATE vuln_runs SET state = 'aborted', ended_at = ? WHERE id = ?`, unix(now), r.id); err != nil {
			return fmt.Errorf("abort run: %w", err)
		}
		return ErrRunExpired
	}
	return nil
}

// AbortExpiredRuns aborts every run past MaxRunDuration (no closures) and
// returns how many it aborted. A completing run is left for the complete
// to finish (see checkRunning).
func (s *Store) AbortExpiredRuns(ctx context.Context) (int, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("vulnstore: abort expired runs: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE vuln_runs SET state = 'aborted', ended_at = ? WHERE state = 'running' AND started_at < ?
		AND json_extract(report, '$.completing') IS NULL`,
		unix(now), unix(now.Add(-MaxRunDuration)))
	if err != nil {
		return 0, fmt.Errorf("vulnstore: abort expired runs: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("vulnstore: abort expired runs: commit: %w", err)
	}
	return int(n), nil
}

// IgnoredChange is one change a raise-only record could not apply (D5),
// listed in the run report.
type IgnoredChange struct {
	Key   string `json:"key"`
	Field string `json:"field"`
}

// runReport is the stored run report. It holds only NOS-checked values:
// pattern-checked IDs, hex keys, field names and counts.
type runReport struct {
	UnknownSources []string        `json:"unknown_sources,omitempty"`
	UnknownCount   int             `json:"unknown_count,omitempty"`
	Ignored        []IgnoredChange `json:"ignored,omitempty"`
	IgnoredCount   int             `json:"ignored_count,omitempty"`
	Downgrades     int             `json:"downgrades,omitempty"`
	Completion     *Completion     `json:"completion,omitempty"`
	// Completing is set while a complete is being applied in several
	// transactions (see Complete); the run takes no batches meanwhile.
	Completing *completeProgress `json:"completing,omitempty"`
}

func parseReport(raw string) runReport {
	var r runReport
	// The report is written only by this package; a broken one restarts
	// empty rather than failing the run.
	_ = json.Unmarshal([]byte(raw), &r)
	return r
}

func saveReport(ctx context.Context, tx *sql.Tx, runID string, r runReport) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_runs SET report = ? WHERE id = ?`, string(b), runID); err != nil {
		return fmt.Errorf("save report: %w", err)
	}
	return nil
}

func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("run id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

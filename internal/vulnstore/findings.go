// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// State is a D6 finding state.
type State string

// Finding states (D6).
const (
	StateOpen          State = "open"
	StateFixed         State = "fixed"
	StateAcceptedRisk  State = "accepted_risk"
	StateFalsePositive State = "false_positive"
)

// ClosedBy says which closure path closed a fixed finding (D6).
type ClosedBy string

// Closure sources (D6).
const (
	ClosedByNOSInventory      ClosedBy = "nos_inventory"
	ClosedBySubjectRemoved    ClosedBy = "subject_removed"
	ClosedByHermesUnconfirmed ClosedBy = "hermes_unconfirmed"
	ClosedByAdminConfirmed    ClosedBy = "admin_confirmed"
)

// NoteVersionUnchanged labels an unconfirmed closure of a checkable finding
// without episode fixed version whose NOS basis version is unchanged.
const NoteVersionUnchanged = "nos_version_unchanged"

// HumanState is the admin decision behind accepted_risk or false_positive.
type HumanState struct {
	By       string
	Reason   string
	Category string
	// BasisVersion is the D4 version basis the decision is bound to.
	BasisVersion string
	// Expires is set for accepted_risk only.
	Expires time.Time
	At      time.Time
	// KEVAtDecision: the episode was KEV-listed when the decision was made.
	KEVAtDecision bool
}

// Finding is a stored finding.
type Finding struct {
	Key     vulnfinding.Key
	Subject Subject
	// Record holds the current values; Assessment.Text is empty once
	// retention removed it.
	Record     vulnfinding.Record
	NOSChecked bool
	State      State
	ClosedBy   ClosedBy
	ClosedNote string
	ClosedAt   time.Time
	// ClosedAdmin and ClosedReason are set for admin_confirmed.
	ClosedAdmin  string
	ClosedReason string
	// StateRunSeq is the run_seq of the run that last wrote the finding.
	StateRunSeq int64
	// Rev counts every write.
	Rev                 int64
	Episode             int64
	EpisodeOpenedAt     time.Time
	EpisodeOpenedRunSeq int64
	// EpisodeFixedVersion is the highest fixed version of the episode;
	// empty when the episode never had one.
	EpisodeFixedVersion string
	// EpisodeKEVDate is the earliest KEV date added in the episode; empty
	// when the episode was never KEV-listed.
	EpisodeKEVDate  string
	EpisodePeakTier Tier
	FirstSeen       time.Time
	LastSeen        time.Time
	Updated         time.Time
	// Human is set for accepted_risk and false_positive.
	Human *HumanState
}

// EpisodeKEV reports whether the episode was ever KEV-listed.
func (f Finding) EpisodeKEV() bool { return f.EpisodeKEVDate != "" }

const findingColumns = `finding_key, subject_kind, record, assessment, nos_checked, state, closed_by, closed_note, closed_at,
	closed_admin, closed_reason, state_run_seq, rev, episode, episode_opened_at, episode_opened_run_seq,
	episode_fixed_version, episode_kev_date, episode_peak_tier, first_seen_at, last_seen_at, updated_at,
	human_by, human_reason, human_category, human_expires_at, human_basis_version, human_kev, human_at`

type scanner interface{ Scan(dest ...any) error }

func scanFinding(sc scanner) (Finding, error) {
	var (
		f                                                                Finding
		key                                                              []byte
		kind, record, state                                              string
		assessment, closedBy, closedAdmin, closedReason, fixedV, kevDate sql.NullString
		humanBy, humanReason, humanCat, humanBasis                       sql.NullString
		closedAt, humanExp, humanKEV, humanAt                            sql.NullInt64
		nosChecked                                                       int
		openedAt, first, last, updated, tier                             int64
	)
	if err := sc.Scan(&key, &kind, &record, &assessment, &nosChecked, &state, &closedBy, &f.ClosedNote, &closedAt,
		&closedAdmin, &closedReason, &f.StateRunSeq, &f.Rev, &f.Episode, &openedAt, &f.EpisodeOpenedRunSeq,
		&fixedV, &kevDate, &tier, &first, &last, &updated,
		&humanBy, &humanReason, &humanCat, &humanExp, &humanBasis, &humanKEV, &humanAt); err != nil {
		return Finding{}, err
	}
	if len(key) != len(f.Key) {
		return Finding{}, fmt.Errorf("stored key length %d", len(key))
	}
	copy(f.Key[:], key)
	if err := json.Unmarshal([]byte(record), &f.Record); err != nil {
		return Finding{}, fmt.Errorf("decode stored record %s: %w", f.Key, err)
	}
	f.Record.Assessment.Text = assessment.String
	f.Subject = SubjectOf(f.Record)
	f.NOSChecked = nosChecked == 1
	f.State = State(state)
	f.ClosedBy = ClosedBy(closedBy.String)
	if closedAt.Valid {
		f.ClosedAt = fromUnix(closedAt.Int64)
	}
	f.ClosedAdmin, f.ClosedReason = closedAdmin.String, closedReason.String
	f.EpisodeOpenedAt = fromUnix(openedAt)
	f.EpisodeFixedVersion, f.EpisodeKEVDate = fixedV.String, kevDate.String
	f.EpisodePeakTier = Tier(tier)
	f.FirstSeen, f.LastSeen, f.Updated = fromUnix(first), fromUnix(last), fromUnix(updated)
	if humanBy.Valid {
		h := &HumanState{By: humanBy.String, Reason: humanReason.String, Category: humanCat.String,
			BasisVersion: humanBasis.String, KEVAtDecision: humanKEV.Int64 == 1}
		if humanExp.Valid {
			h.Expires = fromUnix(humanExp.Int64)
		}
		if humanAt.Valid {
			h.At = fromUnix(humanAt.Int64)
		}
		f.Human = h
	}
	return f, nil
}

func loadFinding(ctx context.Context, q queryer, key vulnfinding.Key) (Finding, error) {
	f, err := scanFinding(q.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM vuln_findings WHERE finding_key = ?`, key[:]))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrFindingNotFound
	}
	if err != nil {
		return Finding{}, fmt.Errorf("load finding: %w", err)
	}
	return f, nil
}

// Get returns the finding with key.
func (s *Store) Get(ctx context.Context, key vulnfinding.Key) (Finding, error) {
	f, err := loadFinding(ctx, s.db, key)
	if err != nil {
		return Finding{}, fmt.Errorf("vulnstore: get %s: %w", key, err)
	}
	return f, nil
}

// SubjectFindings returns the findings of one subject, in key order.
func (s *Store) SubjectFindings(ctx context.Context, subj Subject) ([]Finding, error) {
	return queryFindings(ctx, s.db, `SELECT `+findingColumns+` FROM vuln_findings WHERE subject = ? ORDER BY finding_key`, subj.String())
}

func queryFindings(ctx context.Context, q queryer, query string, args ...any) ([]Finding, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("vulnstore: query findings: %w", err)
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("vulnstore: query findings: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnstore: query findings: %w", err)
	}
	return out, nil
}

// encodeRecord returns the stored record JSON (without assessment text)
// and the text apart.
func encodeRecord(r vulnfinding.Record) (string, any, error) {
	text := r.Assessment.Text
	r.Assessment.Text = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", nil, fmt.Errorf("encode record: %w", err)
	}
	if text == "" {
		return string(b), nil, nil
	}
	return string(b), text, nil
}

// marks are the episode high-water marks.
type marks struct {
	fixed string
	kev   string
	tier  Tier
}

// raiseMarks returns m raised by the applied record r. Marks never fall
// inside an episode. A fixed version that cannot be compared in the
// ecosystem's scheme never replaces an existing mark.
func raiseMarks(m marks, r vulnfinding.Record, t Tier) marks {
	if r.Fix.State == vulnfinding.FixFixed && r.Fix.Version != "" {
		if m.fixed == "" {
			m.fixed = r.Fix.Version
		} else if higherVersion(r.Ecosystem, r.Fix.Version, m.fixed) {
			m.fixed = r.Fix.Version
		}
	}
	if r.Scores.KEV != nil && (m.kev == "" || r.Scores.KEV.DateAdded < m.kev) {
		m.kev = r.Scores.KEV.DateAdded
	}
	if t > m.tier {
		m.tier = t
	}
	return m
}

// higherVersion reports whether a > b in the ecosystem's version scheme;
// false when the ecosystem has no scheme or a version does not parse.
func higherVersion(ecosystem, a, b string) bool {
	sch, err := vulnver.SchemeForEcosystem(ecosystem)
	if err != nil {
		return false
	}
	c, err := vulnver.Compare(sch, a, b)
	return err == nil && c > 0
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) insertFinding(ctx context.Context, tx *sql.Tx, run runRow, subj Subject, it Item, now time.Time) error {
	rec := it.Finding.Record
	t := s.tier(subj, rec)
	m := raiseMarks(marks{}, rec, t)
	js, text, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	n := unix(now)
	_, err = tx.ExecContext(ctx, `INSERT INTO vuln_findings (finding_key, subject, subject_kind, record, assessment, nos_checked, state,
		state_run_seq, episode_opened_at, episode_opened_run_seq, episode_fixed_version, episode_kev_date, episode_peak_tier,
		first_seen_at, last_seen_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		it.Finding.Key[:], subj.String(), string(subj.Kind), js, text, boolInt(it.NOSChecked),
		run.seq, n, run.seq, nullStr(m.fixed), nullStr(m.kev), int(m.tier), n, n, n)
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return logHistory(ctx, tx, it.Finding.Key, subj.String(), n, run.seq, EventOpened, false, "")
}

// reopenFinding re-opens a fixed finding: a new episode whose current
// values and marks are those of the record, even where they are lower than
// the closed episode's (D5).
func (s *Store) reopenFinding(ctx context.Context, tx *sql.Tx, run runRow, subj Subject, cur Finding, it Item, now time.Time) error {
	rec := it.Finding.Record
	t := s.tier(subj, rec)
	m := raiseMarks(marks{}, rec, t)
	js, text, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	n := unix(now)
	_, err = tx.ExecContext(ctx, `UPDATE vuln_findings SET record = ?, assessment = ?, nos_checked = ?, state = 'open',
		closed_by = NULL, closed_note = '', closed_at = NULL, closed_admin = NULL, closed_reason = NULL,
		state_run_seq = ?, rev = rev + 1, episode = episode + 1, episode_opened_at = ?, episode_opened_run_seq = ?,
		episode_fixed_version = ?, episode_kev_date = ?, episode_peak_tier = ?, last_seen_at = ?, updated_at = ?
		WHERE finding_key = ? AND state = 'fixed' AND state_run_seq <= ?`,
		js, text, boolInt(it.NOSChecked), run.seq, n, run.seq, nullStr(m.fixed), nullStr(m.kev), int(m.tier), n, n,
		cur.Key[:], run.seq)
	if err != nil {
		return fmt.Errorf("reopen finding: %w", err)
	}
	// Holds of the closed episode no longer apply.
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE finding_key = ?`, cur.Key[:]); err != nil {
		return fmt.Errorf("reopen finding: drop holds: %w", err)
	}
	return logHistory(ctx, tx, cur.Key, subj.String(), n, run.seq, EventReopened, false, "")
}

// updateFinding applies a record to an open or human-state finding. The
// state never changes here: no run changes accepted_risk or false_positive.
func (s *Store) updateFinding(ctx context.Context, tx *sql.Tx, run runRow, subj Subject, cur Finding, it Item, raise bool, now time.Time, res *BatchResult) error {
	in := it.Finding.Record
	out := in
	keyHex := cur.Key.String()
	if raise {
		var ignored []string
		out, ignored = mergeRaiseOnly(cur.Record, in)
		for _, field := range ignored {
			res.Ignored = append(res.Ignored, IgnoredChange{Key: keyHex, Field: field})
		}
	}
	n := unix(now)
	if !raise {
		// Drops inside an episode are applied as current values (the
		// episode marks keep them for closure checks) and are written to
		// the finding history; the caller audits BatchResult.Dropped.
		var drops []HistoryEvent
		if cur.Record.Scores.KEV != nil && in.Scores.KEV == nil {
			drops = append(drops, EventKEVDropped)
		}
		if s.tier(subj, in) < s.tier(subj, cur.Record) {
			drops = append(drops, EventTierFell)
		}
		for _, ev := range drops {
			res.Downgrades++
			res.Dropped = append(res.Dropped, IgnoredChange{Key: keyHex, Field: string(ev)})
			if err := logHistory(ctx, tx, cur.Key, subj.String(), n, run.seq, ev, false, ""); err != nil {
				return err
			}
		}
	}
	t := s.tier(subj, out)
	m := raiseMarks(marks{fixed: cur.EpisodeFixedVersion, kev: cur.EpisodeKEVDate, tier: cur.EpisodePeakTier}, out, t)
	js, text, err := encodeRecord(out)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE vuln_findings SET record = ?, assessment = ?, nos_checked = ?, state_run_seq = ?, rev = rev + 1,
		episode_fixed_version = ?, episode_kev_date = ?, episode_peak_tier = ?, last_seen_at = ?, updated_at = ?
		WHERE finding_key = ? AND state_run_seq <= ?`,
		js, text, boolInt(it.NOSChecked), run.seq, nullStr(m.fixed), nullStr(m.kev), int(m.tier), n, n, cur.Key[:], run.seq)
	if err != nil {
		return fmt.Errorf("update finding: %w", err)
	}
	return nil
}

// mergeRaiseOnly applies from in only what raises the stake (D5): a higher
// fixed version (or a fixed version where there was none), a KEV flag the
// finding lacked, a higher CVSS or EPSS. It never lowers or clears the
// fixed version, the KEV flag or a score and never replaces the
// assessment; each such change is returned as an ignored field. Context
// fields (installed version, binaries, aliases, matcher) follow in; basis
// sources become the union, so a closure must cover all of them.
func mergeRaiseOnly(cur, in vulnfinding.Record) (vulnfinding.Record, []string) {
	out := in
	var ignored []string

	out.Fix, out.TrackerState = cur.Fix, cur.TrackerState
	switch {
	case in.Fix == cur.Fix:
	case in.Fix.State == vulnfinding.FixFixed && cur.Fix.State != vulnfinding.FixFixed:
		out.Fix, out.TrackerState = in.Fix, in.TrackerState
	case in.Fix.State == vulnfinding.FixFixed && higherVersion(in.Ecosystem, in.Fix.Version, cur.Fix.Version):
		out.Fix, out.TrackerState = in.Fix, in.TrackerState
	default:
		ignored = append(ignored, "fix")
	}

	out.Scores.KEV = cur.Scores.KEV
	if in.Scores.KEV != nil && cur.Scores.KEV == nil {
		out.Scores.KEV = in.Scores.KEV
	} else if in.Scores.KEV == nil && cur.Scores.KEV != nil {
		ignored = append(ignored, "kev")
	}

	out.Scores.CVSS = cur.Scores.CVSS
	switch {
	case in.Scores.CVSS != nil && (cur.Scores.CVSS == nil || in.Scores.CVSS.BaseScore > cur.Scores.CVSS.BaseScore):
		out.Scores.CVSS = in.Scores.CVSS
	case cur.Scores.CVSS != nil && (in.Scores.CVSS == nil || in.Scores.CVSS.BaseScore < cur.Scores.CVSS.BaseScore):
		ignored = append(ignored, "cvss")
	}

	out.Scores.EPSS = cur.Scores.EPSS
	switch {
	case in.Scores.EPSS != nil && (cur.Scores.EPSS == nil || in.Scores.EPSS.Probability > cur.Scores.EPSS.Probability):
		out.Scores.EPSS = in.Scores.EPSS
	case cur.Scores.EPSS != nil && (in.Scores.EPSS == nil || in.Scores.EPSS.Probability < cur.Scores.EPSS.Probability):
		ignored = append(ignored, "epss")
	}

	out.Assessment = cur.Assessment
	if in.Assessment != cur.Assessment {
		ignored = append(ignored, "assessment")
	}

	out.Evidence.BasisSources = unionSources(cur.Evidence.BasisSources, in.Evidence.BasisSources)
	return out, ignored
}

// unionSources returns a followed by the sources of b not in a, at most
// vulnfinding.MaxBasisSources entries; when the cap is hit a's entries win.
func unionSources(a, b []vulnfinding.BasisSource) []vulnfinding.BasisSource {
	out := append([]vulnfinding.BasisSource(nil), a...)
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s.SourceID] = true
	}
	for _, s := range b {
		if !seen[s.SourceID] && len(out) < vulnfinding.MaxBasisSources {
			out = append(out, s)
			seen[s.SourceID] = true
		}
	}
	return out
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// False-positive categories (D6).
const (
	CategoryBackportFixed     = "backport_fixed"
	CategoryNotAffectedConfig = "not_affected_config"
	CategoryComponentNotUsed  = "component_not_used"
	CategoryVendorDisputed    = "vendor_disputed"
	CategoryOther             = "other"
)

// Admin names and version bases are bounded to 128 bytes by their patterns
// (and by the table checks).
var (
	actorRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)
	basisVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
)

// AcceptRisk is an admin's accepted_risk decision. The caller has checked
// that the actor is the maintainer (admin) with a fresh WebAuthn assertion
// (Q4) and audits the change.
type AcceptRisk struct {
	Approver string
	Reason   string
	// Expires defaults to now plus DefaultAcceptExpiry; at most
	// MaxAcceptExpiry ahead.
	Expires time.Time
	// BasisVersion is the D4 version basis the decision is bound to.
	BasisVersion string
}

// MarkFalsePositive is an admin's false_positive decision (same caller
// duties as AcceptRisk).
type MarkFalsePositive struct {
	By           string
	Category     string
	Reason       string
	BasisVersion string
}

func checkReason(reason string) error {
	if reason == "" || len(reason) > MaxHumanReason || !utf8.ValidString(reason) {
		return fmt.Errorf("reason: %w", ErrInvalidInput)
	}
	return nil
}

func checkActor(a string) error {
	if !actorRe.MatchString(a) {
		return fmt.Errorf("actor: %w", ErrInvalidInput)
	}
	return nil
}

// SetAcceptedRisk moves an open finding to accepted_risk.
func (s *Store) SetAcceptedRisk(ctx context.Context, key vulnfinding.Key, a AcceptRisk) error {
	now := s.now().UTC()
	if err := checkActor(a.Approver); err != nil {
		return fmt.Errorf("vulnstore: accept risk: %w", err)
	}
	if err := checkReason(a.Reason); err != nil {
		return fmt.Errorf("vulnstore: accept risk: %w", err)
	}
	if !basisVersionRe.MatchString(a.BasisVersion) {
		return fmt.Errorf("vulnstore: accept risk: basis version: %w", ErrInvalidInput)
	}
	exp := a.Expires
	if exp.IsZero() {
		exp = now.Add(DefaultAcceptExpiry)
	}
	if !exp.After(now) || exp.Sub(now) > MaxAcceptExpiry {
		return fmt.Errorf("vulnstore: accept risk: expiry: %w", ErrInvalidInput)
	}
	return s.setHuman(ctx, key, StateAcceptedRisk, a.Approver, a.Reason, nil, unix(exp), a.BasisVersion, now)
}

// SetFalsePositive moves an open finding to false_positive.
func (s *Store) SetFalsePositive(ctx context.Context, key vulnfinding.Key, m MarkFalsePositive) error {
	now := s.now().UTC()
	if err := checkActor(m.By); err != nil {
		return fmt.Errorf("vulnstore: false positive: %w", err)
	}
	if err := checkReason(m.Reason); err != nil {
		return fmt.Errorf("vulnstore: false positive: %w", err)
	}
	switch m.Category {
	case CategoryBackportFixed, CategoryNotAffectedConfig, CategoryComponentNotUsed, CategoryVendorDisputed, CategoryOther:
	default:
		return fmt.Errorf("vulnstore: false positive: category: %w", ErrInvalidInput)
	}
	if !basisVersionRe.MatchString(m.BasisVersion) {
		return fmt.Errorf("vulnstore: false positive: basis version: %w", ErrInvalidInput)
	}
	return s.setHuman(ctx, key, StateFalsePositive, m.By, m.Reason, m.Category, nil, m.BasisVersion, now)
}

func (s *Store) setHuman(ctx context.Context, key vulnfinding.Key, st State, by, reason string, category, expires any, basis string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return fmt.Errorf("vulnstore: set %s: %w", st, err)
	}
	defer tx.Rollback()
	f, err := loadFinding(ctx, tx, key)
	if err != nil {
		return fmt.Errorf("vulnstore: set %s: %w", st, err)
	}
	if f.State != StateOpen {
		return fmt.Errorf("vulnstore: set %s from %s: %w", st, f.State, ErrWrongState)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_findings SET state = ?, human_by = ?, human_reason = ?, human_category = ?,
		human_expires_at = ?, human_basis_version = ?, human_kev = ?, human_at = ?, rev = rev + 1, updated_at = ?
		WHERE finding_key = ?`, string(st), by, reason, category, expires, basis, boolInt(f.EpisodeKEV()), unix(now), unix(now), key[:]); err != nil {
		return fmt.Errorf("vulnstore: set %s: %w", st, err)
	}
	if err := logHistory(ctx, tx, key, f.Subject.String(), unix(now), 0, EventHumanSet, true, ""); err != nil {
		return fmt.Errorf("vulnstore: set %s: %w", st, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("vulnstore: set %s: commit: %w", st, err)
	}
	return nil
}

// BasisFunc returns NOS's current D4 version basis of a finding's
// component (source:Version, or the mapped running kernel). known is false
// when NOS cannot tell ("kernel version unknown", component not read).
type BasisFunc func(ctx context.Context, f Finding) (version string, known bool, err error)

// ReopenReason says why a human state re-opened.
type ReopenReason string

// Re-open reasons (D6).
const (
	ReopenExpired      ReopenReason = "expired"
	ReopenKEV          ReopenReason = "kev_listed"
	ReopenBasisChanged ReopenReason = "basis_changed"
	ReopenBasisUnknown ReopenReason = "basis_unknown"
)

// Reopened is one human state ReviewHumanStates re-opened.
type Reopened struct {
	Key    vulnfinding.Key
	Reason ReopenReason
}

// ReviewHumanStates re-opens accepted_risk findings that expired or became
// KEV-listed, and every accepted_risk or false_positive finding whose
// version basis changed or became unknown (D6). This is NOS's own sweep,
// never part of a run.
func (s *Store) ReviewHumanStates(ctx context.Context, basis BasisFunc) ([]Reopened, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := queryFindings(ctx, s.db, `SELECT `+findingColumns+` FROM vuln_findings
		WHERE state IN ('accepted_risk', 'false_positive') ORDER BY finding_key`)
	if err != nil {
		return nil, err
	}
	var out []Reopened
	for _, f := range list {
		var reason ReopenReason
		switch {
		case f.State == StateAcceptedRisk && !now.Before(f.Human.Expires):
			reason = ReopenExpired
		case f.State == StateAcceptedRisk && f.EpisodeKEV() && !f.Human.KEVAtDecision:
			reason = ReopenKEV
		default:
			v, known, err := basis(ctx, f)
			switch {
			case err != nil || !known:
				reason = ReopenBasisUnknown
			case v != f.Human.BasisVersion:
				reason = ReopenBasisChanged
			}
		}
		if reason == "" {
			continue
		}
		ok, err := s.reopenHuman(ctx, f, now)
		if err != nil {
			return out, err
		}
		if ok {
			out = append(out, Reopened{Key: f.Key, Reason: reason})
		}
	}
	return out, nil
}

func (s *Store) reopenHuman(ctx context.Context, f Finding, now time.Time) (bool, error) {
	tx, err := s.writeTx(ctx)
	if err != nil {
		return false, fmt.Errorf("vulnstore: reopen human state: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE vuln_findings SET state = 'open', human_by = NULL, human_reason = NULL, human_category = NULL,
		human_expires_at = NULL, human_basis_version = NULL, human_kev = NULL, human_at = NULL, rev = rev + 1, updated_at = ?
		WHERE finding_key = ? AND rev = ?`, unix(now), f.Key[:], f.Rev)
	if err != nil {
		return false, fmt.Errorf("vulnstore: reopen human state: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		if err := logHistory(ctx, tx, f.Key, f.Subject.String(), unix(now), 0, EventHumanReopened, false, ""); err != nil {
			return false, fmt.Errorf("vulnstore: reopen human state: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("vulnstore: reopen human state: commit: %w", err)
	}
	return n == 1, nil
}

// Hold is a held run closure.
type Hold struct {
	RunID   string
	RunSeq  int64
	Key     vulnfinding.Key
	Subject string
	Reason  HoldReason
	Created time.Time
}

// Holds returns the held closures of a finding.
func (s *Store) Holds(ctx context.Context, key vulnfinding.Key) ([]Hold, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT run_id, run_seq, subject, reason, created_at FROM vuln_held_closures
		WHERE finding_key = ? ORDER BY run_seq`, key[:])
	if err != nil {
		return nil, fmt.Errorf("vulnstore: holds: %w", err)
	}
	defer rows.Close()
	var out []Hold
	for rows.Next() {
		h := Hold{Key: key}
		var reason string
		var created int64
		if err := rows.Scan(&h.RunID, &h.RunSeq, &h.Subject, &reason, &created); err != nil {
			return nil, fmt.Errorf("vulnstore: holds: %w", err)
		}
		h.Reason, h.Created = HoldReason(reason), fromUnix(created)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnstore: holds: %w", err)
	}
	return out, nil
}

// ConfirmHeld applies closure path 6: an admin (Q4 assertion rule, checked
// by the caller) confirms a held closure. In one transaction NOS re-checks
// that the finding's state_run_seq is at most the held run's run_seq, the
// subject watermark still equals it and the finding was not written since
// the hold; otherwise the hold is dropped and ErrHoldSuperseded returned.
// It re-classifies: evidenced closes as nos_inventory, unconfirmed as
// admin_confirmed, contradicted is refused with ErrContradicted (the hold
// stays; the admin may discard it or set a human state).
func (s *Store) ConfirmHeld(ctx context.Context, runID string, key vulnfinding.Key, admin, reason string) (ClosedBy, error) {
	now := s.now().UTC()
	if err := checkActor(admin); err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", err)
	}
	if err := checkReason(reason); err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", err)
	}
	defer tx.Rollback()
	var runSeq, rev int64
	var subject string
	err = tx.QueryRowContext(ctx, `SELECT run_seq, finding_rev, subject FROM vuln_held_closures WHERE run_id = ? AND finding_key = ?`,
		runID, key[:]).Scan(&runSeq, &rev, &subject)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", ErrHoldNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", err)
	}
	f, err := loadFinding(ctx, tx, key)
	if err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", err)
	}
	wm, err := watermark(ctx, tx, subject)
	if err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", err)
	}
	if f.State != StateOpen || f.StateRunSeq > runSeq || wm != runSeq || f.Rev != rev {
		if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE run_id = ? AND finding_key = ?`, runID, key[:]); err != nil {
			return "", fmt.Errorf("vulnstore: confirm hold: drop: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return "", fmt.Errorf("vulnstore: confirm hold: commit: %w", err)
		}
		return "", fmt.Errorf("vulnstore: confirm hold: %w", ErrHoldSuperseded)
	}
	class, err := s.classify.Classify(ctx, f)
	if err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: classify: %w", err)
	}
	by := ClosedByAdminConfirmed
	switch class {
	case ClassEvidenced:
		by = ClosedByNOSInventory
	case ClassContradicted:
		return "", fmt.Errorf("vulnstore: confirm hold: %w", ErrContradicted)
	case ClassUnconfirmed, ClassUnconfirmedUnchanged:
	default:
		return "", fmt.Errorf("vulnstore: confirm hold: class %d: %w", class, ErrInvalidInput)
	}
	var admCol, reasonCol any
	if by == ClosedByAdminConfirmed {
		admCol, reasonCol = admin, reason
	}
	n := unix(now)
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_findings SET state = 'fixed', closed_by = ?, closed_note = '', closed_at = ?,
		closed_admin = ?, closed_reason = ?, rev = rev + 1, updated_at = ? WHERE finding_key = ?`,
		string(by), n, admCol, reasonCol, n, key[:]); err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: close: %w", err)
	}
	// Counted by the window guard when applied (closure row 6).
	if err := logHistory(ctx, tx, key, subject, n, 0, EventClosed, true, by); err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE finding_key = ?`, key[:]); err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: drop: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("vulnstore: confirm hold: commit: %w", err)
	}
	return by, nil
}

// DiscardHeld applies closure path 7 for an admin: the hold is dropped and
// the finding stays open.
func (s *Store) DiscardHeld(ctx context.Context, runID string, key vulnfinding.Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return fmt.Errorf("vulnstore: discard hold: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE run_id = ? AND finding_key = ?`, runID, key[:])
	if err != nil {
		return fmt.Errorf("vulnstore: discard hold: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("vulnstore: discard hold: %w", ErrHoldNotFound)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("vulnstore: discard hold: commit: %w", err)
	}
	return nil
}

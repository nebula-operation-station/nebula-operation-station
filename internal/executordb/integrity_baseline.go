// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Baseline digest errors callers branch on.
var (
	// ErrNoBaselineDigest: the executor holds no approved I2 baseline
	// digest for the host.
	ErrNoBaselineDigest = errors.New("executordb: no approved baseline digest for the host")
	// ErrBaselineDigestStale: the approval was not built on the host's
	// current approved digest (or is an initial approval for a host that
	// already has one, or a non-initial approval for a host without one).
	// Nothing was stored.
	ErrBaselineDigestStale = errors.New("executordb: approval is not built on the approved baseline digest")
)

// BaselineApprovalKind says how a baseline digest was approved (ADR 0015
// D7 "Approval").
type BaselineApprovalKind string

// Approval kinds.
const (
	// BaselineApprovalInitial: `nebula integrity approve --initial` in the
	// executor-local CLI; the host had no approved digest.
	BaselineApprovalInitial BaselineApprovalKind = "initial"
	// BaselineApprovalCLI: `nebula integrity approve` in the
	// executor-local CLI.
	BaselineApprovalCLI BaselineApprovalKind = "cli"
	// BaselineApprovalBrowser: a user-verified browser assertion for a
	// proposal without critical-class changes.
	BaselineApprovalBrowser BaselineApprovalKind = "browser"
)

func (k BaselineApprovalKind) valid() bool {
	switch k {
	case BaselineApprovalInitial, BaselineApprovalCLI, BaselineApprovalBrowser:
		return true
	}
	return false
}

// BaselineDigest is the approved I2 baseline digest of one host, held by
// the executor as tamper evidence for the server-held list (ADR 0015 D7
// item 2).
type BaselineDigest struct {
	HostID string
	// Digest is the lowercase hex SHA-256 of the approved baseline list.
	Digest string
	// PreviousDigest is the approved digest this one replaced; empty for
	// an initial approval.
	PreviousDigest string
	Kind           BaselineApprovalKind
	// ApprovedAt is set by the store.
	ApprovedAt time.Time
}

// ValidBaselineDigest reports whether s is a lowercase hex SHA-256.
func ValidBaselineDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (d BaselineDigest) validate() error {
	if !canonical.ValidHostID(d.HostID) {
		return fmt.Errorf("executordb: %w: baseline digest host_id is malformed", ErrInvalid)
	}
	if !ValidBaselineDigest(d.Digest) {
		return fmt.Errorf("executordb: %w: baseline digest must be lowercase hex SHA-256", ErrInvalid)
	}
	if !d.Kind.valid() {
		return fmt.Errorf("executordb: %w: unknown baseline approval kind", ErrInvalid)
	}
	if d.Kind == BaselineApprovalInitial {
		if d.PreviousDigest != "" {
			return fmt.Errorf("executordb: %w: an initial baseline has no previous digest", ErrInvalid)
		}
		return nil
	}
	if !ValidBaselineDigest(d.PreviousDigest) {
		return fmt.Errorf("executordb: %w: previous baseline digest must be lowercase hex SHA-256", ErrInvalid)
	}
	return nil
}

// StoreApprovedBaselineDigest stores d as the host's approved baseline
// digest and keeps the replaced one as history, in one transaction. It is
// the only writer of baseline digests and is called only by the
// executor's own approval paths; no RPC passes a digest to it.
//
// An initial approval needs a host without any digest; any other approval
// needs d.PreviousDigest to be the host's current approved digest. Both
// are checked inside the transaction, so a concurrent approval cannot be
// overwritten; a violation is ErrBaselineDigestStale and stores nothing.
func (db *DB) StoreApprovedBaselineDigest(d BaselineDigest) (BaselineDigest, error) {
	if err := d.validate(); err != nil {
		return BaselineDigest{}, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return BaselineDigest{}, fmt.Errorf("executordb: store baseline digest for %s: %w", d.HostID, err)
	}
	defer tx.Rollback()

	var active string
	err = tx.QueryRow(`SELECT digest FROM integrity_baseline_digests WHERE host_id = ? AND active = 1`, d.HostID).Scan(&active)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if d.Kind != BaselineApprovalInitial {
			return BaselineDigest{}, fmt.Errorf("%w: host %s has no approved digest", ErrBaselineDigestStale, d.HostID)
		}
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM integrity_baseline_digests WHERE host_id = ?`, d.HostID).Scan(&n); err != nil {
			return BaselineDigest{}, fmt.Errorf("executordb: read baseline digest history for %s: %w", d.HostID, err)
		}
		if n > 0 {
			return BaselineDigest{}, fmt.Errorf("%w: host %s has digest history", ErrBaselineDigestStale, d.HostID)
		}
	case err != nil:
		return BaselineDigest{}, fmt.Errorf("executordb: read baseline digest for %s: %w", d.HostID, err)
	default:
		if d.Kind == BaselineApprovalInitial {
			return BaselineDigest{}, fmt.Errorf("%w: host %s already has an approved digest", ErrBaselineDigestStale, d.HostID)
		}
		if active != d.PreviousDigest {
			return BaselineDigest{}, fmt.Errorf("%w: host %s", ErrBaselineDigestStale, d.HostID)
		}
	}
	now := db.now()
	if _, err := tx.Exec(`UPDATE integrity_baseline_digests SET active = 0, superseded_at = ?
		WHERE host_id = ? AND active = 1`, now.Unix(), d.HostID); err != nil {
		return BaselineDigest{}, fmt.Errorf("executordb: supersede baseline digest for %s: %w", d.HostID, err)
	}
	var prev any
	if d.PreviousDigest != "" {
		prev = d.PreviousDigest
	}
	if _, err := tx.Exec(`INSERT INTO integrity_baseline_digests
		(host_id, digest, previous_digest, approval_kind, approved_at, active) VALUES (?, ?, ?, ?, ?, 1)`,
		d.HostID, d.Digest, prev, string(d.Kind), now.Unix()); err != nil {
		return BaselineDigest{}, fmt.Errorf("executordb: insert baseline digest for %s: %w", d.HostID, err)
	}
	if err := tx.Commit(); err != nil {
		return BaselineDigest{}, fmt.Errorf("executordb: store baseline digest for %s: %w", d.HostID, err)
	}
	d.ApprovedAt = time.Unix(now.Unix(), 0).UTC()
	return d, nil
}

// ApprovedBaselineDigest returns the host's active approved baseline
// digest, or ErrNoBaselineDigest.
func (db *DB) ApprovedBaselineDigest(hostID string) (BaselineDigest, error) {
	if !canonical.ValidHostID(hostID) {
		return BaselineDigest{}, fmt.Errorf("executordb: %w: baseline digest host_id is malformed", ErrInvalid)
	}
	var d BaselineDigest
	var prev sql.NullString
	var kind string
	var at int64
	err := db.sql.QueryRow(`SELECT host_id, digest, previous_digest, approval_kind, approved_at
		FROM integrity_baseline_digests WHERE host_id = ? AND active = 1`, hostID).Scan(
		&d.HostID, &d.Digest, &prev, &kind, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return BaselineDigest{}, ErrNoBaselineDigest
	}
	if err != nil {
		return BaselineDigest{}, fmt.Errorf("executordb: read baseline digest for %s: %w", hostID, err)
	}
	d.PreviousDigest = prev.String
	d.Kind = BaselineApprovalKind(kind)
	d.ApprovedAt = time.Unix(at, 0).UTC()
	if err := d.validate(); err != nil {
		return BaselineDigest{}, fmt.Errorf("executordb: stored baseline digest for %s: %w", hostID, err)
	}
	return d, nil
}

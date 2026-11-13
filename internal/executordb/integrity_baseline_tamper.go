// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Limits of the baseline tamper findings.
const (
	// BaselineTamperAuditInterval is how often a still-open baseline
	// tamper finding of one host is written to the audit log again; the
	// mismatches in between only increase its count.
	BaselineTamperAuditInterval = time.Hour
	// MaxBaselineTamperFindings bounds the findings BaselineTamperFindings
	// returns. There is at most one per host with an approved digest.
	MaxBaselineTamperFindings = 4096
)

// BaselineTamperFinding is the executor-held record of an I2 baseline
// digest mismatch of one host (ADR 0015 D7 "Server compromise",
// `integrity.baseline_tamper`). The executor writes it itself, so a
// compromised server cannot drop it.
type BaselineTamperFinding struct {
	HostID string
	// ApprovedDigest is the executor-held approved digest at the latest
	// mismatch.
	ApprovedDigest string
	// PresentedDigest is the digest the executor recomputed from the
	// server's list at the latest mismatch.
	PresentedDigest string
	// FirstSeen and LastSeen come from the store's clock.
	FirstSeen time.Time
	// LastSeen is the latest mismatch.
	LastSeen time.Time
	// Count counts the mismatches since FirstSeen.
	Count int64
	// Opened says this call opened the finding.
	Opened bool
}

// RecordBaselineTamper records a mismatch between approved, the host's
// executor-held approved digest, and presented, the digest the executor
// recomputed from the server's list. The first mismatch of a host opens
// its finding; later ones update the latest digests and the count. audit
// says the caller writes this mismatch to the audit log: on opening and
// then at most once per BaselineTamperAuditInterval. It never touches the
// approved digest.
func (db *DB) RecordBaselineTamper(hostID, approved, presented string) (_ BaselineTamperFinding, audit bool, _ error) {
	if !canonical.ValidHostID(hostID) || !ValidBaselineDigest(approved) || !ValidBaselineDigest(presented) {
		return BaselineTamperFinding{}, false, fmt.Errorf("executordb: %w: baseline tamper host_id or digest is malformed", ErrInvalid)
	}
	if approved == presented {
		return BaselineTamperFinding{}, false, fmt.Errorf("executordb: %w: equal digests are no baseline tamper", ErrInvalid)
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return BaselineTamperFinding{}, false, fmt.Errorf("executordb: record baseline tamper for %s: %w", hostID, err)
	}
	defer tx.Rollback()

	now := db.now().Unix()
	var first, last, audited, count int64
	err = tx.QueryRow(`SELECT first_seen, last_seen, last_audited, count FROM integrity_baseline_tamper
		WHERE host_id = ?`, hostID).Scan(&first, &last, &audited, &count)
	f := BaselineTamperFinding{HostID: hostID, ApprovedDigest: approved, PresentedDigest: presented}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO integrity_baseline_tamper
			(host_id, approved_digest, presented_digest, first_seen, last_seen, count, last_audited)
			VALUES (?, ?, ?, ?, ?, 1, ?)`, hostID, approved, presented, now, now, now); err != nil {
			return BaselineTamperFinding{}, false, fmt.Errorf("executordb: open baseline tamper for %s: %w", hostID, err)
		}
		f.FirstSeen, f.LastSeen, f.Count, f.Opened, audit = unixUTC(now), unixUTC(now), 1, true, true
	case err != nil:
		return BaselineTamperFinding{}, false, fmt.Errorf("executordb: read baseline tamper for %s: %w", hostID, err)
	default:
		// A clock that steps back neither moves last_seen back nor
		// re-opens the audit window early.
		seen := max(now, last)
		audit = now-audited >= int64(BaselineTamperAuditInterval/time.Second)
		if audit {
			audited = now
		}
		if _, err := tx.Exec(`UPDATE integrity_baseline_tamper SET approved_digest = ?, presented_digest = ?,
			last_seen = ?, count = count + 1, last_audited = ? WHERE host_id = ?`,
			approved, presented, seen, audited, hostID); err != nil {
			return BaselineTamperFinding{}, false, fmt.Errorf("executordb: update baseline tamper for %s: %w", hostID, err)
		}
		f.FirstSeen, f.LastSeen, f.Count = unixUTC(first), unixUTC(seen), count+1
	}
	if err := tx.Commit(); err != nil {
		return BaselineTamperFinding{}, false, fmt.Errorf("executordb: record baseline tamper for %s: %w", hostID, err)
	}
	return f, audit, nil
}

// BaselineTamperFindings returns the open baseline tamper findings ordered
// by host ID, at most MaxBaselineTamperFindings.
func (db *DB) BaselineTamperFindings() ([]BaselineTamperFinding, error) {
	rows, err := db.sql.Query(`SELECT host_id, approved_digest, presented_digest, first_seen, last_seen, count
		FROM integrity_baseline_tamper ORDER BY host_id LIMIT ?`, MaxBaselineTamperFindings)
	if err != nil {
		return nil, fmt.Errorf("executordb: list baseline tamper findings: %w", err)
	}
	defer rows.Close()
	var out []BaselineTamperFinding
	for rows.Next() {
		var f BaselineTamperFinding
		var first, last int64
		if err := rows.Scan(&f.HostID, &f.ApprovedDigest, &f.PresentedDigest, &first, &last, &f.Count); err != nil {
			return nil, fmt.Errorf("executordb: read baseline tamper finding: %w", err)
		}
		f.FirstSeen, f.LastSeen = unixUTC(first), unixUTC(last)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: list baseline tamper findings: %w", err)
	}
	return out, nil
}

func unixUTC(s int64) time.Time { return time.Unix(s, 0).UTC() }

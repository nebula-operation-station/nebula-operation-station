// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// InventoryRead is one NOS read of a subject's installed source packages
// (package.list_installed for hosts, image.packages for images).
type InventoryRead struct {
	Subject Subject
	// Complete is the D3 completeness flag; a failed, truncated or partly
	// unparsed read is not complete and closes nothing.
	Complete bool
	// ReadAt is when the read finished.
	ReadAt time.Time
	// SourceVersions maps source package name to its installed source
	// version (D4 basis: the lowest source:Version of its binaries).
	SourceVersions map[string]string
}

// checkable reports whether NOS re-checks the finding's match basis and
// ecosystem (D4): distro_tracker or osv_range on Debian, Ubuntu or Alpine.
func checkable(r vulnfinding.Record) bool {
	if r.MatchBasis != vulnfinding.MatchDistroTracker && r.MatchBasis != vulnfinding.MatchOSVRange {
		return false
	}
	for _, p := range []string{"debian:", "ubuntu:", "alpine:"} {
		if strings.HasPrefix(r.Ecosystem, p) {
			return true
		}
	}
	return false
}

// CloseByInventory applies closure paths 1 and 2 for one subject: an open,
// checkable, non-kernel finding last written before a complete read closes
// as fixed by nos_inventory when its source package is absent from the
// read (path 2) or installed at or above the episode fixed version (path
// 1). Kernel findings are left to the running-kernel check (D4) and never
// close here. It returns the keys it closed.
func (s *Store) CloseByInventory(ctx context.Context, read InventoryRead) ([]vulnfinding.Key, error) {
	if err := read.Subject.validate(); err != nil {
		return nil, fmt.Errorf("vulnstore: inventory close: %w", err)
	}
	if !read.Complete || read.ReadAt.IsZero() {
		return nil, nil
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("vulnstore: inventory close: %w", err)
	}
	defer tx.Rollback()
	open, err := queryFindings(ctx, tx, `SELECT `+findingColumns+` FROM vuln_findings
		WHERE subject = ? AND state = 'open' AND updated_at < ? ORDER BY finding_key`, read.Subject.String(), unix(read.ReadAt))
	if err != nil {
		return nil, err
	}
	var closed []vulnfinding.Key
	n := unix(now)
	for _, f := range open {
		r := f.Record
		if !checkable(r) || vulnver.IsKernelSource(r.Component.SourcePackage) {
			continue
		}
		installed, present := read.SourceVersions[r.Component.SourcePackage]
		if present {
			if f.EpisodeFixedVersion == "" {
				continue
			}
			sch, err := vulnver.SchemeForEcosystem(r.Ecosystem)
			if err != nil {
				continue
			}
			c, err := vulnver.Compare(sch, installed, f.EpisodeFixedVersion)
			if err != nil || c < 0 {
				continue
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE vuln_findings SET state = 'fixed', closed_by = 'nos_inventory', closed_note = '',
			closed_at = ?, rev = rev + 1, updated_at = ? WHERE finding_key = ? AND rev = ?`, n, n, f.Key[:], f.Rev)
		if err != nil {
			return nil, fmt.Errorf("vulnstore: inventory close: %w", err)
		}
		if k, _ := res.RowsAffected(); k != 1 {
			continue
		}
		if err := logHistory(ctx, tx, f.Key, read.Subject.String(), n, 0, EventClosed, true, ClosedByNOSInventory); err != nil {
			return nil, fmt.Errorf("vulnstore: inventory close: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE finding_key = ?`, f.Key[:]); err != nil {
			return nil, fmt.Errorf("vulnstore: inventory close: drop holds: %w", err)
		}
		closed = append(closed, f.Key)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("vulnstore: inventory close: commit: %w", err)
	}
	return closed, nil
}

// CloseSubjectRemoved applies closure path 3: NOS itself removed the
// subject (an admin deleted the host or device, or a complete Docker read
// of every host that ran the image no longer lists it; the caller checks
// that). Every finding of the subject that is not fixed closes as fixed by
// subject_removed and is then kept for the fixed retention.
func (s *Store) CloseSubjectRemoved(ctx context.Context, subj Subject) (int, error) {
	if err := subj.validate(); err != nil {
		return 0, fmt.Errorf("vulnstore: subject removed: %w", err)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("vulnstore: subject removed: %w", err)
	}
	defer tx.Rollback()
	n := unix(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_finding_history (finding_key, subject, at, event, was_open, is_open, closed_by)
		SELECT finding_key, subject, ?, 'closed', state = 'open', 0, 'subject_removed' FROM vuln_findings
		WHERE subject = ? AND state <> 'fixed' ORDER BY finding_key`, n, subj.String()); err != nil {
		return 0, fmt.Errorf("vulnstore: subject removed: history: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE vuln_findings SET state = 'fixed', closed_by = 'subject_removed', closed_note = '',
		closed_at = ?, human_by = NULL, human_reason = NULL, human_category = NULL, human_expires_at = NULL,
		human_basis_version = NULL, human_kev = NULL, human_at = NULL, rev = rev + 1, updated_at = ?
		WHERE subject = ? AND state <> 'fixed'`, n, n, subj.String())
	if err != nil {
		return 0, fmt.Errorf("vulnstore: subject removed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_held_closures WHERE subject = ?`, subj.String()); err != nil {
		return 0, fmt.Errorf("vulnstore: subject removed: drop holds: %w", err)
	}
	k, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("vulnstore: subject removed: commit: %w", err)
	}
	return int(k), nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"fmt"
	"sort"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
)

// BulkAdmitOpts is the input to BulkAdmit.
type BulkAdmitOpts struct {
	// ConfirmedDigest is the manifest digest the admin confirmed; empty
	// for a dry run (no commit).
	ConfirmedDigest string
	// Pins are the old versions to retain (pin); GC keeps them.
	Pins map[string]bool
	// Retired are the old versions to retire (not pin); GC may collect
	// them.
	Retired []string
	// AdminUID is the UID of the admin who ran the command.
	AdminUID int
}

// ScanFinding is the scanner result for one action.
type ScanFinding struct {
	// Module is the module family.
	Module string
	// ActionID is <family>.<action>.
	ActionID string
	// Findings are the scanner findings for the action's script.
	Findings []scanner.Finding
	// Floor is the highest risk among the findings ("" when clean).
	Floor string
}

// TrustTuple is one old/new trust tuple in the retirement audit.
type TrustTuple struct {
	// Module is the module family.
	Module string
	// OldVersion/OldSHA256 is the active version, empty when new.
	OldVersion, OldSHA256 string
	// NewVersion/NewSHA256 is the candidate's, empty when removed.
	NewVersion, NewSHA256 string
	// Status is the module's review status.
	Status string
}

// BulkAdmitResult is the output of BulkAdmit.
type BulkAdmitResult struct {
	// Review is the local review of the candidate.
	Review Review
	// Scans are the scanner findings for each new/changed action.
	Scans []ScanFinding
	// ManifestDigest is the reviewed manifest digest.
	ManifestDigest string
	// NeedsConfirmation reports whether any module needs confirmation.
	NeedsConfirmation bool
	// OldVersions are the old versions to decide (retain or retire).
	OldVersions []string
	// Committed is true when the commit happened.
	Committed bool
	// AdminUID is the UID of the admin who ran the command.
	AdminUID int
	// Pinned are the old versions retained (pinned).
	Pinned []string
	// Retired are the old versions retired (not pinned).
	Retired []string
	// Collected are the versions collected by GC (Result.Collected).
	Collected []string
	// CleanupFailures is the count of unreferenced objects that could
	// not be deleted (Result.CleanupFailures).
	CleanupFailures int
	// Tuples are the old/new trust tuples.
	Tuples []TrustTuple
}

// BulkAdmit reviews a verified candidate, scans its new/changed actions,
// and (when ConfirmedDigest is set) commits the additions/changes
// atomically, bound to the reviewed manifest digest. A dry run (empty
// ConfirmedDigest) returns the review and scanner findings without
// committing. The retirement audit records the admin UID, each old/new
// trust tuple, the retained/retired old versions, and Result.Collected
// and Result.CleanupFailures; it never carries script contents.
func (s *Store) BulkAdmit(c release.Candidate, o BulkAdmitOpts) (BulkAdmitResult, error) {
	r, err := s.Review(c)
	if err != nil {
		return BulkAdmitResult{}, err
	}
	out := BulkAdmitResult{
		Review:            r,
		ManifestDigest:    r.ManifestDigest,
		NeedsConfirmation: r.NeedsConfirmation(),
	}
	// Scanner floors: scan each new/changed action's script.
	for _, m := range r.Modules {
		if m.Status == StatusRemoved || m.Status == StatusUnchanged {
			continue
		}
		for _, a := range m.Actions {
			if a.Status == StatusUnchanged || a.Status == StatusRemoved {
				continue
			}
			b, ok := scriptBytes(c, m.Name, a.ActionID)
			if !ok {
				continue
			}
			f, floor := scanner.Scan(b)
			out.Scans = append(out.Scans, ScanFinding{Module: m.Name, ActionID: a.ActionID, Findings: f, Floor: string(floor)})
		}
	}
	// Old versions to decide (retain or retire).
	for _, m := range r.Modules {
		if m.OldVersion == "" || m.Status == StatusUnchanged {
			continue
		}
		out.OldVersions = append(out.OldVersions, m.Name+"@"+m.OldVersion)
	}
	if o.ConfirmedDigest == "" {
		return out, nil
	}
	// One digest-bound confirmation.
	if o.ConfirmedDigest != r.ManifestDigest {
		return BulkAdmitResult{}, fmt.Errorf("%w: confirmed digest %s does not match the reviewed manifest digest %s",
			ErrStale, o.ConfirmedDigest, r.ManifestDigest)
	}
	// Validate the retirement decisions: every old version exactly once
	// in Pins (retained) or Retired (retired).
	if err := validateDecisions(out.OldVersions, o.Pins, o.Retired); err != nil {
		return BulkAdmitResult{}, err
	}
	// Atomic commit.
	res, err := s.AdmitPinned(c, r, o.Pins)
	if err != nil {
		return BulkAdmitResult{}, err
	}
	// Retirement audit.
	out.Committed = true
	out.AdminUID = o.AdminUID
	out.Pinned = sortedPins(o.Pins)
	out.Retired = append([]string(nil), o.Retired...)
	out.Collected = res.Collected
	out.CleanupFailures = res.CleanupFailures
	for _, m := range r.Modules {
		out.Tuples = append(out.Tuples, TrustTuple{Module: m.Name, OldVersion: m.OldVersion, OldSHA256: m.OldSHA256,
			NewVersion: m.NewVersion, NewSHA256: m.NewSHA256, Status: string(m.Status)})
	}
	return out, nil
}

// scriptBytes returns the raw script bytes for one action of one module.
func scriptBytes(c release.Candidate, moduleName, actionID string) ([]byte, bool) {
	for _, mb := range c.Modules {
		if mb.Module.Name != moduleName {
			continue
		}
		for _, aa := range mb.Actions {
			if aa.ActionID == actionID {
				b, ok := mb.Files[aa.Script]
				return b, ok
			}
		}
	}
	return nil, false
}

// validateDecisions checks that the admin's retirement decisions exactly
// cover the old versions: every old version is retained (in Pins) or
// retired (in Retired), and Pins and Retired hold no other version.
func validateDecisions(old []string, pins map[string]bool, retired []string) error {
	oldSet := map[string]bool{}
	for _, v := range old {
		oldSet[v] = true
	}
	seen := map[string]bool{}
	for v := range pins {
		if !oldSet[v] {
			return fmt.Errorf("retained version %s is not an old version in this review", v)
		}
		if seen[v] {
			return fmt.Errorf("old version %s is both retained and retired", v)
		}
		seen[v] = true
	}
	for _, v := range retired {
		if !oldSet[v] {
			return fmt.Errorf("retired version %s is not an old version in this review", v)
		}
		if seen[v] {
			return fmt.Errorf("old version %s is both retained and retired", v)
		}
		seen[v] = true
	}
	for _, v := range old {
		if !seen[v] {
			return fmt.Errorf("old version %s is neither retained nor retired", v)
		}
	}
	return nil
}

// sortedPins returns the pinned versions in ASCII order.
func sortedPins(pins map[string]bool) []string {
	var out []string
	for v := range pins {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

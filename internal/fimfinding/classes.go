// SPDX-License-Identifier: AGPL-3.0-or-later

package fimfinding

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/integritystore"
)

// ErrInvalidInput is returned for a deviation or report that violates the
// shape fimbaseline.Diff produces. Nothing is classified from such input.
var ErrInvalidInput = errors.New("fimfinding: invalid input")

// ErrNotCovered is returned for a deviation that no covered row of the D9
// table matches (see doc.go). It fails the whole report: a silent default
// class would hide the deviation.
var ErrNotCovered = errors.New("fimfinding: deviation matches no covered D9 row")

// Finding is one finding of a report: a path with its highest class, or the
// scan-level finding of a partial run (Path nil).
type Finding struct {
	// Path is the raw path (show only through EscapePath of integritystore).
	Path []byte
	// Class is the finding class.
	Class integritystore.Class
	// Severity is the severity of Class (D9 table).
	Severity integritystore.Severity
}

// setIDBits are the setuid and setgid bits of a record's mode. The sticky
// bit is not one of them.
const setIDBits uint32 = 0o6000

// knownChanges are all change bits of fimbaseline.
const knownChanges = fimbaseline.ChangeContent | fimbaseline.ChangeNotHashed |
	fimbaseline.ChangeType | fimbaseline.ChangeLink | fimbaseline.ChangeMode |
	fimbaseline.ChangeOwner | fimbaseline.ChangeSize | fimbaseline.ChangeInode |
	fimbaseline.ChangeTimes | fimbaseline.ChangeFSType

// knownRules are all rule bits of fimbaseline.
const knownRules = fimbaseline.RuleFixedPath | fimbaseline.RuleSetID | fimbaseline.RuleShadow |
	fimbaseline.RuleSSHDerived | fimbaseline.RuleSSHSymlink | fimbaseline.RuleUnclassifiable

// etcRoot is the /etc tree of the D9 "other changed or new file" row.
const etcRoot = "/etc"

// validate checks that d has the shape fimbaseline.Diff gives it. Anything
// else is ErrInvalidInput: the classes below assume it.
func validate(d *fimbaseline.Deviation) error {
	if len(d.Path) == 0 || d.Path[0] != '/' {
		return fmt.Errorf("deviation path is not absolute: %w", ErrInvalidInput)
	}
	if d.Changes&^knownChanges != 0 || d.Rules&^knownRules != 0 {
		return fmt.Errorf("unknown change or rule bits: %w", ErrInvalidInput)
	}
	switch d.Kind {
	case fimbaseline.KindAdded:
		if d.Old != nil || d.New == nil || d.Changes&^fimbaseline.ChangeNotHashed != 0 {
			return fmt.Errorf("added deviation shape: %w", ErrInvalidInput)
		}
	case fimbaseline.KindRemoved:
		if d.Old == nil || d.New != nil || d.Changes != 0 {
			return fmt.Errorf("removed deviation shape: %w", ErrInvalidInput)
		}
	case fimbaseline.KindChanged:
		if d.Changes == 0 {
			return fmt.Errorf("changed deviation without change bits: %w", ErrInvalidInput)
		}
		if (d.Old == nil || d.New == nil) && d.Changes&fimbaseline.ChangeFSType == 0 {
			return fmt.Errorf("changed deviation without both records: %w", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("deviation kind %d: %w", d.Kind, ErrInvalidInput)
	}
	for _, r := range []*fimscan.Record{d.Old, d.New} {
		if r != nil && !bytes.Equal(r.Path, d.Path) {
			return fmt.Errorf("record path differs from deviation path: %w", ErrInvalidInput)
		}
	}
	switch d.Class {
	case fimbaseline.ClassCritical:
		if d.Rules == 0 {
			return fmt.Errorf("critical deviation without rules: %w", ErrInvalidInput)
		}
	case fimbaseline.ClassNormal:
		if d.Rules != 0 {
			return fmt.Errorf("normal deviation with rules: %w", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("deviation class %d: %w", d.Class, ErrInvalidInput)
	}
	return nil
}

// Classes returns every D9 class of the table that deviation d alone
// proves, in no particular order, without duplicates. roots are the profile
// roots of the run; only literal /usr roots count as watched /usr roots.
//
// The covered rows are: critical-path-changed (a critical-class path, of any
// kind of change), setid-new (a setuid or setgid bit that is new), owner-mode-
// changed (a changed owner or mode of a changed record) and etc-changed (a
// changed or new path in /etc or a watched /usr root). A deviation that
// matches none returns ErrNotCovered. The highest severity among the classes
// is chosen by Findings.
func Classes(d fimbaseline.Deviation, roots []fimscan.Root) ([]integritystore.Class, error) {
	if err := validate(&d); err != nil {
		return nil, err
	}
	var out []integritystore.Class
	if d.Class == fimbaseline.ClassCritical {
		out = append(out, integritystore.ClassCriticalPathChanged)
	}
	if newSetID(&d) {
		out = append(out, integritystore.ClassSetIDNew)
	}
	if d.Kind == fimbaseline.KindChanged && d.Changes&(fimbaseline.ChangeOwner|fimbaseline.ChangeMode) != 0 {
		out = append(out, integritystore.ClassOwnerModeChanged)
	}
	if (d.Kind == fimbaseline.KindChanged || d.Kind == fimbaseline.KindAdded) && watchedEtcOrUsr(d.Path, roots) {
		out = append(out, integritystore.ClassEtcChanged)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("deviation kind %s: %w", d.Kind, ErrNotCovered)
	}
	return out, nil
}

// newSetID reports whether the new record carries a setuid or setgid bit that
// the baseline record did not have (a new file with such a bit counts as
// having no baseline bits).
func newSetID(d *fimbaseline.Deviation) bool {
	if d.New == nil {
		return false
	}
	var oldMode uint32
	if d.Old != nil {
		oldMode = d.Old.Mode
	}
	return (d.New.Mode & setIDBits &^ oldMode) != 0
}

// watchedEtcOrUsr reports whether p lies in /etc or in a watched /usr root:
// a profile root that is literal, starts with /usr and has no glob
// characters. A glob root is not counted, so the row never widens by
// pattern.
func watchedEtcOrUsr(p []byte, roots []fimscan.Root) bool {
	s := string(p)
	if inTree(s, etcRoot) {
		return true
	}
	for _, r := range roots {
		if literalUsrRoot(r.Pattern) && inTree(s, r.Pattern) {
			return true
		}
	}
	return false
}

// literalUsrRoot reports whether pat is /usr or below it, without glob
// characters.
func literalUsrRoot(pat string) bool {
	if pat != "/usr" && !strings.HasPrefix(pat, "/usr/") {
		return false
	}
	return !strings.ContainsAny(pat, "*?[\\")
}

// inTree reports whether s is root or lies below it.
func inTree(s, root string) bool {
	return s == root || strings.HasPrefix(s, root+"/")
}

// Findings maps a comparison report to findings: one per deviating path
// with the highest severity of its classes (integritystore.Escalate), and,
// first, a scan-partial finding when the report is not complete (D9 "partial
// or stale scan", medium). A nil report, or any deviation Classes rejects,
// fails the whole report.
func Findings(rep *fimbaseline.Report, roots []fimscan.Root) ([]Finding, error) {
	if rep == nil {
		return nil, fmt.Errorf("findings: nil report: %w", ErrInvalidInput)
	}
	var out []Finding
	if !rep.Complete {
		sev, err := integritystore.ClassScanPartial.Severity()
		if err != nil {
			return nil, fmt.Errorf("findings: scan-partial: %w", err)
		}
		out = append(out, Finding{Class: integritystore.ClassScanPartial, Severity: sev})
	}
	for i := range rep.Deviations {
		d := rep.Deviations[i]
		classes, err := Classes(d, roots)
		if err != nil {
			// The index, not the path: the path is untrusted host data.
			return nil, fmt.Errorf("deviation %d: %w", i, err)
		}
		top, ok := integritystore.Escalate(classes...)
		if !ok {
			return nil, fmt.Errorf("deviation %d: no severity: %w", i, ErrNotCovered)
		}
		sev, err := top.Severity()
		if err != nil {
			return nil, fmt.Errorf("deviation %d: %w", i, err)
		}
		out = append(out, Finding{Path: bytes.Clone(d.Path), Class: top, Severity: sev})
	}
	return out, nil
}

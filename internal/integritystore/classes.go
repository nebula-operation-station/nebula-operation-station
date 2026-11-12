// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import "fmt"

// Class is a D9 finding class. Its severity is fixed by the table below.
// Where one path matches several classes, the caller reports the one that
// Escalate picks: the highest severity wins.
type Class string

// Severity of a finding (D9). The order is info < medium < high < critical.
type Severity string

// Severities.
const (
	SeverityInfo     Severity = "info"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// rank orders severities; unknown severities rank below info.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	case SeverityInfo:
		return 0
	default:
		return -1
	}
}

// Classes of D9, in the order of its severity table. The class names are
// stored in integrity_findings and must not change.
const (
	// Critical.
	ClassPkgFileMismatch     Class = "pkg-file-mismatch"
	ClassNOSUnitMismatch     Class = "nos-unit-mismatch"
	ClassCriticalPathChanged Class = "critical-path-changed"
	ClassCriticalPathInJob   Class = "critical-path-changed-in-job"
	ClassSetIDNew            Class = "setid-new"
	ClassNOSKeyMissing       Class = "nos-key-missing"
	ClassSSHKeyExtra         Class = "ssh-key-extra"
	ClassMountUnexpectedCrit Class = "mount-unexpected-critical"
	// High.
	ClassEtcChanged             Class = "etc-changed"
	ClassOwnerModeChanged       Class = "owner-mode-changed"
	ClassBaselineDigestMismatch Class = "baseline-digest-mismatch"
	ClassChangedInJobUnverified Class = "changed-in-job-unverified"
	ClassPkgContentWithoutVer   Class = "pkg-content-without-version"
	ClassPkgDowngraded          Class = "pkg-downgraded"
	ClassMountUnexpected        Class = "mount-unexpected"
	ClassReferenceConflict      Class = "reference-conflict"
	ClassSSHLoginOutsideRoots   Class = "ssh-login-file-outside-roots"
	// Medium.
	ClassPkgUpdatedOutsideNOS Class = "pkg-updated-outside-nos"
	ClassScanPartial          Class = "scan-partial"
	// Info: a verified expected change from a NOS job.
	ClassExpectedChange Class = "expected-change"
)

// classSeverity is the D9 severity table.
var classSeverity = map[Class]Severity{
	ClassPkgFileMismatch:        SeverityCritical,
	ClassNOSUnitMismatch:        SeverityCritical,
	ClassCriticalPathChanged:    SeverityCritical,
	ClassCriticalPathInJob:      SeverityCritical,
	ClassSetIDNew:               SeverityCritical,
	ClassNOSKeyMissing:          SeverityCritical,
	ClassSSHKeyExtra:            SeverityCritical,
	ClassMountUnexpectedCrit:    SeverityCritical,
	ClassEtcChanged:             SeverityHigh,
	ClassOwnerModeChanged:       SeverityHigh,
	ClassBaselineDigestMismatch: SeverityHigh,
	ClassChangedInJobUnverified: SeverityHigh,
	ClassPkgContentWithoutVer:   SeverityHigh,
	ClassPkgDowngraded:          SeverityHigh,
	ClassMountUnexpected:        SeverityHigh,
	ClassReferenceConflict:      SeverityHigh,
	ClassSSHLoginOutsideRoots:   SeverityHigh,
	ClassPkgUpdatedOutsideNOS:   SeverityMedium,
	ClassScanPartial:            SeverityMedium,
	ClassExpectedChange:         SeverityInfo,
}

// Severity returns the D9 severity of the class. An unknown class is
// ErrInvalidInput.
func (c Class) Severity() (Severity, error) {
	sev, ok := classSeverity[c]
	if !ok {
		return "", fmt.Errorf("class %q: %w", string(c), ErrInvalidInput)
	}
	return sev, nil
}

// Escalate returns the class with the highest severity among classes, and
// whether there was one. Unknown classes are skipped; on a tie the first
// one wins.
func Escalate(classes ...Class) (Class, bool) {
	var best Class
	bestRank := -1
	for _, c := range classes {
		sev, err := c.Severity()
		if err != nil {
			continue
		}
		if r := sev.rank(); r > bestRank {
			best, bestRank = c, r
		}
	}
	return best, bestRank >= 0
}

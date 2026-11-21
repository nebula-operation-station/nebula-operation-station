// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// errVulnNoInventory: the host has no complete stored package read, so NOS
// cannot judge a closure of its findings (D5, fail closed). Partial reads
// and failure markers alone count as no read.
var errVulnNoInventory = errors.New("no complete NOS package inventory read for the host")

// errVulnEcosystem: a stored read of the host is of another ecosystem than
// the finding (the host was reinstalled on another release), so NOS's read
// is no basis for the finding (D5, fail closed).
var errVulnEcosystem = errors.New("NOS inventory read is of another ecosystem than the finding")

// errVulnNoKernel: the newest complete read carries no running kernel data.
var errVulnNoKernel = errors.New("latest complete NOS read has no running kernel data")

// errVulnNoEcosystem: a stored read that names packages or is complete has no
// ecosystem, so NOS cannot tell whether it covers the finding (fail closed).
var errVulnNoEcosystem = errors.New("NOS inventory read names no ecosystem")

// vulnListTimeout is the run timeout of package.list_installed
// (internal/executions/actions); a list is produced within one run of it.
const vulnListTimeout = 2 * time.Minute

// vulnListLag is how long before a read's finish time its package list can
// have been taken. The list carries no host time (ADR 0011 D3) and the finish
// time is the server's clock, so the lower bound is the finish time less one
// run (vulnListTimeout) and the clock margin vulninventory.MaxReadSkew. A
// finding last written before that bound was written before the list was taken.
const vulnListLag = vulnListTimeout + vulninventory.MaxReadSkew

// listedAfter reports whether read's list was certainly taken after a write at
// written (D5: strictly newer). It is false whenever the write may fall inside
// the listing lag, so the list could predate it.
func listedAfter(read vulninventory.Read, written time.Time) bool {
	return read.ReadAt.Add(-vulnListLag).After(written)
}

// vulnClassifier classifies a requested run closure against NOS's own
// stored inventory (ADR 0011 D5). It fails closed: any doubt is returned as
// an error, which holds the closure (vulnstore.HoldClassifyFailed).
type vulnClassifier struct {
	inv *vulninventory.Store
}

// vulnAssessment is NOS's view of one finding: its closure class and the
// basis version NOS knows for the component ("" when NOS does not know it).
type vulnAssessment struct {
	class      vulnstore.Class
	nosVersion string
}

// Classify implements vulnstore.Classifier.
func (c vulnClassifier) Classify(ctx context.Context, f vulnstore.Finding) (vulnstore.Class, error) {
	a, err := c.assess(ctx, f)
	if err != nil {
		return 0, err
	}
	return a.class, nil
}

// assess decides the D5 class of f from NOS's inventory. Subjects other than
// hosts and records NOS cannot re-check are unconfirmed, never an error.
//
// The newest read decides the basis when it names the component; otherwise
// the last complete read does (D5). Evidence (closure rows 1 and 2) only comes
// from the last complete read, and only when it was taken strictly after the
// finding's last write. A host without a complete read, a read of another
// ecosystem, a malformed fixed version or a version that cannot be compared
// is an error, which holds the closure. Evidence also holds while the last
// write of the finding may fall inside the listing lag of the complete read
// (listedAfter), and while a newer read still names the package.
func (c vulnClassifier) assess(ctx context.Context, f vulnstore.Finding) (vulnAssessment, error) {
	unconfirmed := vulnAssessment{class: vulnstore.ClassUnconfirmed}
	if f.Subject.Kind != vulnfinding.SubjectHost || !vulnstore.Checkable(f.Record) {
		return unconfirmed, nil
	}
	host := f.Subject.ID
	latest, err := c.inv.Latest(ctx, host)
	if errors.Is(err, vulninventory.ErrNoRead) {
		return vulnAssessment{}, errVulnNoInventory
	}
	if err != nil {
		return vulnAssessment{}, fmt.Errorf("classify: latest read: %w", err)
	}
	lc, err := c.inv.LastComplete(ctx, host)
	if errors.Is(err, vulninventory.ErrNoRead) {
		return vulnAssessment{}, errVulnNoInventory
	}
	if err != nil {
		return vulnAssessment{}, fmt.Errorf("classify: last complete read: %w", err)
	}
	eco := f.Record.Ecosystem
	scheme, err := vulnver.SchemeForEcosystem(eco)
	if err != nil {
		return vulnAssessment{}, fmt.Errorf("classify: ecosystem: %w", err)
	}
	// A read that names an ecosystem must name the finding's one. A read that
	// is complete or names packages must name one at all: an empty ecosystem
	// is no basis (fail closed). Failure markers name none and are no basis.
	for _, r := range []vulninventory.Read{latest, lc} {
		if r.Ecosystem == "" && (r.Complete || len(r.Components) > 0) {
			return vulnAssessment{}, errVulnNoEcosystem
		}
		if r.Ecosystem != "" && r.Ecosystem != eco {
			return vulnAssessment{}, errVulnEcosystem
		}
	}
	// A malformed fixed version holds whatever the reads say (D5, fail closed).
	fixed := f.EpisodeFixedVersion
	if fixed != "" {
		if err := vulnver.Validate(scheme, fixed); err != nil {
			return vulnAssessment{}, fmt.Errorf("classify: episode fixed version: %w", err)
		}
	}
	src := f.Record.Component.SourcePackage
	if vulnver.IsKernelSource(src) {
		return assessKernel(lc, f, scheme)
	}

	// The basis is the component version of the newest read that names it.
	// When the newest read does not name it, the last complete read decides.
	nosV, named := componentVersion(latest, src)
	if !named {
		nosV, named = componentVersion(lc, src)
	}
	a := vulnAssessment{nosVersion: nosV}
	if named && fixed != "" {
		cmp, err := vulnver.Compare(scheme, nosV, fixed)
		if err != nil {
			return vulnAssessment{}, fmt.Errorf("classify: compare basis: %w", err)
		}
		if cmp < 0 {
			a.class = vulnstore.ClassContradicted
			return a, nil
		}
	}
	// Evidence needs the last complete read listed strictly after the last
	// write of the finding (D5 closure rows 1 and 2, listedAfter). Row 2 also
	// needs the newest read not to name the package: a newer partial read that
	// still names it means the package is installed again.
	if listedAfter(lc, f.Updated) {
		lv, present := componentVersion(lc, src)
		if !present {
			if _, namedNow := componentVersion(latest, src); !namedNow {
				a.class = vulnstore.ClassEvidenced // row 2: no longer installed
				return a, nil
			}
		} else if fixed != "" {
			cmp, err := vulnver.Compare(scheme, lv, fixed)
			if err != nil {
				return vulnAssessment{}, fmt.Errorf("classify: compare complete read: %w", err)
			}
			if cmp >= 0 {
				a.class = vulnstore.ClassEvidenced // row 1: installed at or above the fix
				return a, nil
			}
		}
	}
	return unchangedOrUnconfirmed(a, f, named), nil
}

// assessKernel judges an unsigned kernel source (D4): only the running kernel
// of the newest complete read, and only when NOS mapped it, is a basis. Partial
// reads and failure markers decide nothing. A kernel never closes by row 2, a
// removed package.
func assessKernel(lc vulninventory.Read, f vulnstore.Finding, scheme vulnver.Scheme) (vulnAssessment, error) {
	k := lc.Kernel
	if k.State == "" {
		return vulnAssessment{}, errVulnNoKernel
	}
	src := f.Record.Component.SourcePackage
	if k.State != string(osdebian.KernelMapped) || k.Source != src || k.Version == "" {
		return vulnAssessment{class: vulnstore.ClassUnconfirmed}, nil
	}
	a := vulnAssessment{nosVersion: k.Version}
	if fixed := f.EpisodeFixedVersion; fixed != "" {
		cmp, err := vulnver.Compare(scheme, k.Version, fixed)
		if err != nil {
			return vulnAssessment{}, fmt.Errorf("classify: compare kernel: %w", err)
		}
		if cmp < 0 {
			a.class = vulnstore.ClassContradicted
			return a, nil
		}
		if listedAfter(lc, f.Updated) {
			a.class = vulnstore.ClassEvidenced
			return a, nil
		}
	}
	return unchangedOrUnconfirmed(a, f, true), nil
}

// unchangedOrUnconfirmed returns ClassUnconfirmedUnchanged when the finding
// has no episode fixed version and NOS still sees the version the finding
// stored, and ClassUnconfirmed otherwise.
func unchangedOrUnconfirmed(a vulnAssessment, f vulnstore.Finding, named bool) vulnAssessment {
	if named && f.EpisodeFixedVersion == "" && a.nosVersion == f.Record.Component.SourceVersion {
		a.class = vulnstore.ClassUnconfirmedUnchanged
		return a
	}
	a.class = vulnstore.ClassUnconfirmed
	return a
}

// componentVersion returns the installed source version of src in read, and
// whether the read names src at all.
func componentVersion(read vulninventory.Read, src string) (string, bool) {
	for _, c := range read.Components {
		if c.Source == src {
			return c.SourceVersion, true
		}
	}
	return "", false
}

// assessFinding returns NOS's view of f for the finding page. A failure
// gives the zero assessment: the page then shows NOS's version as unknown.
func (v *vulnService) assessFinding(ctx context.Context, f vulnstore.Finding) vulnAssessment {
	a, err := v.classifier.assess(ctx, f)
	if err != nil {
		v.log.Error("vulnerability classify", "subject", f.Subject.String(), "error_class", "classify")
		return vulnAssessment{}
	}
	return a
}

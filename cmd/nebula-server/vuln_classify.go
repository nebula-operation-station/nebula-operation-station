// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// errVulnNoInventory: the host has no stored package read at all, so NOS
// cannot judge a closure of its findings (D5, fail closed).
var errVulnNoInventory = errors.New("no NOS package inventory read for the host")

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
	scheme, err := vulnver.SchemeForEcosystem(f.Record.Ecosystem)
	if err != nil {
		return vulnAssessment{}, fmt.Errorf("classify: ecosystem: %w", err)
	}
	src := f.Record.Component.SourcePackage
	if vulnver.IsKernelSource(src) {
		return assessKernel(latest, f, scheme)
	}
	lc, err := c.inv.LastComplete(ctx, host)
	hasComplete := true
	if errors.Is(err, vulninventory.ErrNoRead) {
		hasComplete = false
	} else if err != nil {
		return vulnAssessment{}, fmt.Errorf("classify: last complete read: %w", err)
	}

	// The basis is the component version of the newest read that names it.
	// When the newest read does not name it, the last complete read decides.
	nosV, named := componentVersion(latest, src)
	if !named && hasComplete {
		nosV, named = componentVersion(lc, src)
	}
	a := vulnAssessment{nosVersion: nosV}
	fixed := f.EpisodeFixedVersion
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
	// Evidence needs a complete read taken after the last write of the
	// finding (D5 closure rows 1 and 2).
	if hasComplete && lc.ReadAt.After(f.Updated) {
		lv, present := componentVersion(lc, src)
		if !present {
			a.class = vulnstore.ClassEvidenced // row 2: no longer installed
			return a, nil
		}
		if fixed != "" {
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

// assessKernel judges an unsigned kernel source (D4): only the running
// kernel of the newest read, and only when NOS mapped it, is a basis. A
// kernel never closes by row 2, a removed package.
func assessKernel(latest vulninventory.Read, f vulnstore.Finding, scheme vulnver.Scheme) (vulnAssessment, error) {
	k := latest.Kernel
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
		if latest.Complete && latest.ReadAt.After(f.Updated) {
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

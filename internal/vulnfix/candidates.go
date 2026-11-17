// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfix

import (
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// candidateVerdict is the outcome of matching update candidates.
type candidateVerdict int

const (
	// candNone: no candidate for the component.
	candNone candidateVerdict = iota
	// candUnverified: candidates exist, but their source versions do not
	// prove the fix (unknown source, partial coverage, mixed versions).
	candUnverified
	// candBelow: every candidate's source version is below the fixed one.
	candBelow
	// candVerified: the candidates bring the fixed source version.
	candVerified
)

// candidateResult is the outcome with the versions it rests on.
type candidateResult struct {
	verdict candidateVerdict
	// lowest and highest are the lowest and highest known candidate
	// source versions.
	lowest, highest string
	// allSecurity: every matched candidate comes from a security archive.
	allSecurity bool
}

// binaryName drops the ":arch" qualifier of an apt package name.
func binaryName(name string) string {
	n, _, _ := strings.Cut(name, ":")
	return n
}

// tally accumulates matched candidates.
type tally struct {
	res                 candidateResult
	matched, below, ok  int
	unknown             bool
	compareFailed       bool
	securityAllMatching bool
}

func newTally() *tally { return &tally{securityAllMatching: true} }

// add records one matched candidate; known is false when its source
// version is unknown or not a basis.
func (t *tally) add(p Package, fixed string, known bool) {
	t.matched++
	if !p.Security {
		t.securityAllMatching = false
	}
	if !known {
		t.unknown = true
		return
	}
	c, err := vulnver.CompareDpkg(p.SourceVersion, fixed)
	if err != nil {
		t.compareFailed = true
		return
	}
	if c < 0 {
		t.below++
	} else {
		t.ok++
	}
	if t.res.lowest == "" {
		t.res.lowest, t.res.highest = p.SourceVersion, p.SourceVersion
		return
	}
	if c, _ := vulnver.CompareDpkg(p.SourceVersion, t.res.lowest); c < 0 {
		t.res.lowest = p.SourceVersion
	}
	if c, _ := vulnver.CompareDpkg(p.SourceVersion, t.res.highest); c > 0 {
		t.res.highest = p.SourceVersion
	}
}

// packageCandidates matches the candidates of a non-kernel source
// package: by known candidate source, or, for candidates whose source is
// unknown, by the finding's installed binary names. The fix is verified
// only when every matched candidate has a known source version at or
// after fixed and every installed binary of the finding has a candidate:
// a binary left behind keeps the host exposed (ADR 0011 D4 basis rule).
func packageCandidates(source, fixed string, installed []vulnfinding.Binary, pkgs []Package) candidateResult {
	bins := map[string]bool{}
	for _, b := range installed {
		bins[b.Name] = true
	}
	covered := map[string]bool{}
	t := newTally()
	for _, p := range pkgs {
		name := binaryName(p.Name)
		switch {
		case p.SourceName != "":
			if p.SourceName != source {
				continue
			}
			t.add(p, fixed, true)
		case bins[name]:
			t.add(p, fixed, false)
		default:
			continue
		}
		covered[name] = true
	}
	allCovered := len(bins) > 0
	for b := range bins {
		if !covered[b] {
			allCovered = false
		}
	}
	return t.verdict(allCovered)
}

// kernelCandidates matches kernel image candidates of the finding's
// unsigned kernel source. Only linux-image-* candidates count; a signed
// image's source (linux-signed-*) is never a version basis, so it and an
// image of unknown source leave the fix unverified. One image candidate
// of the source at or after fixed verifies the fix (it takes effect after
// a reboot into it).
func kernelCandidates(source, fixed string, pkgs []Package) candidateResult {
	t := newTally()
	for _, p := range pkgs {
		if !strings.HasPrefix(binaryName(p.Name), "linux-image-") {
			continue
		}
		switch {
		case p.SourceName == source:
			t.add(p, fixed, true)
		case p.SourceName == "" || vulnver.NeverVersionBasis(p.SourceName):
			t.add(p, fixed, false)
		}
	}
	res := t.res
	res.allSecurity = t.matched > 0 && t.securityAllMatching
	switch {
	case t.matched == 0:
		res.verdict = candNone
	case t.ok > 0 && !t.compareFailed:
		res.verdict = candVerified
	case t.below > 0 && !t.unknown && !t.compareFailed && t.ok == 0:
		res.verdict = candBelow
	default:
		res.verdict = candUnverified
	}
	return res
}

// verdict decides a non-kernel result.
func (t *tally) verdict(allCovered bool) candidateResult {
	res := t.res
	res.allSecurity = t.matched > 0 && t.securityAllMatching
	switch {
	case t.matched == 0:
		res.verdict = candNone
	case t.unknown || t.compareFailed:
		res.verdict = candUnverified
	case t.below == t.matched:
		res.verdict = candBelow
	case t.ok == t.matched && allCovered:
		res.verdict = candVerified
	default:
		res.verdict = candUnverified
	}
	return res
}

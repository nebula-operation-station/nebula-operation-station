// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// "Fix with" links of the vulnerabilities pages (ADR 0011 D8, plan VU-13).
//
// A link only opens an existing flow, prefilled, and never submits
// anything:
//
//   - host package: the operation proposal form of the OS package update
//     (ADR 0006 P2-02, ou02) for that host. It counts as a fix only when
//     every candidate's SOURCE version (package.list_updates with the
//     candidate's apt Source: field, binNMU-aware) is at or after the fixed
//     version under dpkg ordering (internal/vulnver) and every installed
//     binary of the source has a candidate; a candidate known only by its
//     binary version reads "update available, fix not verified"; candidates
//     below the fixed version read "no fix available yet"; no candidate
//     reads "no fix in the configured repositories". A kernel link also
//     says that a reboot is required.
//   - image: the container update page (cu01–cu04) scoped to the image's
//     host, only when the update preview has a candidate, labelled "fix not
//     verified until the new image is scanned".
//   - device: the vendor advisory link NOS builds from a validated advisory
//     ID; NOS has no device patch action.
//
// Everything read here (finding records, host results, previews) is
// untrusted; links are built only from validated IDs and fixed paths.

import (
	"context"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// Limits of the "fix with" links.
const (
	// maxFixPreviewHosts bounds the container update previews one page
	// reads; image findings of further hosts show "candidates unknown".
	maxFixPreviewHosts = 20
)

// Texts of the "fix with" links.
const (
	fixTextVerified      = "Fix available: the update brings the fixed source version"
	fixTextNotVerified   = "Update available, fix not verified"
	fixTextBelowFixed    = "No fix available yet: the candidate's source version is below the fixed version"
	fixTextNoCandidate   = "No fix in the configured repositories"
	fixTextNoList        = "Update candidates unknown: no package update list for this host yet"
	fixTextListsUnread   = "Update candidates unknown: the update lists could not be read"
	fixTextOpsOff        = "Update candidates unknown: operations are off"
	fixTextNoFixYet      = "No fix available yet"
	fixTextWontFix       = "No fix: the distribution will not fix this"
	fixTextNoFixed       = "Fix not verified: the fixed version cannot be compared"
	fixTextReboot        = "Reboot required to take effect"
	fixTextImageCand     = "Container update available, fix not verified until the new image is scanned"
	fixTextImageNone     = "No container update candidate known for this image"
	fixTextImageUnknown  = "Container update candidates unknown: no fresh update preview for this host"
	fixTextDeviceNoPatch = "NOS has no device patch action"
	fixTextDeviceNoLink  = "NOS has no device patch action and no advisory link for this ID"
	fixTextUnsupported   = "No update link for this ecosystem"
	fixLinkSecurity      = "Propose security updates"
	fixLinkAll           = "Propose all updates"
	fixLinkListUpdates   = "Check for updates"
	fixLinkContainers    = "Open container updates"
	fixLinkAdvisory      = "Vendor advisory"
)

// vulnFixView is the "fix with" entry of one finding. Every string is a
// fixed text or went through vulnText; URL is NOS-built.
type vulnFixView struct {
	// Text is the fix status.
	Text  string
	Class string
	// Detail names the compared versions; empty when none.
	Detail string
	// URL opens an existing flow prefilled (GET, never a submission);
	// empty for no link.
	URL      string
	LinkText string
	// External marks a vendor advisory link (opened with noopener).
	External bool
	// Notes are extra lines, e.g. "reboot required to take effect".
	Notes []string
	// Verified: the link counts as a fix of the finding.
	Verified bool
}

// osUpdateURL is the prefilled operation proposal form of the OS package
// update for host (the same links as the chart's update section).
func osUpdateURL(action, hostID string) string {
	return "/operations/new?action=" + url.QueryEscape(action) + "&host=" + url.QueryEscape(hostID)
}

// fixedVersionOf returns the version a candidate must reach: the current
// fixed version, or the episode's highest fixed version when that is
// higher (fail closed: a candidate is a fix only if it reaches both). ok
// is false when no comparable fixed version is known.
func fixedVersionOf(f vulnstore.Finding) (string, bool) {
	fixed := f.Record.Fix.Version
	if vulnver.Validate(vulnver.SchemeDpkg, fixed) != nil {
		return "", false
	}
	if ep := f.EpisodeFixedVersion; ep != "" {
		c, err := vulnver.CompareDpkg(ep, fixed)
		if err != nil {
			return "", false
		}
		if c > 0 {
			fixed = ep
		}
	}
	return fixed, true
}

// dpkgEcosystem reports whether a host record's ecosystem uses dpkg
// versions (Debian, Ubuntu).
func dpkgEcosystem(eco string) bool {
	return strings.HasPrefix(eco, "debian:") || strings.HasPrefix(eco, "ubuntu:")
}

// fixStateView handles the fix states without a fixed version; ok is
// false for FixFixed.
func fixStateView(s vulnfinding.FixState) (vulnFixView, bool) {
	switch s {
	case vulnfinding.FixFixed:
		return vulnFixView{}, false
	case vulnfinding.FixNoFixYet:
		return vulnFixView{Text: fixTextNoFixYet, Class: classWarning}, true
	case vulnfinding.FixWontFix:
		return vulnFixView{Text: fixTextWontFix, Class: classWarning}, true
	default:
		return vulnFixView{}, true
	}
}

// hostFixWith computes the "fix with" entry of a host package finding
// from the host's newest package.list_updates result (nil when the host
// has none).
func hostFixWith(f vulnstore.Finding, upd *osdebian.Updates) vulnFixView {
	r := f.Record
	if v, done := fixStateView(r.Fix.State); done {
		return v
	}
	hostID := f.Subject.ID
	if !vulnSubjectIDRe.MatchString(hostID) {
		return vulnFixView{}
	}
	if !dpkgEcosystem(r.Ecosystem) {
		return vulnFixView{Text: fixTextUnsupported, Class: classUnknown}
	}
	source := r.Component.SourcePackage
	kernel := vulnver.IsKernelSource(source)
	var v vulnFixView
	if kernel {
		v.Notes = []string{fixTextReboot}
	}
	fixed, ok := fixedVersionOf(f)
	if !ok {
		v.Text, v.Class = fixTextNoFixed, classUnknown
		return v
	}
	if upd == nil {
		v.Text, v.Class = fixTextNoList, classUnknown
		v.URL, v.LinkText = osUpdateURL("package.list_updates", hostID), fixLinkListUpdates
		return v
	}
	var res candidateResult
	if kernel {
		res = kernelCandidates(source, fixed, upd.Packages)
	} else {
		res = packageCandidates(source, fixed, r.Component.Binaries, upd.Packages)
	}
	switch res.verdict {
	case candNone:
		v.Text, v.Class = fixTextNoCandidate, classWarning
		return v
	case candBelow:
		v.Text, v.Class = fixTextBelowFixed, classWarning
		v.Detail = "candidate " + vulnText(res.highest, false) + " < fixed " + vulnText(fixed, false)
		return v
	case candVerified:
		v.Text, v.Class, v.Verified = fixTextVerified, "", true
		v.Detail = "candidate " + vulnText(res.lowest, false) + " ≥ fixed " + vulnText(fixed, false)
	default:
		v.Text, v.Class = fixTextNotVerified, classUnknown
	}
	if res.allSecurity {
		v.URL, v.LinkText = osUpdateURL("package.install_security", hostID), fixLinkSecurity
	} else {
		v.URL, v.LinkText = osUpdateURL("package.install_all", hostID), fixLinkAll
	}
	return v
}

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
func (t *tally) add(p osdebian.Package, fixed string, known bool) {
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
func packageCandidates(source, fixed string, installed []vulnfinding.Binary, pkgs []osdebian.Package) candidateResult {
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
func kernelCandidates(source, fixed string, pkgs []osdebian.Package) candidateResult {
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

// imageFixWith computes the "fix with" entry of an image finding from the
// newest container update preview of the image's host; ok is false when
// the preview is unknown (missing, stale, not ok, or not read).
func imageFixWith(f vulnstore.Finding, p executions.ContainerPreview, ok bool) vulnFixView {
	if v, done := fixStateView(f.Record.Fix.State); done {
		return v
	}
	hostID := f.Subject.ID
	if !vulnSubjectIDRe.MatchString(hostID) || !vulnDigestRe.MatchString(f.Subject.ImageDigest) {
		return vulnFixView{}
	}
	link := "/inventory/containers?host=" + url.QueryEscape(hostID)
	if !ok || p.ID == "" || p.Stale != "" || p.Status != dockerhost.PreviewOK {
		return vulnFixView{Text: fixTextImageUnknown, Class: classUnknown, URL: link, LinkText: fixLinkContainers}
	}
	if !imageHasCandidate(f.Subject.ImageDigest, p.Units) {
		return vulnFixView{Text: fixTextImageNone, Class: classWarning}
	}
	return vulnFixView{Text: fixTextImageCand, Class: classUnknown, URL: link, LinkText: fixLinkContainers}
}

// imageHasCandidate reports whether the preview has an update candidate
// for the image with platform digest digest: an available unit's image
// running that digest (a local digest or a resolved tag of it) with a
// resolved tag pointing to another platform digest.
func imageHasCandidate(digest string, units []dockerhost.PreviewUnit) bool {
	for _, u := range units {
		if u.Reason != "" {
			continue
		}
		for _, im := range u.Images {
			if im.Reason != "" {
				continue
			}
			running := slices.Contains(im.OldDigests, digest)
			var other bool
			for _, r := range im.Resolved {
				if r.Reason != "" || r.PlatformDigest == "" {
					continue
				}
				if r.PlatformDigest == digest {
					running = true
				} else if !slices.Contains(im.OldDigests, r.PlatformDigest) {
					other = true
				}
			}
			if running && other {
				return true
			}
		}
	}
	return false
}

// Vendor advisory ID patterns and the NOS-built advisory URLs.
var (
	ciscoAdvisoryRe = regexp.MustCompile(`^cisco-sa-[A-Za-z0-9-]{1,100}$`)
	panAdvisoryRe   = regexp.MustCompile(`^PAN-SA-[0-9]{4}-[0-9]{4}$`)
	panCVERe        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
)

const (
	ciscoAdvisoryBase = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
	panAdvisoryBase   = "https://security.paloaltonetworks.com/"
)

// deviceFixWith builds the vendor advisory link of a device finding from
// its ID or aliases; NOS has no device patch action.
func deviceFixWith(f vulnstore.Finding) vulnFixView {
	r := f.Record
	ids := append([]string{r.Vuln.ID}, r.Vuln.Aliases...)
	link := func(base, id string) vulnFixView {
		return vulnFixView{Text: fixTextDeviceNoPatch, Class: classUnknown, URL: base + url.PathEscape(id),
			LinkText: fixLinkAdvisory + " " + id, External: true}
	}
	switch {
	case strings.HasPrefix(r.Ecosystem, "vendor:cisco:"):
		for _, id := range ids {
			if ciscoAdvisoryRe.MatchString(id) {
				return link(ciscoAdvisoryBase, id)
			}
		}
	case r.Ecosystem == "vendor:paloalto:panos":
		for _, id := range ids {
			if panAdvisoryRe.MatchString(id) {
				return link(panAdvisoryBase, id)
			}
		}
		for _, id := range ids {
			if panCVERe.MatchString(id) {
				return link(panAdvisoryBase, id)
			}
		}
	}
	return vulnFixView{Text: fixTextDeviceNoLink, Class: classUnknown}
}

// vulnFixResolver computes "fix with" entries for one page, reading each
// host result source at most once.
type vulnFixResolver struct {
	// lastResults reads the newest successful result of an action per
	// host; nil when operations are off.
	lastResults func(ctx context.Context, action string) (map[string]executions.LastResultRow, error)
	// preview reads a host's newest container update preview; nil when
	// container updates are off.
	preview func(ctx context.Context, hostID string) (executions.ContainerPreview, error)

	updates       map[string]executions.LastResultRow
	updatesLoaded bool
	updatesFailed bool
	parsed        map[string]*osdebian.Updates
	previews      map[string]previewEntry
}

type previewEntry struct {
	p  executions.ContainerPreview
	ok bool
}

// newVulnFixResolver wires the resolver to the handler's backends.
func (h *Handler) newVulnFixResolver() *vulnFixResolver {
	r := &vulnFixResolver{}
	if h.operations != nil {
		r.lastResults = h.operations.LastResults
	}
	if h.containerBatches != nil {
		r.preview = h.containerBatches.LatestContainerPreview
	}
	return r
}

// fixWith returns the "fix with" entry of a finding; nil when the finding
// is closed (fixed) or none applies.
func (r *vulnFixResolver) fixWith(ctx context.Context, f vulnstore.Finding) *vulnFixView {
	if f.State == vulnstore.StateFixed {
		return nil
	}
	var v vulnFixView
	switch f.Subject.Kind {
	case vulnfinding.SubjectHost:
		upd, known := r.hostUpdates(ctx, f.Subject.ID)
		if !known {
			if fv, done := fixStateView(f.Record.Fix.State); done {
				v = fv
			} else if r.lastResults == nil {
				v = vulnFixView{Text: fixTextOpsOff, Class: classUnknown}
			} else {
				v = vulnFixView{Text: fixTextListsUnread, Class: classUnknown}
			}
			break
		}
		v = hostFixWith(f, upd)
	case vulnfinding.SubjectImage:
		p, ok := r.hostPreview(ctx, f.Subject.ID)
		v = imageFixWith(f, p, ok)
	case vulnfinding.SubjectDevice:
		v = deviceFixWith(f)
	}
	if v.Text == "" {
		return nil
	}
	return &v
}

// hostUpdates returns the parsed newest package.list_updates result of a
// host (nil when it has none or it does not parse); known is false when
// the results cannot be read at all.
func (r *vulnFixResolver) hostUpdates(ctx context.Context, hostID string) (*osdebian.Updates, bool) {
	if r.lastResults == nil {
		return nil, false
	}
	if !r.updatesLoaded {
		r.updatesLoaded = true
		m, err := r.lastResults(ctx, "package.list_updates")
		if err != nil {
			r.updatesFailed = true
		}
		r.updates, r.parsed = m, map[string]*osdebian.Updates{}
	}
	if r.updatesFailed {
		return nil, false
	}
	if u, seen := r.parsed[hostID]; seen {
		return u, true
	}
	var out *osdebian.Updates
	if row, ok := r.updates[hostID]; ok {
		if u, err := osdebian.ParseUpdates(row.Result); err == nil {
			out = &u
		}
	}
	r.parsed[hostID] = out
	return out, true
}

// hostPreview returns a host's newest container update preview; ok is
// false when it cannot be read or the page read too many already.
func (r *vulnFixResolver) hostPreview(ctx context.Context, hostID string) (executions.ContainerPreview, bool) {
	if r.preview == nil {
		return executions.ContainerPreview{}, false
	}
	if e, seen := r.previews[hostID]; seen {
		return e.p, e.ok
	}
	if r.previews == nil {
		r.previews = map[string]previewEntry{}
	}
	if len(r.previews) >= maxFixPreviewHosts {
		return executions.ContainerPreview{}, false
	}
	p, err := r.preview(ctx, hostID)
	e := previewEntry{p: p, ok: err == nil}
	r.previews[hostID] = e
	return e.p, e.ok
}

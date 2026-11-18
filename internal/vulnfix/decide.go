// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnfix decides the "fix with" status of a vulnerability finding
// (ADR 0011 D8, ADR 0016 D4). It returns values only: no texts, no URLs,
// no HTML. The web layer maps a Result to labels and links.
//
// The decision rests on untrusted input (finding records, host update
// lists, container previews). A fix is claimed only when the evidence
// proves it:
//
//   - host package: every matched candidate's SOURCE version (binNMU-aware,
//     apt Source: field) is at or after the fixed version under dpkg
//     ordering, and every installed binary of the source has a candidate.
//   - kernel: one unsigned linux-image candidate of the source at or after
//     the fixed version verifies the fix; a reboot is required.
//   - image: a container update candidate is never a verified fix.
//   - device: NOS has no patch action; only an advisory link is decided.
package vulnfix

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// Status is the outcome of the "fix with" decision.
type Status int

// Statuses. StatusNone means that no "fix with" entry applies.
const (
	// StatusNone: no entry (closed finding, invalid subject, unknown kind).
	StatusNone Status = iota
	// StatusVerified: a candidate's source version brings the fixed version.
	StatusVerified
	// StatusNotVerified: a candidate exists, but it does not prove the fix.
	StatusNotVerified
	// StatusBelowFixed: every candidate's source version is below the fix.
	StatusBelowFixed
	// StatusNoCandidate: the configured repositories offer no candidate.
	StatusNoCandidate
	// StatusNoFixYet: the vendor has announced no fix yet.
	StatusNoFixYet
	// StatusWontFix: the distribution will not fix this.
	StatusWontFix
	// StatusUnknown: the decision cannot be made; Reason says why.
	StatusUnknown
	// StatusImageCandidate: a container update exists; not a verified fix.
	StatusImageCandidate
	// StatusImageNoCandidate: the preview offers no container update.
	StatusImageNoCandidate
	// StatusDeviceNoPatch: NOS has no device patch action; Advisory names
	// the vendor advisory ID to link.
	StatusDeviceNoPatch
)

// Reason explains a StatusUnknown.
type Reason int

// Reasons of StatusUnknown.
const (
	// ReasonNone: no reason (the status is not unknown).
	ReasonNone Reason = iota
	// ReasonNoUpdateList: the host has no package update list yet.
	ReasonNoUpdateList
	// ReasonListsUnread: the update lists could not be read.
	ReasonListsUnread
	// ReasonOpsOff: operations are off, so no lists exist.
	ReasonOpsOff
	// ReasonFixedNotComparable: the fixed version is not a comparable version.
	ReasonFixedNotComparable
	// ReasonUnsupportedEcosystem: the ecosystem has no update link.
	ReasonUnsupportedEcosystem
	// ReasonNoPreview: no fresh container update preview for the host.
	ReasonNoPreview
	// ReasonNoAdvisoryLink: no vendor advisory ID to link.
	ReasonNoAdvisoryLink
)

// Action names the existing flow a "fix with" entry links to. The web
// layer builds the URL from the action and the Result's host ID.
type Action int

// Actions.
const (
	// ActionNone: no link.
	ActionNone Action = iota
	// ActionInstallSecurity: the OS update proposal for security updates.
	ActionInstallSecurity
	// ActionInstallAll: the OS update proposal for all updates.
	ActionInstallAll
	// ActionListUpdates: the OS update list check.
	ActionListUpdates
	// ActionContainers: the container updates page of the host.
	ActionContainers
	// ActionCiscoAdvisory: the Cisco advisory of Result.Advisory.
	ActionCiscoAdvisory
	// ActionPANAdvisory: the Palo Alto advisory of Result.Advisory.
	ActionPANAdvisory
)

// Result is the "fix with" decision of one finding. Versions are the
// compared versions as recorded; they are not formatted here.
type Result struct {
	Status Status
	Reason Reason
	Action Action
	// HostID is the subject's host, the target of host-scoped actions.
	HostID string
	// Reboot: the fix takes effect after a reboot (kernel source).
	Reboot bool
	// Candidate is the candidate source version the decision rests on: when
	// verified, the lowest matched one at or after Fixed (the candidate that
	// reaches the fix, never one below it); when below fixed, the highest.
	Candidate string
	// Fixed is the fixed version the candidate was compared with.
	Fixed string
	// Advisory is the vendor advisory ID for an advisory action.
	Advisory string
}

// Limits of the decision.
const (
	// MaxPreviewHosts bounds the container update previews one page reads;
	// image findings of further hosts are unknown.
	MaxPreviewHosts = 20
)

var (
	subjectIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	digestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

	ciscoAdvisoryRe = regexp.MustCompile(`^cisco-sa-[A-Za-z0-9-]{1,100}$`)
	panAdvisoryRe   = regexp.MustCompile(`^PAN-SA-[0-9]{4}-[0-9]{4}$`)
	panCVERe        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
)

// ValidSubjectID reports whether id has the shape of a NOS subject ID.
// Only validated IDs may appear in a link.
func ValidSubjectID(id string) bool { return subjectIDRe.MatchString(id) }

// ValidDigest reports whether d is a sha256 image digest.
func ValidDigest(d string) bool { return digestRe.MatchString(d) }

// Package is one update candidate of a host's list_updates result.
type Package struct {
	// Name is the binary package name, with an optional ":arch" qualifier.
	Name string
	// SourceName and SourceVersion are the candidate's apt Source: field;
	// empty when the list does not name it.
	SourceName    string
	SourceVersion string
	// Security: the candidate comes from a security archive.
	Security bool
}

// Updates is the parsed newest list_updates result of one host.
type Updates struct {
	Packages []Package
}

// Unit, Image and Resolution mirror the parts of a container update preview
// the decision reads. Failed is set where the preview marks the element
// unavailable.
type (
	Unit struct {
		Failed bool
		Images []Image
	}
	Image struct {
		Failed     bool
		OldDigests []string
		Resolved   []Resolution
	}
	Resolution struct {
		Failed         bool
		PlatformDigest string
	}
)

// Preview is a host's newest container update preview.
type Preview struct {
	// ID is empty when no preview exists.
	ID string
	// Stale: the preview is too old to decide with.
	Stale bool
	// OK: the preview finished successfully.
	OK    bool
	Units []Unit
}

// fixStateResult handles the fix states without a fixed version; done is
// false for FixFixed.
func fixStateResult(s vulnfinding.FixState) (Result, bool) {
	switch s {
	case vulnfinding.FixFixed:
		return Result{}, false
	case vulnfinding.FixNoFixYet:
		return Result{Status: StatusNoFixYet}, true
	case vulnfinding.FixWontFix:
		return Result{Status: StatusWontFix}, true
	default:
		return Result{}, true
	}
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

// HostResult decides the "fix with" status of a host package finding from
// the host's newest list_updates result (nil when the host has none).
func HostResult(f vulnstore.Finding, upd *Updates) Result {
	if r, done := fixStateResult(f.Record.Fix.State); done {
		return r
	}
	hostID := f.Subject.ID
	if !ValidSubjectID(hostID) {
		return Result{}
	}
	r := Result{HostID: hostID}
	if !dpkgEcosystem(f.Record.Ecosystem) {
		r.Status, r.Reason = StatusUnknown, ReasonUnsupportedEcosystem
		return r
	}
	source := f.Record.Component.SourcePackage
	kernel := vulnver.IsKernelSource(source)
	r.Reboot = kernel
	fixed, ok := fixedVersionOf(f)
	if !ok {
		r.Status, r.Reason = StatusUnknown, ReasonFixedNotComparable
		return r
	}
	r.Fixed = fixed
	if upd == nil {
		r.Status, r.Reason, r.Action = StatusUnknown, ReasonNoUpdateList, ActionListUpdates
		return r
	}
	var res candidateResult
	if kernel {
		res = kernelCandidates(source, fixed, upd.Packages)
	} else {
		res = packageCandidates(source, fixed, f.Record.Component.Binaries, upd.Packages)
	}
	switch res.verdict {
	case candNone:
		r.Status = StatusNoCandidate
		return r
	case candBelow:
		r.Status, r.Candidate = StatusBelowFixed, res.highest
		return r
	case candVerified:
		r.Status, r.Candidate = StatusVerified, res.lowestAtFix
	default:
		r.Status = StatusNotVerified
	}
	if res.allSecurity {
		r.Action = ActionInstallSecurity
	} else {
		r.Action = ActionInstallAll
	}
	return r
}

// DeviceResult decides the advisory link of a device finding from its ID or
// aliases. NOS has no device patch action.
func DeviceResult(f vulnstore.Finding) Result {
	r := f.Record
	ids := append([]string{r.Vuln.ID}, r.Vuln.Aliases...)
	link := func(action Action, id string) Result {
		return Result{Status: StatusDeviceNoPatch, Action: action, Advisory: id}
	}
	switch {
	case strings.HasPrefix(r.Ecosystem, "vendor:cisco:"):
		for _, id := range ids {
			if ciscoAdvisoryRe.MatchString(id) {
				return link(ActionCiscoAdvisory, id)
			}
		}
	case r.Ecosystem == "vendor:paloalto:panos":
		for _, id := range ids {
			if panAdvisoryRe.MatchString(id) {
				return link(ActionPANAdvisory, id)
			}
		}
		for _, id := range ids {
			if panCVERe.MatchString(id) {
				return link(ActionPANAdvisory, id)
			}
		}
	}
	return Result{Status: StatusUnknown, Reason: ReasonNoAdvisoryLink}
}

// ImageResult decides the "fix with" status of an image finding from the
// newest container update preview of the image's host; ok is false when the
// preview cannot be read.
func ImageResult(f vulnstore.Finding, p Preview, ok bool) Result {
	if r, done := fixStateResult(f.Record.Fix.State); done {
		return r
	}
	hostID := f.Subject.ID
	if !ValidSubjectID(hostID) || !ValidDigest(f.Subject.ImageDigest) {
		return Result{}
	}
	if !ok || p.ID == "" || p.Stale || !p.OK {
		return Result{Status: StatusUnknown, Reason: ReasonNoPreview, Action: ActionContainers, HostID: hostID}
	}
	if !imageHasCandidate(f.Subject.ImageDigest, p.Units) {
		return Result{Status: StatusImageNoCandidate, HostID: hostID}
	}
	return Result{Status: StatusImageCandidate, Action: ActionContainers, HostID: hostID}
}

// imageHasCandidate reports whether the preview has an update candidate
// for the image with platform digest digest: an available unit's image
// running that digest (a local digest or a resolved tag of it) with a
// resolved tag pointing to another platform digest.
func imageHasCandidate(digest string, units []Unit) bool {
	for _, u := range units {
		if u.Failed {
			continue
		}
		for _, im := range u.Images {
			if im.Failed {
				continue
			}
			running := slices.Contains(im.OldDigests, digest)
			var other bool
			for _, r := range im.Resolved {
				if r.Failed || r.PlatformDigest == "" {
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

// Resolver decides the "fix with" status of findings on one page. It reads
// the host update lists at most once and the container previews of at most
// MaxPreviewHosts hosts. The zero value is not usable; use NewResolver.
type Resolver struct {
	updates  UpdateSource
	previews PreviewSource

	lists       map[string]Updates
	listsLoaded bool
	listsFailed bool
	previewRead map[string]previewEntry
}

// UpdateSource supplies the newest package.list_updates candidates per host.
type UpdateSource interface {
	// Lists returns the parsed result of every host that has a usable one.
	// err means that the results cannot be read at all.
	Lists(ctx context.Context) (map[string]Updates, error)
}

// PreviewSource supplies a host's newest container update preview.
type PreviewSource interface {
	// Preview returns the newest preview of hostID; err when it cannot be read.
	Preview(ctx context.Context, hostID string) (Preview, error)
}

type previewEntry struct {
	p  Preview
	ok bool
}

// NewResolver returns a resolver over the sources. A nil UpdateSource means
// operations are off; a nil PreviewSource means container updates are off.
func NewResolver(updates UpdateSource, previews PreviewSource) *Resolver {
	return &Resolver{updates: updates, previews: previews}
}

// Decide returns the "fix with" status of a finding. A fixed finding has
// no entry (StatusNone).
func (r *Resolver) Decide(ctx context.Context, f vulnstore.Finding) Result {
	if f.State == vulnstore.StateFixed {
		return Result{}
	}
	switch f.Subject.Kind {
	case vulnfinding.SubjectHost:
		upd, known := r.hostUpdates(ctx, f.Subject.ID)
		if !known {
			if res, done := fixStateResult(f.Record.Fix.State); done {
				return res
			}
			if r.updates == nil {
				return Result{Status: StatusUnknown, Reason: ReasonOpsOff}
			}
			return Result{Status: StatusUnknown, Reason: ReasonListsUnread}
		}
		return HostResult(f, upd)
	case vulnfinding.SubjectImage:
		p, ok := r.hostPreview(ctx, f.Subject.ID)
		return ImageResult(f, p, ok)
	case vulnfinding.SubjectDevice:
		return DeviceResult(f)
	}
	return Result{}
}

// hostUpdates returns the parsed newest list_updates result of a host (nil
// when it has none); known is false when the results cannot be read at all.
func (r *Resolver) hostUpdates(ctx context.Context, hostID string) (*Updates, bool) {
	if r.updates == nil {
		return nil, false
	}
	if !r.listsLoaded {
		r.listsLoaded = true
		m, err := r.updates.Lists(ctx)
		if err != nil {
			r.listsFailed = true
		}
		r.lists = m
	}
	if r.listsFailed {
		return nil, false
	}
	if u, ok := r.lists[hostID]; ok {
		return &u, true
	}
	return nil, true
}

// hostPreview returns a host's newest container update preview; ok is false
// when it cannot be read or the page read too many already.
func (r *Resolver) hostPreview(ctx context.Context, hostID string) (Preview, bool) {
	if r.previews == nil {
		return Preview{}, false
	}
	if e, seen := r.previewRead[hostID]; seen {
		return e.p, e.ok
	}
	if r.previewRead == nil {
		r.previewRead = map[string]previewEntry{}
	}
	if len(r.previewRead) >= MaxPreviewHosts {
		return Preview{}, false
	}
	p, err := r.previews.Preview(ctx, hostID)
	e := previewEntry{p: p, ok: err == nil}
	r.previewRead[hostID] = e
	return e.p, e.ok
}

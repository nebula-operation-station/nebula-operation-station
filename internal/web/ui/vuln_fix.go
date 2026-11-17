// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// "Fix with" links of the vulnerabilities pages (ADR 0011 D8, plan VU-13).
//
// The decision (which status a finding gets, which flow it links to, which
// versions it compares) lives in internal/vulnfix, which returns values
// only. This file maps a decision to texts, CSS classes and URLs:
//
//   - host package: the operation proposal form of the OS package update
//     for that host, prefilled. Shown as a fix only when vulnfix verifies it
//     (candidate source version at or after the fixed version).
//   - image: the container update page scoped to the image's host.
//   - device: the vendor advisory link NOS builds from a validated advisory
//     ID; NOS has no device patch action.
//
// Everything read here is untrusted; links are built only from validated
// IDs and fixed paths.

import (
	"context"
	"net/url"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Limits of the "fix with" links.
const (
	// maxFixPreviewHosts bounds the container update previews one page
	// reads; image findings of further hosts show "candidates unknown".
	maxFixPreviewHosts = vulnfix.MaxPreviewHosts
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

// Vendor advisory base URLs; the advisory ID is path-escaped onto them.
const (
	ciscoAdvisoryBase = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
	panAdvisoryBase   = "https://security.paloaltonetworks.com/"
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

// viewOf maps a decision to texts, classes and links. The zero view means
// that no entry applies.
func viewOf(r vulnfix.Result) vulnFixView {
	var v vulnFixView
	switch r.Status {
	case vulnfix.StatusNone:
		return vulnFixView{}
	case vulnfix.StatusVerified:
		v.Text, v.Verified = fixTextVerified, true
		v.Detail = "candidate " + vulnText(r.Candidate, false) + " ≥ fixed " + vulnText(r.Fixed, false)
	case vulnfix.StatusNotVerified:
		v.Text, v.Class = fixTextNotVerified, classUnknown
	case vulnfix.StatusBelowFixed:
		v.Text, v.Class = fixTextBelowFixed, classWarning
		v.Detail = "candidate " + vulnText(r.Candidate, false) + " < fixed " + vulnText(r.Fixed, false)
	case vulnfix.StatusNoCandidate:
		v.Text, v.Class = fixTextNoCandidate, classWarning
	case vulnfix.StatusNoFixYet:
		v.Text, v.Class = fixTextNoFixYet, classWarning
	case vulnfix.StatusWontFix:
		v.Text, v.Class = fixTextWontFix, classWarning
	case vulnfix.StatusImageCandidate:
		v.Text, v.Class = fixTextImageCand, classUnknown
	case vulnfix.StatusImageNoCandidate:
		v.Text, v.Class = fixTextImageNone, classWarning
	case vulnfix.StatusDeviceNoPatch:
		v.Text, v.Class = fixTextDeviceNoPatch, classUnknown
	case vulnfix.StatusUnknown:
		v.Class = classUnknown
		v.Text = unknownText(r.Reason)
	}
	if r.Reboot {
		v.Notes = []string{fixTextReboot}
	}
	v.URL, v.LinkText, v.External = linkOf(r)
	return v
}

// unknownText is the text of an undecidable status. A status without a
// reason never claims a fix.
func unknownText(reason vulnfix.Reason) string {
	switch reason {
	case vulnfix.ReasonNoUpdateList:
		return fixTextNoList
	case vulnfix.ReasonListsUnread:
		return fixTextListsUnread
	case vulnfix.ReasonOpsOff:
		return fixTextOpsOff
	case vulnfix.ReasonUnsupportedEcosystem:
		return fixTextUnsupported
	case vulnfix.ReasonNoPreview:
		return fixTextImageUnknown
	case vulnfix.ReasonNoAdvisoryLink:
		return fixTextDeviceNoLink
	default:
		return fixTextNoFixed
	}
}

// linkOf builds the URL of a decision's action.
func linkOf(r vulnfix.Result) (link, text string, external bool) {
	switch r.Action {
	case vulnfix.ActionInstallSecurity:
		return osUpdateURL("package.install_security", r.HostID), fixLinkSecurity, false
	case vulnfix.ActionInstallAll:
		return osUpdateURL("package.install_all", r.HostID), fixLinkAll, false
	case vulnfix.ActionListUpdates:
		return osUpdateURL("package.list_updates", r.HostID), fixLinkListUpdates, false
	case vulnfix.ActionContainers:
		return "/inventory/containers?host=" + url.QueryEscape(r.HostID), fixLinkContainers, false
	case vulnfix.ActionCiscoAdvisory:
		return ciscoAdvisoryBase + url.PathEscape(r.Advisory), fixLinkAdvisory + " " + r.Advisory, true
	case vulnfix.ActionPANAdvisory:
		return panAdvisoryBase + url.PathEscape(r.Advisory), fixLinkAdvisory + " " + r.Advisory, true
	}
	return "", "", false
}

// updatesOf converts a parsed list_updates result to the decision's form.
func updatesOf(u *osdebian.Updates) *vulnfix.Updates {
	if u == nil {
		return nil
	}
	out := &vulnfix.Updates{Packages: make([]vulnfix.Package, 0, len(u.Packages))}
	for _, p := range u.Packages {
		out.Packages = append(out.Packages, vulnfix.Package{
			Name: p.Name, SourceName: p.SourceName, SourceVersion: p.SourceVersion, Security: p.Security,
		})
	}
	return out
}

// previewOf converts a container update preview to the decision's form.
func previewOf(p executions.ContainerPreview) vulnfix.Preview {
	out := vulnfix.Preview{ID: p.ID, Stale: p.Stale != "", OK: p.Status == dockerhost.PreviewOK}
	for _, u := range p.Units {
		vu := vulnfix.Unit{Failed: u.Reason != ""}
		for _, im := range u.Images {
			vi := vulnfix.Image{Failed: im.Reason != "", OldDigests: im.OldDigests}
			for _, r := range im.Resolved {
				vi.Resolved = append(vi.Resolved, vulnfix.Resolution{Failed: r.Reason != "", PlatformDigest: r.PlatformDigest})
			}
			vu.Images = append(vu.Images, vi)
		}
		out.Units = append(out.Units, vu)
	}
	return out
}

// hostFixWith computes the "fix with" entry of a host package finding
// from the host's newest package.list_updates result (nil when the host
// has none).
func hostFixWith(f vulnstore.Finding, upd *osdebian.Updates) vulnFixView {
	return viewOf(vulnfix.HostResult(f, updatesOf(upd)))
}

// imageFixWith computes the "fix with" entry of an image finding from the
// newest container update preview of the image's host; ok is false when the
// preview cannot be read.
func imageFixWith(f vulnstore.Finding, p executions.ContainerPreview, ok bool) vulnFixView {
	return viewOf(vulnfix.ImageResult(f, previewOf(p), ok))
}

// deviceFixWith builds the vendor advisory link of a device finding from
// its ID or aliases; NOS has no device patch action.
func deviceFixWith(f vulnstore.Finding) vulnFixView {
	return viewOf(vulnfix.DeviceResult(f))
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

	// decider is created on the first call, so the reads are cached for
	// the page.
	decider *vulnfix.Resolver
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
	if r.decider == nil {
		r.decider = vulnfix.NewResolver(r.updateSource(), r.previewSource())
	}
	v := viewOf(r.decider.Decide(ctx, f))
	if v.Text == "" {
		return nil
	}
	return &v
}

// updateSource adapts the operation results to the decision's source; nil
// when operations are off.
func (r *vulnFixResolver) updateSource() vulnfix.UpdateSource {
	if r.lastResults == nil {
		return nil
	}
	return listsSource{r}
}

// previewSource adapts the container previews to the decision's source;
// nil when container updates are off.
func (r *vulnFixResolver) previewSource() vulnfix.PreviewSource {
	if r.preview == nil {
		return nil
	}
	return previewsSource{r}
}

// listsSource reads the newest package.list_updates results of all hosts.
// A host whose result does not parse has no candidates.
type listsSource struct{ r *vulnFixResolver }

// Lists implements vulnfix.UpdateSource.
func (s listsSource) Lists(ctx context.Context) (map[string]vulnfix.Updates, error) {
	rows, err := s.r.lastResults(ctx, "package.list_updates")
	if err != nil {
		return nil, err
	}
	out := make(map[string]vulnfix.Updates, len(rows))
	for hostID, row := range rows {
		u, err := osdebian.ParseUpdates(row.Result)
		if err != nil {
			continue
		}
		out[hostID] = *updatesOf(&u)
	}
	return out, nil
}

// previewsSource reads a host's newest container update preview.
type previewsSource struct{ r *vulnFixResolver }

// Preview implements vulnfix.PreviewSource.
func (s previewsSource) Preview(ctx context.Context, hostID string) (vulnfix.Preview, error) {
	p, err := s.r.preview(ctx, hostID)
	if err != nil {
		return vulnfix.Preview{}, err
	}
	return previewOf(p), nil
}

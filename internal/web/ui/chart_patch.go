// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
)

// patchStateView is the OS patch state of one box, pre-formatted for
// display (ADR 0006 P1-33). It reuses the stored package.list_updates
// observation (executions.HostUpdates): the source is the host's package
// list, the list age is how old that list is, and the state is "unknown"
// when the host was never checked.
type patchStateView struct {
	// Known is false when the host was never checked (no update data);
	// the box then shows "unknown", never a guess.
	Known bool
	// Text is the short state ("⬆ 3" or "✓").
	Text string
	// Class is the badge CSS class.
	Class string
	// Source is the data source label ("package list").
	Source string
	// ListAge is how old the package list is ("2h ago"), "" when the
	// list age is unknown.
	ListAge string
	// ObservedAge is how old the update check is ("5m ago"), "" when
	// unknown.
	ObservedAge string
	// Total, Security, Kernel are the update counts.
	Total    int
	Security int
	Kernel   int
	// Reboot marks a pending reboot.
	Reboot bool
}

// newPatchStateView builds the OS patch state view from a stored update
// observation. A zero observation (host never checked) yields the unknown
// state. now is the reference time for the ages.
func newPatchStateView(u executions.HostUpdates, now time.Time) patchStateView {
	if u.ObservedAt.IsZero() {
		return patchStateView{Known: false, Text: "unknown", Class: "badge--unknown"}
	}
	v := patchStateView{
		Known:       true,
		Source:      "package list",
		ListAge:     ageText(now, u.ListsUpdated),
		ObservedAge: ageText(now, u.ObservedAt),
		Total:       u.Total,
		Security:    u.Security,
		Kernel:      u.Kernel,
		Reboot:      u.RebootRequired,
	}
	switch {
	case u.Total > 0:
		v.Text = "⬆ " + strconv.Itoa(u.Total)
		v.Class = "badge--warning"
	default:
		v.Text = "✓"
		v.Class = "badge--ok"
	}
	return v
}

// ageText renders how old at is relative to now ("just now", "5m ago",
// "2h ago", "3d ago"). A zero at renders "".
func ageText(now, at time.Time) string {
	if at.IsZero() {
		return ""
	}
	d := now.Sub(at)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "d ago"
	}
}

// registryInfo is the stored registry metadata for one image: the tag list
// (for the stable-version comparison) and, when the registry provides
// them, the release notes per tag. Both are untrusted host/registry output.
type registryInfo struct {
	// Tags is the registry's tag list, empty when not fetched.
	Tags []string
	// ReleaseNotes maps a tag to its release notes, "" when absent.
	ReleaseNotes map[string]string
}

// containerUpdateView is the update state of one container, pre-formatted
// for display (ADR 0006 P1-33). It keeps two distinct concepts apart: the
// same-tag status (has the registry's digest for the running tag changed?)
// and the stable version (is a newer stable version tag available?). They
// are never conflated.
type containerUpdateView struct {
	// SameTagText is the same-tag status ("same tag updated", "up to
	// date", "pinned", "unknown"), SameTagClass its badge CSS class.
	SameTagText  string
	SameTagClass string
	// StableText is the stable-version status ("stable 1.26" or
	// "stable unknown"), StableClass its badge CSS class. StableKnown is
	// false when no tag list is available (the version is unknown, not up
	// to date).
	StableText  string
	StableClass string
	StableKnown bool
	// Note is the same-tag note from docker.check_updates, rendered
	// escaped.
	Note string
	// ReleaseNotes are the notes for the stable version, rendered
	// escaped.
	ReleaseNotes string
}

// newContainerUpdateView builds the container update view from the stored
// docker.check_updates status for the running tag and the registry metadata
// (tag list and release notes) for the stable-version comparison via
// registrymeta.LatestStable. status is one of current, update, pinned,
// unknown (or "" when never checked).
func newContainerUpdateView(currentTag, status, note string, info registryInfo) containerUpdateView {
	v := containerUpdateView{SameTagText: "unknown", SameTagClass: "badge--unknown", Note: note}
	switch status {
	case "update":
		v.SameTagText, v.SameTagClass = "same tag updated", "badge--warning"
	case "current":
		v.SameTagText, v.SameTagClass = "up to date", "badge--ok"
	case "pinned":
		v.SameTagText, v.SameTagClass = "pinned", "badge--unknown"
	}
	if len(info.Tags) > 0 {
		if res, err := registrymeta.LatestStable(currentTag, info.Tags, registrymeta.Policy{}); err == nil {
			switch res.Status {
			case registrymeta.StatusNewer:
				v.StableText, v.StableClass, v.StableKnown = "stable "+res.Latest, "badge--warning", true
				v.ReleaseNotes = info.ReleaseNotes[res.Latest]
			case registrymeta.StatusUpToDate:
				v.StableText, v.StableClass, v.StableKnown = "stable "+res.Latest, "badge--ok", true
			default:
				v.StableText, v.StableClass, v.StableKnown = "stable unknown", "badge--unknown", false
			}
		}
	}
	if !v.StableKnown {
		v.StableText, v.StableClass = "stable unknown", "badge--unknown"
	}
	return v
}

// imageTag returns the tag of an image reference: "reg.example.com:5000/
// img:1.25" -> "1.25", "img:1.25" -> "1.25", "img" -> "" (no explicit
// tag), "img@sha256:..." -> "" (digest reference).
func imageTag(image string) string {
	if strings.Contains(image, "@") {
		return "" // digest reference, no tag
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon > slash {
		return image[colon+1:]
	}
	return ""
}

// parseRegistryInfo decodes a stored registry.tags result into registry
// metadata. It tolerates a bare JSON array of tag strings or an object with
// a "tags" string array and an optional "releaseNotes" tag->notes object;
// anything else (or untrusted garbage) yields the empty value, which
// renders the stable version as unknown.
func parseRegistryInfo(result []byte) registryInfo {
	if len(result) == 0 {
		return registryInfo{}
	}
	// Bare array of tag strings.
	var arr []string
	if err := json.Unmarshal(result, &arr); err == nil {
		return registryInfo{Tags: arr}
	}
	// Object with a "tags" array and optional "releaseNotes" map.
	var obj struct {
		Tags         []string          `json:"tags"`
		ReleaseNotes map[string]string `json:"releaseNotes"`
	}
	if err := json.Unmarshal(result, &obj); err == nil {
		return registryInfo{Tags: obj.Tags, ReleaseNotes: obj.ReleaseNotes}
	}
	return registryInfo{}
}

// parseRegistryHostResult decodes a stored per-host registry.tags result
// into a per-image registry metadata map. The result is a JSON object
// mapping an image reference to a {tags, releaseNotes} object; anything
// else (or untrusted garbage) yields an empty map, which renders the stable
// version as unknown.
func parseRegistryHostResult(result []byte) map[string]registryInfo {
	out := map[string]registryInfo{}
	if len(result) == 0 {
		return out
	}
	var doc map[string]registryInfo
	if err := json.Unmarshal(result, &doc); err != nil {
		return out
	}
	for img, info := range doc {
		out[img] = info
	}
	return out
}

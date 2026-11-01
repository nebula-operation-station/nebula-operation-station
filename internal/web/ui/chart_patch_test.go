// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

func TestPatchStateViewUnknownWhenNeverChecked(t *testing.T) {
	v := newPatchStateView(executions.HostUpdates{}, time.Now())
	if v.Known {
		t.Errorf("zero observation must be unknown, got %+v", v)
	}
	if v.Text != "unknown" || v.Class != "badge--unknown" {
		t.Errorf("unknown state text/class = %q/%q, want unknown/badge--unknown", v.Text, v.Class)
	}
	if v.Source != "" || v.ListAge != "" || v.ObservedAge != "" {
		t.Errorf("unknown state must carry no source/ages, got %+v", v)
	}
}

func TestPatchStateViewShowsListAgeAndCounts(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	u := executions.HostUpdates{
		ObservedAt:     now.Add(-5 * time.Minute),
		ListsUpdated:   now.Add(-2 * time.Hour),
		Total:          3,
		Security:       1,
		Kernel:         1,
		RebootRequired: true,
	}
	v := newPatchStateView(u, now)
	if !v.Known {
		t.Fatalf("observation with ObservedAt must be known")
	}
	if v.Text != "⬆ 3" || v.Class != "badge--warning" {
		t.Errorf("pending updates text/class = %q/%q, want ⬆ 3/badge--warning", v.Text, v.Class)
	}
	if v.Source != "package list" {
		t.Errorf("source = %q, want package list", v.Source)
	}
	if v.ListAge != "2h ago" {
		t.Errorf("list age = %q, want 2h ago", v.ListAge)
	}
	if v.ObservedAge != "5m ago" {
		t.Errorf("observed age = %q, want 5m ago", v.ObservedAge)
	}
	if v.Total != 3 || v.Security != 1 || v.Kernel != 1 || !v.Reboot {
		t.Errorf("counts = %+v, want 3/1/1/reboot", v)
	}
}

func TestPatchStateViewUpToDate(t *testing.T) {
	now := time.Now()
	u := executions.HostUpdates{ObservedAt: now.Add(-time.Hour), ListsUpdated: now.Add(-time.Hour), Total: 0}
	v := newPatchStateView(u, now)
	if !v.Known || v.Text != "✓" || v.Class != "badge--ok" {
		t.Errorf("up-to-date = %+v, want known ✓/badge--ok", v)
	}
}

func TestPatchStateViewListAgeUnknownWhenNeverUpdated(t *testing.T) {
	// ObservedAt set but ListsUpdated zero: the list age is unknown, the
	// state is still known.
	now := time.Now()
	u := executions.HostUpdates{ObservedAt: now.Add(-time.Hour), Total: 0}
	v := newPatchStateView(u, now)
	if !v.Known {
		t.Fatalf("must be known")
	}
	if v.ListAge != "" {
		t.Errorf("list age = %q, want empty (unknown)", v.ListAge)
	}
	if v.ObservedAge == "" {
		t.Errorf("observed age must be set")
	}
}

func TestAgeText(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, ""},
		{now.Add(-30 * time.Second), "just now"},
		{now.Add(-5 * time.Minute), "5m ago"},
		{now.Add(-2 * time.Hour), "2h ago"},
		{now.Add(-72 * time.Hour), "3d ago"},
		{now.Add(time.Hour), "just now"}, // future clamps to now
	}
	for _, c := range cases {
		if got := ageText(now, c.at); got != c.want {
			t.Errorf("ageText(%v) = %q, want %q", c.at, got, c.want)
		}
	}
}

func TestContainerUpdateViewDistinguishesSameTagAndStable(t *testing.T) {
	// The running tag is 1.25; the registry has 1.25 and 1.26. The
	// same-tag status is "up to date" (digest unchanged) while a newer
	// stable version (1.26) exists. The two must not be conflated.
	v := newContainerUpdateView("1.25", "current", "", registryInfo{Tags: []string{"1.25", "1.26"}})
	if v.SameTagText != "up to date" || v.SameTagClass != "badge--ok" {
		t.Errorf("same-tag = %q/%q, want up to date/badge--ok", v.SameTagText, v.SameTagClass)
	}
	if v.StableText != "stable 1.26" || v.StableClass != "badge--warning" || !v.StableKnown {
		t.Errorf("stable = %q/%q/known=%v, want stable 1.26/badge--warning/true", v.StableText, v.StableClass, v.StableKnown)
	}
}

func TestContainerUpdateViewSameTagUpdateIsNotAVersionUpdate(t *testing.T) {
	// Same tag, new digest: this is a "same tag updated" state, and it is
	// labelled as such (never just "update").
	v := newContainerUpdateView("1.25", "update", "digest changed", registryInfo{Tags: []string{"1.25"}})
	if v.SameTagText != "same tag updated" || v.SameTagClass != "badge--warning" {
		t.Errorf("same-tag = %q/%q, want same tag updated/badge--warning", v.SameTagText, v.SameTagClass)
	}
	if v.Note != "digest changed" {
		t.Errorf("note = %q, want digest changed", v.Note)
	}
	// Only one tag: the stable version is the current one (up to date).
	if v.StableText != "stable 1.25" || v.StableClass != "badge--ok" {
		t.Errorf("stable = %q/%q, want stable 1.25/badge--ok", v.StableText, v.StableClass)
	}
}

func TestContainerUpdateViewPinned(t *testing.T) {
	v := newContainerUpdateView("", "pinned", "pinned by digest", registryInfo{})
	if v.SameTagText != "pinned" || v.SameTagClass != "badge--unknown" {
		t.Errorf("pinned = %q/%q, want pinned/badge--unknown", v.SameTagText, v.SameTagClass)
	}
	if v.StableText != "stable unknown" || v.StableKnown {
		t.Errorf("no tags -> stable unknown, got %q/known=%v", v.StableText, v.StableKnown)
	}
}

func TestContainerUpdateViewUnknownWhenNeverChecked(t *testing.T) {
	v := newContainerUpdateView("1.25", "", "", registryInfo{})
	if v.SameTagText != "unknown" || v.SameTagClass != "badge--unknown" {
		t.Errorf("never checked = %q/%q, want unknown/badge--unknown", v.SameTagText, v.SameTagClass)
	}
	if v.StableText != "stable unknown" || v.StableKnown {
		t.Errorf("stable = %q/known=%v, want stable unknown/false", v.StableText, v.StableKnown)
	}
}

func TestContainerUpdateViewStableUnknownWhenTagsAmbiguous(t *testing.T) {
	// No comparable version tags: the stable version is unknown, never
	// "up to date".
	v := newContainerUpdateView("latest", "current", "", registryInfo{Tags: []string{"latest", "stable"}})
	if v.StableKnown {
		t.Errorf("ambiguous tags must not be known, got %+v", v)
	}
	if v.StableText != "stable unknown" {
		t.Errorf("stable = %q, want stable unknown", v.StableText)
	}
}

func TestContainerUpdateViewReleaseNotesForStableVersion(t *testing.T) {
	info := registryInfo{
		Tags:         []string{"1.25", "1.26"},
		ReleaseNotes: map[string]string{"1.26": "fixes <script>alert(1)</script> and CVE-2026-1234"},
	}
	v := newContainerUpdateView("1.25", "current", "", info)
	if v.StableText != "stable 1.26" {
		t.Fatalf("stable = %q, want stable 1.26", v.StableText)
	}
	if v.ReleaseNotes != "fixes <script>alert(1)</script> and CVE-2026-1234" {
		t.Errorf("release notes = %q, want the hostile 1.26 notes", v.ReleaseNotes)
	}
}

func TestContainerUpdateViewNoReleaseNotesWhenUpToDate(t *testing.T) {
	info := registryInfo{
		Tags:         []string{"1.26"},
		ReleaseNotes: map[string]string{"1.26": "notes"},
	}
	v := newContainerUpdateView("1.26", "current", "", info)
	if v.StableText != "stable 1.26" || v.StableClass != "badge--ok" {
		t.Fatalf("stable = %q/%q, want stable 1.26/badge--ok", v.StableText, v.StableClass)
	}
	// Up to date: no release notes are surfaced (nothing to update to).
	if v.ReleaseNotes != "" {
		t.Errorf("release notes = %q, want empty when up to date", v.ReleaseNotes)
	}
}

func TestImageTag(t *testing.T) {
	cases := []struct {
		image string
		want  string
	}{
		{"nginx:1.25", "1.25"},
		{"nginx", ""},
		{"reg.example.com:5000/img:1.25", "1.25"},
		{"reg.example.com:5000/img", ""},
		{"docker.io/library/nginx:1.25", "1.25"},
		{"img@sha256:0123456789abcdef", ""},
	}
	for _, c := range cases {
		if got := imageTag(c.image); got != c.want {
			t.Errorf("imageTag(%q) = %q, want %q", c.image, got, c.want)
		}
	}
}

func TestParseRegistryInfo(t *testing.T) {
	// Bare array of tags.
	info := parseRegistryInfo([]byte(`["1.25","1.26"]`))
	if len(info.Tags) != 2 || info.Tags[0] != "1.25" || info.Tags[1] != "1.26" {
		t.Errorf("bare array tags = %+v, want [1.25 1.26]", info.Tags)
	}
	// Object with tags and release notes.
	info = parseRegistryInfo([]byte(`{"tags":["1.25","1.26"],"releaseNotes":{"1.26":"new stuff"}}`))
	if len(info.Tags) != 2 {
		t.Errorf("object tags = %+v, want 2", info.Tags)
	}
	if info.ReleaseNotes["1.26"] != "new stuff" {
		t.Errorf("release notes = %+v, want new stuff for 1.26", info.ReleaseNotes)
	}
	// Garbage yields the empty value.
	info = parseRegistryInfo([]byte(`<html>not json</html>`))
	if len(info.Tags) != 0 || len(info.ReleaseNotes) != 0 {
		t.Errorf("garbage = %+v, want empty", info)
	}
	// Empty yields the empty value.
	info = parseRegistryInfo(nil)
	if len(info.Tags) != 0 {
		t.Errorf("empty = %+v, want empty", info)
	}
}

func TestParseRegistryHostResult(t *testing.T) {
	// Per-host result: image -> {tags, releaseNotes}.
	m := parseRegistryHostResult([]byte(`{
		"nginx:1.25": {"tags": ["1.25", "1.26"], "releaseNotes": {"1.26": "new"}},
		"redis:7": {"tags": ["7", "7.1"]}
	}`))
	if len(m) != 2 {
		t.Fatalf("got %d images, want 2", len(m))
	}
	nginx := m["nginx:1.25"]
	if len(nginx.Tags) != 2 || nginx.ReleaseNotes["1.26"] != "new" {
		t.Errorf("nginx = %+v, want 2 tags and 1.26 notes", nginx)
	}
	if len(m["redis:7"].Tags) != 2 {
		t.Errorf("redis tags = %+v, want 2", m["redis:7"].Tags)
	}
	// Garbage yields an empty map.
	if got := parseRegistryHostResult([]byte(`not json`)); len(got) != 0 {
		t.Errorf("garbage = %+v, want empty", got)
	}
	// Empty yields an empty map.
	if got := parseRegistryHostResult(nil); len(got) != 0 {
		t.Errorf("empty = %+v, want empty", got)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// TestUnseenFeedIsMappedAsNotNamed: a source no run has named maps to
// Unseen, and its stale flag is dropped, so the pages cannot show it as a
// stale feed. A named source keeps its stale flag.
func TestUnseenFeedIsMappedAsNotNamed(t *testing.T) {
	date := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   vulnstore.FeedState
		want ui.VulnFeedStatus
	}{
		{
			name: "never named: undated and not seen",
			in:   vulnstore.FeedState{SourceID: "cisco-csaf", Stale: true, Seen: false},
			want: ui.VulnFeedStatus{SourceID: "cisco-csaf", Listed: true, Unseen: true},
		},
		{
			name: "required core feed never named stays stale",
			in:   vulnstore.FeedState{SourceID: "nvd", Stale: true, Seen: false},
			want: ui.VulnFeedStatus{SourceID: "nvd", Listed: true, Stale: true},
		},
		{
			name: "required core feed that has never synced stays stale",
			in:   vulnstore.FeedState{SourceID: "debian-tracker", Stale: true, Seen: false},
			want: ui.VulnFeedStatus{SourceID: "debian-tracker", Listed: true, Stale: true},
		},
		{
			name: "optional CSAF feed seen and past its age",
			in:   vulnstore.FeedState{SourceID: "paloalto-csaf", Stale: true, Seen: true, ContentDate: date, LastVerdict: vulnstore.SourceAccepted},
			want: ui.VulnFeedStatus{SourceID: "paloalto-csaf", Listed: true, Stale: true, SnapshotDate: date, LastVerdict: vulnstore.SourceAccepted},
		},
		{
			name: "seen and past its age",
			in:   vulnstore.FeedState{SourceID: "nvd", Stale: true, Seen: true, ContentDate: date, LastVerdict: vulnstore.SourceAccepted},
			want: ui.VulnFeedStatus{SourceID: "nvd", Listed: true, Stale: true, SnapshotDate: date, LastVerdict: vulnstore.SourceAccepted},
		},
		{
			name: "seen and fresh",
			in:   vulnstore.FeedState{SourceID: "kev", Seen: true, ContentDate: date, LastVerdict: vulnstore.SourceAccepted},
			want: ui.VulnFeedStatus{SourceID: "kev", Listed: true, SnapshotDate: date, LastVerdict: vulnstore.SourceAccepted},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := uiFeedStatus(tc.in)
			if got.SourceID != tc.want.SourceID || got.Listed != tc.want.Listed || got.Unseen != tc.want.Unseen ||
				got.Stale != tc.want.Stale || !got.SnapshotDate.Equal(tc.want.SnapshotDate) || got.LastVerdict != tc.want.LastVerdict {
				t.Errorf("uiFeedStatus(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

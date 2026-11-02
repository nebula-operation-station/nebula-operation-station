// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

func TestLeasePreviewThrottleIsPerUser(t *testing.T) {
	p := newLeaseProposals()
	now := time.Unix(1_800_000_000, 0)
	if !p.allow("alice", now) || !p.allow("bob", now) {
		t.Fatal("first previews refused")
	}
	if p.allow("alice", now.Add(leasePreviewInterval-time.Millisecond)) {
		t.Error("alice previewed twice within the interval")
	}
	if !p.allow("alice", now.Add(leasePreviewInterval)) {
		t.Error("alice refused after the interval")
	}
	// A clock step backwards does not lock the user out for good.
	if !p.allow("bob", now.Add(-time.Hour)) {
		t.Error("bob refused after the clock stepped back")
	}
}

func TestLeasePreviewThrottleTableIsBounded(t *testing.T) {
	p := newLeaseProposals()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < maxLeaseThrottleUsers; i++ {
		if !p.allow(fmt.Sprintf("u%d", i), now) {
			t.Fatalf("user %d refused", i)
		}
	}
	if p.allow("late", now) {
		t.Error("a full table of fresh users accepted one more")
	}
	if !p.allow("late", now.Add(leasePreviewInterval)) {
		t.Error("stale entries were not pruned")
	}
	if len(p.last) > maxLeaseThrottleUsers {
		t.Errorf("throttle table grew to %d", len(p.last))
	}
}

func TestLeaseProposalsBelongToTheirProposer(t *testing.T) {
	p := newLeaseProposals()
	now := time.Unix(1_800_000_000, 0)
	d := strings.Repeat("a", 64)
	p.put("alice", executions.ReadGrantPreview{Digest: d}, now)
	if _, ok := p.get("bob", d, now); ok {
		t.Error("bob sees alice's proposal")
	}
	if _, ok := p.get("alice", d, now); !ok {
		t.Error("alice cannot see her proposal")
	}
	if _, ok := p.get("alice", d, now.Add(leaseProposalTTL)); ok {
		t.Error("an expired proposal is still shown")
	}
}

func TestLeaseProposalsAreBounded(t *testing.T) {
	p := newLeaseProposals()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < maxLeaseProposals+10; i++ {
		p.put("alice", executions.ReadGrantPreview{Digest: fmt.Sprintf("%064x", i)}, now.Add(time.Duration(i)*time.Second))
	}
	if len(p.props) != maxLeaseProposals {
		t.Fatalf("%d proposals kept, want %d", len(p.props), maxLeaseProposals)
	}
	if _, ok := p.props[fmt.Sprintf("%064x", 0)]; ok {
		t.Error("the oldest proposal was not dropped")
	}
}

func TestLeaseShortRuneBoundary(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "0a1b2c3d"},
		{"abc", "abc"},
		{"", ""},
		{"abcdefgh", "abcdefgh"},
		// multibyte rune at the cut
		{"abcdefgäöü", "abcdefgä"},
		// truncated rune
		{"abcdefg\xc3", "abcdefg�"},
		// invalid run collapses
		{"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7", "�"},
	} {
		got := leaseShort(tc.in)
		if !utf8.ValidString(got) {
			t.Errorf("leaseShort(%q) = %q is not valid UTF-8", tc.in, got)
		}
		if got != tc.want {
			t.Errorf("leaseShort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

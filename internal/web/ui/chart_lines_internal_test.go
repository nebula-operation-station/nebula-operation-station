// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// The production PVE store provides the optional backup freshness read; a
// signature drift must fail the build, not silently hide the backup lines.
var _ chartBackupReader = (*pveinventory.Store)(nil)

// The same holds for the stored guest config read (passthrough lines).
var _ chartGuestConfigReader = (*pveinventory.Store)(nil)

func TestShortImageRef(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := map[string]string{
		"nginx@sha256:" + digest:       "nginx@0123456789ab",
		"ghcr.io/a/b@sha256:" + digest: "ghcr.io/a/b@0123456789ab",
		"no-digest":                    "no-digest",
		"short@sha256:abc":             "short@sha256:abc",
	}
	for in, want := range cases {
		if got := shortImageRef(in); got != want {
			t.Errorf("shortImageRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWorstStateIncludesLines(t *testing.T) {
	lines := []chartLine{{State: StateOK}, {State: StateUnknown}, {State: StateWarn}, {State: StateStale}}
	if got := worstState(lineStates(lines)...); got != StateWarn {
		t.Errorf("worst = %s, want warn", got)
	}
	if got := worstClass(worstState(append(lineStates(lines), StateCrit)...)); got != "chart__node--critical" {
		t.Errorf("class = %s, want critical", got)
	}
	if got := worstClass(worstState(StateUnknown, StateStale)); got != "chart__node--neutral" {
		t.Errorf("unknown/stale class = %s, want neutral", got)
	}
}

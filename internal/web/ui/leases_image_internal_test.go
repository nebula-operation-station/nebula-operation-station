// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// TestImageLeaseProposalIsVisibleToItsProposerOnly checks that an image
// lease preview stored for one user is not returned to another user.
func TestImageLeaseProposalIsVisibleToItsProposerOnly(t *testing.T) {
	p := newLeaseProposals()
	now := time.Unix(1_800_000_000, 0)
	digest := strings.Repeat("c0", 32)
	p.put("alice", executions.ReadGrantPreview{Digest: digest, Params: map[string]map[string]string{
		"image.packages": {"image": "registry.example/app/web@sha256:" + strings.Repeat("a", 64)},
	}}, now)
	if _, ok := p.get("bob", digest, now); ok {
		t.Fatal("another user sees the image lease proposal")
	}
	if _, ok := p.get("alice", digest, now); !ok {
		t.Fatal("the proposer does not see the image lease proposal")
	}
}

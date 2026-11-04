// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"strings"
	"testing"
	"time"
)

// TestGuestPowerProposalStoreChecksUserOnEveryPath checks the proposer
// check of get and of transition separately: the handlers call get first,
// so a missing check in transition alone is not visible over HTTP.
func TestGuestPowerProposalStoreChecksUserOnEveryPath(t *testing.T) {
	now := time.Now()
	p := newGuestPowerProposals()
	digest := strings.Repeat("ab", 32)
	if !p.put(&guestPowerProposal{user: "alice", digest: digest, state: "pending", expires: now.Add(time.Minute)}, now) {
		t.Fatal("put refused")
	}
	if _, ok := p.get("bob", digest, now); ok {
		t.Error("get returns alice's proposal to bob")
	}
	if _, ok := p.transition("bob", digest, "pending", "running", now); ok {
		t.Error("transition moves alice's proposal for bob")
	}
	if x, ok := p.get("alice", digest, now); !ok || x.state != "pending" {
		t.Errorf("alice's proposal = %v %q after bob's attempts", ok, x.state)
	}
	if _, ok := p.transition("alice", digest, "pending", "running", now); !ok {
		t.Error("alice cannot move her own proposal")
	}
}

// TestGuestPowerArtifactHashesMatchExecutor pins the artifact hashes the
// executor (internal/executor, pveGuestPowerArtifact, module 1.0.0)
// produces for each verb, so a drift of the UI's copy is caught here.
func TestGuestPowerArtifactHashesMatchExecutor(t *testing.T) {
	want := map[string]string{
		"75fa24924db6f86220c909264fef5333d261d4b97f20277b69be7541b56bc62d": "shutdown",
		"7fad946ab6a878030fb59de3767e6d2b02f57735bb85aea7d2e0693b61e561b0": "reboot",
		"c3ffd96efe9d42730d432ac778639efce79c607a51b8b9f2f4176c8611621ea0": "stop",
		"0fc8331471b696d4601be036bd3f4b432d956e5659d7a35330d5c16f056c84fa": "reset",
	}
	if len(guestPowerArtifacts) != len(want) {
		t.Fatalf("%d artifacts, want %d", len(guestPowerArtifacts), len(want))
	}
	for h, verb := range want {
		if guestPowerArtifacts[h] != verb {
			t.Errorf("artifact %s = %q, want %q", h, guestPowerArtifacts[h], verb)
		}
	}
}

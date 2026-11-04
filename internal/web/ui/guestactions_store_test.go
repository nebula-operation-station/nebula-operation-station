// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"errors"
	"strconv"
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
	if err := p.put(&guestPowerProposal{user: "alice", digest: digest, state: "pending", expires: now.Add(time.Minute)}, now); err != nil {
		t.Fatalf("put refused: %v", err)
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

// TestGuestPowerPutRefusesAnotherUsersDigest checks that a repeated
// executor digest never hands one user's proposal to another.
func TestGuestPowerPutRefusesAnotherUsersDigest(t *testing.T) {
	now := time.Now()
	p := newGuestPowerProposals()
	digest := strings.Repeat("ab", 32)
	if err := p.put(&guestPowerProposal{user: "alice", digest: digest, state: "pending", expires: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	err := p.put(&guestPowerProposal{user: "bob", digest: digest, state: "pending", expires: now.Add(time.Minute)}, now)
	if !errors.Is(err, errGuestPowerDigest) {
		t.Errorf("bob's put of alice's digest = %v", err)
	}
	if _, ok := p.get("alice", digest, now); !ok {
		t.Error("alice lost her proposal")
	}
	if _, ok := p.get("bob", digest, now); ok {
		t.Error("bob took over alice's proposal")
	}
	// The same user may renew her own pending proposal.
	if err := p.put(&guestPowerProposal{user: "alice", digest: digest, state: "pending", expires: now.Add(2 * time.Minute)}, now); err != nil {
		t.Errorf("alice's renewal = %v", err)
	}
}

// TestGuestPowerPutCapsAndTableLimit fills the table with the open
// proposals of eight users at their cap: a ninth user is refused without
// evicting anyone until a settled proposal can make room.
func TestGuestPowerPutCapsAndTableLimit(t *testing.T) {
	now := time.Now()
	p := newGuestPowerProposals()
	digest := func(u, i int) string { return strings.Repeat("0", 60) + strconv.Itoa(1000 + u*100 + i)[:4] }
	users := maxGuestPowerProposals / maxGuestPowerProposalsPerUser
	for u := 0; u < users; u++ {
		for i := 0; i < maxGuestPowerProposalsPerUser; i++ {
			if err := p.put(&guestPowerProposal{user: "u" + strconv.Itoa(u), digest: digest(u, i), state: "pending", expires: now.Add(time.Minute)}, now); err != nil {
				t.Fatalf("put u%d/%d: %v", u, i, err)
			}
		}
	}
	if err := p.put(&guestPowerProposal{user: "u0", digest: digest(9, 0), state: "pending", expires: now.Add(time.Minute)}, now); !errors.Is(err, errGuestPowerUserCap) {
		t.Errorf("u0 over its cap = %v", err)
	}
	if err := p.put(&guestPowerProposal{user: "late", digest: digest(9, 1), state: "pending", expires: now.Add(time.Minute)}, now); !errors.Is(err, errGuestPowerFull) {
		t.Errorf("a ninth user with a full table = %v", err)
	}
	if len(p.props) != maxGuestPowerProposals {
		t.Fatalf("%d proposals kept", len(p.props))
	}
	p.setResult(digest(3, 5), "done", "", "", nil, now)
	if err := p.put(&guestPowerProposal{user: "late", digest: digest(9, 1), state: "pending", expires: now.Add(time.Minute)}, now); err != nil {
		t.Errorf("put after a settled proposal = %v", err)
	}
	if _, ok := p.props[digest(3, 5)]; ok {
		t.Error("the settled proposal was not the one evicted")
	}
}

// gpStoreProposal is a pending proposal whose executor binding expires at
// bindingExpiry; the page itself lives guestPowerProposalTTL from now.
func gpStoreProposal(user, digest string, now, bindingExpiry time.Time) *guestPowerProposal {
	return &guestPowerProposal{user: user, digest: digest, state: "pending", expires: now.Add(guestPowerProposalTTL),
		bound: guestPowerBinding{Expiry: bindingExpiry}}
}

// gpStoreDigest is a distinct digest per user and index.
func gpStoreDigest(u, i int) string {
	return strings.Repeat("0", 56) + strconv.Itoa(10000000+u*1000+i)
}

// TestGuestPowerExpiredBindingFreesUserCap fills alice's cap with pending
// proposals whose executor binding lasts five minutes: once the bindings
// expired (well before the 15-minute page TTL) they no longer count, so
// alice can propose again while their pages stay visible.
func TestGuestPowerExpiredBindingFreesUserCap(t *testing.T) {
	now := time.Now()
	p := newGuestPowerProposals()
	for i := 0; i < maxGuestPowerProposalsPerUser; i++ {
		if err := p.put(gpStoreProposal("alice", gpStoreDigest(0, i), now, now.Add(5*time.Minute)), now); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if err := p.put(gpStoreProposal("alice", gpStoreDigest(0, 99), now, now.Add(5*time.Minute)), now); !errors.Is(err, errGuestPowerUserCap) {
		t.Fatalf("alice over her cap with live bindings = %v", err)
	}
	// One second before the bindings expire, they still count.
	before := now.Add(5*time.Minute - time.Second)
	if err := p.put(gpStoreProposal("alice", gpStoreDigest(0, 99), before, before.Add(5*time.Minute)), before); !errors.Is(err, errGuestPowerUserCap) {
		t.Fatalf("alice over her cap before the bindings expired = %v", err)
	}
	later := now.Add(5 * time.Minute) // binding expiry reached; page TTL not
	if err := p.put(gpStoreProposal("alice", gpStoreDigest(0, 99), later, later.Add(5*time.Minute)), later); err != nil {
		t.Fatalf("alice after her bindings expired = %v", err)
	}
	if x, ok := p.get("alice", gpStoreDigest(0, 0), later); !ok || x.state != "pending" {
		t.Errorf("the expired proposal's page = %v %q, want still shown", ok, x.state)
	}
}

// TestGuestPowerRunningProposalKeepsCountingAfterBindingExpiry checks that
// only pending proposals lapse: an approving or running one still counts
// after its binding's expiry.
func TestGuestPowerRunningProposalKeepsCountingAfterBindingExpiry(t *testing.T) {
	now := time.Now()
	p := newGuestPowerProposals()
	for i := 0; i < maxGuestPowerProposalsPerUser; i++ {
		x := gpStoreProposal("alice", gpStoreDigest(0, i), now, now.Add(5*time.Minute))
		x.state = []string{"approving", "running"}[i%2]
		if err := p.put(x, now); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	later := now.Add(6 * time.Minute)
	if err := p.put(gpStoreProposal("alice", gpStoreDigest(0, 99), later, later.Add(5*time.Minute)), later); !errors.Is(err, errGuestPowerUserCap) {
		t.Errorf("alice with approving and running proposals past binding expiry = %v, want the cap", err)
	}
}

// TestGuestPowerMismatchedProposalHoldsNoSlot checks that a pending
// proposal whose binding differs from the request (never approvable) does
// not count against the cap, also when the binding names no expiry.
func TestGuestPowerMismatchedProposalHoldsNoSlot(t *testing.T) {
	now := time.Now()
	p := newGuestPowerProposals()
	for i := 0; i < maxGuestPowerProposalsPerUser; i++ {
		x := gpStoreProposal("alice", gpStoreDigest(0, i), now, time.Time{})
		x.mismatch = []string{"the bound request has no expiry"}
		if err := p.put(x, now); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if err := p.put(gpStoreProposal("alice", gpStoreDigest(0, 99), now, now.Add(5*time.Minute)), now); err != nil {
		t.Errorf("alice with only mismatched proposals = %v", err)
	}
}

// TestGuestPowerFullTableEvictsExpiredBindingsNotLiveOnes fills the table
// with eight users at their cap. Once most bindings expired, other users
// get slots by evicting those, never one of u0's proposals whose binding
// is still live; when every remaining proposal is live, the table refuses
// again.
func TestGuestPowerFullTableEvictsExpiredBindingsNotLiveOnes(t *testing.T) {
	now := time.Now()
	p := newGuestPowerProposals()
	users := maxGuestPowerProposals / maxGuestPowerProposalsPerUser
	for u := 0; u < users; u++ {
		bindingExpiry := now.Add(5 * time.Minute)
		if u == 0 {
			bindingExpiry = now.Add(10 * time.Minute) // u0's stay live
		}
		for i := 0; i < maxGuestPowerProposalsPerUser; i++ {
			if err := p.put(gpStoreProposal("u"+strconv.Itoa(u), gpStoreDigest(u, i), now, bindingExpiry), now); err != nil {
				t.Fatalf("put u%d/%d: %v", u, i, err)
			}
		}
	}
	if err := p.put(gpStoreProposal("late0", gpStoreDigest(9, 0), now, now.Add(5*time.Minute)), now); !errors.Is(err, errGuestPowerFull) {
		t.Fatalf("a ninth user with live bindings = %v", err)
	}
	later := now.Add(6 * time.Minute) // past the bindings, within the page TTL
	freeable := (users - 1) * maxGuestPowerProposalsPerUser
	for i := 0; i < freeable; i++ {
		// Each late user stays within its cap.
		k := i / maxGuestPowerProposalsPerUser
		if err := p.put(gpStoreProposal("late"+strconv.Itoa(k), gpStoreDigest(9+k, i%maxGuestPowerProposalsPerUser), later, later.Add(5*time.Minute)), later); err != nil {
			t.Fatalf("late put %d after bindings expired = %v", i, err)
		}
	}
	for i := 0; i < maxGuestPowerProposalsPerUser; i++ {
		if _, ok := p.get("u0", gpStoreDigest(0, i), later); !ok {
			t.Fatalf("u0's live proposal %d was evicted", i)
		}
	}
	if err := p.put(gpStoreProposal("last", gpStoreDigest(99, 0), later, later.Add(5*time.Minute)), later); !errors.Is(err, errGuestPowerFull) {
		t.Errorf("a full table of live proposals = %v, want full", err)
	}
	if len(p.props) != maxGuestPowerProposals {
		t.Errorf("%d proposals kept", len(p.props))
	}
}

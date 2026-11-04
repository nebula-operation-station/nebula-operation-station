// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"errors"
	"fmt"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func dpRun(id, user, state string, now time.Time) *deployRun {
	return &deployRun{id: id, user: user, state: state, created: now, expires: now.Add(deployRunTTL), deadline: now.Add(time.Hour)}
}

func TestDeployRunsGlobalLimitNeverEvictsLiveRuns(t *testing.T) {
	p := newDeployRuns()
	now := time.Unix(1_800_000_000, 0)
	// 8 users with 16 live runs each fill the global limit.
	for u := range maxDeployRuns / maxDeployRunsPerUser {
		for i := range maxDeployRunsPerUser {
			if err := p.put(dpRun(fmt.Sprintf("u%d-%d", u, i), fmt.Sprintf("user%d", u), deployBooting, now), now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := p.room("newcomer", now); !errors.Is(err, errDeployFull) {
		t.Fatalf("room with only live runs = %v", err)
	}
	if err := p.put(dpRun("x", "newcomer", deployProposed, now), now); !errors.Is(err, errDeployFull) {
		t.Fatalf("put evicted a live run: %v", err)
	}
	if err := p.room("user0", now); !errors.Is(err, errDeployUserCap) {
		t.Fatalf("user cap = %v", err)
	}
	// Past their deadline the idle runs fail and stop counting; the
	// finished run that expires first is evicted for a newcomer, a live
	// run of another user never is.
	later := now.Add(2 * time.Hour)
	p.mu.Lock()
	for _, x := range p.runs {
		if x.user != "user7" {
			continue
		}
		x.deadline = later.Add(time.Hour) // user7's runs stay live
	}
	p.mu.Unlock()
	if err := p.room("user0", later); err != nil {
		t.Fatalf("room after the deadline = %v", err)
	}
	if err := p.put(dpRun("y", "newcomer", deployProposed, later), later); err != nil {
		t.Fatalf("put after the deadline = %v", err)
	}
	live := 0
	for _, x := range p.runs {
		if x.user == "user7" {
			if x.final() {
				t.Errorf("run %s of user7 failed before its deadline", x.id)
			}
			live++
		}
		if x.state == deployFailed && (x.failedIn != deployBooting || x.message == "") {
			t.Errorf("expired run %s: failed in %q, reason %q", x.id, x.failedIn, x.message)
		}
	}
	if live != maxDeployRunsPerUser {
		t.Errorf("user7 keeps %d of %d live runs", live, maxDeployRunsPerUser)
	}
}

func TestDeployRunsBusyRunsAreNeverExpired(t *testing.T) {
	p := newDeployRuns()
	now := time.Unix(1_800_000_000, 0)
	creating := dpRun("c", "alice", deployCreating, now)
	joining := dpRun("j", "alice", deployEnrolling, now)
	joining.join = &deployJoin{approving: true}
	planning := dpRun("p", "alice", deployBootstrapping, now)
	planning.approving = true
	for _, x := range []*deployRun{creating, joining, planning} {
		if err := p.put(x, now); err != nil {
			t.Fatal(err)
		}
	}
	later := now.Add(48 * time.Hour)
	p.mu.Lock()
	p.prune(later)
	p.mu.Unlock()
	for _, x := range []*deployRun{creating, joining, planning} {
		if x.final() || p.runs[x.id] == nil {
			t.Errorf("busy run %s (%s) was expired or dropped", x.id, x.state)
		}
	}
}

func TestDeployRunsExpiredProposalIsReleasedOnce(t *testing.T) {
	p := newDeployRuns()
	now := time.Unix(1_800_000_000, 0)
	x := dpRun("a", "alice", deployProposed, now)
	x.ipam = &pb.PVEIPAMBinding{Address: "192.168.10.50"}
	if err := p.put(x, now); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.prune(now.Add(2 * time.Hour))
	p.mu.Unlock()
	if x.state != deployFailed || x.failedIn != deployProposed || x.address != ipamRelease {
		t.Fatalf("expired proposal: %s in %s, address %q", x.state, x.failedIn, x.address)
	}
	got := p.releases()
	if len(got) != 1 || got["a"].String() != "192.168.10.50" || x.address != ipamReleasing {
		t.Fatalf("releases = %v (%q)", got, x.address)
	}
	if again := p.releases(); len(again) != 0 {
		t.Errorf("an address in flight was handed out twice: %v", again)
	}
	// A run whose release is in flight is not pruned.
	p.mu.Lock()
	p.prune(now.Add(72 * time.Hour))
	p.mu.Unlock()
	if p.runs["a"] == nil {
		t.Error("run pruned while its address release is in flight")
	}
}

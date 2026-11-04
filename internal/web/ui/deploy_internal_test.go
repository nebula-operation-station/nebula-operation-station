// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"errors"
	"fmt"
	"strings"
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

// TestDeployRunsExpiredProposalKeepsItsAddress: the expiry of a proposal
// with an IPAM reservation marks the address kept ("may be in use"), never
// for release: the execution may have been committed out of band. A
// proposal without a reservation (DHCP) has nothing to keep.
func TestDeployRunsExpiredProposalKeepsItsAddress(t *testing.T) {
	p := newDeployRuns()
	now := time.Unix(1_800_000_000, 0)
	x := dpRun("a", "alice", deployProposed, now)
	x.ipam, x.vmid = &pb.PVEIPAMBinding{Address: "192.168.10.50"}, 123
	dhcp := dpRun("b", "alice", deployProposed, now)
	for _, r := range []*deployRun{x, dhcp} {
		if err := p.put(r, now); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	p.prune(now.Add(2 * time.Hour))
	p.mu.Unlock()
	if x.state != deployFailed || x.failedIn != deployProposed || x.address != ipamKept {
		t.Fatalf("expired proposal: %s in %s, address %q", x.state, x.failedIn, x.address)
	}
	for _, want := range []string{"may be in use", "192.168.10.50", "VMID 123"} {
		if !strings.Contains(x.message, want) {
			t.Errorf("expired proposal message lacks %q: %s", want, x.message)
		}
	}
	if dhcp.state != deployFailed || dhcp.address != ipamHeld || strings.Contains(dhcp.message, "nothing was created") {
		t.Errorf("expired DHCP proposal: %s, address %q, %q", dhcp.state, dhcp.address, dhcp.message)
	}
	// A kept address holds no run: past the TTL both are pruned (the
	// reservation itself stays in the IPAM).
	p.mu.Lock()
	p.prune(now.Add(72 * time.Hour))
	p.mu.Unlock()
	if len(p.runs) != 0 {
		t.Errorf("%d runs left past the TTL", len(p.runs))
	}
}

// TestDeployRunsKeptAddressesNeverBlockTheLimit: finished runs that keep
// their address are evicted like any finished run, so a store full of them
// never refuses a new deployment.
func TestDeployRunsKeptAddressesNeverBlockTheLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := newDeployRuns()
	for i := range maxDeployRuns {
		x := dpRun(fmt.Sprintf("r%d", i), fmt.Sprintf("user%d", i), deployFailed, now)
		x.ipam, x.address = &pb.PVEIPAMBinding{Address: "192.168.10.50"}, ipamKept
		if err := p.put(x, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.room("bob", now); err != nil {
		t.Errorf("room with only kept-address runs = %v", err)
	}
	if err := p.put(dpRun("new", "bob", deployProposed, now), now); err != nil {
		t.Errorf("put with only kept-address runs = %v", err)
	}
	if len(p.runs) != maxDeployRuns {
		t.Errorf("%d runs, want %d", len(p.runs), maxDeployRuns)
	}
}

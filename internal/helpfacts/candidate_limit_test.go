// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"context"
	"fmt"
	"testing"
)

// manyHostsInBlock returns n hosts whose single endpoint lies in 10.0.0.0/16.
func manyHostsInBlock(n int) []Record {
	hosts := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("h%03d", i)
		addr := fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)
		hosts = append(hosts, baseRecord(id, id, addr))
	}
	return hosts
}

// TestVisibilityIsCheckedAtMostNamedCandidateLimit checks that one question
// cannot trigger an unbounded number of authorisation checks or fact builds:
// a /16 names hundreds of hosts, but at most MaxNamedCandidates are checked.
func TestVisibilityIsCheckedAtMostNamedCandidateLimit(t *testing.T) {
	calls := 0
	vis := func(context.Context, string) (bool, error) {
		calls++
		return true, nil
	}
	src := fakeSource{hosts: manyHostsInBlock(500)}

	res := mustProject(t, request("which hosts are in 10.0.0.0/16?", src, vis))
	if calls > MaxNamedCandidates {
		t.Fatalf("visibility checked %d times, limit is %d", calls, MaxNamedCandidates)
	}
	if len(res.Hosts) != MaxFactHosts {
		t.Fatalf("projected %d hosts, want %d", len(res.Hosts), MaxFactHosts)
	}
	if !res.Truncated {
		t.Fatal("candidate limit reached but Truncated = false")
	}
}

// TestCandidateLimitSuppressesNotInInventory checks that an address literal
// is not reported as missing from the inventory when the check stopped
// before every host that could have it was looked at.
func TestCandidateLimitSuppressesNotInInventory(t *testing.T) {
	hosts := manyHostsInBlock(500)
	// The last host in ID order carries the address the question names.
	// The check stops before it, so it must not be reported as absent.
	hosts[499].Endpoints = []RawEndpoint{lanEndpoint("10.0.1.250")}
	src := fakeSource{hosts: hosts}
	res := mustProject(t, request("is 10.0.1.250 up? what about 10.0.0.0/16?", src, visibleAll(hosts)))
	if len(res.NotInInventory) != 0 {
		t.Fatalf("capped check reported %v as not in inventory", res.NotInInventory)
	}
	if !res.Truncated {
		t.Fatal("capped check must set Truncated")
	}
}

// visibleAll returns a Visibility that allows every host in hosts.
func visibleAll(hosts []Record) Visibility {
	ids := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	return visibleOnly(ids...)
}

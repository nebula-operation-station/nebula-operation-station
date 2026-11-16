// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

// manyHidden is more hidden hosts than any projection shows, so a candidate
// bound below it would have been reached.
const manyHidden = 3 * MaxFactHosts

// hiddenHostsInBlock returns n hosts with IDs a000.. whose endpoints lie in
// 10.0.0.0/16. They sort before any "z" host, so they come first in ID order.
func hiddenHostsInBlock(n int) []Record {
	hosts := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("a%03d", i)
		addr := fmt.Sprintf("10.0.0.%d", i+1)
		hosts = append(hosts, baseRecord(id, id, addr))
	}
	return hosts
}

// TestHiddenNamedHostsLookLikeNonexistentHosts checks the promise of the
// Project doc: a question that names hidden hosts gets the same Result as a
// question that names hosts which do not exist. The counts go past the
// candidate bound on both sides, because that bound is where the leak was.
func TestHiddenNamedHostsLookLikeNonexistentHosts(t *testing.T) {
	const question = "is 10.9.9.9 up? what about 10.0.0.0/16?"
	visible := []Record{baseRecord("z-visible", "z-visible", "10.0.9.9")}
	for _, n := range []int{1, MaxFactHosts, MaxFactHosts + 1, manyHidden, 200} {
		hidden := hiddenHostsInBlock(n)
		all := append(append([]Record{}, hidden...), visible...)
		withHidden := mustProject(t, request(question, fakeSource{hosts: all}, visibleOnly("z-visible")))
		absent := mustProject(t, request(question, fakeSource{hosts: visible}, visibleOnly("z-visible")))
		if !reflect.DeepEqual(withHidden, absent) {
			t.Fatalf("%d hidden hosts: result %+v differs from nonexistent-host result %+v", n, withHidden, absent)
		}
	}
}

// TestHiddenHostsDoNotSetTruncated checks that a question naming more hidden
// hosts than the candidate bound does not claim truncation, so the caller
// cannot count hidden hosts from the flag.
func TestHiddenHostsDoNotSetTruncated(t *testing.T) {
	hidden := hiddenHostsInBlock(manyHidden)
	src := fakeSource{hosts: hidden}
	res := mustProject(t, request("which hosts are in 10.0.0.0/16?", src, visibleOnly()))
	if len(res.Hosts) != 0 {
		t.Fatalf("hidden hosts projected: %v", hostIDs(res))
	}
	if res.Truncated {
		t.Fatal("hidden hosts alone set Truncated")
	}
}

// TestHiddenAddressStaysNotInInventoryWithManyHiddenHosts checks that an
// address held only by a hidden host is reported as not in the inventory
// even when more hidden hosts than the candidate bound also match the question.
func TestHiddenAddressStaysNotInInventoryWithManyHiddenHosts(t *testing.T) {
	hosts := append(hiddenHostsInBlock(manyHidden), baseRecord("z-hidden", "z-hidden", "10.0.9.9"))
	res := mustProject(t, request("10.0.9.9 10.0.0.0/16", fakeSource{hosts: hosts}, visibleOnly()))
	if want := []string{"10.0.9.9"}; !reflect.DeepEqual(res.NotInInventory, want) {
		t.Fatalf("NotInInventory = %v, want %v", res.NotInInventory, want)
	}
	if res.Truncated {
		t.Fatal("hidden hosts alone set Truncated")
	}
}

// TestHiddenLowerIDHostsDoNotPushOutVisibleNamedHost checks that hidden hosts
// with lower IDs take no slot: a visible host named by its CIDR and its exact
// address is still projected when more hidden hosts than the bound match.
func TestHiddenLowerIDHostsDoNotPushOutVisibleNamedHost(t *testing.T) {
	hosts := append(hiddenHostsInBlock(manyHidden), baseRecord("z-target", "z-target", "10.0.9.9"))
	res := mustProject(t, request("10.0.9.9 10.0.0.0/16", fakeSource{hosts: hosts}, visibleOnly("z-target")))
	if want := []string{"z-target"}; !reflect.DeepEqual(hostIDs(res), want) {
		t.Fatalf("projected %v, want %v", hostIDs(res), want)
	}
	if len(res.NotInInventory) != 0 {
		t.Fatalf("visible host reported as not in inventory: %v", res.NotInInventory)
	}
}

// TestVisibleHostsOverTheBoundSetTruncated checks that the flag is still set
// when the visible hosts themselves exceed what one projection shows.
func TestVisibleHostsOverTheBoundSetTruncated(t *testing.T) {
	hosts := hiddenHostsInBlock(MaxFactHosts + 1)
	ids := []string{}
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	res := mustProject(t, request("which hosts are in 10.0.0.0/16?", fakeSource{hosts: hosts}, visibleOnly(ids...)))
	if len(res.Hosts) != MaxFactHosts {
		t.Fatalf("projected %d hosts, want %d", len(res.Hosts), MaxFactHosts)
	}
	if !res.Truncated {
		t.Fatal("visible hosts over the bound but Truncated = false")
	}
}

// TestVisibilityErrorStopsProjection checks that a failing check on a hidden
// candidate still fails the whole projection instead of being skipped.
func TestVisibilityErrorStopsProjection(t *testing.T) {
	hosts := hiddenHostsInBlock(3)
	boom := func(_ context.Context, id string) (bool, error) {
		if id == "a001" {
			return false, fmt.Errorf("auth backend down")
		}
		return false, nil
	}
	if _, err := Project(context.Background(), request("which hosts are in 10.0.0.0/16?", fakeSource{hosts: hosts}, boom)); err == nil {
		t.Fatal("visibility error was swallowed")
	}
}

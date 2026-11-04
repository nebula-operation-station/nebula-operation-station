// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// hostIdentity is a reporter Identity with the given MAC ("" for none)
// and addresses.
func hostIdentity(mac string, addrs ...string) Identity {
	var id Identity
	if mac != "" {
		id.MACs = []string{mac}
	}
	for _, a := range addrs {
		id.Addrs = append(id.Addrs, netip.MustParseAddr(a))
	}
	return id
}

func addrList(addrs ...string) []netip.Addr {
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func mustUpsert(t *testing.T, s *Store, e Endpoint, own Identity) {
	t.Helper()
	if err := s.UpsertEndpoint(context.Background(), e, own); err != nil {
		t.Fatalf("upsert %s/%v by %s: %v", e.MAC, e.Addresses, e.Reporter, err)
	}
}

func mustEndpoint(t *testing.T, s *Store, id string) Endpoint {
	t.Helper()
	e, err := s.Endpoint(context.Background(), id)
	if err != nil {
		t.Fatalf("read endpoint %s: %v", id, err)
	}
	return e
}

// observation returns reporter's observation of e, failing when absent.
func observation(t *testing.T, e Endpoint, reporter string) Observation {
	t.Helper()
	for _, o := range e.Observations {
		if o.Reporter == reporter {
			return o
		}
	}
	t.Fatalf("endpoint %s has no observation by %s (seen by %v)", e.ID, reporter, e.SeenBy)
	return Observation{}
}

func lookupMissing(t *testing.T, s *Store, addr string) {
	t.Helper()
	if e, found, err := s.LookupEndpoint(context.Background(), "", netip.MustParseAddr(addr)); found || err != nil {
		t.Errorf("lookup %s: found=%v (%s) err=%v, want not found", addr, found, e.ID, err)
	}
}

func TestOwnerAddressesNotInIdentityAreNotAttested(t *testing.T) {
	s, db, _ := newTestStore(t)
	const victimMAC, evilMAC = "00:11:22:33:44:01", "00:11:22:33:44:02"

	victim := testEndpoint("10.0.5.5", victimMAC, "victim")
	mustUpsert(t, s, victim, hostIdentity(victimMAC, "10.0.5.5"))
	victimID := mustLookup(t, s, victimMAC, "").ID

	// The owner of its own MAC reports its address and a foreign one by
	// MAC observation: only the address in its records is attached.
	evil := testEndpoint("10.0.0.1", evilMAC, "evil")
	evil.Addresses = addrList("10.0.0.1", "10.66.0.1", "10.0.5.5")
	mustUpsert(t, s, evil, hostIdentity(evilMAC, "10.0.0.1"))
	got := mustLookup(t, s, evilMAC, "")
	if got.Owner != "evil" || !slices.Equal(got.Addresses, addrList("10.0.0.1")) ||
		!slices.Equal(observation(t, got, "evil").Addresses, addrList("10.0.0.1")) {
		t.Errorf("owned endpoint = owner %q addresses %v obs %+v, want only the attested address", got.Owner, got.Addresses, got.Observations)
	}
	lookupMissing(t, s, "10.66.0.1")
	if g := mustLookup(t, s, "", "10.0.5.5"); g.ID != victimID {
		t.Errorf("lookup of the victim's address = %s, want the victim's %s", g.ID, victimID)
	}

	// A MAC-less observation that matches its own endpoint by its own
	// address attaches no foreign address either, and keeps ownership.
	evilNoMAC := testEndpoint("10.0.0.1", "", "evil")
	evilNoMAC.Addresses = addrList("10.0.0.1", "10.0.5.5", "10.66.0.2")
	mustUpsert(t, s, evilNoMAC, hostIdentity(evilMAC, "10.0.0.1"))
	got = mustEndpoint(t, s, got.ID)
	if got.Owner != "evil" || !slices.Equal(observation(t, got, "evil").Addresses, addrList("10.0.0.1")) {
		t.Errorf("after MAC-less report: owner %q evil addresses %v, want evil with 10.0.0.1 only",
			got.Owner, observation(t, got, "evil").Addresses)
	}
	if g := mustLookup(t, s, "", "10.0.5.5"); g.ID != victimID {
		t.Errorf("lookup of the victim's address = %s, want %s", g.ID, victimID)
	}
	lookupMissing(t, s, "10.66.0.2")

	// A MAC-less endpoint owned by its address: a mixed observation keeps
	// ownership but attaches only the attested address.
	self := testEndpoint("10.0.4.1", "", "host-4")
	mustUpsert(t, s, self, hostIdentity("", "10.0.4.1"))
	selfID := mustLookup(t, s, "", "10.0.4.1").ID
	self.Addresses = addrList("10.0.4.1", "10.0.5.5")
	mustUpsert(t, s, self, hostIdentity("", "10.0.4.1"))
	g := mustEndpoint(t, s, selfID)
	if g.Owner != "host-4" || !slices.Equal(g.Addresses, addrList("10.0.4.1")) {
		t.Errorf("MAC-less owned endpoint = owner %q addresses %v, want host-4 with 10.0.4.1", g.Owner, g.Addresses)
	}
	if g := mustLookup(t, s, "", "10.0.5.5"); g.ID != victimID {
		t.Errorf("lookup of the victim's address = %s, want %s", g.ID, victimID)
	}
	checkCounters(t, s, db)
}

func TestMACLessMatchingIgnoresNonOwnerAddresses(t *testing.T) {
	s, db, now := newTestStore(t)
	const mac = "00:11:22:33:44:55"

	mustUpsert(t, s, testEndpoint("10.0.0.1", mac, "victim"), hostIdentity(mac, "10.0.0.1"))
	victimID := mustLookup(t, s, mac, "").ID

	// A hostile host reports the victim's MAC with an address X and keeps
	// that observation fresh.
	*now = now.Add(time.Minute)
	evil := testEndpoint("10.0.0.99", mac, "evil")
	evil.LastSeen = *now
	mustUpsert(t, s, evil, Identity{})

	// A new reporter's MAC-less observation of X does not join the owned
	// endpoint: it gets an endpoint of its own.
	obs := testEndpoint("10.0.0.99", "", "observer")
	obs.LastSeen = *now
	for range 2 {
		mustUpsert(t, s, obs, Identity{})
	}
	if g := mustEndpoint(t, s, victimID); !slices.Equal(g.SeenBy, []string{"evil", "victim"}) {
		t.Errorf("victim endpoint seen by %v, want evil and victim only", g.SeenBy)
	}
	g := mustLookup(t, s, "", "10.0.0.99")
	if g.ID == victimID || g.MAC != "" || !slices.Equal(g.SeenBy, []string{"observer"}) {
		t.Errorf("observation of X = %+v, want a separate endpoint seen by the observer", g)
	}
	if n := mustCount(t, s.CountEndpoints); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}

	// The owner's attested address still matches the owned endpoint.
	mustUpsert(t, s, testEndpoint("10.0.0.1", "", "observer"), Identity{})
	if g := mustEndpoint(t, s, victimID); !slices.Equal(g.SeenBy, []string{"evil", "observer", "victim"}) {
		t.Errorf("victim endpoint seen by %v, want the observer joined", g.SeenBy)
	}
	checkCounters(t, s, db)
}

func TestAuthoritativeMACLessNotCapturedByForeignMAC(t *testing.T) {
	s, _, _ := newTestStore(t)

	// A hostile host reports a made-up MAC with the reporter's address.
	mustUpsert(t, s, testEndpoint("10.0.7.1", "00:11:22:33:44:99", "evil"), Identity{})
	fakeID := mustLookup(t, s, "00:11:22:33:44:99", "").ID

	// The reporter's own MAC-less observation of its address does not
	// join the foreign MAC endpoint.
	mustUpsert(t, s, testEndpoint("10.0.7.1", "", "host-7"), hostIdentity("00:11:22:33:44:07", "10.0.7.1"))
	g := mustLookup(t, s, "", "10.0.7.1")
	if g.ID == fakeID || g.Owner != "host-7" {
		t.Errorf("lookup = %s owner %q, want host-7's own endpoint", g.ID, g.Owner)
	}
	if f := mustEndpoint(t, s, fakeID); !slices.Equal(f.SeenBy, []string{"evil"}) {
		t.Errorf("fake endpoint seen by %v, want evil only", f.SeenBy)
	}

	// The reporter's own MAC endpoint, observed first by someone else,
	// is joined and taken over.
	const own = "00:11:22:33:44:08"
	mustUpsert(t, s, testEndpoint("10.0.8.1", own, "observer"), Identity{})
	ownID := mustLookup(t, s, own, "").ID
	mustUpsert(t, s, testEndpoint("10.0.8.1", "", "host-8"), hostIdentity(own, "10.0.8.1"))
	if g := mustEndpoint(t, s, ownID); g.Owner != "host-8" {
		t.Errorf("own MAC endpoint owner = %q, want host-8", g.Owner)
	}
}

func TestOwnershipFollowsIdentity(t *testing.T) {
	s, db, now := newTestStore(t)
	const mac = "00:11:22:33:44:55"

	// MAC endpoint: the owner's records lose the MAC (moved to another
	// host): it loses ownership on its next report.
	mustUpsert(t, s, testEndpoint("10.0.0.1", mac, "old"), hostIdentity(mac, "10.0.0.1"))
	id := mustLookup(t, s, mac, "").ID
	*now = now.Add(time.Minute)
	e := testEndpoint("10.0.0.1", mac, "old")
	e.LastSeen = *now
	mustUpsert(t, s, e, hostIdentity("", "10.0.0.1"))
	if g := mustEndpoint(t, s, id); g.Owner != "" {
		t.Errorf("owner = %q after the MAC left old's records, want none", g.Owner)
	}
	lookupOwnedMissing := func(addr string) {
		t.Helper()
		if g, found, _ := s.LookupEndpoint(context.Background(), "", netip.MustParseAddr(addr)); found && g.Owner != "" {
			t.Errorf("lookup %s = owned by %q, want no owner", addr, g.Owner)
		}
	}
	lookupOwnedMissing("10.0.0.1")
	// The new holder by the server's records becomes the owner.
	mustUpsert(t, s, testEndpoint("10.0.0.2", mac, "new"), hostIdentity(mac, "10.0.0.2"))
	if g := mustEndpoint(t, s, id); g.Owner != "new" || !slices.Equal(g.Addresses, addrList("10.0.0.2")) {
		t.Errorf("owner/addresses = %q/%v, want new with 10.0.0.2", g.Owner, g.Addresses)
	}

	// A later holder takes over directly, without the former owner
	// reporting first.
	mustUpsert(t, s, testEndpoint("10.0.0.3", mac, "newer"), hostIdentity(mac, "10.0.0.3"))
	if g := mustEndpoint(t, s, id); g.Owner != "newer" || !slices.Equal(g.Addresses, addrList("10.0.0.3")) {
		t.Errorf("owner/addresses = %q/%v, want newer with 10.0.0.3", g.Owner, g.Addresses)
	}
	// The former owner's attributions no longer resolve to it.
	if g, found, err := s.LookupEndpoint(context.Background(), "", netip.MustParseAddr("10.0.0.2")); err != nil || (found && g.Owner != "") {
		t.Errorf("lookup 10.0.0.2: found=%v owner=%q err=%v, want no owned match", found, g.Owner, err)
	}

	// The owner's addresses follow its records: an address that left
	// them is dropped on its next report.
	e = testEndpoint("10.0.0.3", mac, "newer")
	e.Addresses = addrList("10.0.0.3", "10.0.0.4")
	mustUpsert(t, s, e, hostIdentity(mac, "10.0.0.3", "10.0.0.4"))
	if g := mustLookup(t, s, "", "10.0.0.4"); g.ID != id {
		t.Errorf("lookup 10.0.0.4 = %s, want %s", g.ID, id)
	}
	e.Addresses = addrList("10.0.0.3")
	mustUpsert(t, s, e, hostIdentity(mac, "10.0.0.3"))
	if g := mustEndpoint(t, s, id); !slices.Equal(g.Addresses, addrList("10.0.0.3")) {
		t.Errorf("addresses = %v, want the stale 10.0.0.4 dropped", g.Addresses)
	}
	lookupMissing(t, s, "10.0.0.4")

	// MAC-less endpoint owned by its address: the lease moves; the old
	// holder's next report drops its ownership, and the new holder takes
	// it.
	mustUpsert(t, s, testEndpoint("10.0.9.1", "", "lease-a"), hostIdentity("", "10.0.9.1"))
	leaseID := mustLookup(t, s, "", "10.0.9.1").ID
	mustUpsert(t, s, testEndpoint("10.0.9.1", "", "lease-a"), Identity{})
	if g := mustEndpoint(t, s, leaseID); g.Owner != "" {
		t.Errorf("owner = %q after the lease left lease-a's records, want none", g.Owner)
	}
	mustUpsert(t, s, testEndpoint("10.0.9.1", "", "lease-b"), hostIdentity("", "10.0.9.1"))
	if g := mustLookup(t, s, "", "10.0.9.1"); g.ID != leaseID || g.Owner != "lease-b" {
		t.Errorf("lookup = %s owner %q, want %s owned by lease-b", g.ID, g.Owner, leaseID)
	}
	// A further holder takes the MAC-less endpoint over directly.
	mustUpsert(t, s, testEndpoint("10.0.9.1", "", "lease-c"), hostIdentity("", "10.0.9.1"))
	if g := mustLookup(t, s, "", "10.0.9.1"); g.ID != leaseID || g.Owner != "lease-c" {
		t.Errorf("lookup = %s owner %q, want %s owned by lease-c", g.ID, g.Owner, leaseID)
	}
	checkCounters(t, s, db)
}

func TestReportersCapKeepsSlotForOwner(t *testing.T) {
	s, db, _ := newTestStore(t)
	const mac = "00:11:22:33:44:55"
	for i := range MaxReportersPerEndpoint {
		e := testEndpoint("10.0.0.1", mac, fmt.Sprintf("r%02d", i))
		if i == 7 {
			e.LastSeen = testNow.Add(-time.Hour)
		}
		mustUpsert(t, s, e, Identity{})
	}
	if err := s.UpsertEndpoint(context.Background(), testEndpoint("10.0.0.1", mac, "late"), Identity{}); !errors.Is(err, ErrLimit) {
		t.Errorf("non-owner beyond the endpoint cap: err = %v, want ErrLimit", err)
	}
	// The authoritative reporter is admitted; the least recently seen
	// non-owner makes room.
	mustUpsert(t, s, testEndpoint("10.0.0.1", mac, "owner"), hostIdentity(mac, "10.0.0.1"))
	g := mustLookup(t, s, mac, "")
	if g.Owner != "owner" || len(g.SeenBy) != MaxReportersPerEndpoint || slices.Contains(g.SeenBy, "r07") {
		t.Errorf("owner %q seen by %d %v, want owner admitted and r07 evicted", g.Owner, len(g.SeenBy), g.SeenBy)
	}
	if g := mustLookup(t, s, "", "10.0.0.1"); g.ID == "" || g.Owner != "owner" {
		t.Errorf("address lookup owner = %q, want owner", g.Owner)
	}
	checkCounters(t, s, db)
}

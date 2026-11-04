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
	var reporters []string
	for i := range MaxReportersPerEndpoint {
		r := fmt.Sprintf("r%02d", i)
		reporters = append(reporters, r)
		e := testEndpoint("10.0.0.1", mac, r)
		if i == 7 {
			e.LastSeen = testNow.Add(-time.Hour)
		}
		mustUpsert(t, s, e, Identity{})
	}
	if err := s.UpsertEndpoint(context.Background(), testEndpoint("10.0.0.1", mac, "late"), Identity{}); !errors.Is(err, ErrLimit) {
		t.Errorf("non-owner beyond the endpoint cap: err = %v, want ErrLimit", err)
	}
	// The authoritative reporter is admitted into its reserved slot; no
	// other reporter's observation is evicted.
	mustUpsert(t, s, testEndpoint("10.0.0.1", mac, "owner"), hostIdentity(mac, "10.0.0.1"))
	g := mustLookup(t, s, mac, "")
	want := append(slices.Clone(reporters), "owner")
	slices.Sort(want)
	if g.Owner != "owner" || !slices.Equal(g.SeenBy, want) {
		t.Errorf("owner %q seen by %d %v, want owner admitted and all %d others kept", g.Owner, len(g.SeenBy), g.SeenBy, MaxReportersPerEndpoint)
	}
	if o := observation(t, g, "r07"); !slices.Equal(o.Addresses, addrList("10.0.0.1")) {
		t.Errorf("r07 addresses = %v, want kept", o.Addresses)
	}
	// The kept reporters still report; a further non-owner is refused.
	mustUpsert(t, s, testEndpoint("10.0.0.1", mac, "r07"), Identity{})
	if err := s.UpsertEndpoint(context.Background(), testEndpoint("10.0.0.1", mac, "late"), Identity{}); !errors.Is(err, ErrLimit) {
		t.Errorf("non-owner beyond the endpoint cap with owner: err = %v, want ErrLimit", err)
	}
	if g := mustLookup(t, s, "", "10.0.0.1"); g.ID == "" || g.Owner != "owner" {
		t.Errorf("address lookup owner = %q, want owner", g.Owner)
	}
	checkCounters(t, s, db)
}

func TestOwnedMACEndpointWithoutAttestedAddress(t *testing.T) {
	s, db, _ := newTestStore(t)
	const mac = "00:11:22:33:44:55"

	// The owner's own MAC observed with addresses outside its records:
	// the owned endpoint exists, attested by its MAC only.
	e := testEndpoint("10.0.9.9", mac, "host")
	e.Addresses = addrList("10.0.9.9", "fe80::1")
	mustUpsert(t, s, e, hostIdentity(mac, "10.0.0.1"))
	g := mustLookup(t, s, mac, "")
	if g.Owner != "host" || len(g.Addresses) != 0 || len(observation(t, g, "host").Addresses) != 0 {
		t.Errorf("endpoint = owner %q addresses %v obs %v, want owned without addresses", g.Owner, g.Addresses, observation(t, g, "host").Addresses)
	}
	// It never resolves by address, and a non-owner's MAC-less report of
	// such an address does not attach to it.
	lookupMissing(t, s, "10.0.9.9")
	mustUpsert(t, s, testEndpoint("10.0.9.9", "", "observer"), Identity{})
	if g := mustEndpoint(t, s, g.ID); !slices.Equal(g.SeenBy, []string{"host"}) {
		t.Errorf("owned endpoint seen by %v, want host only", g.SeenBy)
	}
	if g2 := mustLookup(t, s, "", "10.0.9.9"); g2.ID == g.ID || g2.Owner != "" {
		t.Errorf("lookup 10.0.9.9 = %s owner %q, want the observer's own endpoint", g2.ID, g2.Owner)
	}
	// One endpoint per MAC: repeated reports keep the single endpoint.
	e.Addresses = addrList("10.0.9.8")
	mustUpsert(t, s, e, hostIdentity(mac, "10.0.0.1"))
	if n := mustCount(t, s.CountEndpoints); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
	checkCounters(t, s, db)
}

func TestReconcileReleasesSilentOwner(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	const mac = "00:11:22:33:44:55"

	// host-a owns a MAC endpoint (10.0.0.1, 10.0.0.2) and a MAC-less one
	// (10.0.1.1); an observer also sees the MAC endpoint.
	ownA := hostIdentity(mac, "10.0.0.1", "10.0.0.2", "10.0.1.1")
	e := testEndpoint("10.0.0.1", mac, "host-a")
	e.Addresses = addrList("10.0.0.1", "10.0.0.2")
	mustUpsert(t, s, e, ownA)
	macID := mustLookup(t, s, mac, "").ID
	mustUpsert(t, s, testEndpoint("10.0.0.1", mac, "observer"), Identity{})
	mustUpsert(t, s, testEndpoint("10.0.1.1", "", "host-a"), ownA)
	lessID := mustLookup(t, s, "", "10.0.1.1").ID
	// host-c owns an endpoint its records still back.
	const macC = "00:11:22:33:44:0c"
	mustUpsert(t, s, testEndpoint("10.0.2.1", macC, "host-c"), hostIdentity(macC, "10.0.2.1"))
	cID := mustLookup(t, s, macC, "").ID

	// host-a's records lose 10.0.0.2 and 10.0.1.1 while it is silent.
	current := map[string]Identity{
		"host-a": hostIdentity(mac, "10.0.0.1"),
		"host-c": hostIdentity(macC, "10.0.2.1"),
	}
	n, err := s.ReconcileIdentities(ctx, current)
	if err != nil || n != 1 {
		t.Fatalf("reconcile = %d, %v, want 1 released", n, err)
	}
	if g := mustEndpoint(t, s, macID); g.Owner != "host-a" || !slices.Equal(g.Addresses, addrList("10.0.0.1")) {
		t.Errorf("MAC endpoint = owner %q addresses %v, want host-a with 10.0.0.1", g.Owner, g.Addresses)
	}
	lookupMissing(t, s, "10.0.0.2")
	if g := mustEndpoint(t, s, lessID); g.Owner != "" || len(g.Addresses) != 0 {
		t.Errorf("MAC-less endpoint = owner %q addresses %v, want released", g.Owner, g.Addresses)
	}
	lookupMissing(t, s, "10.0.1.1")

	// host-a drops out of the records entirely: it loses the MAC endpoint
	// and its attestations; the observer's own report is kept.
	delete(current, "host-a")
	if n, err := s.ReconcileIdentities(ctx, current); err != nil || n != 1 {
		t.Fatalf("reconcile = %d, %v, want 1 released", n, err)
	}
	g := mustEndpoint(t, s, macID)
	if g.Owner != "" || !slices.Equal(g.SeenBy, []string{"host-a", "observer"}) ||
		len(observation(t, g, "host-a").Addresses) != 0 ||
		!slices.Equal(observation(t, g, "observer").Addresses, addrList("10.0.0.1")) {
		t.Errorf("MAC endpoint = owner %q seen by %v obs %+v, want no owner, host-a without addresses, observer kept",
			g.Owner, g.SeenBy, g.Observations)
	}
	if g := mustEndpoint(t, s, cID); g.Owner != "host-c" || !slices.Equal(g.Addresses, addrList("10.0.2.1")) {
		t.Errorf("host-c endpoint = owner %q addresses %v, want unchanged", g.Owner, g.Addresses)
	}
	// Idempotent; ownership is never granted by reconciling.
	if n, err := s.ReconcileIdentities(ctx, map[string]Identity{"host-a": ownA, "host-c": hostIdentity(macC, "10.0.2.1")}); err != nil || n != 0 {
		t.Errorf("reconcile again = %d, %v, want 0", n, err)
	}
	if g := mustEndpoint(t, s, macID); g.Owner != "" {
		t.Errorf("owner = %q after reconcile, want none until host-a reports", g.Owner)
	}
	// A malformed record backs nothing (fail closed) and does not stop
	// the reconcile of other hosts: host-c's ownership is released, and
	// the valid record of host-d keeps its endpoint.
	const macD = "00:11:22:33:44:0d"
	mustUpsert(t, s, testEndpoint("10.0.3.1", macD, "host-d"), hostIdentity(macD, "10.0.3.1"))
	dID := mustLookup(t, s, macD, "").ID
	n, err = s.ReconcileIdentities(ctx, map[string]Identity{
		"host-c": {MACs: []string{"bad"}},
		"host-d": hostIdentity(macD, "10.0.3.1"),
	})
	if err != nil || n != 1 {
		t.Fatalf("reconcile with a malformed record = %d, %v, want 1 released", n, err)
	}
	if g := mustEndpoint(t, s, cID); g.Owner != "" {
		t.Errorf("host-c owner = %q after its record turned malformed, want released", g.Owner)
	}
	if g := mustEndpoint(t, s, dID); g.Owner != "host-d" {
		t.Errorf("host-d owner = %q, want host-d", g.Owner)
	}
	checkCounters(t, s, db)
}

func TestReassignedAddressResolvesToNewHolder(t *testing.T) {
	s, db, _ := newTestStore(t)
	const macA, macB = "00:11:22:33:44:0a", "00:11:22:33:44:0b"

	// host-a owns its MAC endpoint with 10.0.0.5 and a MAC-less endpoint
	// with 10.0.0.6, then goes silent.
	ownA := hostIdentity(macA, "10.0.0.1", "10.0.0.5", "10.0.0.6")
	e := testEndpoint("10.0.0.1", macA, "host-a")
	e.Addresses = addrList("10.0.0.1", "10.0.0.5")
	mustUpsert(t, s, e, ownA)
	aID := mustLookup(t, s, macA, "").ID
	mustUpsert(t, s, testEndpoint("10.0.0.6", "", "host-a"), ownA)
	lessID := mustLookup(t, s, "", "10.0.0.6").ID

	// The addresses are reassigned to host-b, which reports its own MAC
	// with them: they resolve to host-b's endpoint, not ambiguously.
	ownB := hostIdentity(macB, "10.0.0.5", "10.0.0.6")
	b := testEndpoint("10.0.0.5", macB, "host-b")
	b.Addresses = addrList("10.0.0.5", "10.0.0.6")
	mustUpsert(t, s, b, ownB)
	bID := mustLookup(t, s, macB, "").ID
	for _, a := range []string{"10.0.0.5", "10.0.0.6"} {
		if g := mustLookup(t, s, "", a); g.ID != bID || g.Owner != "host-b" {
			t.Errorf("lookup %s = %s owner %q, want host-b's %s", a, g.ID, g.Owner, bID)
		}
	}
	// host-a keeps its MAC endpoint with its remaining address; the
	// MAC-less endpoint, left without an attested address, has no owner.
	if g := mustEndpoint(t, s, aID); g.Owner != "host-a" || !slices.Equal(g.Addresses, addrList("10.0.0.1")) {
		t.Errorf("host-a endpoint = owner %q addresses %v, want host-a with 10.0.0.1", g.Owner, g.Addresses)
	}
	if g := mustEndpoint(t, s, lessID); g.Owner != "" {
		t.Errorf("MAC-less endpoint owner = %q, want released", g.Owner)
	}

	// A new endpoint created by the new holder releases them likewise.
	const macC = "00:11:22:33:44:0c"
	mustUpsert(t, s, testEndpoint("10.0.0.1", macC, "host-c"), hostIdentity(macC, "10.0.0.1"))
	if g := mustLookup(t, s, "", "10.0.0.1"); g.Owner != "host-c" {
		t.Errorf("lookup 10.0.0.1 owner = %q, want host-c", g.Owner)
	}
	if g := mustEndpoint(t, s, aID); g.Owner != "host-a" || len(g.Addresses) != 0 {
		t.Errorf("host-a endpoint = owner %q addresses %v, want host-a owning by MAC only", g.Owner, g.Addresses)
	}
	checkCounters(t, s, db)
}

func TestOwnerJoinReleasesOtherAttestations(t *testing.T) {
	s, db, _ := newTestStore(t)
	const macA, macB = "00:11:22:33:44:1a", "00:11:22:33:44:1b"

	// host-a owns its MAC endpoint with 10.0.0.5; host-b already owns its
	// own MAC endpoint with 10.0.0.9.
	ownA := hostIdentity(macA, "10.0.0.1", "10.0.0.5")
	a := testEndpoint("10.0.0.1", macA, "host-a")
	a.Addresses = addrList("10.0.0.1", "10.0.0.5")
	mustUpsert(t, s, a, ownA)
	aID := mustLookup(t, s, macA, "").ID
	mustUpsert(t, s, testEndpoint("10.0.0.9", macB, "host-b"), hostIdentity(macB, "10.0.0.9"))
	bID := mustLookup(t, s, macB, "").ID

	// 10.0.0.5 moves to host-b, which reports its existing endpoint (the
	// join path, not a new endpoint): host-a's attestation is released.
	b := testEndpoint("10.0.0.9", macB, "host-b")
	b.Addresses = addrList("10.0.0.9", "10.0.0.5")
	mustUpsert(t, s, b, hostIdentity(macB, "10.0.0.9", "10.0.0.5"))
	if g := mustLookup(t, s, "", "10.0.0.5"); g.ID != bID || g.Owner != "host-b" {
		t.Errorf("lookup 10.0.0.5 = %s owner %q, want host-b's %s", g.ID, g.Owner, bID)
	}
	if g := mustEndpoint(t, s, aID); g.Owner != "host-a" || !slices.Equal(g.Addresses, addrList("10.0.0.1")) {
		t.Errorf("host-a endpoint = owner %q addresses %v, want host-a with 10.0.0.1 only", g.Owner, g.Addresses)
	}
	checkCounters(t, s, db)
}

func TestMACLessReassignedAddressKeepsOwnerWhileItHoldsAnother(t *testing.T) {
	s, db, now := newTestStore(t)

	// host-a owns the MAC-less endpoint E with 10.0.1.1 and 10.0.1.2; an
	// observer also sees E.
	ownA := hostIdentity("", "10.0.1.1", "10.0.1.2")
	a := testEndpoint("10.0.1.1", "", "host-a")
	a.Addresses = addrList("10.0.1.1", "10.0.1.2")
	a.Hostname = "host-a"
	mustUpsert(t, s, a, ownA)
	eID := mustLookup(t, s, "", "10.0.1.1").ID
	mustUpsert(t, s, testEndpoint("10.0.1.2", "", "observer"), Identity{})

	// 10.0.1.1 is reassigned to host-b, which reports it authoritatively
	// before host-a reports again.
	*now = now.Add(time.Minute)
	ownB := hostIdentity("", "10.0.1.1")
	b := testEndpoint("10.0.1.1", "", "host-b")
	b.Hostname = "host-b"
	b.LastSeen = *now
	mustUpsert(t, s, b, ownB)

	// host-a keeps E, its ID and history, with only the address it still
	// holds; host-b neither owns nor joins E.
	g := mustEndpoint(t, s, eID)
	if g.Owner != "host-a" || !slices.Equal(g.Addresses, addrList("10.0.1.2")) ||
		!slices.Equal(g.SeenBy, []string{"host-a", "observer"}) || g.Hostname != "host-a" {
		t.Errorf("E = owner %q addresses %v seen by %v hostname %q, want host-a with 10.0.1.2, seen by host-a and observer",
			g.Owner, g.Addresses, g.SeenBy, g.Hostname)
	}
	// host-b gets a separate endpoint of its own for 10.0.1.1.
	gb := mustLookup(t, s, "", "10.0.1.1")
	if gb.ID == eID || gb.Owner != "host-b" || !slices.Equal(gb.SeenBy, []string{"host-b"}) ||
		!slices.Equal(gb.Addresses, addrList("10.0.1.1")) {
		t.Errorf("lookup 10.0.1.1 = %s owner %q seen by %v addresses %v, want host-b's own endpoint, not %s",
			gb.ID, gb.Owner, gb.SeenBy, gb.Addresses, eID)
	}
	if g := mustLookup(t, s, "", "10.0.1.2"); g.ID != eID {
		t.Errorf("lookup 10.0.1.2 = %s, want E %s", g.ID, eID)
	}
	if n := mustCount(t, s.CountEndpoints); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}

	// Further reports keep the split: host-b stays on its endpoint, host-a
	// (now holding 10.0.1.2 only) on E.
	mustUpsert(t, s, b, ownB)
	a.Addresses = addrList("10.0.1.2")
	mustUpsert(t, s, a, hostIdentity("", "10.0.1.2"))
	if g := mustEndpoint(t, s, eID); g.Owner != "host-a" || !slices.Equal(g.Addresses, addrList("10.0.1.2")) {
		t.Errorf("E after further reports = owner %q addresses %v, want host-a with 10.0.1.2", g.Owner, g.Addresses)
	}
	if g := mustLookup(t, s, "", "10.0.1.1"); g.ID != gb.ID || g.Owner != "host-b" {
		t.Errorf("lookup 10.0.1.1 = %s owner %q, want host-b's %s", g.ID, g.Owner, gb.ID)
	}
	if n := mustCount(t, s.CountEndpoints); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
	checkCounters(t, s, db)
}

func TestMACLessReassignedAddressPrefersReportersOwnEndpoint(t *testing.T) {
	s, db, _ := newTestStore(t)

	// host-b already owns F with 10.0.1.9; host-a owns E with 10.0.1.1 and
	// 10.0.1.2.
	mustUpsert(t, s, testEndpoint("10.0.1.9", "", "host-b"), hostIdentity("", "10.0.1.9"))
	fID := mustLookup(t, s, "", "10.0.1.9").ID
	a := testEndpoint("10.0.1.1", "", "host-a")
	a.Addresses = addrList("10.0.1.1", "10.0.1.2")
	mustUpsert(t, s, a, hostIdentity("", "10.0.1.1", "10.0.1.2"))
	eID := mustLookup(t, s, "", "10.0.1.1").ID

	// 10.0.1.1 moves to host-b, which reports it with 10.0.1.9: it joins
	// F, and E keeps host-a with 10.0.1.2.
	b := testEndpoint("10.0.1.9", "", "host-b")
	b.Addresses = addrList("10.0.1.1", "10.0.1.9")
	mustUpsert(t, s, b, hostIdentity("", "10.0.1.1", "10.0.1.9"))
	if g := mustEndpoint(t, s, fID); g.Owner != "host-b" || !slices.Equal(g.Addresses, addrList("10.0.1.1", "10.0.1.9")) {
		t.Errorf("F = owner %q addresses %v, want host-b with 10.0.1.1 and 10.0.1.9", g.Owner, g.Addresses)
	}
	if g := mustEndpoint(t, s, eID); g.Owner != "host-a" || !slices.Equal(g.Addresses, addrList("10.0.1.2")) ||
		!slices.Equal(g.SeenBy, []string{"host-a"}) {
		t.Errorf("E = owner %q addresses %v seen by %v, want host-a with 10.0.1.2 only", g.Owner, g.Addresses, g.SeenBy)
	}
	if g := mustLookup(t, s, "", "10.0.1.1"); g.ID != fID {
		t.Errorf("lookup 10.0.1.1 = %s, want F %s", g.ID, fID)
	}
	if n := mustCount(t, s.CountEndpoints); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
	checkCounters(t, s, db)
}

func TestMACLessReassignedSingleAddressMovesToNewHolder(t *testing.T) {
	s, db, now := newTestStore(t)

	// host-a owns E with its only address 10.0.1.1.
	a := testEndpoint("10.0.1.1", "", "host-a")
	mustUpsert(t, s, a, hostIdentity("", "10.0.1.1"))
	eID := mustLookup(t, s, "", "10.0.1.1").ID

	// 10.0.1.1 is reassigned to host-b: host-a holds none of E's addresses
	// any more, so host-b, the holder by the records, owns E.
	*now = now.Add(time.Minute)
	b := testEndpoint("10.0.1.1", "", "host-b")
	b.LastSeen = *now
	mustUpsert(t, s, b, hostIdentity("", "10.0.1.1"))
	g := mustLookup(t, s, "", "10.0.1.1")
	if g.ID != eID || g.Owner != "host-b" || !slices.Equal(g.Addresses, addrList("10.0.1.1")) {
		t.Errorf("lookup 10.0.1.1 = %s owner %q addresses %v, want %s owned by host-b", g.ID, g.Owner, g.Addresses, eID)
	}
	if o := observation(t, g, "host-a"); len(o.Addresses) != 0 {
		t.Errorf("host-a still attests %v on E, want released", o.Addresses)
	}
	// host-a's next report, without the address in its records, does not
	// regain E.
	mustUpsert(t, s, a, Identity{})
	if g := mustEndpoint(t, s, eID); g.Owner != "host-b" {
		t.Errorf("E owner = %q after host-a's report, want host-b", g.Owner)
	}
	if n := mustCount(t, s.CountEndpoints); n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
	checkCounters(t, s, db)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

func testGuestSnapshot(remote string, at time.Time, nics ...GuestNIC) GuestNICSnapshot {
	return GuestNICSnapshot{Remote: remote, ObservedAt: at, NICs: nics}
}

func testGuestNIC(vmid uint64, index int, mac string) GuestNIC {
	return GuestNIC{VMID: vmid, Kind: pvecontract.GuestQEMU, Index: index, Bridge: "vmbr0", VLAN: 20, MAC: mac}
}

func TestReplaceGuestNICsStoresProviderLinks(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	at := testNow.Add(-time.Minute)
	snap := testGuestSnapshot("pve-a", at,
		testGuestNIC(101, 1, "bc:24:11:00:00:02"),
		testGuestNIC(101, 0, "bc:24:11:00:00:01"),
		GuestNIC{VMID: 200, Kind: pvecontract.GuestLXC, Index: 0, MAC: "bc:24:11:00:00:03"},
	)
	if err := s.ReplaceGuestNICs(ctx, snap); err != nil {
		t.Fatalf("ReplaceGuestNICs: %v", err)
	}
	got, err := s.GuestNICs(ctx, "pve-a")
	if err != nil {
		t.Fatalf("GuestNICs: %v", err)
	}
	want := []GuestLink{
		{Source: SourceProvider, Remote: "pve-a", VMID: 101, Kind: pvecontract.GuestQEMU, Index: 0, Bridge: "vmbr0", VLAN: 20, MAC: "bc:24:11:00:00:01", ObservedAt: at},
		{Source: SourceProvider, Remote: "pve-a", VMID: 101, Kind: pvecontract.GuestQEMU, Index: 1, Bridge: "vmbr0", VLAN: 20, MAC: "bc:24:11:00:00:02", ObservedAt: at},
		{Source: SourceProvider, Remote: "pve-a", VMID: 200, Kind: pvecontract.GuestLXC, Index: 0, MAC: "bc:24:11:00:00:03", ObservedAt: at},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d links, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !got[i].ObservedAt.Equal(want[i].ObservedAt) {
			t.Errorf("link %d observed %v, want %v", i, got[i].ObservedAt, want[i].ObservedAt)
		}
		got[i].ObservedAt, want[i].ObservedAt = time.Time{}, time.Time{}
		if got[i] != want[i] {
			t.Errorf("link %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if n, err := s.CountGuestNICs(ctx); err != nil || n != 3 {
		t.Fatalf("CountGuestNICs = %d, %v; want 3", n, err)
	}
}

func TestReplaceGuestNICsReplacesWholeSnapshot(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	first := testGuestSnapshot("pve-a", testNow.Add(-2*time.Minute),
		testGuestNIC(101, 0, "bc:24:11:00:00:01"), testGuestNIC(102, 0, "bc:24:11:00:00:02"))
	if err := s.ReplaceGuestNICs(ctx, first); err != nil {
		t.Fatal(err)
	}
	other := testGuestSnapshot("pve-b", testNow.Add(-2*time.Minute), testGuestNIC(101, 0, "bc:24:11:00:00:09"))
	if err := s.ReplaceGuestNICs(ctx, other); err != nil {
		t.Fatal(err)
	}
	second := testGuestSnapshot("pve-a", testNow.Add(-time.Minute), testGuestNIC(102, 0, "bc:24:11:00:00:05"))
	if err := s.ReplaceGuestNICs(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := s.GuestNICs(ctx, "pve-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VMID != 102 || got[0].MAC != "bc:24:11:00:00:05" {
		t.Fatalf("pve-a after replace = %+v", got)
	}
	// Another remote's snapshot is untouched.
	if got, err := s.GuestNICs(ctx, "pve-b"); err != nil || len(got) != 1 {
		t.Fatalf("pve-b = %+v, %v", got, err)
	}
	if n, _ := s.CountGuestNICs(ctx); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
	// An empty snapshot clears the remote's NICs but keeps its time.
	if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-a", testNow)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GuestNICs(ctx, "pve-a"); len(got) != 0 {
		t.Fatalf("pve-a after empty snapshot = %+v", got)
	}
	if err := s.ReplaceGuestNICs(ctx, second); !errors.Is(err, ErrStaleSnapshot) {
		t.Fatalf("older snapshot after empty one: %v, want ErrStaleSnapshot", err)
	}
}

func TestReplaceGuestNICsRefusesOlderSnapshot(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	newer := testGuestSnapshot("pve-a", testNow, testGuestNIC(101, 0, "bc:24:11:00:00:01"))
	if err := s.ReplaceGuestNICs(ctx, newer); err != nil {
		t.Fatal(err)
	}
	older := testGuestSnapshot("pve-a", testNow.Add(-time.Minute), testGuestNIC(101, 0, "bc:24:11:00:00:02"))
	if err := s.ReplaceGuestNICs(ctx, older); !errors.Is(err, ErrStaleSnapshot) {
		t.Fatalf("older snapshot: %v, want ErrStaleSnapshot", err)
	}
	got, _ := s.GuestNICs(ctx, "pve-a")
	if len(got) != 1 || got[0].MAC != "bc:24:11:00:00:01" {
		t.Fatalf("stale snapshot changed the store: %+v", got)
	}
	// The same snapshot again is an idempotent retry.
	if err := s.ReplaceGuestNICs(ctx, newer); err != nil {
		t.Fatalf("retry of the same snapshot: %v", err)
	}
}

func TestReplaceGuestNICsRejectsMalformed(t *testing.T) {
	good := testGuestNIC(101, 0, "bc:24:11:00:00:01")
	with := func(f func(*GuestNIC)) GuestNIC { n := good; f(&n); return n }
	cases := []struct {
		name string
		snap GuestNICSnapshot
		want error
	}{
		{"bad remote", testGuestSnapshot("PVE A", testNow, good), ErrInvalidGuestNIC},
		{"empty remote", testGuestSnapshot("", testNow, good), ErrInvalidGuestNIC},
		{"zero time", testGuestSnapshot("pve-a", time.Time{}, good), ErrInvalidGuestNIC},
		{"future", testGuestSnapshot("pve-a", testNow.Add(maxClockSkew+time.Second), good), ErrInvalidGuestNIC},
		{"expired", testGuestSnapshot("pve-a", testNow.Add(-DefaultRetention-time.Second), good), ErrOutOfRange},
		{"vmid low", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.VMID = 99 })), ErrInvalidGuestNIC},
		{"vmid high", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.VMID = pvecontract.MaxVMID + 1 })), ErrInvalidGuestNIC},
		{"kind", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.Kind = "docker" })), ErrInvalidGuestNIC},
		{"index negative", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.Index = -1 })), ErrInvalidGuestNIC},
		{"index high", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.Index = MaxGuestNICIndex })), ErrInvalidGuestNIC},
		{"bridge", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.Bridge = "vmbr0;rm" })), ErrInvalidGuestNIC},
		{"bridge control", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.Bridge = "vmbr\x00" })), ErrInvalidGuestNIC},
		{"vlan negative", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.VLAN = -1 })), ErrInvalidGuestNIC},
		{"vlan high", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.VLAN = 4095 })), ErrInvalidGuestNIC},
		{"mac empty", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.MAC = "" })), ErrInvalidGuestNIC},
		{"mac upper", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.MAC = "BC:24:11:00:00:01" })), ErrInvalidGuestNIC},
		{"mac short", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.MAC = "bc:24:11:00:00" })), ErrInvalidGuestNIC},
		{"mac zero", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.MAC = "00:00:00:00:00:00" })), ErrInvalidGuestNIC},
		{"mac multicast", testGuestSnapshot("pve-a", testNow, with(func(n *GuestNIC) { n.MAC = "01:00:5e:00:00:01" })), ErrInvalidGuestNIC},
		{"duplicate", testGuestSnapshot("pve-a", testNow, good, with(func(n *GuestNIC) { n.MAC = "bc:24:11:00:00:02" })), ErrInvalidGuestNIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := newTestStore(t)
			err := s.ReplaceGuestNICs(context.Background(), tc.snap)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// Errors never echo the untrusted values.
			if err != nil && (strings.Contains(err.Error(), "vmbr0;rm") || strings.Contains(err.Error(), "docker")) {
				t.Fatalf("error echoes untrusted input: %v", err)
			}
			if n, _ := s.CountGuestNICs(context.Background()); n != 0 {
				t.Fatalf("rejected snapshot stored %d rows", n)
			}
		})
	}
}

func TestReplaceGuestNICsEnforcesCaps(t *testing.T) {
	ctx := context.Background()
	nics := func(base uint64, n int) []GuestNIC {
		out := make([]GuestNIC, n)
		for i := range out {
			out[i] = testGuestNIC(base+uint64(i), 0, fmt.Sprintf("bc:24:11:00:%02x:%02x", base%256, i))
		}
		return out
	}
	t.Run("per remote", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		s.guestNICCapRemote = 3
		err := s.ReplaceGuestNICs(ctx, GuestNICSnapshot{Remote: "pve-a", ObservedAt: testNow, NICs: nics(100, 4)})
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("err = %v, want ErrLimit", err)
		}
	})
	t.Run("total", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		s.guestNICCap = 5
		if err := s.ReplaceGuestNICs(ctx, GuestNICSnapshot{Remote: "pve-a", ObservedAt: testNow, NICs: nics(100, 3)}); err != nil {
			t.Fatal(err)
		}
		err := s.ReplaceGuestNICs(ctx, GuestNICSnapshot{Remote: "pve-b", ObservedAt: testNow, NICs: nics(200, 3)})
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("err = %v, want ErrLimit", err)
		}
		// Replacing a remote's own rows does not count them twice.
		if err := s.ReplaceGuestNICs(ctx, GuestNICSnapshot{Remote: "pve-a", ObservedAt: testNow.Add(time.Second), NICs: nics(100, 5)}); err != nil {
			t.Fatalf("replace within the cap: %v", err)
		}
		if n, _ := s.CountGuestNICs(ctx); n != 5 {
			t.Fatalf("count = %d, want 5", n)
		}
	})
	t.Run("remotes", func(t *testing.T) {
		s, _, _ := newTestStore(t)
		s.guestRemoteCap = 2
		for _, r := range []string{"pve-a", "pve-b"} {
			if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot(r, testNow)); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-c", testNow)); !errors.Is(err, ErrLimit) {
			t.Fatalf("third remote: %v, want ErrLimit", err)
		}
		// A known remote is still admitted.
		if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-a", testNow.Add(time.Second))); err != nil {
			t.Fatalf("known remote: %v", err)
		}
	})
}

func TestPruneRemovesExpiredGuestNICs(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()
	if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-old", testNow.Add(-time.Hour), testGuestNIC(101, 0, "bc:24:11:00:00:01"))); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-new", testNow.Add(time.Hour), testGuestNIC(101, 0, "bc:24:11:00:00:02"))); err == nil {
		t.Fatal("future snapshot beyond skew was accepted")
	}
	if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-new", testNow, testGuestNIC(101, 0, "bc:24:11:00:00:02"))); err != nil {
		t.Fatal(err)
	}
	*now = testNow.Add(DefaultRetention - 30*time.Minute)
	if _, _, err := s.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GuestNICs(ctx, "pve-old"); len(got) != 0 {
		t.Fatalf("expired snapshot kept: %+v", got)
	}
	if got, _ := s.GuestNICs(ctx, "pve-new"); len(got) != 1 {
		t.Fatalf("current snapshot pruned: %+v", got)
	}
	if n, _ := s.CountGuestNICs(ctx); n != 1 {
		t.Fatalf("count after prune = %d, want 1", n)
	}
	// The expired remote may report again with any newer snapshot.
	if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-old", *now, testGuestNIC(101, 0, "bc:24:11:00:00:01"))); err != nil {
		t.Fatalf("re-report after prune: %v", err)
	}
}

func TestEndpointGuestLinksMatchByMACOnly(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	// Observed endpoint (tier socket) with the MAC of a guest NIC.
	ep := testEndpoint("10.0.20.5", "bc:24:11:00:00:01", "reporter-a")
	if err := s.UpsertEndpoint(ctx, ep, Identity{}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	// An endpoint without a MAC never matches.
	noMAC := testEndpoint("10.0.20.6", "", "reporter-a")
	if err := s.UpsertEndpoint(ctx, noMAC, Identity{}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	snap := testGuestSnapshot("pve-a", testNow,
		testGuestNIC(101, 0, "bc:24:11:00:00:01"),
		testGuestNIC(102, 0, "bc:24:11:00:00:02"))
	if err := s.ReplaceGuestNICs(ctx, snap); err != nil {
		t.Fatal(err)
	}
	// A cloned guest on another remote reports the same MAC: both links
	// are returned, each under its own remote, never merged.
	if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-b", testNow, testGuestNIC(900, 3, "bc:24:11:00:00:01"))); err != nil {
		t.Fatal(err)
	}
	e, ok, err := s.LookupEndpoint(ctx, "bc:24:11:00:00:01", ep.Addresses[0])
	if err != nil || !ok {
		t.Fatalf("LookupEndpoint: %v %v", ok, err)
	}
	links, err := s.EndpointGuestLinks(ctx, e.ID)
	if err != nil {
		t.Fatalf("EndpointGuestLinks: %v", err)
	}
	if len(links) != 2 || links[0].Remote != "pve-a" || links[0].VMID != 101 || links[1].Remote != "pve-b" || links[1].Index != 3 {
		t.Fatalf("links = %+v", links)
	}
	for _, l := range links {
		if l.Source != SourceProvider {
			t.Fatalf("link source = %q, want %q", l.Source, SourceProvider)
		}
	}
	// The observed endpoint keeps its own tier and VLAN: provider data is
	// never written into the observed tiers.
	after, err := s.Endpoint(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Tier != flowagg.TierSocket || after.VLAN != ep.VLAN || len(after.Addresses) != 1 {
		t.Fatalf("observed endpoint changed by provider import: %+v", after)
	}
	if n, _ := s.CountEndpoints(ctx); n != 2 {
		t.Fatalf("provider import created endpoints: %d", n)
	}
	m, _, err := s.LookupEndpoint(ctx, "", netip.MustParseAddr("10.0.20.6"))
	if err != nil {
		t.Fatal(err)
	}
	if links, err := s.EndpointGuestLinks(ctx, m.ID); err != nil || len(links) != 0 {
		t.Fatalf("mac-less endpoint links = %+v, %v", links, err)
	}
	if _, err := s.EndpointGuestLinks(ctx, "ep-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing endpoint: %v, want ErrNotFound", err)
	}
}

func TestGuestLinksByMAC(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.ReplaceGuestNICs(ctx, testGuestSnapshot("pve-a", testNow, testGuestNIC(101, 0, "bc:24:11:00:00:01"))); err != nil {
		t.Fatal(err)
	}
	links, err := s.GuestLinksByMAC(ctx, "bc:24:11:00:00:01")
	if err != nil || len(links) != 1 || links[0].Source != SourceProvider {
		t.Fatalf("links = %+v, %v", links, err)
	}
	if links, err := s.GuestLinksByMAC(ctx, "bc:24:11:00:00:09"); err != nil || len(links) != 0 {
		t.Fatalf("unknown mac = %+v, %v", links, err)
	}
	if _, err := s.GuestLinksByMAC(ctx, "not-a-mac"); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad mac: %v, want ErrInvalidQuery", err)
	}
	if _, err := s.GuestNICs(ctx, "Bad Remote"); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad remote: %v, want ErrInvalidQuery", err)
	}
}

func TestProviderIsNotAnObservedTier(t *testing.T) {
	s, _, _ := newTestStore(t)
	ep := testEndpoint("10.0.20.5", "bc:24:11:00:00:01", "reporter-a")
	ep.Tier = SourceProvider
	if err := s.UpsertEndpoint(context.Background(), ep, Identity{}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("endpoint with provider tier: %v, want ErrInvalidEndpoint", err)
	}
}

func TestGuestNICQueryPlansUseIndexes(t *testing.T) {
	_, db, _ := newTestStore(t)
	cases := []struct {
		name    string
		query   string
		args    []any
		want    []string
		notScan string
	}{
		{"prune snapshots", pruneGuestSnapshotsSQL, []any{1}, []string{"idx_net_guest_nic_snapshots_observed"}, "SCAN net_guest_nic_snapshots"},
		{"snapshot time", guestSnapshotSQL, []any{"pve-a"}, []string{"SEARCH net_guest_nic_snapshots USING INDEX sqlite_autoindex_net_guest_nic_snapshots_1"}, "SCAN"},
		{"delete remote nics", deleteGuestNICsSQL, []any{"pve-a"}, []string{"SEARCH net_guest_nics USING", "sqlite_autoindex_net_guest_nics_1 (remote=?)"}, "SCAN"},
		{"list remote", guestNICsByRemoteSQL, []any{"pve-a", maxGuestLinks}, []string{"SEARCH g USING INDEX sqlite_autoindex_net_guest_nics_1 (remote=?)"}, "SCAN"},
		{"by mac", guestNICsByMACSQL, []any{"bc:24:11:00:00:01", maxGuestLinks}, []string{"idx_net_guest_nics_mac (mac=?)"}, "SCAN g"},
		{"endpoint mac", endpointMACSQL, []any{"ep-x"},
			[]string{"SEARCH net_endpoints USING INDEX sqlite_autoindex_net_endpoints_1"}, "SCAN"},
		{"count remote nics", countRemoteGuestNICSQL, []any{"pve-a"},
			[]string{"SEARCH net_guest_nics USING", "(remote=?)"}, "SCAN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := queryPlan(t, db, tc.query, tc.args...)
			for _, w := range tc.want {
				if !strings.Contains(plan, w) {
					t.Errorf("plan lacks %q:\n%s", w, plan)
				}
			}
			if strings.Contains(plan, tc.notScan) {
				t.Errorf("plan scans the table:\n%s", plan)
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// suggestFixture ingests five guests on remote-a that together cover every
// candidate kind: a MAC match via an IPAM asset, a guest-agent IP match, a
// plain interface IP match (POSSIBLE MATCH in the UI), a cloud-init IP
// match, a cloned MAC (conflict), one IP on two managed hosts (conflict)
// and a guest without any candidate.
func suggestFixture(t *testing.T) (*Store, []GuestRef) {
	t.Helper()
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	cloud := mkGuestWithIfaces(500, 1, "vm5", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:05", Bridge: "vmbr0", Source: pvecontract.SourceLXCAPI},
	})
	cloud.Config = pvecontract.AvailableDataset(pvecontract.GuestConfig{
		CPUCount:    1,
		RAMBytes:    1 << 30,
		CloudInitIP: &pvecontract.CloudInitIP{IP: "10.77.10.105/24", Gateway: "10.77.10.1"},
		Capabilities: pvecontract.GuestCapabilities{
			Snapshots: pvecontract.Unknown, LiveMigration: pvecontract.Unknown, RAMSnapshots: pvecontract.Unknown,
		},
	})
	mustIngestGuest(t, s, newObsA().guests(
		// 100: MAC via IPAM asset (web1) and guest-agent IP (web1).
		mkGuestWithIfaces(100, 1, "vm1", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		// 200: plain (non-agent) interface IP only (db1) -> POSSIBLE MATCH.
		mkGuestWithIfaces(200, 1, "vm2", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:02", Bridge: "vmbr0", IPs: []string{"10.77.10.102/24"}, Source: pvecontract.SourceLXCAPI},
		}),
		// 300 and 400: cloned MAC with an IPAM asset of app1 (conflict);
		// 400 also has an agent IP that is an endpoint of two hosts.
		mkGuestWithIfaces(300, 1, "vm3", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:03", Bridge: "vmbr0", IPs: []string{"10.77.10.103/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		mkGuestWithIfaces(400, 1, "vm4", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:03", Bridge: "vmbr0", IPs: []string{"10.77.10.150/24", "dhcp"}, Source: pvecontract.SourceQEMUAgent},
		}),
		// 500: cloud-init IP only (cache1).
		cloud,
		// 600: no candidates at all.
		mkGuestWithIfaces(600, 1, "vm6", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:06", Bridge: "vmbr0", IPs: []string{"10.77.99.1/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
	).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	mustCreateHost(t, s.db, mkManagedHost("db1", "10.77.10.102"))
	mustCreateHost(t, s.db, mkManagedHost("app1", "10.77.10.200"))
	mustCreateHost(t, s.db, mkManagedHost("dup1", "10.77.10.150"))
	mustCreateHost(t, s.db, mkManagedHost("dup2", "10.77.10.150"))
	mustCreateHost(t, s.db, mkManagedHost("cache1", "10.77.10.105"))
	ipa := ipam.New(db, nil)
	for _, a := range []ipam.Asset{
		{ID: "asset-1", Name: "web1", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:01",
			Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.101")}, HostID: "web1"},
		{ID: "asset-3", Name: "app1", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:03",
			Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.200")}, HostID: "app1"},
	} {
		if err := ipa.SaveAsset(ctx, a); err != nil {
			t.Fatalf("SaveAsset %s: %v", a.ID, err)
		}
	}
	return s, []GuestRef{
		{VMID: 100, Generation: 1}, {VMID: 200, Generation: 1}, {VMID: 300, Generation: 1},
		{VMID: 400, Generation: 1}, {VMID: 500, Generation: 1}, {VMID: 600, Generation: 1},
	}
}

// suggestGolden is the SuggestHosts output for suggestFixture, pinned from
// the per-guest implementation before the batch variant existed.
var suggestGolden = map[GuestRef][]Candidate{
	{VMID: 100, Generation: 1}: {
		{HostID: "web1", Match: MatchAgentIP, Detail: "guest agent IP 10.77.10.101 matches an endpoint of host web1"},
		{HostID: "web1", Match: MatchMAC, Detail: "MAC aa:bb:cc:dd:ee:01 matches an IPAM asset of host web1"},
	},
	{VMID: 200, Generation: 1}: {
		{HostID: "db1", Match: MatchIP, Detail: "IP 10.77.10.102 matches an endpoint of host db1"},
	},
	{VMID: 300, Generation: 1}: {
		{HostID: "app1", Match: MatchMAC, Detail: "MAC aa:bb:cc:dd:ee:03 matches an IPAM asset of host app1 (conflict: MAC also seen on guest 400 (gen 1))", Conflict: true},
	},
	{VMID: 400, Generation: 1}: {
		{HostID: "app1", Match: MatchMAC, Detail: "MAC aa:bb:cc:dd:ee:03 matches an IPAM asset of host app1 (conflict: MAC also seen on guest 300 (gen 1))", Conflict: true},
		{HostID: "dup1", Match: MatchAgentIP, Detail: "guest agent IP 10.77.10.150 matches an endpoint of host dup1 (conflict: IP also matches 1 other hosts)", Conflict: true},
		{HostID: "dup2", Match: MatchAgentIP, Detail: "guest agent IP 10.77.10.150 matches an endpoint of host dup2 (conflict: IP also matches 1 other hosts)", Conflict: true},
	},
	{VMID: 500, Generation: 1}: {
		{HostID: "cache1", Match: MatchIP, Detail: "IP 10.77.10.105 matches an endpoint of host cache1"},
	},
	{VMID: 600, Generation: 1}: nil,
}

func TestSuggestHostsBatchEqualsPerGuest(t *testing.T) {
	s, refs := suggestFixture(t)
	ctx := context.Background()
	// Duplicates in the input are computed once and do not change results.
	got, err := s.SuggestHostsBatch(ctx, "remote-a", append(refs, refs[0]))
	if err != nil {
		t.Fatalf("SuggestHostsBatch: %v", err)
	}
	if len(got) != len(refs) {
		t.Fatalf("SuggestHostsBatch returned %d guests, want %d", len(got), len(refs))
	}
	for _, ref := range refs {
		t.Run(fmt.Sprintf("vmid-%d", ref.VMID), func(t *testing.T) {
			batch, ok := got[ref]
			if !ok {
				t.Fatalf("batch result misses guest %d", ref.VMID)
			}
			single, err := s.SuggestHosts(ctx, "remote-a", ref.VMID, ref.Generation)
			if err != nil {
				t.Fatalf("SuggestHosts: %v", err)
			}
			if !reflect.DeepEqual(batch, single) {
				t.Errorf("batch =\n%+v\nper guest =\n%+v", batch, single)
			}
			if want := suggestGolden[ref]; !reflect.DeepEqual(batch, want) {
				t.Errorf("batch =\n%+v\ngolden =\n%+v", batch, want)
			}
		})
	}
}

func TestSuggestHostsBatchEmpty(t *testing.T) {
	s, _ := suggestFixture(t)
	got, err := s.SuggestHostsBatch(context.Background(), "remote-a", nil)
	if err != nil {
		t.Fatalf("SuggestHostsBatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty batch = %+v, want empty", got)
	}
}

func TestSuggestHostsBatchRejectsUnknownGuest(t *testing.T) {
	s, refs := suggestFixture(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		remote string
		ref    GuestRef
	}{
		"unknown vmid":       {"remote-a", GuestRef{VMID: 999, Generation: 1}},
		"unknown generation": {"remote-a", GuestRef{VMID: 100, Generation: 2}},
		"other remote":       {"remote-b", refs[0]},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := s.SuggestHostsBatch(ctx, tc.remote, append([]GuestRef{refs[1]}, tc.ref))
			if !errors.Is(err, ErrGuestNotFound) {
				t.Fatalf("SuggestHostsBatch = %v, want ErrGuestNotFound", err)
			}
			if got != nil {
				t.Fatalf("failed batch must not return partial results: %+v", got)
			}
			if _, err := s.SuggestHosts(ctx, tc.remote, tc.ref.VMID, tc.ref.Generation); !errors.Is(err, ErrGuestNotFound) {
				t.Fatalf("SuggestHosts = %v, want ErrGuestNotFound", err)
			}
		})
	}
}

func TestSuggestHostsBatchRejectsTooManyGuests(t *testing.T) {
	s, _ := suggestFixture(t)
	refs := make([]GuestRef, MaxSuggestBatch+1)
	for i := range refs {
		refs[i] = GuestRef{VMID: uint64(100 + i), Generation: 1}
	}
	if _, err := s.SuggestHostsBatch(context.Background(), "remote-a", refs); !errors.Is(err, ErrSuggestBatchTooLarge) {
		t.Fatalf("SuggestHostsBatch over limit = %v, want ErrSuggestBatchTooLarge", err)
	}
}

func TestSuggestHostsMatchesGolden(t *testing.T) {
	s, refs := suggestFixture(t)
	for _, ref := range refs {
		got, err := s.SuggestHosts(context.Background(), "remote-a", ref.VMID, ref.Generation)
		if err != nil {
			t.Fatalf("SuggestHosts %d: %v", ref.VMID, err)
		}
		if want := suggestGolden[ref]; !reflect.DeepEqual(got, want) {
			t.Errorf("SuggestHosts %d =\n%+v\nwant\n%+v", ref.VMID, got, want)
		}
	}
}

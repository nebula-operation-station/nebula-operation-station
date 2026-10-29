// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// mkGuestWithIfaces builds a guest observation with available interfaces.
func mkGuestWithIfaces(vmid, gen uint64, name string, ifaces []pvecontract.GuestInterface) pvecontract.GuestObservation {
	g := mkGuest(vmid, gen, name)
	if len(ifaces) > 0 {
		g.Interfaces = pvecontract.AvailableDataset(ifaces)
	}
	return g
}

// mkManagedHost builds a minimal valid inventory host with one endpoint.
func mkManagedHost(id, addr string) inventory.Host {
	return inventory.Host{
		ID:          id,
		DisplayName: id,
		Environment: "PROD",
		Criticality: "LOW",
		Endpoints:   []inventory.Endpoint{{Address: addr}},
	}
}

// mustCreateHost creates a managed host in the test database.
func mustCreateHost(t *testing.T, db *sql.DB, h inventory.Host) {
	t.Helper()
	if _, err := inventory.New(db).Create(context.Background(), h, inventory.CreateOptions{}); err != nil {
		t.Fatalf("Create host %s: %v", h.ID, err)
	}
}

func mustIngestGuest(t *testing.T, s *Store, obs pvecontract.Observation) {
	t.Helper()
	if _, err := s.IngestObservation(context.Background(), obs); err != nil {
		t.Fatalf("ingest: %v", err)
	}
}

func TestCreateLinkExplicit(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 1, "vm1")).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))

	link, err := s.CreateLink(ctx, "remote-a", 100, 1, "web1", "alice")
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if link.HostID != "web1" || link.VMID != 100 || link.Generation != 1 || link.CreatedBy != "alice" {
		t.Fatalf("unexpected link: %+v", link)
	}
	if !link.UnlinkedAt.IsZero() {
		t.Fatalf("new link must be active, got unlinked at %v", link.UnlinkedAt)
	}

	got, err := s.GetLink(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.HostID != "web1" {
		t.Fatalf("GetLink host = %q", got.HostID)
	}

	if _, err := s.CreateLink(ctx, "remote-a", 100, 1, "web1", "bob"); !errors.Is(err, ErrLinkExists) {
		t.Fatalf("second CreateLink = %v, want ErrLinkExists", err)
	}
	if _, err := s.CreateLink(ctx, "remote-a", 100, 1, "ghost", "alice"); !errors.Is(err, ErrManagedHostNotFound) {
		t.Fatalf("CreateLink unknown host = %v, want ErrManagedHostNotFound", err)
	}
	if _, err := s.CreateLink(ctx, "remote-a", 999, 1, "web1", "alice"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("CreateLink unknown guest = %v, want ErrGuestNotFound", err)
	}
	if _, err := s.CreateLink(ctx, "remote-a", 100, 1, "web1", "bad actor!"); err == nil {
		t.Fatalf("CreateLink with invalid actor must fail")
	}

	links, err := s.LinksForHost(ctx, "web1")
	if err != nil {
		t.Fatalf("LinksForHost: %v", err)
	}
	if len(links) != 1 || links[0].VMID != 100 {
		t.Fatalf("LinksForHost = %+v", links)
	}
	all, err := s.ListLinks(ctx, "remote-a", 0)
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("ListLinks = %d, want 1", len(all))
	}
}

func TestUnlinkTombstonesAndKeepsHistory(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 1, "vm1")).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	if _, err := s.CreateLink(ctx, "remote-a", 100, 1, "web1", "alice"); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	unlinked, err := s.Unlink(ctx, "remote-a", 100, 1, "alice", "wrong host")
	if err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if unlinked.UnlinkedAt.IsZero() || unlinked.UnlinkReason != "wrong host" {
		t.Fatalf("unlinked link = %+v", unlinked)
	}
	if _, err := s.GetLink(ctx, "remote-a", 100, 1); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("GetLink after unlink = %v, want ErrLinkNotFound", err)
	}
	hist, err := s.LinkHistory(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("LinkHistory: %v", err)
	}
	if len(hist) != 1 || hist[0].UnlinkReason != "wrong host" {
		t.Fatalf("LinkHistory = %+v", hist)
	}
	// Re-linking after an unlink is possible; the second unlink works
	// again, and only then is there no active link left.
	if _, err := s.CreateLink(ctx, "remote-a", 100, 1, "web1", "bob"); err != nil {
		t.Fatalf("re-CreateLink: %v", err)
	}
	if _, err := s.Unlink(ctx, "remote-a", 100, 1, "bob", "changed mind"); err != nil {
		t.Fatalf("second Unlink: %v", err)
	}
	if _, err := s.Unlink(ctx, "remote-a", 100, 1, "alice", "x"); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("Unlink without active link = %v, want ErrLinkNotFound", err)
	}
}

func TestHostAlreadyLinkedIsFlagged(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 1, "vm1"), mkGuest(200, 1, "vm2")).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	if _, err := s.CreateLink(ctx, "remote-a", 100, 1, "web1", "alice"); err != nil {
		t.Fatalf("CreateLink 100: %v", err)
	}
	if _, err := s.CreateLink(ctx, "remote-a", 200, 1, "web1", "alice"); !errors.Is(err, ErrHostAlreadyLinked) {
		t.Fatalf("CreateLink 200 -> web1 = %v, want ErrHostAlreadyLinked", err)
	}
}

func TestSuggestHostsByMACAndAgentIP(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(100, 1, "vm1", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
		{Name: "net1", MAC: "aa:bb:cc:dd:ee:02", Bridge: "vmbr0", IPs: []string{"10.77.10.102/24"}, Source: pvecontract.SourceQEMUAgent},
	})).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	mustCreateHost(t, s.db, mkManagedHost("db1", "10.77.10.102"))
	ipa := ipam.New(db, nil)
	if err := ipa.SaveAsset(ctx, ipam.Asset{
		ID: "asset-1", Name: "web1", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:01",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.101")},
		HostID:    "web1",
	}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	cands, err := s.SuggestHosts(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("SuggestHosts: %v", err)
	}
	byKey := map[string]Candidate{}
	for _, c := range cands {
		byKey[c.HostID+"|"+c.Match] = c
	}
	mac, ok := byKey["web1|mac"]
	if !ok {
		t.Fatalf("missing MAC candidate web1: %+v", cands)
	}
	if mac.Conflict {
		t.Fatalf("MAC candidate must not be a conflict: %+v", mac)
	}
	agent, ok := byKey["db1|agent-ip"]
	if !ok {
		t.Fatalf("missing agent-ip candidate db1: %+v", cands)
	}
	if agent.Conflict {
		t.Fatalf("agent-ip candidate must not be a conflict: %+v", agent)
	}
	if _, err := s.GetLink(ctx, "remote-a", 100, 1); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("candidates must never create a link, got %v", err)
	}
}

func TestSuggestHostsFlagsIPOnTwoHosts(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(100, 1, "vm1", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
	})).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	mustCreateHost(t, s.db, mkManagedHost("web2", "10.77.10.101"))

	cands, err := s.SuggestHosts(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("SuggestHosts: %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("want 2 candidates, got %+v", cands)
	}
	for _, c := range cands {
		if !c.Conflict {
			t.Fatalf("IP on two hosts must flag both candidates: %+v", c)
		}
	}
	conflicts, err := s.GuestConflicts(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("GuestConflicts: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("want 1 conflict, got %q", conflicts)
	}
}

func TestSuggestHostsFlagsClonedMAC(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(
		mkGuestWithIfaces(100, 1, "vm1", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		mkGuestWithIfaces(200, 1, "vm2", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.102/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
	).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	ipa := ipam.New(db, nil)
	if err := ipa.SaveAsset(ctx, ipam.Asset{
		ID: "asset-1", Name: "web1", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:01",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.101")},
		HostID:    "web1",
	}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	cands, err := s.SuggestHosts(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("SuggestHosts: %v", err)
	}
	found := false
	for _, c := range cands {
		if c.Match == MatchMAC && c.HostID == "web1" {
			found = true
			if !c.Conflict {
				t.Fatalf("cloned MAC must flag the candidate: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("missing MAC candidate: %+v", cands)
	}
	conflicts, err := s.GuestConflicts(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("GuestConflicts: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("want 1 cloned-MAC conflict, got %q", conflicts)
	}
}

func TestVMIDReuseUnlinksWithVisibleNotice(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 1, "vm1-old")).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	if _, err := s.CreateLink(ctx, "remote-a", 100, 1, "web1", "alice"); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	// The VMID is reused: a new incarnation is ingested, tombstoning gen 1.
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 2, "vm1-new")).build())

	notices, err := s.SweepVMIDReuse(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepVMIDReuse: %v", err)
	}
	if len(notices) != 1 {
		t.Fatalf("want 1 reuse notice, got %+v", notices)
	}
	n := notices[0]
	if n.VMID != 100 || n.OldGeneration != 1 || n.OldHostID != "web1" || n.NewGeneration != 2 {
		t.Fatalf("unexpected notice: %+v", n)
	}
	if n.Notice == "" {
		t.Fatalf("notice message must not be empty")
	}
	if _, err := s.GetLink(ctx, "remote-a", 100, 1); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("old link must be unlinked, got %v", err)
	}
	if _, err := s.GetLink(ctx, "remote-a", 100, 2); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("new incarnation must not be linked automatically, got %v", err)
	}
	hist, err := s.LinkHistory(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("LinkHistory: %v", err)
	}
	if len(hist) != 1 || hist[0].UnlinkReason != "vmid reused: new incarnation" {
		t.Fatalf("LinkHistory = %+v", hist)
	}
	// The sweep is idempotent.
	again, err := s.SweepVMIDReuse(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepVMIDReuse again: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second sweep must be empty, got %+v", again)
	}
}

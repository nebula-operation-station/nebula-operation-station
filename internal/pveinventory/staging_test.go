// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

func TestSweepStagingClassifiesGuests(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	// 100: no match at all -> NEW
	// 200: MAC matches asset of web1 -> EXISTING
	// 300/400: cloned MAC matching web2 -> CONFLICT
	// 500: linked below -> managed, not staged
	mustIngestGuest(t, s, newObsA().guests(
		mkGuestWithIfaces(100, 1, "vm-new", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:10", Bridge: "vmbr0", IPs: []string{"10.77.10.110/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		mkGuestWithIfaces(200, 1, "vm-web", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		mkGuestWithIfaces(300, 1, "vm-a", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:02", Bridge: "vmbr0", IPs: []string{"10.77.10.102/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		mkGuestWithIfaces(400, 1, "vm-b", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:02", Bridge: "vmbr0", IPs: []string{"10.77.10.103/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		mkGuest(500, 1, "vm-linked"),
	).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	mustCreateHost(t, s.db, mkManagedHost("web2", "10.77.10.102"))
	ipa := ipam.New(db, nil)
	if err := ipa.SaveAsset(ctx, ipam.Asset{
		ID: "asset-1", Name: "web1", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:01",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.101")}, HostID: "web1",
	}); err != nil {
		t.Fatalf("SaveAsset web1: %v", err)
	}
	if err := ipa.SaveAsset(ctx, ipam.Asset{
		ID: "asset-2", Name: "web2", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:02",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.102")}, HostID: "web2",
	}); err != nil {
		t.Fatalf("SaveAsset web2: %v", err)
	}

	// A linked guest is managed and must not appear in staging.
	mustCreateHost(t, s.db, mkManagedHost("linked1", "10.77.10.150"))
	if _, err := s.CreateLink(ctx, "remote-a", 500, 1, "linked1", "alice"); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	rows, err := s.SweepStaging(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}
	byVMID := map[uint64]StagingEntry{}
	for _, r := range rows {
		byVMID[r.VMID] = r
	}
	if _, ok := byVMID[500]; ok {
		t.Fatalf("linked guest 500 must not be staged: %+v", rows)
	}
	if got := byVMID[100].Status; got != StagingNew {
		t.Fatalf("guest 100 status = %q, want NEW", got)
	}
	if got := byVMID[200].Status; got != StagingExisting {
		t.Fatalf("guest 200 status = %q, want EXISTING", got)
	}
	if len(byVMID[200].Candidates) == 0 || byVMID[200].Candidates[0].HostID != "web1" {
		t.Fatalf("guest 200 candidates = %+v", byVMID[200].Candidates)
	}
	if got := byVMID[300].Status; got != StagingConflict {
		t.Fatalf("guest 300 status = %q, want CONFLICT (cloned MAC)", got)
	}
	if got := byVMID[400].Status; got != StagingConflict {
		t.Fatalf("guest 400 status = %q, want CONFLICT (cloned MAC)", got)
	}

	stored, err := s.ListStaging(ctx, "remote-a", 0)
	if err != nil {
		t.Fatalf("ListStaging: %v", err)
	}
	if len(stored) != 4 {
		t.Fatalf("ListStaging = %d rows, want 4", len(stored))
	}
}

func TestImportStagedAddsNewManagedHost(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(100, 1, "backup-server", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:10", Bridge: "vmbr0", IPs: []string{"10.77.10.110/24"}, Source: pvecontract.SourceQEMUAgent},
	})).build())
	if _, err := s.SweepStaging(ctx, "remote-a"); err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}

	hostID, err := s.ImportStaged(ctx, "remote-a", 100, 1, "", "alice")
	if err != nil {
		t.Fatalf("ImportStaged: %v", err)
	}
	if hostID != "backup-server" {
		t.Fatalf("created host id = %q, want backup-server", hostID)
	}
	host, err := s.hostStore().Get(ctx, hostID)
	if err != nil {
		t.Fatalf("Get created host: %v", err)
	}
	if host.DisplayName != "backup-server" || len(host.Endpoints) != 1 || host.Endpoints[0].Address != "10.77.10.110" {
		t.Fatalf("created host = %+v", host)
	}
	link, err := s.GetLink(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("ImportStaged must create the explicit link: %v", err)
	}
	if link.HostID != hostID {
		t.Fatalf("link host = %q, want %q", link.HostID, hostID)
	}
	stored, err := s.getStaging(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("getStaging: %v", err)
	}
	if stored.ImportedAt.IsZero() || stored.ImportedBy != "alice" || stored.ImportedAsset != hostID {
		t.Fatalf("staging row not marked imported: %+v", stored)
	}
}

func TestImportStagedLinksExistingHostPreservingIDs(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(200, 1, "vm-web", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
	})).build())
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	if _, err := s.SweepStaging(ctx, "remote-a"); err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}

	hostID, err := s.ImportStaged(ctx, "remote-a", 200, 1, "web1", "bob")
	if err != nil {
		t.Fatalf("ImportStaged: %v", err)
	}
	if hostID != "web1" {
		t.Fatalf("imported host = %q, want the existing web1", hostID)
	}
	link, err := s.GetLink(ctx, "remote-a", 200, 1)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if link.HostID != "web1" || link.CreatedBy != "bob" {
		t.Fatalf("link = %+v", link)
	}
	// The existing host is preserved untouched.
	host, err := s.hostStore().Get(ctx, "web1")
	if err != nil {
		t.Fatalf("Get web1: %v", err)
	}
	if host.ID != "web1" || host.Endpoints[0].Address != "10.77.10.101" {
		t.Fatalf("existing host changed: %+v", host)
	}
}

func TestImportStagedRefusesConflictAndRepeat(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(
		mkGuestWithIfaces(300, 1, "vm-a", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:02", Bridge: "vmbr0", IPs: []string{"10.77.10.102/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
		mkGuestWithIfaces(400, 1, "vm-b", []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:02", Bridge: "vmbr0", IPs: []string{"10.77.10.103/24"}, Source: pvecontract.SourceQEMUAgent},
		}),
	).build())
	mustCreateHost(t, s.db, mkManagedHost("web2", "10.77.10.102"))
	ipa := ipam.New(db, nil)
	if err := ipa.SaveAsset(ctx, ipam.Asset{
		ID: "asset-2", Name: "web2", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:02",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.102")}, HostID: "web2",
	}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	if _, err := s.SweepStaging(ctx, "remote-a"); err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}

	if _, err := s.ImportStaged(ctx, "remote-a", 300, 1, "web2", "alice"); !errors.Is(err, ErrStagingConflict) {
		t.Fatalf("import of CONFLICT entry = %v, want ErrStagingConflict", err)
	}
	if _, err := s.GetLink(ctx, "remote-a", 300, 1); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("conflict import must not create a link, got %v", err)
	}

	// A non-conflicting entry can be imported, but only once.
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(100, 1, "vm-new", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:10", Bridge: "vmbr0", IPs: []string{"10.77.10.110/24"}, Source: pvecontract.SourceQEMUAgent},
	})).build())
	if _, err := s.SweepStaging(ctx, "remote-a"); err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}
	if _, err := s.ImportStaged(ctx, "remote-a", 100, 1, "", "alice"); err != nil {
		t.Fatalf("ImportStaged: %v", err)
	}
	if _, err := s.ImportStaged(ctx, "remote-a", 100, 1, "", "bob"); !errors.Is(err, ErrStagingImported) {
		t.Fatalf("second import = %v, want ErrStagingImported", err)
	}
}

func TestImportStagedUnknownHostRefused(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(100, 1, "vm-new", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:10", Bridge: "vmbr0", IPs: []string{"10.77.10.110/24"}, Source: pvecontract.SourceQEMUAgent},
	})).build())
	if _, err := s.SweepStaging(ctx, "remote-a"); err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}
	if _, err := s.ImportStaged(ctx, "remote-a", 100, 1, "ghost", "alice"); !errors.Is(err, ErrManagedHostNotFound) {
		t.Fatalf("import to unknown host = %v, want ErrManagedHostNotFound", err)
	}
	if _, err := s.GetLink(ctx, "remote-a", 100, 1); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("failed import must not create a link, got %v", err)
	}
}

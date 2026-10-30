// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// mkGuestWithConfig builds a guest with an available config dataset.
func mkGuestWithConfig(vmid, gen uint64, name string, ramBytes uint64, ifaces []pvecontract.GuestInterface) pvecontract.GuestObservation {
	g := mkGuestWithIfaces(vmid, gen, name, ifaces)
	g.Config = pvecontract.AvailableDataset(pvecontract.GuestConfig{
		CPUCount: 2, RAMBytes: ramBytes,
		Capabilities: pvecontract.GuestCapabilities{
			Snapshots: pvecontract.Unknown, LiveMigration: pvecontract.Unknown, RAMSnapshots: pvecontract.Unknown,
		},
	})
	return g
}

// setupLinkedGuest creates a remote, a guest, a linked host and the
// explicit link, returning the store and host id.
func setupLinkedGuest(t *testing.T, guest pvecontract.GuestObservation, host inventory.Host) *Store {
	t.Helper()
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	mustIngestGuest(t, s, newObsA().guests(guest).build())
	mustCreateHost(t, s.db, host)
	if _, err := s.CreateLink(ctx, "remote-a", guest.VMID, guest.Generation, host.ID, "alice"); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	return s
}

func TestDriftIPHintAcceptUpdatesDisplayOnly(t *testing.T) {
	guest := mkGuestWithConfig(100, 1, "vm1", 4<<30, []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.200/24"}, Source: pvecontract.SourceQEMUAgent},
	})
	s := setupLinkedGuest(t, guest, mkManagedHost("web1", "10.77.10.101"))
	ctx := context.Background()

	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepDrift: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("want 1 drift hint (ip), got %+v", hints)
	}
	h := hints[0]
	if h.Field != DriftFieldIP || h.HostID != "web1" || h.PVEValue != "10.77.10.200" {
		t.Fatalf("unexpected hint: %+v", h)
	}
	if !h.ResolvedAt.IsZero() {
		t.Fatalf("hint must be open: %+v", h)
	}

	resolved, err := s.ResolveDriftHint(ctx, h.ID, DriftAccepted, "alice")
	if err != nil {
		t.Fatalf("ResolveDriftHint accept: %v", err)
	}
	if resolved.Resolution != DriftAccepted || resolved.ResolvedBy != "alice" || resolved.ResolvedAt.IsZero() {
		t.Fatalf("resolved hint = %+v", resolved)
	}
	host, err := s.hostStore().Get(ctx, "web1")
	if err != nil {
		t.Fatalf("Get web1: %v", err)
	}
	if host.Tags[TagPVEIP] != "10.77.10.200" {
		t.Fatalf("accept must record the PVE IP in the display tag, tags = %v", host.Tags)
	}
	// SSH endpoints, credential ref and criticality must be untouched.
	if len(host.Endpoints) != 1 || host.Endpoints[0].Address != "10.77.10.101" {
		t.Fatalf("accept must never change SSH endpoints: %+v", host.Endpoints)
	}
	if host.Criticality != "LOW" {
		t.Fatalf("accept must never change criticality: %q", host.Criticality)
	}
	if host.CredentialRef != "" {
		t.Fatalf("accept must never touch the credential ref: %q", host.CredentialRef)
	}
}

func TestDriftRAMNodeStateHints(t *testing.T) {
	guest := mkGuestWithConfig(100, 1, "vm1", 4<<30, nil)
	host := mkManagedHost("web1", "10.77.10.101")
	host.Tags = map[string]string{
		TagPVERAM:   "8 GiB",
		TagPVENode:  "p1",
		TagPVEState: "stopped",
	}
	s := setupLinkedGuest(t, guest, host)
	ctx := context.Background()

	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepDrift: %v", err)
	}
	byField := map[string]DriftHint{}
	for _, h := range hints {
		byField[h.Field] = h
	}
	// RAM differs (8 GiB vs 4 GiB); node matches (p1); state differs
	// (stopped vs running).
	if _, ok := byField[DriftFieldRAM]; !ok {
		t.Fatalf("want RAM hint, got %+v", hints)
	}
	if _, ok := byField[DriftFieldNode]; ok {
		t.Fatalf("node matches, no hint expected: %+v", byField[DriftFieldNode])
	}
	if _, ok := byField[DriftFieldState]; !ok {
		t.Fatalf("want state hint, got %+v", hints)
	}
	ram := byField[DriftFieldRAM]
	if ram.InventoryValue != "8 GiB" || ram.PVEValue != "4 GiB" {
		t.Fatalf("RAM hint values = %q vs %q", ram.InventoryValue, ram.PVEValue)
	}

	resolved, err := s.ResolveDriftHint(ctx, ram.ID, DriftAccepted, "bob")
	if err != nil {
		t.Fatalf("accept RAM: %v", err)
	}
	if resolved.Resolution != DriftAccepted {
		t.Fatalf("resolution = %q", resolved.Resolution)
	}
	host, err = s.hostStore().Get(ctx, "web1")
	if err != nil {
		t.Fatalf("Get web1: %v", err)
	}
	if host.Tags[TagPVERAM] != "4 GiB" {
		t.Fatalf("RAM tag not updated: %v", host.Tags)
	}
	if host.Tags[TagPVENode] != "p1" || host.Tags[TagPVEState] != "stopped" {
		t.Fatalf("accepting RAM must not touch other tags: %v", host.Tags)
	}
}

func TestDriftIgnoreLeavesHostUntouched(t *testing.T) {
	guest := mkGuestWithConfig(100, 1, "vm1", 4<<30, []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.200/24"}, Source: pvecontract.SourceQEMUAgent},
	})
	s := setupLinkedGuest(t, guest, mkManagedHost("web1", "10.77.10.101"))
	ctx := context.Background()

	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepDrift: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("want 1 hint, got %+v", hints)
	}
	resolved, err := s.ResolveDriftHint(ctx, hints[0].ID, DriftIgnored, "alice")
	if err != nil {
		t.Fatalf("ResolveDriftHint ignore: %v", err)
	}
	if resolved.Resolution != DriftIgnored {
		t.Fatalf("resolution = %q", resolved.Resolution)
	}
	host, err := s.hostStore().Get(ctx, "web1")
	if err != nil {
		t.Fatalf("Get web1: %v", err)
	}
	if len(host.Tags) != 0 {
		t.Fatalf("ignore must not change the host: tags = %v", host.Tags)
	}
}

func TestDriftNoHintWhenValuesMatch(t *testing.T) {
	guest := mkGuestWithConfig(100, 1, "vm1", 4<<30, []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
	})
	s := setupLinkedGuest(t, guest, mkManagedHost("web1", "10.77.10.101"))
	ctx := context.Background()

	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepDrift: %v", err)
	}
	if len(hints) != 0 {
		t.Fatalf("no drift expected, got %+v", hints)
	}
	// The sweep is idempotent: a second run records nothing new.
	again, err := s.SweepDrift(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepDrift again: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second sweep must be empty, got %+v", again)
	}
}

func TestDriftResolveTwiceAndInvalidRefused(t *testing.T) {
	guest := mkGuestWithConfig(100, 1, "vm1", 4<<30, []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", Bridge: "vmbr0", IPs: []string{"10.77.10.200/24"}, Source: pvecontract.SourceQEMUAgent},
	})
	s := setupLinkedGuest(t, guest, mkManagedHost("web1", "10.77.10.101"))
	ctx := context.Background()

	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil {
		t.Fatalf("SweepDrift: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("want 1 hint, got %+v", hints)
	}
	if _, err := s.ResolveDriftHint(ctx, hints[0].ID, "bogus", "alice"); err == nil {
		t.Fatalf("invalid resolution must be refused")
	}
	if _, err := s.ResolveDriftHint(ctx, hints[0].ID, DriftAccepted, "alice"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := s.ResolveDriftHint(ctx, hints[0].ID, DriftIgnored, "bob"); !errors.Is(err, ErrDriftResolved) {
		t.Fatalf("second resolve = %v, want ErrDriftResolved", err)
	}
	if _, err := s.ResolveDriftHint(ctx, 999, DriftAccepted, "alice"); !errors.Is(err, ErrDriftHintNotFound) {
		t.Fatalf("unknown hint = %v, want ErrDriftHintNotFound", err)
	}
}

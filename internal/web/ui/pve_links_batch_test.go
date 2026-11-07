// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for review round 1 of PR #353: the PVE detail page computes the
// link suggestions of all unlinked guests with one
// pveinventory.Store.SuggestHostsBatch call (managed hosts and IPAM assets
// read once per page), renders exactly what per-guest SuggestHosts calls
// rendered, and a guest that vanished meanwhile only loses its own
// suggestions.

package ui_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// batchModeStore is the real store. With perGuest set its
// SuggestHostsBatch is the old per-guest path (one SuggestHosts call per
// guest); drop names a guest left out of the batch result (vanished).
type batchModeStore struct {
	*pveinventory.Store
	perGuest bool
	drop     *pveinventory.GuestRef
	calls    atomic.Int64
	single   atomic.Int64
}

func (b *batchModeStore) SuggestHosts(ctx context.Context, remoteID string, vmid, gen uint64) ([]pveinventory.Candidate, error) {
	b.single.Add(1)
	return b.Store.SuggestHosts(ctx, remoteID, vmid, gen)
}

func (b *batchModeStore) SuggestHostsBatch(ctx context.Context, remoteID string, guests []pveinventory.GuestRef) (map[pveinventory.GuestRef][]pveinventory.Candidate, error) {
	b.calls.Add(1)
	var out map[pveinventory.GuestRef][]pveinventory.Candidate
	if b.perGuest {
		out = map[pveinventory.GuestRef][]pveinventory.Candidate{}
		for _, g := range guests {
			cands, err := b.Store.SuggestHosts(ctx, remoteID, g.VMID, g.Generation)
			if err != nil {
				return nil, err
			}
			out[g] = cands
		}
	} else {
		var err error
		if out, err = b.Store.SuggestHostsBatch(ctx, remoteID, guests); err != nil {
			return nil, err
		}
	}
	if b.drop != nil {
		delete(out, *b.drop)
	}
	return out, nil
}

// newBatchEnv seeds guests covering every candidate kind: 101 MAC (IPAM
// asset) and agent IP of h1, 102/103 a cloned MAC on an asset of h2
// (conflict), 104 an agent IP that is an endpoint of h3 and h4 (conflict),
// 105 no candidate.
func newBatchEnv(t *testing.T) (*linkEnv, *batchModeStore) {
	t.Helper()
	b := &batchModeStore{}
	e := newLinkEnvWith(t, func(s *pveinventory.Store) ui.PVEStore {
		b.Store = s
		return b
	})
	e.guests(1,
		agentGuest(101, 1, "vm-a", "aa:bb:cc:dd:ee:01", "10.77.10.101"),
		agentGuest(102, 1, "vm-b", "aa:bb:cc:dd:ee:02", "10.77.10.102"),
		agentGuest(103, 1, "vm-c", "aa:bb:cc:dd:ee:02", "10.77.10.103"),
		agentGuest(104, 1, "vm-d", "aa:bb:cc:dd:ee:04", "10.77.10.150"),
		agentGuest(105, 1, "vm-e", "aa:bb:cc:dd:ee:05", "10.77.99.1"),
	)
	e.host("h1", "Host one", "10.77.10.101")
	e.host("h2", "Host two", "10.77.20.2")
	e.host("h3", "Host three", "10.77.10.150")
	e.host("h4", "Host four", "10.77.10.150")
	for _, a := range []struct{ host, mac, ip string }{
		{"h1", "aa:bb:cc:dd:ee:01", "10.77.10.101"},
		{"h2", "aa:bb:cc:dd:ee:02", "10.77.20.2"},
	} {
		if err := e.ipam.SaveAsset(context.Background(), ipam.Asset{
			ID: "asset-" + a.host, Name: a.host, Kind: ipam.KindServer, MAC: a.mac,
			Addresses: []netip.Addr{netip.MustParseAddr(a.ip)}, HostID: a.host,
		}); err != nil {
			t.Fatalf("SaveAsset %s: %v", a.host, err)
		}
	}
	return e, b
}

// TestPVESuggestionsOneBatchRenderPerGuestResult checks that the page asks
// for all guest suggestions with one batch call and renders exactly the
// page the per-guest SuggestHosts path renders.
func TestPVESuggestionsOneBatchRenderPerGuestResult(t *testing.T) {
	e, b := newBatchEnv(t)

	batchBody := e.page()
	if n := b.calls.Load(); n != 1 {
		t.Fatalf("SuggestHostsBatch calls = %d, want 1 per page", n)
	}
	if n := b.single.Load(); n != 0 {
		t.Fatalf("per-guest SuggestHosts calls = %d, want 0", n)
	}
	for _, want := range []string{
		`name="host" value="h1"`, `name="host" value="h2"`, `name="host" value="h3"`, `name="host" value="h4"`,
		"MAC aa:bb:cc:dd:ee:01 matches an IPAM asset of host h1",
		"MAC also seen on guest 103 (gen 1)", "MAC also seen on guest 102 (gen 1)",
		"IP also matches 1 other hosts", `name="confirm_conflict"`,
	} {
		if !strings.Contains(batchBody, want) {
			t.Errorf("batch page misses %q", want)
		}
	}

	b.perGuest = true
	perGuestBody := e.page()
	if batchBody != perGuestBody {
		t.Errorf("batch page differs from the per-guest page\nbatch:\n%s\nper guest:\n%s", batchBody, perGuestBody)
	}
}

// TestPVESuggestionVanishedGuestOnlyLosesItsOwn checks that a guest missing
// from the batch result (no longer an active incarnation) shows
// "Suggestions unavailable." while the other guests keep their candidates.
func TestPVESuggestionVanishedGuestOnlyLosesItsOwn(t *testing.T) {
	e, b := newBatchEnv(t)
	b.drop = &pveinventory.GuestRef{VMID: 101, Generation: 1}
	body := e.page()
	if n := strings.Count(body, "Suggestions unavailable."); n != 1 {
		t.Errorf("unavailable notes = %d, want 1 (only the vanished guest)", n)
	}
	if strings.Contains(body, "MAC aa:bb:cc:dd:ee:01 matches an IPAM asset of host h1") {
		t.Errorf("vanished guest still shows candidates")
	}
	for _, want := range []string{`name="host" value="h2"`, `name="host" value="h3"`} {
		if !strings.Contains(body, want) {
			t.Errorf("other guests lost their candidates: %q missing", want)
		}
	}
	if !strings.Contains(e.logs.String(), fmt.Sprintf("vmid=%d", 101)) {
		t.Errorf("vanished guest not logged:\n%s", e.logs.String())
	}
}

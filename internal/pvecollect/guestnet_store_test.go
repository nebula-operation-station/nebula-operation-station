// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// guestNetStoreNow is shortly after validGuestNetRecord's observation.
var guestNetStoreNow = time.Unix(1_700_000_100, 0)

func newGuestNetTestStore(t *testing.T) *trafficstore.Store {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return trafficstore.NewWithNow(db, func() time.Time { return guestNetStoreNow })
}

func TestNewGuestNetStoreSinkRequiresStore(t *testing.T) {
	if _, err := NewGuestNetStoreSink(nil); err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestGuestNetStoreSinkImportsProviderLinks(t *testing.T) {
	ctx := context.Background()
	store := newGuestNetTestStore(t)
	sink, err := NewGuestNetStoreSink(store)
	if err != nil {
		t.Fatal(err)
	}
	w := newTestSpool(t)
	r, err := OpenSpool(w.root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	im, err := NewGuestNetImporter(r, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	im.Now = func() time.Time { return guestNetStoreNow }
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil || rep != (GuestNetImportReport{Files: 1, Imported: 1}) {
		t.Fatalf("report = %+v, %v", rep, err)
	}
	links, err := store.GuestNICs(ctx, "pve-lab")
	if err != nil {
		t.Fatal(err)
	}
	want := validGuestNetRecord().NICs
	if len(links) != len(want) {
		t.Fatalf("links = %+v", links)
	}
	for i, l := range links {
		n := want[i]
		if l.Source != trafficstore.SourceProvider || l.Remote != "pve-lab" || l.VMID != n.VMID || l.Kind != n.Kind ||
			l.Index != n.Index || l.Bridge != n.Bridge || l.VLAN != n.VLAN || l.MAC != n.MAC ||
			l.ObservedAt.Unix() != validGuestNetRecord().ObservedUnix {
			t.Errorf("link %d = %+v, want %+v", i, l, n)
		}
	}
	// No endpoint (and so no address) is created from provider data.
	if n, err := store.CountEndpoints(ctx); err != nil || n != 0 {
		t.Fatalf("endpoints after provider import = %d, %v", n, err)
	}
}

func TestGuestNetStoreSinkMatchesObservedEndpointByMAC(t *testing.T) {
	ctx := context.Background()
	store := newGuestNetTestStore(t)
	sink, err := NewGuestNetStoreSink(store)
	if err != nil {
		t.Fatal(err)
	}
	ep := trafficstore.Endpoint{
		MAC:       "bc:24:11:00:00:03",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.30.7")},
		FirstSeen: guestNetStoreNow.Add(-time.Minute),
		LastSeen:  guestNetStoreNow,
		Tier:      flowagg.TierSocket,
		Reporter:  "host-a",
	}
	if err := store.UpsertEndpoint(ctx, ep, trafficstore.Identity{}); err != nil {
		t.Fatal(err)
	}
	if err := sink.ImportGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LookupEndpoint(ctx, ep.MAC, ep.Addresses[0])
	if err != nil || !ok {
		t.Fatalf("lookup: %v %v", ok, err)
	}
	links, err := store.EndpointGuestLinks(ctx, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].VMID != 200 || links[0].Kind != "lxc" || links[0].VLAN != 4094 || links[0].Source != trafficstore.SourceProvider {
		t.Fatalf("links = %+v", links)
	}
	if got.Tier != flowagg.TierSocket || got.VLAN != 0 {
		t.Fatalf("observed endpoint took provider values: %+v", got)
	}
}

func TestGuestNetStoreSinkMapsStoreRefusals(t *testing.T) {
	ctx := context.Background()
	store := newGuestNetTestStore(t)
	sink, err := NewGuestNetStoreSink(store)
	if err != nil {
		t.Fatal(err)
	}
	rec := validGuestNetRecord()
	if err := sink.ImportGuestNet(ctx, rec); err != nil {
		t.Fatal(err)
	}
	older := rec
	older.ObservedUnix--
	if err := sink.ImportGuestNet(ctx, older); !errors.Is(err, ErrGuestNetStale) {
		t.Fatalf("older record: %v, want ErrGuestNetStale", err)
	}
	expired := rec
	expired.Remote = "pve-old"
	expired.ObservedUnix = guestNetStoreNow.Add(-trafficstore.DefaultRetention - time.Hour).Unix()
	if err := sink.ImportGuestNet(ctx, expired); !errors.Is(err, ErrGuestNetStale) {
		t.Fatalf("expired record: %v, want ErrGuestNetStale", err)
	}
	bad := rec
	bad.Remote = "pve-bad"
	bad.NICs = append([]GuestNIC(nil), rec.NICs...)
	bad.NICs[0].MAC = "01:00:5e:00:00:01"
	if err := sink.ImportGuestNet(ctx, bad); !errors.Is(err, ErrGuestNetInvalid) {
		t.Fatalf("invalid record: %v, want ErrGuestNetInvalid", err)
	}
	if links, _ := store.GuestNICs(ctx, "pve-bad"); len(links) != 0 {
		t.Fatalf("invalid record stored: %+v", links)
	}
}

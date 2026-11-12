// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// seenDevice stores a network device row the way netdevinventory does.
func seenDevice(t *testing.T, s *Store, id, family string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO netdev_devices_seen (device_id, family, label, trust_generation, created_at, updated_at)
		VALUES (?, ?, '', 1, 0, 0)`, id, family); err != nil {
		t.Fatal(err)
	}
}

func saveAsset(t *testing.T, s *Store, id string, kind Kind, mac string) {
	t.Helper()
	if err := s.SaveAsset(context.Background(), Asset{ID: id, Name: strings.ToUpper(id), Kind: kind, MAC: mac}); err != nil {
		t.Fatal(err)
	}
}

func linkCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM netdev_asset_links`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSuggestDeviceAssetsListsMACMatchesWithSource(t *testing.T) {
	assets := []Asset{
		{ID: "sw-core", Name: "Core switch", Kind: KindSwitch, MAC: "aa:bb:cc:00:00:01"},
		{ID: "nas", Name: "NAS", Kind: KindNAS, MAC: "aa:bb:cc:00:00:02"},
		{ID: "nomac", Name: "No MAC", Kind: KindSwitch},
	}
	entries := []netdevcontract.MACEntry{
		{VLAN: 10, MAC: "AA-BB-CC-00-00-02", Port: "gi1/0/5", Type: netdevcontract.MACDynamic},
		{VLAN: 1, MAC: "aa:bb:cc:00:00:01", Type: netdevcontract.MACOther},
		{VLAN: 10, MAC: "aa:bb:cc:00:00:99", Port: "gi1/0/6", Type: netdevcontract.MACDynamic},
		{VLAN: 10, MAC: "", Port: "gi1/0/7", Type: netdevcontract.MACDynamic},
	}
	got := SuggestDeviceAssets(assets, entries)
	if len(got) != 2 {
		t.Fatalf("suggestions = %+v, want 2", got)
	}
	// The switch's own (non-dynamic) entry comes first.
	if got[0].AssetID != "sw-core" || !got[0].SelfEntry || !got[0].KindMatches || got[0].Source != SourceMACTable {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].AssetID != "nas" || got[1].SelfEntry || got[1].KindMatches || got[1].Port != "gi1/0/5" || got[1].MAC != "aa:bb:cc:00:00:02" {
		t.Errorf("second = %+v", got[1])
	}
}

func TestSuggestDeviceAssetsIsCapped(t *testing.T) {
	assets := []Asset{{ID: "sw", Name: "SW", Kind: KindSwitch, MAC: "aa:bb:cc:00:00:01"}}
	var entries []netdevcontract.MACEntry
	for v := range MaxDeviceAssetSuggestions + 10 {
		entries = append(entries, netdevcontract.MACEntry{VLAN: uint16(v + 1), MAC: "aa:bb:cc:00:00:01", Type: netdevcontract.MACDynamic})
	}
	if got := SuggestDeviceAssets(assets, entries); len(got) != MaxDeviceAssetSuggestions {
		t.Errorf("suggestions = %d, want %d", len(got), MaxDeviceAssetSuggestions)
	}
}

func TestSuggestionNeverCreatesLink(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	seenDevice(t, s, "sw-core", "cbs")
	saveAsset(t, s, "core", KindSwitch, "aa:bb:cc:00:00:01")
	assets, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := SuggestDeviceAssets(assets, []netdevcontract.MACEntry{{VLAN: 1, MAC: "aa:bb:cc:00:00:01", Type: netdevcontract.MACOther}})
	if len(got) != 1 {
		t.Fatalf("suggestions = %+v", got)
	}
	if n := linkCount(t, s); n != 0 {
		t.Errorf("links after suggesting = %d, want 0", n)
	}
	if _, err := s.DeviceLink(ctx, "sw-core"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeviceLink = %v, want ErrNotFound", err)
	}
}

func TestConfirmDeviceLinkRecordsActorAndTime(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	seenDevice(t, s, "sw-core", "cbs")
	saveAsset(t, s, "core", KindSwitch, "")
	l, err := s.ConfirmDeviceLink(ctx, "sw-core", "core", "alice")
	if err != nil {
		t.Fatal(err)
	}
	want := DeviceLink{DeviceID: "sw-core", AssetID: "core", ConfirmedBy: "alice", ConfirmedAt: time.Unix(1_800_000_000, 0)}
	if l != want {
		t.Errorf("confirm = %+v, want %+v", l, want)
	}
	got, err := s.DeviceLink(ctx, "sw-core")
	if err != nil || got != want {
		t.Errorf("DeviceLink = %+v, %v; want %+v", got, err, want)
	}
}

func TestConfirmDeviceLinkRejections(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	seenDevice(t, s, "sw-core", "cbs")
	seenDevice(t, s, "sw-edge", "cbs")
	saveAsset(t, s, "core", KindSwitch, "")
	saveAsset(t, s, "edge", KindSwitch, "")
	saveAsset(t, s, "nas", KindNAS, "")
	if _, err := s.ConfirmDeviceLink(ctx, "sw-core", "core", "alice"); err != nil {
		t.Fatal(err)
	}
	var ve *ValidationError
	cases := []struct {
		name                 string
		device, asset, actor string
		check                func(error) bool
	}{
		{"unknown device", "sw-gone", "edge", "alice", func(e error) bool { return errors.Is(e, ErrDeviceUnknown) }},
		{"unknown asset", "sw-edge", "nope", "alice", func(e error) bool { return errors.Is(e, ErrNotFound) }},
		{"wrong asset kind", "sw-edge", "nas", "alice", func(e error) bool { return errors.As(e, &ve) }},
		{"device already linked", "sw-core", "edge", "alice", func(e error) bool { return errors.Is(e, ErrDeviceLinked) }},
		{"asset already linked", "sw-edge", "core", "alice", func(e error) bool { return errors.Is(e, ErrAssetLinked) }},
		{"bad device id", "SW CORE", "edge", "alice", func(e error) bool { return errors.As(e, &ve) }},
		{"bad asset id", "sw-edge", "Edge!", "alice", func(e error) bool { return errors.As(e, &ve) }},
		{"empty actor", "sw-edge", "edge", "", func(e error) bool { return errors.As(e, &ve) }},
		{"long actor", "sw-edge", "edge", strings.Repeat("a", MaxLinkActor+1), func(e error) bool { return errors.As(e, &ve) }},
		{"control in actor", "sw-edge", "edge", "al\nice", func(e error) bool { return errors.As(e, &ve) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.ConfirmDeviceLink(ctx, c.device, c.asset, c.actor)
			if err == nil || !c.check(err) {
				t.Errorf("err = %v", err)
			}
		})
	}
	if n := linkCount(t, s); n != 1 {
		t.Errorf("links = %d, want 1", n)
	}
}

func TestRemoveDeviceLink(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	seenDevice(t, s, "sw-core", "cbs")
	saveAsset(t, s, "core", KindSwitch, "")
	if _, err := s.ConfirmDeviceLink(ctx, "sw-core", "core", "alice"); err != nil {
		t.Fatal(err)
	}
	old, err := s.RemoveDeviceLink(ctx, "sw-core")
	if err != nil || old.AssetID != "core" || old.ConfirmedBy != "alice" {
		t.Fatalf("remove = %+v, %v", old, err)
	}
	if _, err := s.DeviceLink(ctx, "sw-core"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after remove: %v, want ErrNotFound", err)
	}
	if _, err := s.RemoveDeviceLink(ctx, "sw-core"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second remove: %v, want ErrNotFound", err)
	}
	var ve *ValidationError
	if _, err := s.RemoveDeviceLink(ctx, "BAD ID"); !errors.As(err, &ve) {
		t.Errorf("bad id: %v, want ValidationError", err)
	}
}

func TestDeviceLinkGoneAfterAssetRemoval(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	seenDevice(t, s, "sw-core", "cbs")
	saveAsset(t, s, "core", KindSwitch, "aa:bb:cc:00:00:01")
	if _, err := s.ConfirmDeviceLink(ctx, "sw-core", "core", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(ctx, "core"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeviceLink(ctx, "sw-core"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after asset removal: %v, want ErrNotFound", err)
	}
	// A new asset with the same ID does not inherit the old confirmation.
	saveAsset(t, s, "core", KindSwitch, "aa:bb:cc:00:00:01")
	if _, err := s.DeviceLink(ctx, "sw-core"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after asset re-creation: %v, want ErrNotFound", err)
	}
	if n := linkCount(t, s); n != 0 {
		t.Errorf("links = %d, want 0", n)
	}
}

func TestDeviceLinkReplacingAssetKeepsLink(t *testing.T) {
	// SaveAsset is an upsert; an edit of the asset must not drop the link.
	s := newStore(t, nil)
	ctx := context.Background()
	seenDevice(t, s, "fw", "panos")
	saveAsset(t, s, "fw1", KindFirewall, "")
	if _, err := s.ConfirmDeviceLink(ctx, "fw", "fw1", "alice"); err != nil {
		t.Fatal(err)
	}
	saveAsset(t, s, "fw1", KindFirewall, "aa:bb:cc:00:00:09")
	if l, err := s.DeviceLink(ctx, "fw"); err != nil || l.AssetID != "fw1" {
		t.Errorf("after edit: %+v, %v", l, err)
	}
}

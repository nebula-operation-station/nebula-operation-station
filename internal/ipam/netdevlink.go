// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Network device ↔ asset link (ADR 0010 D4 "Device as an asset", ticket
// ND-18 part 2).
//
// A network device (a switch or firewall of the netdevinventory store) is
// linked to an IPAM asset only by an explicit admin confirmation:
// ConfirmDeviceLink is the one and only writer of the link table, and the
// caller (the device page) calls it only on an admin's POST. A MAC that a
// device's MAC table shares with an asset is a suggestion
// (SuggestDeviceAssets): a pure function over data already read, with no
// store access, so computing or showing suggestions can never create a
// link.
//
// The table cascades on asset and device deletion: a deleted asset takes
// its link with it, and an asset re-created under the same ID starts
// unlinked.

// MaxLinkActor is the longest user name recorded as a link's confirmer.
const MaxLinkActor = 64

// MaxDeviceAssetSuggestions caps the suggestions for one device.
const MaxDeviceAssetSuggestions = 32

// Link errors callers branch on.
var (
	// ErrDeviceUnknown: the device is not in the network device inventory.
	ErrDeviceUnknown = errors.New("ipam: network device not known")
	// ErrDeviceLinked: the device is already linked to an asset; remove
	// that link first.
	ErrDeviceLinked = errors.New("ipam: network device already linked to an asset")
	// ErrAssetLinked: the asset is already linked to another device.
	ErrAssetLinked = errors.New("ipam: asset already linked to another network device")
)

// DeviceLink is one confirmed network device ↔ asset link.
type DeviceLink struct {
	DeviceID    string
	AssetID     string
	ConfirmedBy string
	ConfirmedAt time.Time
}

// DeviceAssetSuggestion is an asset whose MAC appears in a device's MAC
// table. It is a hint for the admin and never a link.
type DeviceAssetSuggestion struct {
	AssetID   string
	AssetName string
	AssetKind Kind
	// KindMatches is true for asset kinds a network device can be
	// linked to (switch, firewall).
	KindMatches bool
	// MAC is the normalized shared MAC address.
	MAC string
	// VLAN, Port and EntryType are the matching MAC table entry's. Port
	// is untrusted device text.
	VLAN      uint16
	Port      string
	EntryType netdevcontract.MACType
	// SelfEntry is true for a static or "other" entry: those are the
	// device's own or configured MACs, the strongest hint that the asset
	// is the device itself. A dynamic entry is an endpoint seen on a port.
	SelfEntry bool
	// Source labels the data the suggestion rests on (SourceMACTable).
	Source string
}

// linkableKind reports whether a network device may be linked to an
// asset of kind k (ADR 0010 D4: the device is an asset of kind switch or
// firewall).
func linkableKind(k Kind) bool { return k == KindSwitch || k == KindFirewall }

// SuggestDeviceAssets lists the assets whose MAC appears in entries,
// self entries first, then by asset ID, VLAN and port, at most
// MaxDeviceAssetSuggestions. It reads and writes nothing.
func SuggestDeviceAssets(assets []Asset, entries []netdevcontract.MACEntry) []DeviceAssetSuggestion {
	byMAC := make(map[string][]Asset, len(assets))
	for _, a := range assets {
		if m, ok := NormalizeMAC(a.MAC); ok && m != "" {
			byMAC[m] = append(byMAC[m], a)
		}
	}
	var out []DeviceAssetSuggestion
	for _, e := range entries {
		m, ok := NormalizeMAC(e.MAC)
		if !ok || m == "" {
			continue
		}
		for _, a := range byMAC[m] {
			out = append(out, DeviceAssetSuggestion{
				AssetID: a.ID, AssetName: a.Name, AssetKind: a.Kind, KindMatches: linkableKind(a.Kind),
				MAC: m, VLAN: e.VLAN, Port: e.Port, EntryType: e.Type, SelfEntry: !IsDynamicMAC(e),
				Source: SourceMACTable,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.SelfEntry != y.SelfEntry {
			return x.SelfEntry
		}
		if x.AssetID != y.AssetID {
			return x.AssetID < y.AssetID
		}
		if x.VLAN != y.VLAN {
			return x.VLAN < y.VLAN
		}
		return x.Port < y.Port
	})
	if len(out) > MaxDeviceAssetSuggestions {
		out = out[:MaxDeviceAssetSuggestions]
	}
	return out
}

func checkLinkIDs(deviceID, assetID string) error {
	if !netdevcontract.ValidDeviceID(deviceID) {
		return invalid("the network device ID is not valid")
	}
	if !idRe.MatchString(assetID) {
		return invalid("the asset ID is not valid")
	}
	return nil
}

// ConfirmDeviceLink records the admin's confirmation that device deviceID
// is asset assetID. actor is the confirming web user; the caller must
// have checked the admin role. The device must be in the inventory, the
// asset must exist with kind switch or firewall, and neither may be
// linked already (ErrDeviceLinked, ErrAssetLinked).
func (s *Store) ConfirmDeviceLink(ctx context.Context, deviceID, assetID, actor string) (DeviceLink, error) {
	if err := checkLinkIDs(deviceID, assetID); err != nil {
		return DeviceLink{}, err
	}
	if len(actor) > MaxLinkActor || !userRe.MatchString(actor) {
		return DeviceLink{}, invalid("the confirming user name is not valid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceLink{}, fmt.Errorf("confirm device link %s: %w", deviceID, err)
	}
	defer func() { _ = tx.Rollback() }()
	var one int
	switch err := tx.QueryRowContext(ctx, `SELECT 1 FROM netdev_devices_seen WHERE device_id = ?`, deviceID).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return DeviceLink{}, ErrDeviceUnknown
	case err != nil:
		return DeviceLink{}, fmt.Errorf("confirm device link %s: read device: %w", deviceID, err)
	}
	var kind string
	switch err := tx.QueryRowContext(ctx, `SELECT kind FROM assets WHERE id = ?`, assetID).Scan(&kind); {
	case errors.Is(err, sql.ErrNoRows):
		return DeviceLink{}, ErrNotFound
	case err != nil:
		return DeviceLink{}, fmt.Errorf("confirm device link %s: read asset: %w", deviceID, err)
	}
	if !linkableKind(Kind(kind)) {
		return DeviceLink{}, invalid("a network device can only be linked to an asset of kind switch or firewall")
	}
	var other string
	switch err := tx.QueryRowContext(ctx, `SELECT asset_id FROM netdev_asset_links WHERE device_id = ?`, deviceID).Scan(&other); {
	case err == nil:
		return DeviceLink{}, ErrDeviceLinked
	case !errors.Is(err, sql.ErrNoRows):
		return DeviceLink{}, fmt.Errorf("confirm device link %s: read link: %w", deviceID, err)
	}
	switch err := tx.QueryRowContext(ctx, `SELECT device_id FROM netdev_asset_links WHERE asset_id = ?`, assetID).Scan(&other); {
	case err == nil:
		return DeviceLink{}, ErrAssetLinked
	case !errors.Is(err, sql.ErrNoRows):
		return DeviceLink{}, fmt.Errorf("confirm device link %s: read asset link: %w", deviceID, err)
	}
	l := DeviceLink{DeviceID: deviceID, AssetID: assetID, ConfirmedBy: actor, ConfirmedAt: time.Unix(s.now().Unix(), 0)}
	if _, err := tx.ExecContext(ctx, `INSERT INTO netdev_asset_links (device_id, asset_id, confirmed_by, confirmed_at) VALUES (?, ?, ?, ?)`,
		l.DeviceID, l.AssetID, l.ConfirmedBy, l.ConfirmedAt.Unix()); err != nil {
		return DeviceLink{}, fmt.Errorf("confirm device link %s: %w", deviceID, err)
	}
	if err := tx.Commit(); err != nil {
		return DeviceLink{}, fmt.Errorf("confirm device link %s: %w", deviceID, err)
	}
	return l, nil
}

// RemoveDeviceLink removes the link of device deviceID and returns the
// removed link, or ErrNotFound when the device has none. The caller must
// have checked the admin role.
func (s *Store) RemoveDeviceLink(ctx context.Context, deviceID string) (DeviceLink, error) {
	if !netdevcontract.ValidDeviceID(deviceID) {
		return DeviceLink{}, invalid("the network device ID is not valid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceLink{}, fmt.Errorf("remove device link %s: %w", deviceID, err)
	}
	defer func() { _ = tx.Rollback() }()
	l, err := readDeviceLink(ctx, tx, deviceID)
	if err != nil {
		return DeviceLink{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM netdev_asset_links WHERE device_id = ?`, deviceID); err != nil {
		return DeviceLink{}, fmt.Errorf("remove device link %s: %w", deviceID, err)
	}
	if err := tx.Commit(); err != nil {
		return DeviceLink{}, fmt.Errorf("remove device link %s: %w", deviceID, err)
	}
	return l, nil
}

// DeviceLink returns the confirmed link of device deviceID, or
// ErrNotFound.
func (s *Store) DeviceLink(ctx context.Context, deviceID string) (DeviceLink, error) {
	if !netdevcontract.ValidDeviceID(deviceID) {
		return DeviceLink{}, invalid("the network device ID is not valid")
	}
	return readDeviceLink(ctx, s.db, deviceID)
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func readDeviceLink(ctx context.Context, q rowQuerier, deviceID string) (DeviceLink, error) {
	l := DeviceLink{DeviceID: deviceID}
	var at int64
	err := q.QueryRowContext(ctx, `SELECT l.asset_id, l.confirmed_by, l.confirmed_at FROM netdev_asset_links l
		JOIN assets a ON a.id = l.asset_id WHERE l.device_id = ?`, deviceID).Scan(&l.AssetID, &l.ConfirmedBy, &at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return DeviceLink{}, ErrNotFound
	case err != nil:
		return DeviceLink{}, fmt.Errorf("read device link %s: %w", deviceID, err)
	}
	l.ConfirmedAt = time.Unix(at, 0)
	return l, nil
}

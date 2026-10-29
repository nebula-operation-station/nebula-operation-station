// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"fmt"
)

// TriState is a three-valued yes/no/unknown flag for capability hints.
//
// TODO(p102): replace with pvecontract.TriState once
// agent/p102-pve-contracts lands on main.
type TriState int

// TriState values.
const (
	// TriUnknown means the capability could not be determined.
	TriUnknown TriState = iota
	// TriNo means the capability is known to be absent.
	TriNo
	// TriYes means the capability is present.
	TriYes
)

// String renders the tri-state for display and logs.
func (t TriState) String() string {
	switch t {
	case TriNo:
		return "no"
	case TriYes:
		return "yes"
	default:
		return "unknown"
	}
}

// Storage is one PVE storage with derived snapshot capability.
type Storage struct {
	// ID is the storage id, e.g. "local-lvm".
	ID string
	// Type is the PVE storage type, e.g. "dir", "lvm", "zfspool".
	Type string
	// Format is the volume format the storage reports ("" if none).
	Format string
	// Content lists supported content types, e.g. "images", "backup".
	Content []string
	// Shared reports whether the storage is cluster-shared.
	Shared bool
	// Active reports whether the storage is active on the node.
	Active bool
	// TotalBytes and UsedBytes are reported capacity in bytes.
	TotalBytes uint64
	UsedBytes  uint64
	// CapacityKnown reports whether PVE reported space at all; some
	// storage types (e.g. pbs) do not.
	CapacityKnown bool
	// Snapshots is the derived snapshot capability (yes/no/unknown).
	Snapshots TriState
}

// StorageList is a node's storage inventory.
type StorageList struct {
	// Storages holds the parsed storages, at most MaxStoragesPerRemote.
	Storages []Storage
	// Complete is false when the response exceeded the object limit and
	// Storages holds only the first MaxStoragesPerRemote entries.
	Complete bool
}

// storageWire is the PVE 8/9 response shape of /nodes/{node}/storage.
// Unknown fields are dropped on decode.
type storageWire struct {
	ID      string            `json:"id"`
	Type    string            `json:"type"`
	Format  string            `json:"format"`
	Content []string          `json:"content"`
	Active  *int              `json:"active"`
	Shared  *int              `json:"shared"`
	Space   *storageSpaceWire `json:"space"`
}

// storageSpaceWire is the space sub-object; absent for types without
// capacity reporting.
type storageSpaceWire struct {
	Used  *uint64 `json:"used"`
	Total *uint64 `json:"total"`
}

// ListStorages reads /nodes/{node}/storage and returns the node's storage
// inventory with derived snapshot capabilities. A permission-denied or
// other read failure returns ErrUnavailable; an empty list is an empty,
// complete result.
func (c *Client) ListStorages(ctx context.Context, node string) (StorageList, error) {
	if err := validNodeName(node); err != nil {
		return StorageList{}, err
	}
	path := "/nodes/" + node + "/storage"
	var wire []storageWire
	if err := c.get(ctx, path, &wire); err != nil {
		return StorageList{}, err
	}
	storages := make([]Storage, 0, len(wire))
	complete := len(wire) <= MaxStoragesPerRemote
	for _, w := range wire {
		if len(storages) >= MaxStoragesPerRemote {
			break
		}
		st, err := storageFromWire(w)
		if err != nil {
			return StorageList{}, schemaErr(path)
		}
		storages = append(storages, st)
	}
	return StorageList{Storages: storages, Complete: complete}, nil
}

// GetStorage reads /nodes/{node}/storage/{id} for one storage.
func (c *Client) GetStorage(ctx context.Context, node, storageID string) (Storage, error) {
	if err := validNodeName(node); err != nil {
		return Storage{}, err
	}
	if err := validStorageID(storageID); err != nil {
		return Storage{}, err
	}
	path := "/nodes/" + node + "/storage/" + storageID
	var w storageWire
	if err := c.get(ctx, path, &w); err != nil {
		return Storage{}, err
	}
	st, err := storageFromWire(w)
	if err != nil {
		return Storage{}, schemaErr(path)
	}
	return st, nil
}

// storageFromWire validates one wire record and derives its snapshot
// capability.
func storageFromWire(w storageWire) (Storage, error) {
	if err := validStorageID(w.ID); err != nil {
		return Storage{}, err
	}
	if w.Type == "" || len(w.Type) > MaxRefBytes {
		return Storage{}, fmt.Errorf("storage %s: invalid type", w.ID)
	}
	for i := 0; i < len(w.Type); i++ {
		ch := w.Type[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return Storage{}, fmt.Errorf("storage %s: invalid type %q", w.ID, w.Type)
		}
	}
	if len(w.Format) > MaxStorageFormatBytes {
		return Storage{}, fmt.Errorf("storage %s: format too long", w.ID)
	}
	if len(w.Content) > MaxContentTypes {
		return Storage{}, fmt.Errorf("storage %s: too many content types", w.ID)
	}
	content := make([]string, 0, len(w.Content))
	for _, ct := range w.Content {
		if ct == "" || len(ct) > MaxRefBytes {
			return Storage{}, fmt.Errorf("storage %s: invalid content type", w.ID)
		}
		for i := 0; i < len(ct); i++ {
			ch := ct[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
				return Storage{}, fmt.Errorf("storage %s: invalid content type %q", w.ID, ct)
			}
		}
		content = append(content, ct)
	}
	if w.Active == nil || (*w.Active != 0 && *w.Active != 1) {
		return Storage{}, fmt.Errorf("storage %s: invalid active flag", w.ID)
	}
	if w.Shared == nil || (*w.Shared != 0 && *w.Shared != 1) {
		return Storage{}, fmt.Errorf("storage %s: invalid shared flag", w.ID)
	}
	st := Storage{
		ID:        w.ID,
		Type:      w.Type,
		Format:    w.Format,
		Content:   content,
		Active:    *w.Active == 1,
		Shared:    *w.Shared == 1,
		Snapshots: SnapshotCapability(w.Type, w.Format),
	}
	if w.Space != nil {
		if w.Space.Used == nil || w.Space.Total == nil {
			return Storage{}, fmt.Errorf("storage %s: incomplete space object", w.ID)
		}
		st.TotalBytes = *w.Space.Total
		st.UsedBytes = *w.Space.Used
		st.CapacityKnown = true
	}
	return st, nil
}

// SnapshotCapability derives whether guest snapshots are supported on a
// storage type and volume format (ADR 0006: capabilities are yes/no/unknown
// hints, never guarantees).
//
//   - zfspool, lvmthin, rbd: yes
//   - lvm (thick), cephfs: no
//   - dir: yes only for qcow2 volumes, no for raw (the default)
//   - anything else: unknown
func SnapshotCapability(storageType, volumeFormat string) TriState {
	switch storageType {
	case "zfspool", "lvmthin", "rbd":
		return TriYes
	case "lvm", "cephfs":
		return TriNo
	case "dir":
		if volumeFormat == "qcow2" {
			return TriYes
		}
		return TriNo
	default:
		return TriUnknown
	}
}

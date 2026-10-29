// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Snapshot is one guest snapshot observation. The description text is
// dropped (ADR 0006: descriptions are not spooled); only its byte length
// is kept.
type Snapshot struct {
	// Name is the snapshot name, unique per guest.
	Name string
	// Parent is the parent snapshot name ("" for the first snapshot).
	Parent string
	// SnapTimeUnix is the snapshot time in Unix seconds.
	SnapTimeUnix int64
	// HasVMState reports whether the snapshot includes VM state (RAM).
	HasVMState bool
	// DescriptionBytes is the byte length of the (dropped) description.
	DescriptionBytes int
}

// SnapshotList is a guest's snapshot inventory.
type SnapshotList struct {
	// Snapshots holds the parsed snapshots, at most MaxSnapshotsPerGuest.
	Snapshots []Snapshot
	// Complete is false when the response exceeded the object limit and
	// Snapshots holds only the first MaxSnapshotsPerGuest entries.
	Complete bool
}

// snapshotWire is the PVE 8/9 response shape of
// /nodes/{node}/{qemu|lxc}/{vmid}/snapshot. Unknown fields are dropped on
// decode.
type snapshotWire struct {
	Name         string          `json:"name"`
	Parent       string          `json:"parent"`
	SnapTime     json.RawMessage `json:"snaptime"`
	SnapTimeUnix *int64          `json:"snaptime_unix"`
	VMState      *int            `json:"vmstate"`
	Description  string          `json:"description"`
}

// ListSnapshots reads /nodes/{node}/{guestKind}/{vmid}/snapshot for a
// QEMU guest or container. A permission-denied or other read failure
// returns ErrUnavailable; a guest without snapshots is an empty, complete
// result.
func (c *Client) ListSnapshots(ctx context.Context, node, guestKind string, vmid int64) (SnapshotList, error) {
	if err := validNodeName(node); err != nil {
		return SnapshotList{}, err
	}
	if err := validGuestKind(guestKind); err != nil {
		return SnapshotList{}, err
	}
	if err := validVMID(vmid); err != nil {
		return SnapshotList{}, err
	}
	path := fmt.Sprintf("/nodes/%s/%s/%d/snapshot", node, guestKind, vmid)
	wire := recordPage[snapshotWire]{
		limit:   MaxSnapshotsPerGuest,
		include: func(w snapshotWire) bool { return w.Name != "current" },
	}
	if err := c.get(ctx, path, &wire); err != nil {
		return SnapshotList{}, err
	}
	snapshots := make([]Snapshot, 0, len(wire.records))
	seen := make(map[string]bool, len(wire.records))
	for _, w := range wire.records {
		s, err := snapshotFromWire(w)
		if err != nil {
			return SnapshotList{}, schemaErr(path)
		}
		if seen[s.Name] {
			return SnapshotList{}, schemaErr(path)
		}
		seen[s.Name] = true
		snapshots = append(snapshots, s)
	}
	return SnapshotList{Snapshots: snapshots, Complete: wire.complete}, nil
}

// snapshotFromWire validates one wire record.
func snapshotFromWire(w snapshotWire) (Snapshot, error) {
	if err := validSnapshotName(w.Name); err != nil {
		return Snapshot{}, err
	}
	if w.Parent != "" {
		if err := validSnapshotName(w.Parent); err != nil {
			return Snapshot{}, err
		}
	}
	var snapTime int64
	if w.SnapTimeUnix != nil {
		if *w.SnapTimeUnix < 0 || *w.SnapTimeUnix > MaxSnapTimeUnix {
			return Snapshot{}, fmt.Errorf("snapshot %s: snaptime out of range", w.Name)
		}
		snapTime = *w.SnapTimeUnix
	} else if len(w.SnapTime) > 0 && string(w.SnapTime) != "null" {
		if w.SnapTime[0] == '"' {
			// Retain compatibility with older RFC3339 observations.
			var text string
			if err := json.Unmarshal(w.SnapTime, &text); err != nil {
				return Snapshot{}, fmt.Errorf("snapshot %s: bad snaptime", w.Name)
			}
			t, err := time.Parse(time.RFC3339, text)
			if err != nil {
				return Snapshot{}, fmt.Errorf("snapshot %s: bad snaptime", w.Name)
			}
			snapTime = t.Unix()
		} else if err := json.Unmarshal(w.SnapTime, &snapTime); err != nil {
			return Snapshot{}, fmt.Errorf("snapshot %s: bad snaptime", w.Name)
		}
		if snapTime < 0 || snapTime > MaxSnapTimeUnix {
			return Snapshot{}, fmt.Errorf("snapshot %s: snaptime out of range", w.Name)
		}
	} else {
		return Snapshot{}, fmt.Errorf("snapshot %s: missing snaptime", w.Name)
	}
	if len(w.SnapTime) > MaxTextFieldBytes {
		return Snapshot{}, fmt.Errorf("snapshot %s: snaptime too long", w.Name)
	}
	if w.VMState != nil && *w.VMState != 0 && *w.VMState != 1 {
		return Snapshot{}, fmt.Errorf("snapshot %s: invalid vmstate flag", w.Name)
	}
	return Snapshot{
		Name:             w.Name,
		Parent:           w.Parent,
		SnapTimeUnix:     snapTime,
		HasVMState:       w.VMState != nil && *w.VMState == 1,
		DescriptionBytes: len(w.Description),
	}, nil
}

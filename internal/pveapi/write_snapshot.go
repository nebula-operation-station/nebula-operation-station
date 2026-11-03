// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// Snapshot write limits, named next to the code that enforces them.
const (
	// MaxSnapshotNameLen bounds a snapshot name we create or reference
	// (ADR 0006 P2-01: PVE rule, at most 40).
	MaxSnapshotNameLen = 40
	// MaxSnapshotDescriptionChars bounds a snapshot description (ADR 0006
	// P2-01: at most 200 chars, no control characters).
	MaxSnapshotDescriptionChars = 200
)

// validWriteSnapshotName reports whether name is a snapshot name we may send
// to PVE (ADR 0006 P2-01): it must start with a letter, be at most
// MaxSnapshotNameLen bytes of [A-Za-z0-9_-], and never be "current" (PVE's
// reserved pointer to the latest snapshot). It is the write-path counterpart
// of the read-side validSnapshotName (client.go), which is deliberately
// looser because it only bounds untrusted PVE-returned names.
func validWriteSnapshotName(name string) bool {
	if name == "" || len(name) > MaxSnapshotNameLen || name == "current" {
		return false
	}
	first := name[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

// validSnapshotDescription reports whether desc is a snapshot description we
// may send (ADR 0006 P2-01): at most MaxSnapshotDescriptionChars characters
// and no control characters.
func validSnapshotDescription(desc string) bool {
	if utf8.RuneCountInString(desc) > MaxSnapshotDescriptionChars {
		return false
	}
	for _, r := range desc {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// SnapshotRequest creates a guest snapshot
// (POST /nodes/{node}/{kind}/{vmid}/snapshot).
type SnapshotRequest struct {
	// Kind is the guest family (QEMU or LXC).
	Kind GuestKind
	// Node is the node holding the guest.
	Node string
	// VMID is the guest.
	VMID int64
	// Name is the exact snapshot name (see validWriteSnapshotName).
	Name string
	// VMState requests a memory (RAM) snapshot. It is QEMU-only: with an LXC
	// container it is an error. For QEMU the choice is always sent explicitly
	// as vmstate=1/0.
	VMState bool
	// Description is an optional free-text note (see validSnapshotDescription).
	Description string
}

// CreateSnapshot creates a guest snapshot and returns the UPID of the
// snapshot task (qmsnapshot for QEMU, vzsnapshot for LXC).
func (w *Writer) CreateSnapshot(ctx context.Context, r SnapshotRequest) (string, error) {
	const op = "snapshot-create"
	path, err := guestKindPath(op, r.Kind, r.Node, r.VMID)
	if err != nil {
		return "", err
	}
	if !validWriteSnapshotName(r.Name) {
		return "", invalid(op, "name")
	}
	if !validSnapshotDescription(r.Description) {
		return "", invalid(op, "description")
	}
	wantType := "qmsnapshot"
	if r.Kind == GuestLXC {
		if r.VMState {
			return "", invalid(op, "vmstate")
		}
		wantType = "vzsnapshot"
	}
	form := url.Values{"snapname": {r.Name}}
	if r.Description != "" {
		form.Set("description", r.Description)
	}
	if r.Kind == GuestQEMU {
		if r.VMState {
			form.Set("vmstate", "1")
		} else {
			form.Set("vmstate", "0")
		}
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/snapshot", form: form},
		r.Node, wantType, strconv.FormatInt(r.VMID, 10))
}

// DeleteSnapshot deletes a guest snapshot by exact name and returns the UPID
// of the delete task (qmdelsnapshot for QEMU, vzdelsnapshot for LXC). It never
// sends force, so a snapshot in use is left to PVE to refuse.
func (w *Writer) DeleteSnapshot(ctx context.Context, kind GuestKind, node string, vmid int64, name string) (string, error) {
	const op = "snapshot-delete"
	path, err := guestKindPath(op, kind, node, vmid)
	if err != nil {
		return "", err
	}
	if !validWriteSnapshotName(name) {
		return "", invalid(op, "name")
	}
	wantType := "qmdelsnapshot"
	if kind == GuestLXC {
		wantType = "vzdelsnapshot"
	}
	// DELETE with no parameters; force is never offered.
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodDelete, path: path + "/snapshot/" + url.PathEscape(name), form: url.Values{}},
		node, wantType, strconv.FormatInt(vmid, 10))
}

// RollbackSnapshot rolls a guest back to a snapshot by exact name and returns
// the UPID of the rollback task (qmrollback for QEMU, vzrollback for LXC). The
// start flag is always sent explicitly (start=1/0) so the post-rollback power
// state is never left to a default.
func (w *Writer) RollbackSnapshot(ctx context.Context, kind GuestKind, node string, vmid int64, name string, start bool) (string, error) {
	const op = "snapshot-rollback"
	path, err := guestKindPath(op, kind, node, vmid)
	if err != nil {
		return "", err
	}
	if !validWriteSnapshotName(name) {
		return "", invalid(op, "name")
	}
	wantType := "qmrollback"
	if kind == GuestLXC {
		wantType = "vzrollback"
	}
	startVal := "0"
	if start {
		startVal = "1"
	}
	form := url.Values{"start": {startVal}}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/snapshot/" + url.PathEscape(name) + "/rollback", form: form},
		node, wantType, strconv.FormatInt(vmid, 10))
}

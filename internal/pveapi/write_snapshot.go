// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"fmt"
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
// may send (ADR 0006 P2-01): valid UTF-8, at most MaxSnapshotDescriptionChars
// characters (runes, not bytes), no control characters (Cc) and no format
// characters (Cf, e.g. bidi overrides such as U+202E or zero-width marks)
// and no line or paragraph separators (U+2028, U+2029), since the
// description is later shown in the UI.
func validSnapshotDescription(desc string) bool {
	if !utf8.ValidString(desc) || utf8.RuneCountInString(desc) > MaxSnapshotDescriptionChars {
		return false
	}
	for _, r := range desc {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			unicode.In(r, unicode.Zl, unicode.Zp) {
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

// ErrSnapshotNotFound reports that the exact snapshot named for a rollback
// is not in the guest's snapshot list.
var ErrSnapshotNotFound = errors.New("pveapi: snapshot not found")

// SnapshotRollbackPlan is the checked input of RollbackSnapshot. It is built
// only by Client.PlanSnapshotRollback, which reads the snapshot's RAM flag
// with the read token (ADR 0006: prechecks use the read token) so the
// rollback's power-state side effect is known before anything is sent. All
// fields are unexported, so a plan cannot be retargeted (another snapshot,
// guest or start flag) after planning; a zero plan is refused by
// RollbackSnapshot.
type SnapshotRollbackPlan struct {
	kind       GuestKind
	node       string
	vmid       int64
	name       string
	start      bool
	hasVMState bool
	checked    bool // set only by PlanSnapshotRollback
}

// Kind is the guest family (QEMU or LXC).
func (p SnapshotRollbackPlan) Kind() GuestKind { return p.kind }

// Node is the node holding the guest.
func (p SnapshotRollbackPlan) Node() string { return p.node }

// VMID is the guest.
func (p SnapshotRollbackPlan) VMID() int64 { return p.vmid }

// Name is the exact snapshot name.
func (p SnapshotRollbackPlan) Name() string { return p.name }

// Start is the requested start flag, always sent explicitly (start=1/0).
func (p SnapshotRollbackPlan) Start() bool { return p.start }

// HasVMState reports that the snapshot includes RAM (vmstate). Only a QEMU
// snapshot can include RAM.
func (p SnapshotRollbackPlan) HasVMState() bool { return p.hasVMState }

// GuestRunsAfter reports whether the guest will be running after a
// successful rollback. It is true when Start is set, and also for a QEMU
// snapshot with RAM: PVE resumes such a guest from the saved RAM regardless
// of start, so start=0 is not honoured there. Callers that present the
// rollback for approval must show this side effect.
func (p SnapshotRollbackPlan) GuestRunsAfter() bool { return p.start || p.hasVMState }

// PlanSnapshotRollback checks a rollback before it is dispatched: it
// validates the arguments, reads the guest's snapshot list with the read
// token and finds the exact snapshot to learn whether it includes RAM. A
// missing snapshot returns ErrSnapshotNotFound; a read failure returns
// ErrUnavailable. Nothing is mutated.
func (c *Client) PlanSnapshotRollback(ctx context.Context, kind GuestKind, node string, vmid int64, name string, start bool) (SnapshotRollbackPlan, error) {
	const op = "snapshot-rollback-plan"
	if _, err := guestKindPath(op, kind, node, vmid); err != nil {
		return SnapshotRollbackPlan{}, err
	}
	if !validWriteSnapshotName(name) {
		return SnapshotRollbackPlan{}, invalid(op, "name")
	}
	list, err := c.ListSnapshots(ctx, node, string(kind), vmid)
	if err != nil {
		return SnapshotRollbackPlan{}, err
	}
	for _, s := range list.Snapshots {
		if s.Name != name {
			continue
		}
		if s.HasVMState && kind != GuestQEMU {
			// PVE has no RAM snapshots for containers; a flag here is
			// a response we do not understand.
			return SnapshotRollbackPlan{}, schemaErr(fmt.Sprintf("/nodes/%s/%s/%d/snapshot", node, kind, vmid))
		}
		return SnapshotRollbackPlan{
			kind: kind, node: node, vmid: vmid, name: name, start: start,
			hasVMState: s.HasVMState, checked: true,
		}, nil
	}
	return SnapshotRollbackPlan{}, fmt.Errorf("%w: %s", ErrSnapshotNotFound, name)
}

// RollbackResult is the outcome of dispatching a rollback.
type RollbackResult struct {
	// UPID is the rollback task (qmrollback for QEMU, vzrollback for LXC).
	UPID string
	// HasVMState and GuestRunsAfter repeat the plan's side effects, so the
	// result records them next to the task.
	HasVMState bool
	// GuestRunsAfter reports whether the guest will run after the rollback
	// (see SnapshotRollbackPlan.GuestRunsAfter).
	GuestRunsAfter bool
}

// RollbackSnapshot rolls a guest back to a snapshot by exact name, using a
// plan from Client.PlanSnapshotRollback, and returns the UPID of the rollback
// task with the plan's side effects. The start flag is always sent explicitly
// (start=1/0). For a QEMU snapshot that includes RAM, PVE starts (resumes)
// the guest even with start=0; the plan and result report this as
// GuestRunsAfter instead of hiding it.
func (w *Writer) RollbackSnapshot(ctx context.Context, plan SnapshotRollbackPlan) (RollbackResult, error) {
	const op = "snapshot-rollback"
	if !plan.checked {
		return RollbackResult{}, invalid(op, "plan")
	}
	path, err := guestKindPath(op, plan.kind, plan.node, plan.vmid)
	if err != nil {
		return RollbackResult{}, err
	}
	if !validWriteSnapshotName(plan.name) {
		return RollbackResult{}, invalid(op, "name")
	}
	wantType := "qmrollback"
	if plan.kind == GuestLXC {
		wantType = "vzrollback"
	}
	startVal := "0"
	if plan.start {
		startVal = "1"
	}
	form := url.Values{"start": {startVal}}
	upid, err := w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/snapshot/" + url.PathEscape(plan.name) + "/rollback", form: form},
		plan.node, wantType, strconv.FormatInt(plan.vmid, 10))
	if err != nil {
		return RollbackResult{}, err
	}
	return RollbackResult{UPID: upid, HasVMState: plan.hasVMState, GuestRunsAfter: plan.GuestRunsAfter()}, nil
}

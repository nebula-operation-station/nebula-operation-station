// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// UPIDs returned by the fake PVE server for the snapshot-operation tests. The
// task ID is the VMID (120 QEMU, 200 LXC) and the type must match the
// operation and guest kind, or dispatch rejects the response.
const (
	upidQSnapCreate   = "UPID:pve1:00001234:00ABCDEF:6900A000:qmsnapshot:120:nos@pve!action:"
	upidVSnapCreate   = "UPID:pve1:00001234:00ABCDEF:6900A000:vzsnapshot:200:nos@pve!action:"
	upidQSnapDelete   = "UPID:pve1:00001234:00ABCDEF:6900A000:qmdelsnapshot:120:nos@pve!action:"
	upidVSnapDelete   = "UPID:pve1:00001234:00ABCDEF:6900A000:vzdelsnapshot:200:nos@pve!action:"
	upidQSnapRollback = "UPID:pve1:00001234:00ABCDEF:6900A000:qmrollback:120:nos@pve!action:"
	upidVSnapRollback = "UPID:pve1:00001234:00ABCDEF:6900A000:vzrollback:200:nos@pve!action:"
)

// TestCreateSnapshotSendsExactRequest pins the exact request for create across
// both guest kinds: POST .../snapshot with snapname, the explicit RAM choice
// (vmstate=1/0) for QEMU only, and the optional description.
func TestCreateSnapshotSendsExactRequest(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     GuestKind
		vmid     int64
		vmstate  bool
		desc     string
		upid     string
		path     string
		wantForm url.Values
	}{
		{"qemu vmstate", GuestQEMU, 120, true, "", upidQSnapCreate,
			"/api2/json/nodes/pve1/qemu/120/snapshot",
			url.Values{"snapname": {"snap1"}, "vmstate": {"1"}}},
		{"qemu no vmstate", GuestQEMU, 120, false, "", upidQSnapCreate,
			"/api2/json/nodes/pve1/qemu/120/snapshot",
			url.Values{"snapname": {"snap1"}, "vmstate": {"0"}}},
		{"lxc", GuestLXC, 200, false, "", upidVSnapCreate,
			"/api2/json/nodes/pve1/lxc/200/snapshot",
			url.Values{"snapname": {"snap1"}}},
		{"qemu description", GuestQEMU, 120, true, "before update", upidQSnapCreate,
			"/api2/json/nodes/pve1/qemu/120/snapshot",
			url.Values{"snapname": {"snap1"}, "vmstate": {"1"}, "description": {"before update"}}},
		{"lxc description", GuestLXC, 200, false, "note", upidVSnapCreate,
			"/api2/json/nodes/pve1/lxc/200/snapshot",
			url.Values{"snapname": {"snap1"}, "description": {"note"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(tc.upid)}
			w := newTestWriter(t, f)
			got, err := w.CreateSnapshot(context.Background(), SnapshotRequest{
				Kind: tc.kind, Node: "pve1", VMID: tc.vmid,
				Name: "snap1", VMState: tc.vmstate, Description: tc.desc,
			})
			if err != nil || got != tc.upid {
				t.Fatalf("CreateSnapshot = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodPost || r.path != tc.path {
				t.Errorf("request = %s %s, want POST %s", r.method, r.path, tc.path)
			}
			if r.auth != testToken || r.ctype != "application/x-www-form-urlencoded" {
				t.Errorf("headers auth=%q ctype=%q", r.auth, r.ctype)
			}
			if r.form.Encode() != tc.wantForm.Encode() {
				t.Errorf("form = %v, want %v", r.form, tc.wantForm)
			}
		})
	}
}

// TestCreateSnapshotRefusesVMStateWithLXC pins ADR 0006 P2-01: a RAM snapshot
// is QEMU-only, so VMState with an LXC container is rejected before anything
// is sent.
func TestCreateSnapshotRefusesVMStateWithLXC(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidVSnapCreate)}
	w := newTestWriter(t, f)
	_, err := w.CreateSnapshot(context.Background(), SnapshotRequest{
		Kind: GuestLXC, Node: "pve1", VMID: 200, Name: "snap1", VMState: true,
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
	if n := f.count(); n != 0 {
		t.Errorf("requests = %d, want 0", n)
	}
}

// invalidSnapshotNames is the write-path name rule (ADR 0006 P2-01): starts
// with a letter, [A-Za-z0-9_-], max 40, never "current".
var invalidSnapshotNames = []struct {
	name  string
	label string
}{
	{"", "empty"},
	{"current", "reserved"},
	{strings.Repeat("a", 41), "too-long"},
	{"1abc", "leading-digit"},
	{"a/b", "slash"},
	{"sna p", "space"},
	{"sna.p", "dot"},
	{"-abc", "leading-dash"},
	{"_abc", "leading-underscore"},
	{"é", "unicode"},
}

// TestSnapshotRejectsInvalidNames pins that all three snapshot operations
// reject an invalid exact name before sending anything.
func TestSnapshotRejectsInvalidNames(t *testing.T) {
	for _, op := range []struct {
		name string
		call func(*Writer, string) error
	}{
		{"create", func(w *Writer, name string) error {
			_, err := w.CreateSnapshot(context.Background(), SnapshotRequest{
				Kind: GuestQEMU, Node: "pve1", VMID: 120, Name: name,
			})
			return err
		}},
		{"delete", func(w *Writer, name string) error {
			_, err := w.DeleteSnapshot(context.Background(), GuestQEMU, "pve1", 120, name)
			return err
		}},
		{"rollback", func(w *Writer, name string) error {
			_, err := w.RollbackSnapshot(context.Background(), GuestQEMU, "pve1", 120, name, false)
			return err
		}},
	} {
		for _, tc := range invalidSnapshotNames {
			t.Run(op.name+"/"+tc.label, func(t *testing.T) {
				f := &fakeWriteServer{body: upidBody(upidQSnapCreate)}
				w := newTestWriter(t, f)
				err := op.call(w, tc.name)
				if !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("err = %v, want ErrInvalidArgument", err)
				}
				if n := f.count(); n != 0 {
					t.Errorf("requests = %d, want 0", n)
				}
			})
		}
	}
}

// TestDeleteSnapshotSendsExactRequest pins the exact request for delete across
// both guest kinds: DELETE .../snapshot/{name} with no parameters (force is
// never offered).
func TestDeleteSnapshotSendsExactRequest(t *testing.T) {
	for _, tc := range []struct {
		kind GuestKind
		vmid int64
		upid string
		path string
	}{
		{GuestQEMU, 120, upidQSnapDelete, "/api2/json/nodes/pve1/qemu/120/snapshot/snap1"},
		{GuestLXC, 200, upidVSnapDelete, "/api2/json/nodes/pve1/lxc/200/snapshot/snap1"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(tc.upid)}
			w := newTestWriter(t, f)
			got, err := w.DeleteSnapshot(context.Background(), tc.kind, "pve1", tc.vmid, "snap1")
			if err != nil || got != tc.upid {
				t.Fatalf("DeleteSnapshot = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodDelete || r.path != tc.path {
				t.Errorf("request = %s %s, want DELETE %s", r.method, r.path, tc.path)
			}
			if r.form.Get("force") != "" {
				t.Errorf("form sent force=%q, want none", r.form.Get("force"))
			}
			if len(r.form) != 0 {
				t.Errorf("form = %v, want empty", r.form)
			}
		})
	}
}

// TestRollbackSnapshotSendsExactRequest pins the exact request for rollback
// across both guest kinds: POST .../snapshot/{name}/rollback with the start
// flag always sent explicitly (start=1/0).
func TestRollbackSnapshotSendsExactRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  GuestKind
		vmid  int64
		start bool
		upid  string
		path  string
	}{
		{"qemu start", GuestQEMU, 120, true, upidQSnapRollback,
			"/api2/json/nodes/pve1/qemu/120/snapshot/snap1/rollback"},
		{"qemu nostart", GuestQEMU, 120, false, upidQSnapRollback,
			"/api2/json/nodes/pve1/qemu/120/snapshot/snap1/rollback"},
		{"lxc start", GuestLXC, 200, true, upidVSnapRollback,
			"/api2/json/nodes/pve1/lxc/200/snapshot/snap1/rollback"},
		{"lxc nostart", GuestLXC, 200, false, upidVSnapRollback,
			"/api2/json/nodes/pve1/lxc/200/snapshot/snap1/rollback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(tc.upid)}
			w := newTestWriter(t, f)
			got, err := w.RollbackSnapshot(context.Background(), tc.kind, "pve1", tc.vmid, "snap1", tc.start)
			if err != nil || got != tc.upid {
				t.Fatalf("RollbackSnapshot = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodPost || r.path != tc.path {
				t.Errorf("request = %s %s, want POST %s", r.method, r.path, tc.path)
			}
			wantStart := "0"
			if tc.start {
				wantStart = "1"
			}
			if r.form.Get("start") != wantStart {
				t.Errorf("form start = %q, want %q", r.form.Get("start"), wantStart)
			}
			if len(r.form) != 1 {
				t.Errorf("form = %v, want only start", r.form)
			}
		})
	}
}

// TestSnapshotRejectsWrongUPIDType pins that a snapshot operation rejects a
// response whose UPID task type does not match the operation (ADR 0006 P2-01).
func TestSnapshotRejectsWrongUPIDType(t *testing.T) {
	// upidStart is a qmstart UPID (ID 120); the type is wrong for all three.
	for _, op := range []struct {
		name string
		call func(*Writer) error
	}{
		{"create", func(w *Writer) error {
			_, err := w.CreateSnapshot(context.Background(), SnapshotRequest{
				Kind: GuestQEMU, Node: "pve1", VMID: 120, Name: "snap1",
			})
			return err
		}},
		{"delete", func(w *Writer) error {
			_, err := w.DeleteSnapshot(context.Background(), GuestQEMU, "pve1", 120, "snap1")
			return err
		}},
		{"rollback", func(w *Writer) error {
			_, err := w.RollbackSnapshot(context.Background(), GuestQEMU, "pve1", 120, "snap1", false)
			return err
		}},
	} {
		t.Run(op.name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidStart)}
			w := newTestWriter(t, f)
			err := op.call(w)
			var we *WriteError
			if !errors.As(err, &we) || we.Reason != ReasonSchema {
				t.Fatalf("err = %v, want schema", err)
			}
		})
	}
}

// TestValidWriteSnapshotName pins the write-path name rule directly.
func TestValidWriteSnapshotName(t *testing.T) {
	for s, want := range map[string]bool{
		"a":                     true,
		"A":                     true,
		"snap1":                 true,
		"a-b_c9":                true,
		strings.Repeat("a", 40): true,
		"":                      false,
		"current":               false,
		strings.Repeat("a", 41): false,
		"1abc":                  false,
		"a/b":                   false,
		"sna p":                 false,
		"sna.p":                 false,
		"-abc":                  false,
		"_abc":                  false,
		"é":                     false,
	} {
		if got := validWriteSnapshotName(s); got != want {
			t.Errorf("validWriteSnapshotName(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestCreateSnapshotRejectsBadDescription pins the description rule (ADR 0006
// P2-01): at most 200 chars and no control characters, enforced before
// anything is sent.
func TestCreateSnapshotRejectsBadDescription(t *testing.T) {
	for _, desc := range []string{
		strings.Repeat("a", 201), // over the 200-char limit
		"bad\nnewline",           // control character (newline)
		"bad\ttab",               // control character (tab)
		"bad\x00nul",             // control character (NUL)
	} {
		f := &fakeWriteServer{body: upidBody(upidQSnapCreate)}
		w := newTestWriter(t, f)
		_, err := w.CreateSnapshot(context.Background(), SnapshotRequest{
			Kind: GuestQEMU, Node: "pve1", VMID: 120, Name: "snap1", Description: desc,
		})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("desc %q: err = %v, want ErrInvalidArgument", desc, err)
		}
		if n := f.count(); n != 0 {
			t.Errorf("desc %q: requests = %d, want 0", desc, n)
		}
	}
	// Boundary: exactly 200 chars is accepted.
	f := &fakeWriteServer{body: upidBody(upidQSnapCreate)}
	w := newTestWriter(t, f)
	if _, err := w.CreateSnapshot(context.Background(), SnapshotRequest{
		Kind: GuestQEMU, Node: "pve1", VMID: 120, Name: "snap1",
		Description: strings.Repeat("a", 200),
	}); err != nil {
		t.Fatalf("200-char description: %v", err)
	}
}

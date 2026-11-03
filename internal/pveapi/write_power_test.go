// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

// UPIDs returned by the fake PVE server for the power-operation tests.
const (
	upidQShutdown = "UPID:pve1:00001234:00ABCDEF:6900A000:qmshutdown:120:nos@pve!action:"
	upidQReboot   = "UPID:pve1:00001234:00ABCDEF:6900A000:qmreboot:120:nos@pve!action:"
	upidVShutdown = "UPID:pve1:00001234:00ABCDEF:6900A000:vzshutdown:120:nos@pve!action:"
	upidVReboot   = "UPID:pve1:00001234:00ABCDEF:6900A000:vzreboot:120:nos@pve!action:"
)

// TestShutdownGuestSendsGracefulShutdown pins the exact request for both
// guest kinds: POST status/shutdown with the bounded timeout and forceStop=0
// (ADR 0006 P2-01: no automatic force-stop fallback).
func TestShutdownGuestSendsGracefulShutdown(t *testing.T) {
	for _, tc := range []struct {
		kind GuestKind
		upid string
		path string
	}{
		{GuestQEMU, upidQShutdown, "/api2/json/nodes/pve1/qemu/120/status/shutdown"},
		{GuestLXC, upidVShutdown, "/api2/json/nodes/pve1/lxc/120/status/shutdown"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(tc.upid)}
			w := newTestWriter(t, f)
			got, err := w.ShutdownGuest(context.Background(), tc.kind, "pve1", 120, 30)
			if err != nil || got != tc.upid {
				t.Fatalf("ShutdownGuest = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodPost || r.path != tc.path {
				t.Errorf("request = %s %s", r.method, r.path)
			}
			if r.auth != testToken || r.ctype != "application/x-www-form-urlencoded" {
				t.Errorf("headers auth=%q ctype=%q", r.auth, r.ctype)
			}
			want := url.Values{"timeout": {"30"}, "forceStop": {"0"}}
			if r.form.Encode() != want.Encode() {
				t.Errorf("form = %v, want %v", r.form, want)
			}
		})
	}
}

// TestRebootGuestSendsTimeout pins the exact request for both guest kinds:
// POST status/reboot with only the bounded timeout (no force parameters).
func TestRebootGuestSendsTimeout(t *testing.T) {
	for _, tc := range []struct {
		kind GuestKind
		upid string
		path string
	}{
		{GuestQEMU, upidQReboot, "/api2/json/nodes/pve1/qemu/120/status/reboot"},
		{GuestLXC, upidVReboot, "/api2/json/nodes/pve1/lxc/120/status/reboot"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(tc.upid)}
			w := newTestWriter(t, f)
			got, err := w.RebootGuest(context.Background(), tc.kind, "pve1", 120, 30)
			if err != nil || got != tc.upid {
				t.Fatalf("RebootGuest = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodPost || r.path != tc.path {
				t.Errorf("request = %s %s", r.method, r.path)
			}
			want := url.Values{"timeout": {"30"}}
			if len(r.form) != 1 || r.form.Encode() != want.Encode() {
				t.Errorf("form = %v, want %v", r.form, want)
			}
		})
	}
}

// TestPowerGuestTimeoutBoundsAndForceStop checks that the timeout range ends
// are accepted and that shutdown always sends forceStop=0.
func TestPowerGuestTimeoutBoundsAndForceStop(t *testing.T) {
	for _, timeout := range []int{MinPowerTimeoutSec, MaxPowerTimeoutSec} {
		t.Run("shutdown "+strconv.Itoa(timeout), func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidQShutdown)}
			w := newTestWriter(t, f)
			if _, err := w.ShutdownGuest(context.Background(), GuestQEMU, "pve1", 120, timeout); err != nil {
				t.Fatalf("ShutdownGuest: %v", err)
			}
			r := f.only(t)
			if r.form.Get("timeout") != strconv.Itoa(timeout) || r.form.Get("forceStop") != "0" {
				t.Errorf("form = %v, want timeout=%d forceStop=0", r.form, timeout)
			}
		})
	}
}

// TestPowerGuestRejectsInvalidArguments checks that an invalid kind, node,
// VMID or timeout is rejected before anything is sent.
func TestPowerGuestRejectsInvalidArguments(t *testing.T) {
	for _, op := range []struct {
		name string
		call func(*Writer, GuestKind, string, int64, int) error
	}{
		{"shutdown", func(w *Writer, kind GuestKind, node string, vmid int64, timeout int) error {
			_, err := w.ShutdownGuest(context.Background(), kind, node, vmid, timeout)
			return err
		}},
		{"reboot", func(w *Writer, kind GuestKind, node string, vmid int64, timeout int) error {
			_, err := w.RebootGuest(context.Background(), kind, node, vmid, timeout)
			return err
		}},
	} {
		for name, tc := range map[string]struct {
			kind    GuestKind
			node    string
			vmid    int64
			timeout int
		}{
			"kind empty":     {kind: "", node: "pve1", vmid: 120, timeout: 30},
			"kind unknown":   {kind: "kvm", node: "pve1", vmid: 120, timeout: 30},
			"kind uppercase": {kind: "QEMU", node: "pve1", vmid: 120, timeout: 30},
			"node empty":     {kind: GuestQEMU, node: "", vmid: 120, timeout: 30},
			"node path":      {kind: GuestQEMU, node: "../pve1", vmid: 120, timeout: 30},
			"node slash":     {kind: GuestLXC, node: "pve1/x", vmid: 120, timeout: 30},
			"vmid low":       {kind: GuestQEMU, node: "pve1", vmid: MinVMID - 1, timeout: 30},
			"vmid high":      {kind: GuestLXC, node: "pve1", vmid: MaxVMID + 1, timeout: 30},
			"timeout zero":   {kind: GuestQEMU, node: "pve1", vmid: 120, timeout: 0},
			"timeout neg":    {kind: GuestQEMU, node: "pve1", vmid: 120, timeout: -5},
			"timeout above":  {kind: GuestLXC, node: "pve1", vmid: 120, timeout: MaxPowerTimeoutSec + 1},
		} {
			t.Run(op.name+"/"+name, func(t *testing.T) {
				f := &fakeWriteServer{body: upidBody(upidQShutdown)}
				w := newTestWriter(t, f)
				if err := op.call(w, tc.kind, tc.node, tc.vmid, tc.timeout); !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("err = %v, want ErrInvalidArgument", err)
				}
				if f.count() != 0 {
					t.Error("invalid request reached the server")
				}
			})
		}
	}
}

// TestPowerGuestRejectsMismatchedUPID checks that a UPID whose task type does
// not match the requested kind and operation is rejected (ADR 0006 P2-01:
// only the exact qm/vz shutdown/reboot task is accepted).
func TestPowerGuestRejectsMismatchedUPID(t *testing.T) {
	cases := []struct {
		name string
		body string
		call func(*Writer) error
	}{
		{"shutdown qemu gets lxc type", upidBody(upidVShutdown), func(w *Writer) error {
			_, err := w.ShutdownGuest(context.Background(), GuestQEMU, "pve1", 120, 30)
			return err
		}},
		{"shutdown lxc gets qemu type", upidBody(upidQShutdown), func(w *Writer) error {
			_, err := w.ShutdownGuest(context.Background(), GuestLXC, "pve1", 120, 30)
			return err
		}},
		{"reboot qemu gets lxc type", upidBody(upidVReboot), func(w *Writer) error {
			_, err := w.RebootGuest(context.Background(), GuestQEMU, "pve1", 120, 30)
			return err
		}},
		{"reboot lxc gets qemu type", upidBody(upidQReboot), func(w *Writer) error {
			_, err := w.RebootGuest(context.Background(), GuestLXC, "pve1", 120, 30)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{body: tc.body}
			w := newTestWriter(t, f)
			err := tc.call(w)
			var we *WriteError
			if !errors.As(err, &we) || we.Reason != ReasonSchema || !we.OutcomeUnknown() {
				t.Fatalf("err = %v, want schema error with unknown outcome", err)
			}
		})
	}
}

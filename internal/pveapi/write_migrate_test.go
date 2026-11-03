// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// UPIDs returned by the fake PVE server for the migration tests.
const (
	upidQMigrate  = "UPID:pve1:00001234:00ABCDEF:6900A000:qmigrate:120:nos@pve!action:"
	upidVZMigrate = "UPID:pve1:00001234:00ABCDEF:6900A000:vzmigrate:120:nos@pve!action:"
)

// TestMigrateGuestSendsQEMUMigrate pins the exact QEMU migration request:
// POST /nodes/{node}/qemu/{vmid}/migrate with target, online=1/0, and
// with-local-disks / targetstorage only when set (ADR 0006 P2-01).
func TestMigrateGuestSendsQEMUMigrate(t *testing.T) {
	cases := []struct {
		name string
		req  MigrateRequest
		want url.Values
	}{
		{
			name: "live",
			req:  MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true},
			want: url.Values{"target": {"pve2"}, "online": {"1"}},
		},
		{
			name: "stop and migrate",
			req:  MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: false},
			want: url.Values{"target": {"pve2"}, "online": {"0"}},
		},
		{
			name: "with local disks",
			req:  MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true, WithLocalDisks: true},
			want: url.Values{"target": {"pve2"}, "online": {"1"}, "with-local-disks": {"1"}},
		},
		{
			name: "with storage id",
			req:  MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true, TargetStorage: "local-lvm"},
			want: url.Values{"target": {"pve2"}, "online": {"1"}, "targetstorage": {"local-lvm"}},
		},
		{
			name: "with storage mapping",
			req:  MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: false, TargetStorage: "local:local-lvm,nfs1:ceph"},
			want: url.Values{"target": {"pve2"}, "online": {"0"}, "targetstorage": {"local:local-lvm,nfs1:ceph"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidQMigrate)}
			w := newTestWriter(t, f)
			got, err := w.MigrateGuest(context.Background(), tc.req)
			if err != nil || got != upidQMigrate {
				t.Fatalf("MigrateGuest = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/qemu/120/migrate" {
				t.Errorf("request = %s %s", r.method, r.path)
			}
			if r.auth != testToken || r.ctype != "application/x-www-form-urlencoded" {
				t.Errorf("headers auth=%q ctype=%q", r.auth, r.ctype)
			}
			if r.form.Encode() != tc.want.Encode() {
				t.Errorf("form = %v, want %v", r.form, tc.want)
			}
			if _, ok := r.form["force"]; ok {
				t.Error("force sent")
			}
			if _, ok := r.form["migration_network"]; ok {
				t.Error("migration_network sent")
			}
		})
	}
}

// TestMigrateGuestSendsLXCMigrate pins the exact LXC migration request:
// POST /nodes/{node}/lxc/{vmid}/migrate with target, restart=1/0, and timeout
// only for a restart migration (the shutdown timeout, pct(1)).
func TestMigrateGuestSendsLXCMigrate(t *testing.T) {
	cases := []struct {
		name string
		req  MigrateRequest
		want url.Values
	}{
		{
			name: "live",
			req:  MigrateRequest{Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: false},
			want: url.Values{"target": {"pve2"}, "restart": {"0"}},
		},
		{
			name: "restart",
			req:  MigrateRequest{Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: true, TimeoutSec: 120},
			want: url.Values{"target": {"pve2"}, "restart": {"1"}, "timeout": {"120"}},
		},
		{
			name: "restart with storage",
			req:  MigrateRequest{Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: true, TimeoutSec: 60, TargetStorage: "local"},
			want: url.Values{"target": {"pve2"}, "restart": {"1"}, "timeout": {"60"}, "target-storage": {"local"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidVZMigrate)}
			w := newTestWriter(t, f)
			got, err := w.MigrateGuest(context.Background(), tc.req)
			if err != nil || got != upidVZMigrate {
				t.Fatalf("MigrateGuest = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/lxc/120/migrate" {
				t.Errorf("request = %s %s", r.method, r.path)
			}
			if r.auth != testToken || r.ctype != "application/x-www-form-urlencoded" {
				t.Errorf("headers auth=%q ctype=%q", r.auth, r.ctype)
			}
			if r.form.Encode() != tc.want.Encode() {
				t.Errorf("form = %v, want %v", r.form, tc.want)
			}
			if _, ok := r.form["force"]; ok {
				t.Error("force sent")
			}
			if _, ok := r.form["migration_network"]; ok {
				t.Error("migration_network sent")
			}
		})
	}
}

// TestMigrateGuestTimeoutBounds checks that the LXC restart-migration timeout
// range ends (MinPowerTimeoutSec and MaxPowerTimeoutSec) are accepted and
// sent.
func TestMigrateGuestTimeoutBounds(t *testing.T) {
	for _, timeout := range []int{MinPowerTimeoutSec, MaxPowerTimeoutSec} {
		t.Run(strconv.Itoa(timeout), func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidVZMigrate)}
			w := newTestWriter(t, f)
			if _, err := w.MigrateGuest(context.Background(), MigrateRequest{Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: true, TimeoutSec: timeout}); err != nil {
				t.Fatalf("MigrateGuest: %v", err)
			}
			if got := f.only(t).form.Get("timeout"); got != strconv.Itoa(timeout) {
				t.Errorf("timeout = %q, want %d", got, timeout)
			}
		})
	}
}

// TestMigrateGuestRefusesSameNode pins that the source and destination nodes
// must differ (ADR 0006 P2-01: "exact source/destination nodes").
func TestMigrateGuestRefusesSameNode(t *testing.T) {
	for _, kind := range []GuestKind{GuestQEMU, GuestLXC} {
		t.Run(string(kind), func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidQMigrate)}
			w := newTestWriter(t, f)
			_, err := w.MigrateGuest(context.Background(), MigrateRequest{Kind: kind, Node: "pve1", VMID: 120, Target: "pve1"})
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

// TestMigrateGuestRejectsInvalidArguments checks that an invalid kind, node,
// VMID, or target, and a kind-inappropriate mode or timeout, are refused
// before anything is sent.
func TestMigrateGuestRejectsInvalidArguments(t *testing.T) {
	cases := map[string]MigrateRequest{
		"kind empty":                {Kind: "", Node: "pve1", VMID: 120, Target: "pve2", Online: true},
		"kind unknown":              {Kind: "kvm", Node: "pve1", VMID: 120, Target: "pve2", Online: true},
		"kind uppercase":            {Kind: "QEMU", Node: "pve1", VMID: 120, Target: "pve2", Online: true},
		"node empty":                {Kind: GuestQEMU, Node: "", VMID: 120, Target: "pve2", Online: true},
		"node path":                 {Kind: GuestQEMU, Node: "../pve1", VMID: 120, Target: "pve2", Online: true},
		"vmid low":                  {Kind: GuestQEMU, Node: "pve1", VMID: MinVMID - 1, Target: "pve2", Online: true},
		"vmid high":                 {Kind: GuestLXC, Node: "pve1", VMID: MaxVMID + 1, Target: "pve2", Restart: true, TimeoutSec: 60},
		"target empty":              {Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "", Online: true},
		"target path":               {Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "../pve2", Online: true},
		"target = node":             {Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve1", Online: true},
		"qemu restart":              {Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true, Restart: true},
		"qemu timeout":              {Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true, TimeoutSec: 60},
		"lxc online":                {Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Online: true},
		"lxc with local disks":      {Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", WithLocalDisks: true},
		"lxc restart no timeout":    {Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: true},
		"lxc restart timeout above": {Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: true, TimeoutSec: MaxPowerTimeoutSec + 1},
		"lxc live with timeout":     {Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: false, TimeoutSec: 60},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidQMigrate)}
			w := newTestWriter(t, f)
			if _, err := w.MigrateGuest(context.Background(), req); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

// TestMigrateGuestRejectsBadStorageMapping checks that an invalid targetstorage
// value is refused before anything is sent (ADR 0006 P2-01: "complete storage
// mapping").
func TestMigrateGuestRejectsBadStorageMapping(t *testing.T) {
	for name, storage := range map[string]string{
		"empty mapping pair":  "local:",
		"missing dst":         ":local",
		"triple colon":        "a:b:c",
		"comma without colon": "a,b",
		"trailing comma":      "a:b,",
		"leading comma":       ",a:b",
		"empty pair in list":  "a:b,,c:d",
		"space":               "a b:c",
		"slash":               "a/b:c",
		"too long":            strings.Repeat("a", MaxStorageTargetBytes+1),
		"too many pairs":      strings.Repeat("a:b,", MaxStorageMappingPairs) + "c:d",
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidQMigrate)}
			w := newTestWriter(t, f)
			_, err := w.MigrateGuest(context.Background(), MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true, TargetStorage: storage})
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

// TestMigrateGuestRejectsMismatchedUPID checks that a UPID whose task type
// does not match the requested kind is refused (ADR 0006 P2-01: only the
// exact qmigrate/vzmigrate task is accepted).
func TestMigrateGuestRejectsMismatchedUPID(t *testing.T) {
	cases := []struct {
		name string
		body string
		call func(*Writer) error
	}{
		{"qemu gets lxc type", upidBody(upidVZMigrate), func(w *Writer) error {
			_, err := w.MigrateGuest(context.Background(), MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true})
			return err
		}},
		{"lxc gets qemu type", upidBody(upidQMigrate), func(w *Writer) error {
			_, err := w.MigrateGuest(context.Background(), MigrateRequest{Kind: GuestLXC, Node: "pve1", VMID: 120, Target: "pve2", Restart: true, TimeoutSec: 60})
			return err
		}},
		{"qemu gets start type", upidBody(upidStart), func(w *Writer) error {
			_, err := w.MigrateGuest(context.Background(), MigrateRequest{Kind: GuestQEMU, Node: "pve1", VMID: 120, Target: "pve2", Online: true})
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

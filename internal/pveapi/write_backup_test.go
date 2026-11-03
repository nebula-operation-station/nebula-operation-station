// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// UPID returned by the fake PVE server for the backup tests. The task ID is
// the VMID (120) and the type must be vzdump, or dispatch rejects the
// response.
const upidVzdump = "UPID:pve1:00001234:00ABCDEF:6900A000:vzdump:120:nos@pve!action:"

// forbiddenBackupParams are the vzdump parameters that BackupNow must never
// send (ADR 0006 P2-01: no pruning/deletion flags, no extra targets or
// side channels).
var forbiddenBackupParams = []string{
	"all", "exclude", "prune-backups", "mailto", "script", "dumpdir", "stdout",
}

// TestBackupNowSendsExactRequest pins the exact request for BackupNow across
// modes, compressions and the optional bandwidth limit: POST
// /nodes/{node}/vzdump with a single vmid, the storage, the mode, the
// compression (zstd by default) and remove=0 always; no forbidden flag.
func TestBackupNowSendsExactRequest(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		bw       int
		compress string
		wantForm url.Values
	}{
		{"snapshot default", "snapshot", 0, "",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"snapshot"}, "compress": {"zstd"}, "remove": {"0"}}},
		{"suspend", "suspend", 0, "",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"suspend"}, "compress": {"zstd"}, "remove": {"0"}}},
		{"stop", "stop", 0, "",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"stop"}, "compress": {"zstd"}, "remove": {"0"}}},
		{"bwlimit", "snapshot", 50000, "",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"snapshot"}, "compress": {"zstd"}, "remove": {"0"}, "bwlimit": {"50000"}}},
		{"bwlimit one", "snapshot", 1, "",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"snapshot"}, "compress": {"zstd"}, "remove": {"0"}, "bwlimit": {"1"}}},
		{"bwlimit max", "snapshot", MaxBackupBandwidthKiB, "",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"snapshot"}, "compress": {"zstd"}, "remove": {"0"}, "bwlimit": {"10000000"}}},
		{"lzo", "snapshot", 0, "lzo",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"snapshot"}, "compress": {"lzo"}, "remove": {"0"}}},
		{"gzip", "snapshot", 0, "gzip",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"snapshot"}, "compress": {"gzip"}, "remove": {"0"}}},
		{"no compress", "snapshot", 0, "0",
			url.Values{"vmid": {"120"}, "storage": {"local"}, "mode": {"snapshot"}, "compress": {"0"}, "remove": {"0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidVzdump)}
			w := newTestWriter(t, f)
			got, err := w.BackupNow(context.Background(), BackupRequest{
				Node: "pve1", VMID: 120, Storage: "local",
				Mode: tc.mode, BandwidthKiB: tc.bw, Compress: tc.compress,
			})
			if err != nil || got != upidVzdump {
				t.Fatalf("BackupNow = %q, %v", got, err)
			}
			r := f.only(t)
			if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/vzdump" {
				t.Errorf("request = %s %s, want POST /api2/json/nodes/pve1/vzdump", r.method, r.path)
			}
			if r.auth != testToken || r.ctype != "application/x-www-form-urlencoded" {
				t.Errorf("headers auth=%q ctype=%q", r.auth, r.ctype)
			}
			if r.form.Encode() != tc.wantForm.Encode() {
				t.Errorf("form = %v, want %v", r.form, tc.wantForm)
			}
			if len(r.form["vmid"]) != 1 {
				t.Errorf("vmid count = %d, want exactly 1", len(r.form["vmid"]))
			}
			if r.form.Get("remove") != "0" {
				t.Errorf("remove = %q, want 0", r.form.Get("remove"))
			}
			for _, k := range forbiddenBackupParams {
				if v := r.form.Get(k); v != "" {
					t.Errorf("forbidden param %s = %q, want none", k, v)
				}
			}
			if r.query != "" {
				t.Errorf("query = %q, want none", r.query)
			}
		})
	}
}

// TestBackupNowRejectsInvalidArguments pins that BackupNow rejects an
// invalid argument before sending anything (ADR 0006 P2-01).
func TestBackupNowRejectsInvalidArguments(t *testing.T) {
	ok := BackupRequest{Node: "pve1", VMID: 120, Storage: "local", Mode: "snapshot"}
	cases := map[string]func(*BackupRequest){
		"node empty":     func(r *BackupRequest) { r.Node = "" },
		"node path":      func(r *BackupRequest) { r.Node = "../pve1" },
		"node slash":     func(r *BackupRequest) { r.Node = "pve1/x" },
		"vmid low":       func(r *BackupRequest) { r.VMID = 99 },
		"vmid zero":      func(r *BackupRequest) { r.VMID = 0 },
		"vmid high":      func(r *BackupRequest) { r.VMID = MaxVMID + 1 },
		"storage empty":  func(r *BackupRequest) { r.Storage = "" },
		"storage path":   func(r *BackupRequest) { r.Storage = "local/../x" },
		"storage space":  func(r *BackupRequest) { r.Storage = "local disk" },
		"mode empty":     func(r *BackupRequest) { r.Mode = "" },
		"mode unknown":   func(r *BackupRequest) { r.Mode = "paused" },
		"mode upper":     func(r *BackupRequest) { r.Mode = "SNAPSHOT" },
		"mode inject":    func(r *BackupRequest) { r.Mode = "stop,exclude=1" },
		"bw negative":    func(r *BackupRequest) { r.BandwidthKiB = -1 },
		"bw huge":        func(r *BackupRequest) { r.BandwidthKiB = MaxBackupBandwidthKiB + 1 },
		"compress other": func(r *BackupRequest) { r.Compress = "bzip2" },
		"compress upper": func(r *BackupRequest) { r.Compress = "ZSTD" },
		"compress 00":    func(r *BackupRequest) { r.Compress = "00" },
		"compress space": func(r *BackupRequest) { r.Compress = "zstd " },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidVzdump)}
			w := newTestWriter(t, f)
			r := ok
			mut(&r)
			_, err := w.BackupNow(context.Background(), r)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

// TestBackupNowRejectsWrongUPIDType pins that BackupNow rejects a response
// whose UPID task type is not vzdump (ADR 0006 P2-01).
func TestBackupNowRejectsWrongUPIDType(t *testing.T) {
	// upidStart is a qmstart UPID (ID 120); the type is wrong for vzdump.
	f := &fakeWriteServer{body: upidBody(upidStart)}
	w := newTestWriter(t, f)
	_, err := w.BackupNow(context.Background(), BackupRequest{
		Node: "pve1", VMID: 120, Storage: "local", Mode: "snapshot",
	})
	var we *WriteError
	if !errors.As(err, &we) || we.Reason != ReasonSchema {
		t.Fatalf("err = %v, want schema", err)
	}
}

// TestBackupNowRejectsWrongUPIDTarget pins that a vzdump UPID naming a
// different guest is rejected (exactly one exact guest, ADR 0006 P2-01).
func TestBackupNowRejectsWrongUPIDTarget(t *testing.T) {
	f := &fakeWriteServer{body: upidBody("UPID:pve1:00001234:00ABCDEF:6900A000:vzdump:121:nos@pve!action:")}
	w := newTestWriter(t, f)
	_, err := w.BackupNow(context.Background(), BackupRequest{
		Node: "pve1", VMID: 120, Storage: "local", Mode: "snapshot",
	})
	var we *WriteError
	if !errors.As(err, &we) || we.Reason != ReasonSchema {
		t.Fatalf("err = %v, want schema", err)
	}
}

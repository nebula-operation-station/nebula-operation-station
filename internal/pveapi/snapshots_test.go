// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	descShort   = "first snapshot"
	descLong    = "second, with a longer description text to measure"
	descLXCSnap = ""
)

func TestListSnapshotsQemuPVE8(t *testing.T) {
	ts := storageServer(t, "testdata/snapshot_qemu_pve8.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if !list.Complete || len(list.Snapshots) != 2 {
		t.Fatalf("list = %+v", list)
	}
	s1 := list.Snapshots[0]
	if s1.Name != "snap1" || s1.Parent != "" || s1.SnapTimeUnix != 1793260800 || !s1.HasVMState {
		t.Fatalf("snap1 = %+v", s1)
	}
	if s1.DescriptionBytes != len(descShort) {
		t.Fatalf("snap1 DescriptionBytes = %d, want %d", s1.DescriptionBytes, len(descShort))
	}
	s2 := list.Snapshots[1]
	if s2.Name != "snap2" || s2.Parent != "snap1" || s2.SnapTimeUnix != 1793266200 || s2.HasVMState {
		t.Fatalf("snap2 = %+v", s2)
	}
	if s2.DescriptionBytes != len(descLong) {
		t.Fatalf("snap2 DescriptionBytes = %d, want %d", s2.DescriptionBytes, len(descLong))
	}
}

func TestListSnapshotsQemuPVE9DropsUnknownFields(t *testing.T) {
	ts := storageServer(t, "testdata/snapshot_qemu_pve9.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(list.Snapshots) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(list.Snapshots))
	}
	if s := list.Snapshots[0]; s.Name != "snap1" || !s.HasVMState {
		t.Fatalf("snap1 = %+v", s)
	}
}

func TestListSnapshotsLXC(t *testing.T) {
	ts := storageServer(t, "testdata/snapshot_lxc.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListSnapshots(context.Background(), "n1", "lxc", 200)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(list.Snapshots) != 1 {
		t.Fatalf("got %d snapshots, want 1", len(list.Snapshots))
	}
	s := list.Snapshots[0]
	if s.Name != "before-update" || s.Parent != "" || s.SnapTimeUnix != 1793268000 || s.HasVMState {
		t.Fatalf("snap = %+v", s)
	}
	if s.DescriptionBytes != len(descLXCSnap) {
		t.Fatalf("DescriptionBytes = %d, want 0", s.DescriptionBytes)
	}
}

func TestListSnapshotsSnapTimeFallback(t *testing.T) {
	ts := storageServer(t, "testdata/snapshot_no_unix.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(list.Snapshots) != 1 {
		t.Fatalf("got %d snapshots, want 1", len(list.Snapshots))
	}
	if got := list.Snapshots[0].SnapTimeUnix; got != 1793260800 {
		t.Fatalf("SnapTimeUnix = %d, want 1793260800 (parsed from snaptime)", got)
	}
}

func TestListSnapshotsEmptyIsNotUnavailable(t *testing.T) {
	ts := storageServer(t, "testdata/empty_list.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(list.Snapshots) != 0 || !list.Complete {
		t.Fatalf("list = %+v, want empty and complete", list)
	}
}

func TestListSnapshotsTooManyMarksIncomplete(t *testing.T) {
	entries := make([]map[string]any, MaxSnapshotsPerGuest+1)
	for i := range entries {
		entries[i] = map[string]any{
			"name":          fmt.Sprintf("s%03d", i),
			"snaptime":      "2026-10-29T08:00:00Z",
			"snaptime_unix": 1793260800 + i,
			"vmstate":       0,
		}
	}
	body, _ := json.Marshal(entries)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(list.Snapshots) != MaxSnapshotsPerGuest {
		t.Fatalf("got %d snapshots, want %d", len(list.Snapshots), MaxSnapshotsPerGuest)
	}
	if list.Complete {
		t.Fatal("Complete = true for oversize list")
	}
}

func TestListSnapshotsSchemaRejectsBadName(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"name":"bad name!","snaptime":"2026-10-29T08:00:00Z","snaptime_unix":1793260800,"vmstate":0}]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonSchema {
		t.Fatalf("err = %v, want reason %q", err, ReasonSchema)
	}
}

func TestListSnapshotsSchemaRejectsDuplicateNames(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[`+
			`{"name":"dup","snaptime":"2026-10-29T08:00:00Z","snaptime_unix":1,"vmstate":0},`+
			`{"name":"dup","parent":"dup","snaptime":"2026-10-29T09:00:00Z","snaptime_unix":2,"vmstate":0}]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonSchema {
		t.Fatalf("err = %v, want reason %q", err, ReasonSchema)
	}
}

func TestListSnapshotsSchemaRejectsBadVMState(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"name":"s1","snaptime":"2026-10-29T08:00:00Z","snaptime_unix":1,"vmstate":7}]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonSchema {
		t.Fatalf("err = %v, want reason %q", err, ReasonSchema)
	}
}

func TestListSnapshotsSchemaRejectsBadSnapTime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// snaptime present but unparseable; snaptime_unix absent.
		fmt.Fprint(w, `[{"name":"s1","snaptime":"not-a-time","vmstate":0}]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonSchema {
		t.Fatalf("err = %v, want reason %q", err, ReasonSchema)
	}
}

func TestListSnapshotsUnavailable403(t *testing.T) {
	ts := storageServer(t, "testdata/error_403.json", http.StatusForbidden)
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListSnapshots(context.Background(), "n1", "qemu", 101)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestListSnapshotsRejectsBadArguments(t *testing.T) {
	c, err := NewClient(&http.Client{}, "https://pve.example:8006", func(ctx context.Context) (string, error) {
		return "tok", nil
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	badVMIDs := []int64{0, 99, 10000000000, -1}
	for _, vmid := range badVMIDs {
		if _, err := c.ListSnapshots(context.Background(), "n1", "qemu", vmid); err == nil {
			t.Fatalf("ListSnapshots(vmid=%d): expected error", vmid)
		}
	}
	for _, kind := range []string{"", "kvm", "QEMU", "lxc ", strings.Repeat("x", 16)} {
		if _, err := c.ListSnapshots(context.Background(), "n1", kind, 101); err == nil {
			t.Fatalf("ListSnapshots(kind=%q): expected error", kind)
		}
	}
	if _, err := c.ListSnapshots(context.Background(), "BAD NODE", "qemu", 101); err == nil {
		t.Fatal("ListSnapshots(bad node): expected error")
	}
}

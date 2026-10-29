// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func storageServer(t *testing.T, path string, status int) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
		}
		w.Write(body)
	}))
}

func TestSnapshotCapabilityTable(t *testing.T) {
	tests := []struct {
		storageType  string
		volumeFormat string
		want         TriState
	}{
		{"zfspool", "", TriYes},
		{"lvmthin", "", TriYes},
		{"rbd", "", TriYes},
		{"cephfs", "", TriNo},
		{"cephfs", "qcow2", TriNo},
		{"lvm", "", TriNo},
		{"lvm", "raw", TriNo},
		{"dir", "qcow2", TriYes},
		{"dir", "raw", TriNo},
		{"dir", "", TriNo},
		{"nfs", "qcow2", TriUnknown},
		{"nfs", "", TriUnknown},
		{"pbs", "", TriUnknown},
		{"glue", "", TriUnknown},
		{"", "", TriUnknown},
		{"weird_type", "qcow2", TriUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.storageType+"/"+tt.volumeFormat, func(t *testing.T) {
			if got := SnapshotCapability(tt.storageType, tt.volumeFormat); got != tt.want {
				t.Fatalf("SnapshotCapability(%q, %q) = %v, want %v", tt.storageType, tt.volumeFormat, got, tt.want)
			}
		})
	}
}

func TestListStoragesPVE8(t *testing.T) {
	ts := storageServer(t, "testdata/storage_pve8.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListStorages(context.Background(), "n1")
	if err != nil {
		t.Fatalf("ListStorages: %v", err)
	}
	if !list.Complete {
		t.Fatal("Complete = false for in-limit response")
	}
	if len(list.Storages) != 10 {
		t.Fatalf("got %d storages, want 10", len(list.Storages))
	}
	byID := make(map[string]Storage, len(list.Storages))
	for _, s := range list.Storages {
		byID[s.ID] = s
	}

	local := byID["local"]
	if local.Type != "dir" || local.Format != "raw" || !local.Active || local.Shared {
		t.Fatalf("local = %+v", local)
	}
	if local.TotalBytes != 2147483648 || local.UsedBytes != 1073741824 || !local.CapacityKnown {
		t.Fatalf("local capacity = %+v", local)
	}
	if len(local.Content) != 4 || local.Content[0] != "images" {
		t.Fatalf("local content = %v", local.Content)
	}
	if local.Snapshots != TriNo {
		t.Fatalf("local (dir/raw) Snapshots = %v, want no", local.Snapshots)
	}

	if got := byID["local-qcow"].Snapshots; got != TriYes {
		t.Fatalf("local-qcow Snapshots = %v, want yes", got)
	}
	if got := byID["local-lvm"].Snapshots; got != TriNo {
		t.Fatalf("local-lvm Snapshots = %v, want no", got)
	}
	if got := byID["Datastore_4TB_NVME"].Snapshots; got != TriNo {
		t.Fatalf("Datastore_4TB_NVME Snapshots = %v, want no", got)
	}
	if got := byID["tank-vms"].Snapshots; got != TriYes {
		t.Fatalf("tank-vms Snapshots = %v, want yes", got)
	}
	if got := byID["rbdstore"].Snapshots; got != TriYes {
		t.Fatalf("rbdstore Snapshots = %v, want yes", got)
	}
	if got := byID["cephfs1"].Snapshots; got != TriNo {
		t.Fatalf("cephfs1 Snapshots = %v, want no", got)
	}
	if cephfs := byID["cephfs1"]; !cephfs.Shared || !cephfs.Active {
		t.Fatalf("cephfs1 shared/active = %+v", cephfs)
	}
	if got := byID["thin1"].Snapshots; got != TriYes {
		t.Fatalf("thin1 Snapshots = %v, want yes", got)
	}
	pbs := byID["pbs1"]
	if pbs.CapacityKnown {
		t.Fatalf("pbs1 CapacityKnown = true, want false (no space reported)")
	}
	if pbs.TotalBytes != 0 || pbs.UsedBytes != 0 {
		t.Fatalf("pbs1 bytes = %+v", pbs)
	}
	if got := byID["nfs-old"].Snapshots; got != TriUnknown {
		t.Fatalf("nfs-old Snapshots = %v, want unknown", got)
	}
	if nfs := byID["nfs-old"]; nfs.Active {
		t.Fatalf("nfs-old Active = true, want false")
	}
}

func TestListStoragesPVE9DropsUnknownFields(t *testing.T) {
	ts := storageServer(t, "testdata/storage_pve9.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListStorages(context.Background(), "n1")
	if err != nil {
		t.Fatalf("ListStorages: %v", err)
	}
	if len(list.Storages) != 2 {
		t.Fatalf("got %d storages, want 2", len(list.Storages))
	}
	if got := list.Storages[1].Snapshots; got != TriUnknown {
		t.Fatalf("glue Snapshots = %v, want unknown", got)
	}
	if s := list.Storages[1]; s.ID != "mystery" || s.Type != "glue" || !s.Shared {
		t.Fatalf("mystery = %+v", s)
	}
}

func TestListStoragesEmptyIsNotUnavailable(t *testing.T) {
	ts := storageServer(t, "testdata/empty_list.json", 0)
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListStorages(context.Background(), "n1")
	if err != nil {
		t.Fatalf("ListStorages: %v", err)
	}
	if len(list.Storages) != 0 || !list.Complete {
		t.Fatalf("list = %+v, want empty and complete", list)
	}
}

func TestListStoragesUnavailable403(t *testing.T) {
	ts := storageServer(t, "testdata/error_403.json", http.StatusForbidden)
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListStorages(context.Background(), "n1")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Status != http.StatusForbidden {
		t.Fatalf("err = %v, want http_error/403", err)
	}
}

func TestListStoragesTooManyMarksIncomplete(t *testing.T) {
	entries := make([]map[string]any, MaxStoragesPerRemote+1)
	for i := range entries {
		entries[i] = map[string]any{
			"content": []string{"images"},
			"id":      fmt.Sprintf("s%03d", i),
			"shared":  0,
			"type":    "dir",
			"active":  1,
		}
	}
	body, _ := json.Marshal(entries)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	list, err := c.ListStorages(context.Background(), "n1")
	if err != nil {
		t.Fatalf("ListStorages: %v", err)
	}
	if len(list.Storages) != MaxStoragesPerRemote {
		t.Fatalf("got %d storages, want %d", len(list.Storages), MaxStoragesPerRemote)
	}
	if list.Complete {
		t.Fatal("Complete = true for oversize list")
	}
}

func TestListStoragesSchemaRejectsBadID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"id":"bad id!","type":"dir","active":1,"shared":0,"content":["images"]}]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListStorages(context.Background(), "n1")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonSchema {
		t.Fatalf("err = %v, want reason %q", err, ReasonSchema)
	}
}

func TestListStoragesSchemaRejectsMissingActive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"id":"local","type":"dir","shared":0,"content":["images"]}]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.ListStorages(context.Background(), "n1")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonSchema {
		t.Fatalf("err = %v, want reason %q", err, ReasonSchema)
	}
}

func TestListStoragesRejectsBadNodeName(t *testing.T) {
	c, err := NewClient(&http.Client{}, "https://pve.example:8006", func(ctx context.Context) (string, error) {
		return "tok", nil
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, node := range []string{"", "UPPER", "has space", strings.Repeat("a", MaxNodeNameBytes+1)} {
		if _, err := c.ListStorages(context.Background(), node); err == nil {
			t.Fatalf("ListStorages(%q): expected error", node)
		}
	}
}

func TestGetStorage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/n1/storage/local-lvm" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body, _ := os.ReadFile("testdata/storage_single.json")
		w.Write(body)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	st, err := c.GetStorage(context.Background(), "n1", "local-lvm")
	if err != nil {
		t.Fatalf("GetStorage: %v", err)
	}
	if st.ID != "local-lvm" || st.Type != "lvm" || st.Snapshots != TriNo {
		t.Fatalf("st = %+v", st)
	}
	if st.TotalBytes != 10737418240 || st.UsedBytes != 5368709120 || !st.CapacityKnown {
		t.Fatalf("capacity = %+v", st)
	}
}

func TestGetStorageUnavailable404(t *testing.T) {
	ts := storageServer(t, "testdata/error_403.json", http.StatusNotFound)
	defer ts.Close()
	c := testClient(t, ts)
	_, err := c.GetStorage(context.Background(), "n1", "nope")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Status != http.StatusNotFound {
		t.Fatalf("err = %v, want http_error/404", err)
	}
}

func TestGetStorageRejectsBadID(t *testing.T) {
	c, err := NewClient(&http.Client{}, "https://pve.example:8006", func(ctx context.Context) (string, error) {
		return "tok", nil
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, id := range []string{"", "bad/id", "bad id", strings.Repeat("a", MaxRefBytes+1)} {
		if _, err := c.GetStorage(context.Background(), "n1", id); err == nil {
			t.Fatalf("GetStorage(%q): expected error", id)
		}
	}
}

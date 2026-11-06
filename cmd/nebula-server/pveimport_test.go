// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

const (
	testObservationName = "remote-a.gen-00000000000000000001.json"
	testRetention       = 24 * time.Hour
)

// makeSpoolDirs creates the directories the installer provisions; the
// server only ever opens them.
func makeSpoolDirs(t *testing.T, root string) {
	t.Helper()
	for _, d := range []string{"results", "guestnet"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o770); err != nil {
			t.Fatal(err)
		}
	}
}

// spoolTestFiles publishes one observation and one guest NIC record the
// way the collector does and returns their paths.
func spoolTestFiles(t *testing.T, root string) []string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := pvecontract.MarshalObservation(pvecontract.Observation{
		RemoteID:             "remote-a",
		ObservedAt:           now,
		Source:               "test-collector",
		CollectionGeneration: 1,
		Complete:             true,
		Nodes:                pvecontract.UnavailableDataset[[]pvecontract.NodeObservation]("not read"),
		Guests:               pvecontract.UnavailableDataset[[]pvecontract.GuestObservation]("not read"),
		Storages:             pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("not read"),
		Cluster:              pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("not read"),
		Tasks:                pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("not read"),
	})
	if err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(root, "results", testObservationName)
	if err := os.WriteFile(result, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	rec, err := pvecollect.MarshalGuestNet(pvecollect.GuestNetRecord{
		Version:      pvecollect.GuestNetVersion,
		Remote:       "remote-a",
		ObservedUnix: now.Unix(),
		NICs: []pvecollect.GuestNIC{
			{VMID: 101, Kind: pvecontract.GuestQEMU, Index: 0, Bridge: "vmbr0", MAC: "bc:24:11:00:00:01"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	guest := filepath.Join(root, "guestnet", fmt.Sprintf("remote-a.obs-%020d.json", now.Unix()))
	if err := os.WriteFile(guest, rec, 0o640); err != nil {
		t.Fatal(err)
	}
	return []string{result, guest}
}

// waitConsumed waits until the importers unlinked every path.
func waitConsumed(t *testing.T, paths []string, diag func() string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		left := 0
		for _, p := range paths {
			if _, err := os.Lstat(p); err == nil {
				left++
			}
		}
		if left == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d spool files not consumed: %s", left, diag())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertImported checks both destinations of the spool.
func assertImported(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := pveinventory.New(db).GetRemote(ctx, "remote-a"); err != nil {
		t.Errorf("observation did not reach the inventory: %v", err)
	}
	traffic, err := trafficstore.NewWithRetention(db, testRetention)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := traffic.CountGuestNICs(ctx); err != nil || n != 1 {
		t.Errorf("guest NICs = %d, %v, want 1", n, err)
	}
}

// syncBuffer is a log sink a running goroutine and the test share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRunImportsConfiguredPVESpool drives the real startup: run itself must
// start both importers on pve_spool_dir, and they must stop with it.
func TestRunImportsConfiguredPVESpool(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "elsewhere", "pve")
	makeSpoolDirs(t, root)
	files := spoolTestFiles(t, root)
	path := writeConfig(t, dir, map[string]any{
		"listen":          freeListenAddr(t),
		"public_origin":   "https://nebula.example.org",
		"data_dir":        dir,
		"executor_socket": filepath.Join(dir, "no-executor.sock"),
		"executor_user":   u.Username,
		"pve_spool_dir":   root,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr syncBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &stderr) }()

	waitConsumed(t, files, stderr.String)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not stop")
	}

	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertImported(t, db)
}

func newTestPVEImport(t *testing.T, root string, logs *syncBuffer) (*pveImport, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewJSONHandler(logs, nil))
	p, err := newPVEImport(db, root, testRetention, log)
	if err != nil {
		t.Fatal(err)
	}
	p.interval = 5 * time.Millisecond
	return p, db
}

// A spool that is not there yet (no collector installed) must not stop the
// server: the wait is logged once and ends as soon as the directories exist.
func TestPVEImportWaitsForSpool(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pve")
	var logs syncBuffer
	p, db := newTestPVEImport(t, root, &logs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "PVE spool unavailable") {
		if time.Now().After(deadline) {
			t.Fatal("unavailable spool not logged")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // several retries
	if n := strings.Count(logs.String(), "PVE spool unavailable"); n != 1 {
		t.Fatalf("unavailable spool logged %d times, want once:\n%s", n, logs.String())
	}

	makeSpoolDirs(t, root)
	waitConsumed(t, spoolTestFiles(t, root), logs.String)
	cancel()
	<-done
	assertImported(t, db)
}

func TestPVEImportStopsWhileWaitingForSpool(t *testing.T) {
	var logs syncBuffer
	p, _ := newTestPVEImport(t, filepath.Join(t.TempDir(), "pve"), &logs)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop while waiting for the spool")
	}
}

// A planted symlink in place of a spool directory is refused like a
// missing directory: nothing behind it is read.
func TestPVEImportRefusesSymlinkedResults(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pve")
	if err := os.MkdirAll(root, 0o770); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "results")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, testObservationName), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	p, _ := newTestPVEImport(t, root, &logs)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	p.run(ctx)
	if !strings.Contains(logs.String(), "PVE spool unavailable") {
		t.Fatalf("symlink not refused:\n%s", logs.String())
	}
	if _, err := os.Stat(filepath.Join(outside, testObservationName)); err != nil {
		t.Fatalf("file behind the symlink touched: %v", err)
	}
}

// The log line carries the fixed message and the path, nothing from the
// spool's contents, and is valid JSON for the service log.
func TestPVEImportLogLineIsStructured(t *testing.T) {
	var logs syncBuffer
	root := filepath.Join(t.TempDir(), "pve")
	p, _ := newTestPVEImport(t, root, &logs)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	p.run(ctx)
	line, _, _ := strings.Cut(logs.String(), "\n")
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("log line %q: %v", line, err)
	}
	if rec["root"] != root {
		t.Fatalf("root = %v, want %s", rec["root"], root)
	}
}

func TestPVEImportIntervalBeatsTheCollector(t *testing.T) {
	// The collector publishes per remote once a minute by default; a
	// slower importer would let results/ grow while it is healthy.
	if pveImportInterval <= 0 || pveImportInterval >= time.Minute {
		t.Fatalf("pveImportInterval = %s", pveImportInterval)
	}
}

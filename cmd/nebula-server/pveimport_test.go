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
	publishSpoolFile(t, result, raw)
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
	publishSpoolFile(t, guest, rec)
	return []string{result, guest}
}

// publishSpoolFile writes data under a temporary name and renames it into
// place, as the collector does: the importers poll the directory and must
// never see a final name on a half-written file.
func publishSpoolFile(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
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

// assertImported checks both destinations of the spool. An observation
// counts only with every dataset applied: each one commits on its own, so
// the remote alone does not prove it arrived whole.
func assertImported(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	store := pveinventory.New(db)
	if _, err := store.GetRemote(ctx, "remote-a"); err != nil {
		t.Errorf("observation did not reach the inventory: %v", err)
	}
	for _, dataset := range []string{
		pveinventory.DatasetNodes, pveinventory.DatasetGuests, pveinventory.DatasetStorages,
		pveinventory.DatasetCluster, pveinventory.DatasetTasks,
	} {
		if _, err := store.GetDatasetStatus(ctx, "remote-a", dataset); err != nil {
			t.Errorf("dataset %s did not reach the inventory: %v", dataset, err)
		}
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

// handoffLogRoots returns the root of every failed live handoff open.
func handoffLogRoots(t *testing.T, logs string) []string {
	t.Helper()
	var roots []string
	for line := range strings.Lines(logs) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == "live chart: provider handoff unavailable" {
			root, _ := rec["root"].(string)
			roots = append(roots, root)
		}
	}
	return roots
}

// One collector, one spool root: run must point the live handoff at
// pve_spool_dir too, or a custom root silently leaves the live chart on the
// default path. The spool here has no requests/ or live/, so the failed open
// names the root it used.
func TestRunUsesPVESpoolDirForLiveHandoff(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "elsewhere", "pve")
	makeSpoolDirs(t, root)
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

	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(stderr.String(), "provider handoff unavailable") {
		if time.Now().After(deadline) {
			t.Fatalf("live handoff never opened:\n%s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not stop")
	}
	roots := handoffLogRoots(t, stderr.String())
	if len(roots) == 0 {
		t.Fatalf("no handoff line:\n%s", stderr.String())
	}
	for _, got := range roots {
		if got != root {
			t.Errorf("live handoff opened %q, want pve_spool_dir %q", got, root)
		}
	}
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
	p.retentionInterval = 5 * time.Millisecond
	return p, db
}

const testRetentionRemote = "remote-retention"

// seedRetentionRows writes one expired and one young row of each kind the
// retention removes: a tombstoned guest, a task, and a metric bucket. The
// expired rows are older than the store's own windows.
func seedRetentionRows(t *testing.T, db *sql.DB, now time.Time) {
	t.Helper()
	old := now.Add(-(pveinventory.TombstoneRetention + 24*time.Hour))
	young := now.Add(-24 * time.Hour)
	stamp := func(at time.Time) string { return at.UTC().Format(time.RFC3339) }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO pve_guests (remote_id, vmid, generation, observed_at, state, tombstoned, tombstoned_at)
		VALUES (?, 901, 1, ?, 'available', 1, ?)`, testRetentionRemote, stamp(old), stamp(old))
	exec(`INSERT INTO pve_guests (remote_id, vmid, generation, observed_at, state, tombstoned, tombstoned_at)
		VALUES (?, 902, 1, ?, 'available', 1, ?)`, testRetentionRemote, stamp(young), stamp(young))
	exec(`INSERT INTO pve_tasks (remote_id, node, actor, type, target, started_unix, observed_at)
		VALUES (?, 'pve', 'root@pam', 'vzdump', 'old', ?, ?)`, testRetentionRemote, old.Unix(), stamp(old))
	exec(`INSERT INTO pve_tasks (remote_id, node, actor, type, target, started_unix, observed_at)
		VALUES (?, 'pve', 'root@pam', 'vzdump', 'young', ?, ?)`, testRetentionRemote, young.Unix(), stamp(young))
	exec(`INSERT INTO pve_metric_buckets (remote_id, target_kind, node, vmid, generation, metric, bucket_start_unix, sum, count)
		VALUES (?, 'node', 'pve', 0, 0, 'cpu', ?, 1, 1)`, testRetentionRemote, now.Add(-48*time.Hour).Unix())
	exec(`INSERT INTO pve_metric_buckets (remote_id, target_kind, node, vmid, generation, metric, bucket_start_unix, sum, count)
		VALUES (?, 'node', 'pve', 0, 0, 'mem', ?, 1, 1)`, testRetentionRemote, now.Add(-time.Hour).Unix())
}

// countRows returns the result of a single-value count query.
func countRows(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// retentionState reports which seeded expired rows are still stored, as
// counts: expired guest, expired task, expired bucket, then the young ones.
func retentionState(t *testing.T, db *sql.DB) (oldGuest, oldTask, oldBucket, youngGuest, youngTask, youngBucket int) {
	t.Helper()
	oldGuest = countRows(t, db, `SELECT COUNT(*) FROM pve_guests WHERE remote_id = ? AND vmid = 901`, testRetentionRemote)
	oldTask = countRows(t, db, `SELECT COUNT(*) FROM pve_tasks WHERE remote_id = ? AND target = 'old'`, testRetentionRemote)
	oldBucket = countRows(t, db, `SELECT COUNT(*) FROM pve_metric_buckets WHERE remote_id = ? AND metric = 'cpu'`, testRetentionRemote)
	youngGuest = countRows(t, db, `SELECT COUNT(*) FROM pve_guests WHERE remote_id = ? AND vmid = 902`, testRetentionRemote)
	youngTask = countRows(t, db, `SELECT COUNT(*) FROM pve_tasks WHERE remote_id = ? AND target = 'young'`, testRetentionRemote)
	youngBucket = countRows(t, db, `SELECT COUNT(*) FROM pve_metric_buckets WHERE remote_id = ? AND metric = 'mem'`, testRetentionRemote)
	return
}

// stopRun cancels ctx and fails the test unless run returns promptly.
func stopRun(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after context end")
	}
}

// Expired rows are removed by the store's own retention during run; young
// rows stay; the count of removed rows is logged once, not on every pass.
func TestPVEImportRetentionRemovesOnlyExpiredRows(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pve")
	makeSpoolDirs(t, root)
	var logs syncBuffer
	p, db := newTestPVEImport(t, root, &logs)
	seedRetentionRows(t, db, time.Now())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx) }()

	deadline := time.Now().Add(15 * time.Second)
	for {
		og, ot, ob, _, _, _ := retentionState(t, db)
		if og == 0 && ot == 0 && ob == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired rows not removed: guest=%d task=%d bucket=%d\n%s", og, ot, ob, logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	stopRun(t, cancel, done)

	_, _, _, yg, yt, yb := retentionState(t, db)
	if yg != 1 || yt != 1 || yb != 1 {
		t.Fatalf("young rows removed: guest=%d task=%d bucket=%d", yg, yt, yb)
	}
	if n := strings.Count(logs.String(), "PVE retention removed expired rows"); n != 1 {
		t.Fatalf("removal logged %d times, want once (zero passes stay silent):\n%s", n, logs.String())
	}
}

// A failing retention pass is logged with its context and does not stop the
// import: a spool entry published after the failure is still imported. The
// next pass, after the failure is gone, removes the expired rows.
func TestPVEImportRetentionErrorDoesNotStopImport(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pve")
	makeSpoolDirs(t, root)
	var logs syncBuffer
	p, db := newTestPVEImport(t, root, &logs)
	seedRetentionRows(t, db, time.Now())
	// Force Prune to fail: any delete of a task row aborts its transaction.
	exec := func(q string) {
		t.Helper()
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TRIGGER test_block_task_prune BEFORE DELETE ON pve_tasks
		BEGIN SELECT RAISE(ABORT, 'forced prune failure'); END`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx) }()

	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(logs.String(), "PVE retention failed") {
		if time.Now().After(deadline) {
			t.Fatalf("forced prune failure not logged:\n%s", logs.String())
		}
		time.Sleep(time.Millisecond)
	}
	if og, _, _, _, _, _ := retentionState(t, db); og != 1 {
		t.Fatalf("failed pass changed the tombstone: %d rows left, want 1", og)
	}

	files := spoolTestFiles(t, root)
	waitConsumed(t, files, logs.String)
	assertImported(t, db)

	exec(`DROP TRIGGER test_block_task_prune`)
	deadline = time.Now().Add(15 * time.Second)
	for {
		og, ot, _, _, _, _ := retentionState(t, db)
		if og == 0 && ot == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("next pass did not retry the expired rows: guest=%d task=%d\n%s", og, ot, logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	stopRun(t, cancel, done)
	if strings.Contains(logs.String(), "context canceled") {
		t.Fatalf("shutdown logged a retention error:\n%s", logs.String())
	}
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"crypto/sha256"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

var (
	_ permit.Store                = (*DB)(nil)
	_ webauthnverify.CounterStore = (*DB)(nil)
)

func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// openAtT opens a database whose clock (bound_at, updated_at) is fixed at now.
func openAtT(t *testing.T, dir string, now time.Time) *DB {
	t.Helper()
	db, err := open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func openT(t *testing.T, dir string) *DB {
	t.Helper()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func digest(s string) canonical.Digest { return canonical.Digest(sha256.Sum256([]byte(s))) }

var t0 = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func TestOpenCreatesPrivateFile(t *testing.T) {
	dir := privateDir(t)
	openT(t, dir)
	fi, err := os.Lstat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s has mode %o, want 0600", FileName, fi.Mode().Perm())
	}
}

func TestOpenRefusesNonPrivateDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("database opened in a group-readable directory")
	}
}

func TestOpenRefusesLooseExistingFile(t *testing.T) {
	dir := privateDir(t)
	p := filepath.Join(dir, FileName)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("world-readable database file accepted")
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatal("Open changed the mode of a file it refused")
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	dir := privateDir(t)
	elsewhere := filepath.Join(privateDir(t), "other.db")
	if err := os.WriteFile(elsewhere, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("symlinked database accepted")
	}
}

func TestOpenRefusesDSNCharacters(t *testing.T) {
	base := privateDir(t)
	for _, name := range []string{"a?b", "a#b"} {
		dir := filepath.Join(base, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir); err == nil {
			t.Errorf("data dir %q accepted; it would change the DSN", name)
		}
	}
}

func TestPragmas(t *testing.T) {
	db := openT(t, privateDir(t))
	var mode string
	var fk, sync int
	if err := db.sql.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := db.sql.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if err := db.sql.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" || fk != 1 || sync != 2 {
		t.Fatalf("journal_mode=%s foreign_keys=%d synchronous=%d; want wal/1/2 (FULL)", mode, fk, sync)
	}
}

func TestMigrationsRecordedAndIdempotent(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	want, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	count := func(db *DB) int {
		var n int
		if err := db.sql.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(db); got != len(want) {
		t.Fatalf("%d migrations recorded, %d shipped", got, len(want))
	}
	db.Close()
	db2 := openT(t, dir)
	if got := count(db2); got != len(want) {
		t.Fatalf("reopen changed the migration count to %d", got)
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	if _, err := db.sql.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (9999, 0)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err := Open(dir)
	if err == nil || !strings.Contains(err.Error(), "9999") {
		t.Fatalf("database from a newer binary opened: %v", err)
	}
}

func TestFailingMigrationRollsBack(t *testing.T) {
	db := openT(t, privateDir(t))
	bad := []migration{{version: 1000, name: "1000_bad.sql", sql: `CREATE TABLE half_done (x INTEGER); SELECT * FROM missing_table;`}}
	err := migrateWith(db.sql, append(mustMigrations(t), bad...), func() time.Time { return t0 })
	if err == nil || !strings.Contains(err.Error(), "1000") {
		t.Fatalf("failing migration: %v", err)
	}
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'half_done'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("partial migration left a table behind")
	}
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1000`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("failed migration was recorded")
	}
}

func mustMigrations(t *testing.T) []migration {
	t.Helper()
	m, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMigrationFileNames(t *testing.T) {
	ok := fstest.MapFS{"m/0001_a.sql": {Data: []byte("SELECT 1;")}, "m/0002_b.sql": {Data: []byte("SELECT 1;")}}
	if _, err := loadMigrationsFrom(ok, "m"); err != nil {
		t.Fatal(err)
	}
	for name, fsys := range map[string]fstest.MapFS{
		"bad name":  {"m/001_a.sql": {Data: []byte("SELECT 1;")}},
		"duplicate": {"m/0001_a.sql": {Data: []byte("SELECT 1;")}, "m/0001_b.sql": {Data: []byte("SELECT 1;")}},
		"other ext": {"m/0001_a.txt": {Data: []byte("x")}},
	} {
		if _, err := loadMigrationsFrom(fsys, "m"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExecutionBindingIsUniqueAndDurable(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	const id = "00000000-0000-4000-8000-000000000001"
	if err := db.BindExecution(id, digest("a"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.BindExecution(id, digest("a"), t0.Add(time.Hour)); !errors.Is(err, permit.ErrExecutionBound) {
		t.Fatalf("second binding of the same ID: %v", err)
	}
	if err := db.BindExecution(id, digest("b"), t0.Add(time.Hour)); !errors.Is(err, permit.ErrExecutionBound) {
		t.Fatalf("re-binding to other content: %v", err)
	}
	db.Close()

	db2 := openT(t, dir)
	d, ok, err := db2.LookupExecution(id)
	if err != nil || !ok || d != digest("a") {
		t.Fatalf("after reopen: d=%s ok=%v err=%v", d, ok, err)
	}
	if _, ok, err := db2.LookupExecution("00000000-0000-4000-8000-000000000002"); ok || err != nil {
		t.Fatalf("unknown ID: ok=%v err=%v", ok, err)
	}
}

func TestPruneOnlyRemovesLongExpiredIDs(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	ids := map[string]time.Time{
		"00000000-0000-4000-8000-000000000001": t0.Add(-RetainSpentExecutions - time.Hour), // long expired
		"00000000-0000-4000-8000-000000000002": t0.Add(-RetainSpentExecutions + time.Hour), // expired, still retained
		"00000000-0000-4000-8000-000000000003": t0.Add(time.Hour),                          // live
	}
	for id, exp := range ids {
		if err := db.BindExecution(id, digest(id), exp); err != nil {
			t.Fatal(err)
		}
	}
	n, err := db.PruneExecutions(t0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	if _, ok, _ := db.LookupExecution("00000000-0000-4000-8000-000000000001"); ok {
		t.Error("long-expired ID kept")
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"} {
		if _, ok, _ := db.LookupExecution(id); !ok {
			t.Errorf("%s pruned too early", id)
		}
	}
}

func TestCountersDurableAndMonotonic(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	id := []byte{0x01, 0x02, 0xff}
	if err := db.SaveCounter(id, 5); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCounter(id, 3); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCounter([]byte{0x09}, math.MaxUint32); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db2 := openT(t, dir)
	c, err := db2.LoadCounters()
	if err != nil {
		t.Fatal(err)
	}
	if c[string(id)] != 5 {
		t.Fatalf("counter %d, want 5 (a lower value must never overwrite)", c[string(id)])
	}
	if c[string([]byte{0x09})] != math.MaxUint32 {
		t.Fatalf("max counter stored as %d", c[string([]byte{0x09})])
	}
}

func TestCounterRejectsEmptyCredentialID(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveCounter(nil, 1); err == nil {
		t.Fatal("empty credential ID accepted")
	}
}

func TestSecondOpenIsRefusedWhileLocked(t *testing.T) {
	old := busyTimeout
	busyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { busyTimeout = old })

	dir := privateDir(t)
	first := openT(t, dir)
	if _, err := Open(dir); err == nil {
		t.Fatal("a second executor could open the database while the first holds it")
	}
	first.Close()
	// After the first one closed, opening works again.
	openT(t, dir)
}

func TestOpenRefusesRelativePath(t *testing.T) {
	dir := privateDir(t)
	t.Chdir(filepath.Dir(dir))
	for _, rel := range []string{filepath.Base(dir), "file:" + filepath.Base(dir)} {
		if db, err := Open(rel); err == nil {
			db.Close()
			t.Errorf("relative data directory %q accepted", rel)
		}
	}
}

// Exclusive locking mode must be set before WAL is enabled; then SQLite
// keeps the WAL index in heap memory and never creates a -shm file, also
// when an existing database is reopened. The -wal file must be as private
// as the database.
func TestNoSharedMemoryFileAndPrivateWAL(t *testing.T) {
	dir := privateDir(t)
	for i := 0; i < 2; i++ {
		db := openT(t, dir)
		if err := db.SaveCounter([]byte{0x01}, uint32(i+1)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(dir, FileName+"-shm")); !os.IsNotExist(err) {
			t.Fatalf("open #%d: -shm file exists (err=%v): exclusive mode was not set before WAL", i+1, err)
		}
		wal := filepath.Join(dir, FileName+"-wal")
		if fi, err := os.Lstat(wal); err == nil {
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("-wal has mode %o, want 0600", fi.Mode().Perm())
			}
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCreatedReportsANewFile(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	if !db.Created() {
		t.Fatal("first open: Created() = false")
	}
	db.Close()
	db = openT(t, dir)
	if db.Created() {
		t.Fatal("reopen: Created() = true")
	}
}

// A clock that jumps forward before this run bound anything must not prune
// IDs whose requests are still live.
func TestPruneIgnoresClockJumpingForward(t *testing.T) {
	dir := privateDir(t)
	db := openAtT(t, dir, t0)
	live := "00000000-0000-4000-8000-000000000010"
	if err := db.BindExecution(live, digest(live), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db = openAtT(t, dir, t0.Add(365*24*time.Hour))
	n, err := db.PruneExecutions(t0.Add(365 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("pruned %d live IDs after a clock jump", n)
	}
	if _, ok, _ := db.LookupExecution(live); !ok {
		t.Fatal("live execution ID pruned after a clock jump")
	}
}

// The directory lock is held by the DB, not by an SQLite connection: it
// stays while the database is in use and is released by Close.
func TestDirectoryLockHeldUntilClose(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	if err := db.SaveCounter([]byte{0x02}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := lockDir(dir); err == nil {
		t.Fatal("data directory not locked while the database is open")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := lockDir(dir)
	if err != nil {
		t.Fatalf("lock not released by Close: %v", err)
	}
	f.Close()
}

// Once a database existed, a missing one is refused instead of being
// recreated empty (counters and spent IDs would restart); removing the
// marker starts empty on purpose.
func TestMissingDatabaseIsRefusedAfterInstall(t *testing.T) {
	dir := privateDir(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := os.Stat(filepath.Join(dir, MarkerName)); err != nil {
		t.Fatal("no marker", err)
	}
	for _, f := range []string{FileName, FileName + "-wal"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	if _, err := Open(dir); !errors.Is(err, ErrMissingDatabase) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatal("an empty database was created anyway")
	}
	_ = os.Remove(filepath.Join(dir, MarkerName))
	db, err = Open(dir)
	if err != nil || !db.Created() {
		t.Fatal(err)
	}
	db.Close()
}

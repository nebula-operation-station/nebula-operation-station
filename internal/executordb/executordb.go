// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executordb is the executor's private SQLite database,
// executor.db in the executor's 0700 data directory.
//
// It stores only state that makes the executor stricter after a restart:
// spent execution IDs and WebAuthn signature counters. Permits and the
// privileged session are never stored, so a restart revokes them.
//
// The file is created with mode 0600 and checked with internal/fsguard on
// every start. Open takes an flock on the data directory for the lifetime
// of the DB and opens SQLite in exclusive locking mode, so a second executor
// on the same directory cannot start. Schema changes are forward-only
// migrations, each applied in its own transaction.
package executordb

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fsguard"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// FileName is the database file inside the executor data directory.
const FileName = "executor.db"

// MarkerName is written next to the database once it exists; with the
// marker present, a missing database is refused.
const MarkerName = "executor.db.installed"

// ErrMissingDatabase: the database is gone although the marker says one
// existed.
var ErrMissingDatabase = errors.New("executordb: the database is missing")

// RetainSpentExecutions is how long an execution ID stays spent after its
// request expired. An expired request can never be authorized again
// (permit.Authorize checks the expiry), so pruning afterwards only frees
// space.
const RetainSpentExecutions = 30 * 24 * time.Hour

// Limits enforced on stored values.
const (
	maxExecutionIDLen = 64
	maxCredentialID   = 1023 // WebAuthn credential IDs are at most 1023 bytes
)

// busyTimeout bounds how long a statement waits for an SQLite lock. The
// directory flock already keeps a second executor out; this only covers
// other processes that open the file directly.
var busyTimeout = 5 * time.Second

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB is the executor database. It is safe for concurrent use.
type DB struct {
	sql       *sql.DB
	dirLock   *os.File // flock(LOCK_EX) on the data directory
	created   bool
	now       func() time.Time
	closeOnce sync.Once
	closeErr  error
}

// Open opens (and if needed creates) executor.db in dataDir. dataDir must
// be an absolute path to a private directory (fsguard.CheckPrivateDir); the
// file is created with mode 0600 and refused if it exists with a looser
// mode, another owner or as a symlink. Pending migrations are applied
// before Open returns.
func Open(dataDir string) (*DB, error) {
	return open(dataDir, time.Now)
}

func open(dataDir string, now func() time.Time) (_ *DB, err error) {
	// An absolute path also rules out a "file:" prefix, which SQLite would
	// read as a URI and decode differently from the path checked here.
	if !filepath.IsAbs(dataDir) {
		return nil, fmt.Errorf("executordb: data directory %q must be an absolute path", dataDir)
	}
	if err := fsguard.CheckPrivateDir(dataDir); err != nil {
		return nil, fmt.Errorf("executordb: %w", err)
	}
	path := filepath.Join(dataDir, FileName)
	// The pragmas travel in the DSN query string; '?' or '#' in the path
	// would change them.
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("executordb: path %q must not contain '?' or '#'", path)
	}

	// One executor per data directory. The flock lives on its own file
	// description for as long as the DB is open, independent of SQLite's
	// connection handling (a reopened connection would otherwise drop the
	// SQLite lock silently). It is taken before the database file is
	// touched, so the created flag below cannot race another executor.
	dirLock, err := lockDir(dataDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			dirLock.Close()
		}
	}()

	_, statErr := os.Lstat(path)
	created := os.IsNotExist(statErr)
	// Once a database existed here, a missing one is an accident or an
	// attack (counters and spent execution IDs would restart): refuse,
	// unless the admin removes the marker on purpose.
	marker := filepath.Join(dataDir, MarkerName)
	if _, err := os.Lstat(marker); created && err == nil {
		return nil, fmt.Errorf("executordb: %s is missing but %s says one existed: restore it (sudo nebula restore) or, to start empty on purpose, remove %s: %w",
			path, MarkerName, marker, ErrMissingDatabase)
	}
	if err := fsguard.EnsurePrivateFile(path); err != nil {
		return nil, fmt.Errorf("executordb: %w", err)
	}

	// _pragma values run in alphabetical order (after busy_timeout); the
	// _journal_mode and _synchronous keys run after all of them. So the
	// exclusive locking mode is set before WAL is enabled, and SQLite keeps
	// the WAL index in heap memory instead of a shared -shm file.
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=locking_mode(EXCLUSIVE)&_journal_mode=WAL&_synchronous=FULL",
		path, busyTimeout.Milliseconds())
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("executordb: open: %w", err)
	}
	// One connection: the exclusive lock belongs to it, and every write is
	// serialized anyway.
	sdb.SetMaxOpenConns(1)
	sdb.SetMaxIdleConns(1)
	sdb.SetConnMaxLifetime(0)

	// Take the write lock now, so that a second executor fails here and not
	// at its first proposal.
	if _, err := sdb.Exec(`BEGIN IMMEDIATE; COMMIT;`); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("executordb: lock %s (is another executor running?): %w", path, err)
	}
	// SQLite creates the -wal file with the mode and owner of the main
	// file; check both now that they exist.
	for _, p := range []string{path, path + "-wal"} {
		if err := fsguard.CheckPrivateFile(p); err != nil && !os.IsNotExist(err) {
			sdb.Close()
			return nil, fmt.Errorf("executordb: %w", err)
		}
	}

	migrations, err := loadMigrations()
	if err != nil {
		sdb.Close()
		return nil, err
	}
	if err := migrateWith(sdb, migrations, now); err != nil {
		sdb.Close()
		return nil, err
	}
	if err := fsguard.EnsurePrivateFile(marker); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("executordb: %w", err)
	}
	return &DB{sql: sdb, dirLock: dirLock, created: created, now: now}, nil
}

// lockDir takes a non-blocking exclusive flock on dir.
func lockDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("executordb: open %s for locking: %w", dir, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("executordb: %s is in use by another executor", dir)
		}
		return nil, fmt.Errorf("executordb: lock %s: %w", dir, err)
	}
	return f, nil
}

// Created reports whether Open created executor.db. On a data directory
// that already holds credentials this means the stored counters and spent
// execution IDs were lost (deleted file, restore without the database), and
// the executor logs a warning.
func (db *DB) Created() bool { return db.created }

// Close closes the database and then releases the directory lock. It is
// safe to call more than once.
func (db *DB) Close() error {
	db.closeOnce.Do(func() {
		db.closeErr = db.sql.Close()
		if err := db.dirLock.Close(); db.closeErr == nil {
			db.closeErr = err
		}
	})
	return db.closeErr
}

// BindExecution implements permit.Store. The row is committed with
// synchronous=FULL before it returns.
func (db *DB) BindExecution(executionID string, d canonical.Digest, expiresAt time.Time) error {
	if executionID == "" || len(executionID) > maxExecutionIDLen {
		return fmt.Errorf("executordb: execution ID length %d outside 1..%d", len(executionID), maxExecutionIDLen)
	}
	res, err := db.sql.Exec(`INSERT INTO execution_ids (execution_id, digest, expires_at, bound_at)
		VALUES (?, ?, ?, ?) ON CONFLICT(execution_id) DO NOTHING`,
		executionID, d[:], expiresAt.Unix(), db.now().Unix())
	if err != nil {
		return fmt.Errorf("executordb: bind execution: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("executordb: bind execution: %w", err)
	}
	if n == 0 {
		return permit.ErrExecutionBound
	}
	return nil
}

// LookupExecution implements permit.Store.
func (db *DB) LookupExecution(executionID string) (canonical.Digest, bool, error) {
	var d canonical.Digest
	var raw []byte
	err := db.sql.QueryRow(`SELECT digest FROM execution_ids WHERE execution_id = ?`, executionID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return d, false, nil
	}
	if err != nil {
		return d, false, fmt.Errorf("executordb: lookup execution: %w", err)
	}
	if len(raw) != len(d) {
		return d, false, fmt.Errorf("executordb: stored digest has %d bytes", len(raw))
	}
	copy(d[:], raw)
	return d, true, nil
}

// PruneExecutions deletes execution IDs whose request expired more than
// RetainSpentExecutions before now, and returns how many were deleted.
//
// now is capped at the newest bound_at in the table, so a clock that jumps
// forward (bad RTC, spoofed NTP) before the first binding of this run
// cannot prune IDs whose requests are still live.
func (db *DB) PruneExecutions(now time.Time) (int64, error) {
	res, err := db.sql.Exec(`DELETE FROM execution_ids
		WHERE expires_at < MIN(?, (SELECT COALESCE(MAX(bound_at), 0) FROM execution_ids)) - ?`,
		now.Unix(), int64(RetainSpentExecutions/time.Second))
	if err != nil {
		return 0, fmt.Errorf("executordb: prune executions: %w", err)
	}
	return res.RowsAffected()
}

// LoadCounters implements webauthnverify.CounterStore.
func (db *DB) LoadCounters() (map[string]uint32, error) {
	rows, err := db.sql.Query(`SELECT credential_id, sign_count FROM webauthn_counters`)
	if err != nil {
		return nil, fmt.Errorf("executordb: load counters: %w", err)
	}
	defer rows.Close()
	out := map[string]uint32{}
	for rows.Next() {
		var id []byte
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("executordb: load counters: %w", err)
		}
		if n < 0 || n > 1<<32-1 {
			return nil, fmt.Errorf("executordb: stored counter %d out of range", n)
		}
		out[string(id)] = uint32(n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: load counters: %w", err)
	}
	return out, nil
}

// SaveCounter implements webauthnverify.CounterStore. A value lower than
// the stored one is ignored, so the stored counter never decreases.
func (db *DB) SaveCounter(credentialID []byte, count uint32) error {
	if len(credentialID) == 0 || len(credentialID) > maxCredentialID {
		return fmt.Errorf("executordb: credential ID length %d outside 1..%d", len(credentialID), maxCredentialID)
	}
	_, err := db.sql.Exec(`INSERT INTO webauthn_counters (credential_id, sign_count, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(credential_id) DO UPDATE SET sign_count = excluded.sign_count, updated_at = excluded.updated_at
		WHERE excluded.sign_count > webauthn_counters.sign_count`,
		credentialID, int64(count), db.now().Unix())
	if err != nil {
		return fmt.Errorf("executordb: save counter: %w", err)
	}
	return nil
}

// --- migrations -------------------------------------------------------------

type migration struct {
	version int
	name    string
	sql     string
}

var migrationName = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

func loadMigrations() ([]migration, error) { return loadMigrationsFrom(migrationFS, "migrations") }

// loadMigrationsFrom reads dir of fsys. Every file must be NNNN_name.sql and
// versions must be unique; anything else is an error, so a misnamed
// migration can never be skipped silently.
func loadMigrationsFrom(fsys fs.FS, dir string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("executordb: read migrations: %w", err)
	}
	seen := map[int]string{}
	var out []migration
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("executordb: unexpected directory %s in migrations", e.Name())
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("executordb: migration file %s does not match NNNN_name.sql", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("executordb: duplicate migration version %04d (%s, %s)", v, prev, e.Name())
		}
		seen[v] = e.Name()
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("executordb: read migration %s: %w", e.Name(), err)
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// migrateWith applies the pending migrations in version order, each in its
// own transaction together with its schema_migrations row. A database with
// a newer version than the binary knows is refused.
func migrateWith(db *sql.DB, migrations []migration, now func() time.Time) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("executordb: create schema_migrations: %w", err)
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("executordb: read schema version: %w", err)
	}
	newest := 0
	if len(migrations) > 0 {
		newest = migrations[len(migrations)-1].version
	}
	if current > newest {
		return fmt.Errorf("executordb: database schema version %d is newer than this binary supports (%d); refusing to open", current, newest)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := apply(db, m, now); err != nil {
			return err
		}
	}
	return nil
}

func apply(db *sql.DB, m migration, now func() time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("executordb: migration %04d: begin: %w", m.version, err)
	}
	if _, err := tx.Exec(m.sql); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("executordb: migration %04d (%s) failed and was rolled back: %w", m.version, m.name, err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, m.version, now().Unix()); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("executordb: migration %04d: record: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: migration %04d: commit: %w", m.version, err)
	}
	return nil
}

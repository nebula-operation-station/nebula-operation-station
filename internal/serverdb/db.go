// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serverdb opens the Nebula server SQLite database and applies
// forward-only, embedded migrations.
//
// Migrations are SQL files named NNNN_name.sql embedded in the binary.
// Every .sql file in migrations/ must match that pattern; anything else is
// an error at startup. They are applied in version order, each in its own
// transaction, and recorded in the schema_migrations table. A failing
// migration rolls back completely and Open returns an error naming the
// version. Opening a database whose schema version is newer than the newest
// migration this binary knows fails with a clear error.
package serverdb

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DefaultBusyTimeout is the default SQLite busy timeout.
const DefaultBusyTimeout = 5 * time.Second

// migration is a single embedded migration.
type migration struct {
	version int
	name    string
	sql     string
}

// Options configures Open.
type Options struct {
	// Now returns the current time, used for the applied_at column of newly
	// applied migrations. Defaults to time.Now.
	Now func() time.Time
	// BusyTimeout is the SQLite busy timeout. Defaults to DefaultBusyTimeout.
	BusyTimeout time.Duration
}

// Open opens the SQLite database at path with WAL, foreign keys enabled and
// a busy timeout, applies any pending migrations, and returns the database.
// The caller is responsible for closing it.
func Open(path string) (*sql.DB, error) {
	return OpenWithOptions(path, Options{})
}

// OpenWithOptions is like Open but uses the provided options.
//
// path must not contain '?' or '#': the pragmas are appended to the path
// as a DSN query string, so either character in the path would silently
// change which pragmas apply.
func OpenWithOptions(path string, opts Options) (*sql.DB, error) {
	if strings.ContainsAny(path, "#?") {
		return nil, fmt.Errorf("serverdb: open %s: path must not contain '?' or '#'", path)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	busy := opts.BusyTimeout
	if busy <= 0 {
		busy = DefaultBusyTimeout
	}

	// The pragmas are set on every connection in the pool via the DSN, so
	// foreign_keys and busy_timeout hold for all connections, not just the
	// first one.
	dsn := fmt.Sprintf(
		"%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(%d)",
		path, int(busy.Milliseconds()),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("serverdb: open %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("serverdb: open %s: %w", path, err)
	}

	if err := migrate(db, now); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// migrate loads the embedded migrations and applies any pending ones to db,
// recording them in schema_migrations. It is idempotent: already-applied
// migrations are skipped.
func migrate(db *sql.DB, now func() time.Time) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	return migrateWith(db, migrations, now)
}

// migrateWith applies the given migrations to db. See migrate for the
// contract: in version order, each in its own transaction, recorded in
// schema_migrations, a newer database version is refused.
func migrateWith(db *sql.DB, migrations []migration, now func() time.Time) error {
	// Bootstrap the bookkeeping table. This is not a versioned migration;
	// it must exist before we can read the current version.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("serverdb: create schema_migrations: %w", err)
	}

	if len(migrations) == 0 {
		return nil
	}

	current, err := currentVersion(db)
	if err != nil {
		return err
	}

	// A database migrated by a newer binary must not be opened by an older
	// one: applying nothing would leave it inconsistent, and we cannot know
	// what the newer schema expects.
	newest := migrations[len(migrations)-1].version
	if current > newest {
		return fmt.Errorf("serverdb: database schema version %d is newer than this binary supports (%d); refusing to open", current, newest)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyMigration(db, m, now); err != nil {
			return err
		}
	}
	return nil
}

// currentVersion returns the highest applied migration version, or 0 if
// none.
func currentVersion(db *sql.DB) (int, error) {
	var v int
	err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("serverdb: read schema version: %w", err)
	}
	return v, nil
}

// applyMigration runs a single migration in its own transaction and records
// it. If the migration fails, the transaction is rolled back and the error
// names the version.
func applyMigration(db *sql.DB, m migration, now func() time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("serverdb: migration %04d %s: begin: %w", m.version, m.name, err)
	}

	if _, err := tx.Exec(m.sql); err != nil {
		tx.Rollback()
		return fmt.Errorf("serverdb: migration %04d %s failed, rolled back: %w", m.version, m.name, err)
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, now().UTC().Format(time.RFC3339),
	); err != nil {
		tx.Rollback()
		return fmt.Errorf("serverdb: migration %04d %s: record: %w", m.version, m.name, err)
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return fmt.Errorf("serverdb: migration %04d %s: commit: %w", m.version, m.name, err)
	}
	return nil
}

// migrationName matches NNNN_name.sql, where NNNN is the zero-padded
// version.
var migrationName = regexp.MustCompile(`^(\d{4})_.+\.sql$`)

// loadMigrations reads the embedded migration files.
func loadMigrations() ([]migration, error) {
	return loadMigrationsFrom(migrationFS, "migrations")
}

// loadMigrationsFrom reads the migration files in dir of fsys, parses
// their versions, and returns them sorted by version. Any file that does
// not match NNNN_name.sql is an error, as is a duplicate version:
// silently ignoring either would let a migration sit in the release tree
// without ever being applied.
func loadMigrationsFrom(fsys fs.FS, dir string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("serverdb: read migrations: %w", err)
	}

	var migrations []migration
	seen := make(map[int]string)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m, ok := parseMigrationName(e.Name())
		if !ok {
			return nil, fmt.Errorf("serverdb: migration file %s does not match NNNN_name.sql", e.Name())
		}
		if prev, dup := seen[m.version]; dup {
			return nil, fmt.Errorf("serverdb: duplicate migration version %04d (%s and %s)", m.version, prev, e.Name())
		}
		seen[m.version] = e.Name()
		data, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("serverdb: read migration %s: %w", e.Name(), err)
		}
		m.sql = string(data)
		migrations = append(migrations, m)
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

// parseMigrationName splits NNNN_name.sql into a migration. The boolean
// result is false for names that do not conform.
func parseMigrationName(name string) (migration, bool) {
	m := migrationName.FindStringSubmatch(name)
	if m == nil {
		return migration{}, false
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return migration{}, false
	}
	return migration{version: v, name: name}, true
}

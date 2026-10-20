// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LatestVersion is the newest schema version this binary knows.
func LatestVersion() (int, error) {
	m, err := loadMigrations()
	if err != nil || len(m) == 0 {
		return 0, err
	}
	return m[len(m)-1].version, nil
}

// Snapshot writes a consistent copy of the database to dst (which must not
// exist) with VACUUM INTO, then checks the copy with PRAGMA
// integrity_check and returns its schema version. The executor holds an
// exclusive lock on executor.db, so a backup can only be made this way.
func (db *DB) Snapshot(dst string) (int, error) {
	if !filepath.IsAbs(dst) || strings.ContainsAny(dst, "?#") {
		return 0, errors.New("executordb: snapshot path must be absolute, without ? or #")
	}
	if _, err := os.Lstat(dst); err == nil {
		return 0, errors.New("executordb: snapshot target exists")
	}
	if _, err := db.sql.Exec(`VACUUM INTO ?`, dst); err != nil {
		return 0, fmt.Errorf("executordb: snapshot: %w", err)
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return 0, err
	}
	return CheckFile(dst)
}

// CheckFile opens a database file read-only, runs PRAGMA integrity_check
// and returns its schema version.
func CheckFile(path string) (int, error) {
	if strings.ContainsAny(path, "?#") {
		return 0, errors.New("executordb: path must not contain ? or #")
	}
	c, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return 0, err
	}
	defer c.Close()
	var res string
	if err := c.QueryRow(`PRAGMA integrity_check`).Scan(&res); err != nil {
		return 0, fmt.Errorf("executordb: integrity check: %w", err)
	}
	if res != "ok" {
		return 0, fmt.Errorf("executordb: integrity check failed: %s", res)
	}
	var v int
	if err := c.QueryRow(`SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("executordb: schema version: %w", err)
	}
	return v, nil
}

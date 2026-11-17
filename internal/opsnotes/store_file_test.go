// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fsguard"
)

// privateTestDir returns a fresh directory of mode 0700 under t.TempDir. The
// temporary directory itself may be group-writable under the test umask, and
// Open refuses a database whose directory is not private.
func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "notes")
	if err := fsguard.EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	return dir
}

// TestOpenCreatesPrivateDatabaseFiles checks that the notes database and its
// -wal and -shm files are private (0600, owned by us), as executordb's are.
func TestOpenCreatesPrivateDatabaseFiles(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "notes.db")
	s, err := Open(path, (&fakeClock{t: baseTime}).Now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, _, err := s.Put(context.Background(), newFakeResolver(), validFix(), testSnapshot); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := fsguard.CheckPrivateFile(p); err != nil && !os.IsNotExist(err) {
			t.Errorf("%s is not private: %v", p, err)
		}
	}
	if err := fsguard.CheckPrivateFile(path); err != nil {
		t.Errorf("database file: %v", err)
	}
}

// TestOpenRefusesLooseDatabaseFile checks that an existing database with a
// group- or world-readable mode is refused, never repaired silently.
func TestOpenRefusesLooseDatabaseFile(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "notes.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if s, err := Open(path, nil); err == nil {
		_ = s.Close()
		t.Fatalf("Open of a 0644 database succeeded; want refusal")
	}
}

// TestOpenRefusesLooseDirectory checks that the directory holding the
// database must be private (0700, owned by us).
func TestOpenRefusesLooseDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if s, err := Open(filepath.Join(dir, "notes.db"), nil); err == nil {
		_ = s.Close()
		t.Fatalf("Open in a 0755 directory succeeded; want refusal")
	}
}

// TestOpenRefusesPathThatChangesDSN checks that a path which would start the
// DSN's query or fragment is refused, so no pragma can be injected or
// overridden (the foreign key cascade depends on foreign_keys).
func TestOpenRefusesPathThatChangesDSN(t *testing.T) {
	dir := privateTestDir(t)
	for _, name := range []string{"x?foreign_keys=0.db", "x#.db", "x?_journal_mode=DELETE"} {
		if s, err := Open(filepath.Join(dir, name), nil); err == nil {
			_ = s.Close()
			t.Errorf("Open(%q) succeeded; want refusal", name)
		}
	}
}

// TestOpenRefusesRelativePath checks that the database path must be absolute,
// so the directory check applies to the directory the file really lives in.
func TestOpenRefusesRelativePath(t *testing.T) {
	if s, err := Open("notes.db", nil); err == nil {
		_ = s.Close()
		t.Fatalf("Open of a relative path succeeded; want refusal")
	}
}

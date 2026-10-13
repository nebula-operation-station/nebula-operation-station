// SPDX-License-Identifier: AGPL-3.0-or-later

package fsguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDir(t *testing.T) {
	base := t.TempDir()
	p := filepath.Join(base, "private")
	if err := EnsurePrivateDir(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(p); err == nil {
		t.Fatal("group-readable directory accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(link); err == nil {
		t.Fatal("symlink accepted")
	}
	f := filepath.Join(base, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(f); err == nil {
		t.Fatal("file accepted as directory")
	}
}

func TestPrivateFile(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	ok := filepath.Join(base, "state.db")
	if err := os.WriteFile(ok, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(ok); err != nil {
		t.Fatalf("0600 file rejected: %v", err)
	}

	for name, mode := range map[string]os.FileMode{"group-readable": 0o640, "world-readable": 0o604, "group-writable": 0o620} {
		p := filepath.Join(base, name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckPrivateFile(p); err == nil {
			t.Errorf("%s file (mode %o) accepted", name, mode)
		}
	}

	link := filepath.Join(base, "link.db")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(link); err == nil {
		t.Error("symlink accepted as private file")
	}
	if err := CheckPrivateFile(base); err == nil {
		t.Error("directory accepted as private file")
	}
	if err := CheckPrivateFile(filepath.Join(base, "missing.db")); !os.IsNotExist(err) {
		t.Errorf("missing file: got %v, want a not-exist error", err)
	}
}

func TestCreatePrivateFile(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(base, "state.db")
	if err := EnsurePrivateFile(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("created mode %o, want 0600 regardless of umask", fi.Mode().Perm())
	}
	// Existing private file: accepted unchanged.
	if err := EnsurePrivateFile(p); err != nil {
		t.Fatalf("existing private file rejected: %v", err)
	}
	// Existing file with loose mode is refused, never silently fixed.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(p); err == nil {
		t.Fatal("existing 0644 file accepted")
	}
	// A symlink at the path is refused, even if it points to a private file.
	target := filepath.Join(base, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(link); err == nil {
		t.Fatal("symlink accepted")
	}
}

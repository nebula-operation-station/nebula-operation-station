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

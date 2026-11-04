// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// blockSetgidChmod makes every directory chmod fail with EPERM, as the
// collector's systemd unit (RestrictSUIDSGID=yes) does for setgid modes.
func blockSetgidChmod(t *testing.T) {
	t.Helper()
	orig := chmodDir
	chmodDir = func(*os.File, os.FileMode) error { return unix.EPERM }
	t.Cleanup(func() { chmodDir = orig })
}

func openDir(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirModeLeavesProvisionedModeAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	want := os.FileMode(0o770) | os.ModeSetgid
	mkdirMode(t, dir, want)
	blockSetgidChmod(t)
	if err := ensureDirMode(openDir(t, dir), want); err != nil {
		t.Fatalf("ensureDirMode on a provisioned directory: %v", err)
	}
}

func TestEnsureDirModeRepairsWrongMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	mkdirMode(t, dir, 0o700)
	want := os.FileMode(0o770) | os.ModeSetgid
	if err := ensureDirMode(openDir(t, dir), want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode() & dirModeMask; got != want {
		t.Fatalf("mode = %v, want %v", got, want)
	}
}

func TestEnsureDirModeExplainsBlockedChmod(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	mkdirMode(t, dir, 0o700)
	blockSetgidChmod(t)
	err := ensureDirMode(openDir(t, dir), os.FileMode(0o770)|os.ModeSetgid)
	if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "install.sh") {
		t.Fatalf("err = %v, want EPERM with a hint to install.sh", err)
	}
}

// TestSpoolsOpenUnderSetgidRestriction is the regression for the lab
// failure "chmod spool root: operation not permitted": with every
// directory created as install.sh does, the collector's spool and live
// handoff open although setgid chmods are refused.
func TestSpoolsOpenUnderSetgidRestriction(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pve")
	mkdirMode(t, root, spoolRootMode)
	mkdirMode(t, filepath.Join(root, resultsDirName), spoolDirMode)
	mkdirMode(t, filepath.Join(root, guestNetDirName), spoolDirMode)
	mkdirMode(t, filepath.Join(root, requestsDirName), requestsDirMode)
	mkdirMode(t, filepath.Join(root, liveDirName), liveDirMode)
	blockSetgidChmod(t)

	s, err := NewSpool(root)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	defer s.Close()
	gn, err := s.guestNetDir()
	if err != nil {
		t.Fatalf("guestNetDir: %v", err)
	}
	gn.Close()
	h, err := NewLiveHandoff(root)
	if err != nil {
		t.Fatalf("NewLiveHandoff: %v", err)
	}
	h.Close()
}

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
	expectTempDirOwnership(t, dir)
	blockSetgidChmod(t)
	if err := ensureDirMode(openDir(t, dir), want); err != nil {
		t.Fatalf("ensureDirMode on a provisioned directory: %v", err)
	}
}

func TestEnsureDirModeRepairsWrongMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	mkdirMode(t, dir, 0o700)
	expectTempDirOwnership(t, dir)
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
	expectTempDirOwnership(t, dir)
	blockSetgidChmod(t)
	err := ensureDirMode(openDir(t, dir), os.FileMode(0o770)|os.ModeSetgid)
	if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "install.sh") {
		t.Fatalf("err = %v, want EPERM with a hint to install.sh", err)
	}
}

// expectOwnership makes ensureDirMode expect uid and gid as the collector's
// spool ownership.
func expectOwnership(t *testing.T, uid, gid uint32) {
	t.Helper()
	orig := spoolOwnership
	spoolOwnership = func() (uint32, uint32, error) { return uid, gid, nil }
	t.Cleanup(func() { spoolOwnership = orig })
}

// countChmods records every directory chmod without changing anything.
func countChmods(t *testing.T) *int {
	t.Helper()
	n := new(int)
	orig := chmodDir
	chmodDir = func(*os.File, os.FileMode) error { *n++; return nil }
	t.Cleanup(func() { chmodDir = orig })
	return n
}

func dirOwner(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Uid, st.Gid
}

// expectTempDirOwnership makes ensureDirMode expect the owner of dir, which
// is the owner of every directory created inside dir (a new directory gets
// the process's primary GID, or the parent's GID under a setgid parent).
// Without the stub, defaultSpoolOwnership expects the nebula-rpc GID on
// hosts where the test user is a member of that group, and the TempDir
// directories fail the ownership check; the stub keeps the tests
// independent of the host's group database.
func expectTempDirOwnership(t *testing.T, dir string) {
	t.Helper()
	uid, gid := dirOwner(t, dir)
	expectOwnership(t, uid, gid)
}

// foreignDir returns a directory owned by a UID other than the test's:
// "/" (root) for an unprivileged test, and a directory chowned to nobody
// when the test runs as root.
func foreignDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	if os.Geteuid() != 0 {
		return "/"
	}
	dir := filepath.Join(t.TempDir(), "foreign")
	mkdirMode(t, dir, mode)
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestEnsureDirModeRejectsForeignOwnedDir: a spool directory pre-created by
// another UID is refused, even with exactly the wanted mode and the
// expected group, and is never chmodded.
func TestEnsureDirModeRejectsForeignOwnedDir(t *testing.T) {
	want := os.FileMode(0o770) | os.ModeSetgid
	dir := foreignDir(t, want)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, gid := dirOwner(t, dir)
	expectOwnership(t, uint32(os.Geteuid()), gid)
	chmods := countChmods(t)
	for _, mode := range []os.FileMode{fi.Mode() & dirModeMask, want} {
		err := ensureDirMode(openDir(t, dir), mode)
		if !errors.Is(err, ErrSpoolOwnership) {
			t.Fatalf("mode %v: err = %v, want ErrSpoolOwnership", mode, err)
		}
	}
	if *chmods != 0 {
		t.Fatalf("foreign directory chmodded %d times", *chmods)
	}
}

// TestEnsureDirModeChecksOwnerAndGroup: with the mode exactly right, only
// the collector UID together with the shared group is accepted.
func TestEnsureDirModeChecksOwnerAndGroup(t *testing.T) {
	want := os.FileMode(0o770) | os.ModeSetgid
	dir := filepath.Join(t.TempDir(), "d")
	mkdirMode(t, dir, want)
	uid, gid := dirOwner(t, dir)
	cases := []struct {
		name     string
		uid, gid uint32
		ok       bool
	}{
		{"collector and shared group", uid, gid, true},
		{"other owner", uid + 1, gid, false},
		{"other group", uid, gid + 1, false},
		{"other owner and group", uid + 1, gid + 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expectOwnership(t, c.uid, c.gid)
			chmods := countChmods(t)
			err := ensureDirMode(openDir(t, dir), want)
			if c.ok && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !c.ok && !errors.Is(err, ErrSpoolOwnership) {
				t.Fatalf("err = %v, want ErrSpoolOwnership", err)
			}
			if *chmods != 0 {
				t.Fatalf("chmodded %d times", *chmods)
			}
		})
	}
}

// TestEnsureDirModeOwnershipLookupFailureFailsClosed: when the expected
// ownership cannot be determined, no directory is accepted.
func TestEnsureDirModeOwnershipLookupFailureFailsClosed(t *testing.T) {
	want := os.FileMode(0o770) | os.ModeSetgid
	dir := filepath.Join(t.TempDir(), "d")
	mkdirMode(t, dir, want)
	boom := errors.New("group database unavailable")
	orig := spoolOwnership
	spoolOwnership = func() (uint32, uint32, error) { return 0, 0, boom }
	t.Cleanup(func() { spoolOwnership = orig })
	if err := ensureDirMode(openDir(t, dir), want); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}

// supersetModes are modes that contain every bit of 0o770|setgid plus more.
var supersetModes = []os.FileMode{
	os.FileMode(0o777) | os.ModeSetgid,
	os.FileMode(0o771) | os.ModeSetgid,
	os.FileMode(0o770) | os.ModeSetgid | os.ModeSticky,
	os.FileMode(0o770) | os.ModeSetgid | os.ModeSetuid,
	os.FileMode(0o777) | os.ModeSetgid | os.ModeSetuid | os.ModeSticky,
}

// TestEnsureDirModeRejectsSupersetModeWhenChmodBlocked: a superset of the
// wanted mode is never accepted; if it cannot be repaired the open fails.
func TestEnsureDirModeRejectsSupersetModeWhenChmodBlocked(t *testing.T) {
	want := os.FileMode(0o770) | os.ModeSetgid
	for _, mode := range supersetModes {
		dir := filepath.Join(t.TempDir(), "d")
		mkdirMode(t, dir, mode)
		if got := mustMode(t, dir); got != mode {
			t.Fatalf("setup: mode = %v, want %v", got, mode)
		}
		expectTempDirOwnership(t, dir)
		orig := chmodDir
		chmodDir = func(*os.File, os.FileMode) error { return unix.EPERM }
		err := ensureDirMode(openDir(t, dir), want)
		chmodDir = orig
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("mode %v: err = %v, want EPERM", mode, err)
		}
	}
}

// TestEnsureDirModeRepairsSupersetModeExactly: with chmod allowed, a
// superset mode is changed to exactly the wanted mode.
func TestEnsureDirModeRepairsSupersetModeExactly(t *testing.T) {
	want := os.FileMode(0o770) | os.ModeSetgid
	for _, mode := range supersetModes {
		dir := filepath.Join(t.TempDir(), "d")
		mkdirMode(t, dir, mode)
		expectTempDirOwnership(t, dir)
		if err := ensureDirMode(openDir(t, dir), want); err != nil {
			t.Fatalf("mode %v: %v", mode, err)
		}
		if got := mustMode(t, dir); got != want {
			t.Fatalf("mode %v repaired to %v, want exactly %v", mode, got, want)
		}
	}
}

// TestSpoolsRefuseForeignOwnedRoot: the collector's spool and live handoff
// do not open over a directory that is not owned by the collector.
func TestSpoolsRefuseForeignOwnedRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pve")
	mkdirMode(t, root, spoolRootMode)
	uid, gid := dirOwner(t, root)
	expectOwnership(t, uid+1, gid)
	if s, err := NewSpool(root); !errors.Is(err, ErrSpoolOwnership) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("NewSpool: err = %v, want ErrSpoolOwnership", err)
	}
	if h, err := NewLiveHandoff(root); !errors.Is(err, ErrSpoolOwnership) {
		if err == nil {
			h.Close()
		}
		t.Fatalf("NewLiveHandoff: err = %v, want ErrSpoolOwnership", err)
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode() & dirModeMask
}

// TestSpoolsOpenUnderSetgidRestriction is the regression for the lab
// failure "chmod spool root: operation not permitted": with every
// directory created as install.sh does, the collector's spool and live
// handoff open although setgid chmods are refused.
func TestSpoolsOpenUnderSetgidRestriction(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pve")
	mkdirMode(t, root, spoolRootMode)
	expectTempDirOwnership(t, root)
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

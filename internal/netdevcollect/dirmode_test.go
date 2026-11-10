// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// expectOwnership makes the writer expect uid and gid as the spool owner.
func expectOwnership(t *testing.T, uid, gid uint32) {
	t.Helper()
	orig := spoolOwnership
	spoolOwnership = func() (uint32, uint32, error) { return uid, gid, nil }
	t.Cleanup(func() { spoolOwnership = orig })
}

// expectDirOwnership makes the writer expect the actual owner of path, so
// tests do not depend on the host's group database.
func expectDirOwnership(t *testing.T, path string) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	expectOwnership(t, st.Uid, st.Gid)
}

// blockChmod makes every directory chmod fail with EPERM, as the
// collector's systemd unit (RestrictSUIDSGID=yes) does for setgid modes.
func blockChmod(t *testing.T) *int {
	t.Helper()
	n := new(int)
	orig := chmodDir
	chmodDir = func(*os.File, os.FileMode) error { *n++; return unix.EPERM }
	t.Cleanup(func() { chmodDir = orig })
	return n
}

func dirMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode() & dirModeMask
}

func TestWriterLeavesProvisionedModeAlone(t *testing.T) {
	s := newSpool(t)
	chmods := blockChmod(t)
	mustWrite(t, s, testDevice, testRead, `{}`)
	if *chmods != 0 {
		t.Fatalf("provisioned directory was chmodded %d times", *chmods)
	}
}

func TestWriterRepairsWrongModeExactly(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o777, 0o777 | os.ModeSetgid | os.ModeSticky} {
		s := newSpool(t)
		if err := os.Chmod(s.Dir, mode); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, s, testDevice, testRead, `{}`)
		if got := dirMode(t, s.Dir); got != spoolDirMode {
			t.Fatalf("mode %v repaired to %v, want %v", mode, got, spoolDirMode)
		}
	}
}

func TestWriterExplainsBlockedChmod(t *testing.T) {
	s := newSpool(t)
	if err := os.Chmod(s.Dir, 0o777); err != nil {
		t.Fatal(err)
	}
	blockChmod(t)
	_, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{}`))
	if !errors.Is(err, ErrDirMode) || !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "install.sh") {
		t.Fatalf("err = %v, want ErrDirMode and EPERM with a hint to install.sh", err)
	}
	if got := dirNames(t, s.Dir); len(got) != 0 {
		t.Fatalf("write into a wrong-mode directory left %v", got)
	}
}

func TestReaderRefusesWrongModeAndNeverChanges(t *testing.T) {
	s := newSpool(t)
	name := mustWrite(t, s, testDevice, testRead, `{}`)
	chmods := blockChmod(t)
	for _, mode := range []os.FileMode{0o777 | os.ModeSetgid, 0o770, 0o750 | os.ModeSetgid, 0o770 | os.ModeSetgid | os.ModeSticky} {
		if err := os.Chmod(s.Dir, mode); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if _, err := s.List(ctx); !errors.Is(err, ErrDirMode) {
			t.Errorf("%v: List err = %v, want ErrDirMode", mode, err)
		}
		if _, err := s.Take(ctx, name); !errors.Is(err, ErrDirMode) {
			t.Errorf("%v: Take err = %v, want ErrDirMode", mode, err)
		}
		if err := s.Discard(ctx, name); !errors.Is(err, ErrDirMode) {
			t.Errorf("%v: Discard err = %v, want ErrDirMode", mode, err)
		}
		if got := dirMode(t, s.Dir); got != mode {
			t.Errorf("reader changed mode %v to %v", mode, got)
		}
	}
	if *chmods != 0 {
		t.Fatalf("reader attempted %d chmods", *chmods)
	}
}

func TestWriterRefusesForeignOwnership(t *testing.T) {
	s := newSpool(t)
	var st unix.Stat_t
	if err := unix.Stat(s.Dir, &st); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ uid, gid uint32 }{{st.Uid + 1, st.Gid}, {st.Uid, st.Gid + 1}} {
		expectOwnership(t, c.uid, c.gid)
		chmods := blockChmod(t)
		if _, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{}`)); !errors.Is(err, ErrSpoolOwnership) {
			t.Fatalf("expected %d:%d, err = %v, want ErrSpoolOwnership", c.uid, c.gid, err)
		}
		if *chmods != 0 || len(dirNames(t, s.Dir)) != 0 {
			t.Fatal("foreign-owned spool was changed")
		}
	}
}

func TestWriterOwnershipLookupFailureFailsClosed(t *testing.T) {
	s := newSpool(t)
	orig := spoolOwnership
	spoolOwnership = func() (uint32, uint32, error) { return 0, 0, errors.New("group database unavailable") }
	t.Cleanup(func() { spoolOwnership = orig })
	if _, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{}`)); err == nil {
		t.Fatal("Write succeeded without known ownership")
	}
	if got := dirNames(t, s.Dir); len(got) != 0 {
		t.Fatalf("write left %v", got)
	}
}

func TestMissingSpoolDirIsNotCreated(t *testing.T) {
	dir := t.TempDir() + "/missing"
	s := &Spool{Dir: dir, Now: fixedNow(testTime)}
	if _, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{}`)); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("err = %v, want ENOENT", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool directory was created: %v", err)
	}
}

// TestDefaultSpoolOwnership checks the production ownership rule with an
// injected group lookup and supplementary group list.
func TestDefaultSpoolOwnership(t *testing.T) {
	uid := uint32(os.Geteuid())
	egid := uint32(os.Getegid())
	sharedGID := egid + 1
	if sharedGID == 0 {
		sharedGID = 1
	}
	group := func(gid string) *user.Group { return &user.Group{Name: spoolGroupName, Gid: gid} }
	cases := []struct {
		name             string
		group            *user.Group
		lookupErr        error
		supplementary    []int
		supplementaryErr error
		wantGID          uint32
		wantErr          bool
	}{
		{name: "group is the primary group", group: group(strconv.FormatUint(uint64(egid), 10)), wantGID: egid},
		{name: "group is a supplementary group", group: group(strconv.FormatUint(uint64(sharedGID), 10)), supplementary: []int{int(sharedGID)}, wantGID: sharedGID},
		{name: "not a member falls back to the effective GID", group: group(strconv.FormatUint(uint64(sharedGID), 10)), wantGID: egid},
		{name: "missing group falls back to the effective GID", lookupErr: user.UnknownGroupError(spoolGroupName), wantGID: egid},
		{name: "lookup error fails closed", lookupErr: errors.New("group database unavailable"), wantErr: true},
		{name: "unparsable GID fails closed", group: group("not-a-gid"), wantErr: true},
		{name: "supplementary lookup error fails closed", group: group(strconv.FormatUint(uint64(sharedGID), 10)), supplementaryErr: errors.New("cannot read groups"), wantErr: true},
	}
	origLookup, origGroups := spoolGroupLookup, spoolSupplementaryGroups
	t.Cleanup(func() { spoolGroupLookup, spoolSupplementaryGroups = origLookup, origGroups })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spoolGroupLookup = func(string) (*user.Group, error) { return tc.group, tc.lookupErr }
			spoolSupplementaryGroups = func() ([]int, error) { return tc.supplementary, tc.supplementaryErr }
			gotUID, gotGID, err := defaultSpoolOwnership()
			if tc.wantErr {
				if err == nil {
					t.Fatal("ownership lookup did not fail closed")
				}
				return
			}
			if err != nil || gotUID != uid || gotGID != tc.wantGID {
				t.Fatalf("= %d:%d, %v; want %d:%d", gotUID, gotGID, err, uid, tc.wantGID)
			}
		})
	}
}

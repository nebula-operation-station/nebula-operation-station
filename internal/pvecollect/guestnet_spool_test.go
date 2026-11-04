// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guestNetPath(s *Spool, name string) string {
	return filepath.Join(s.root, guestNetDirName, name)
}

func TestGuestNetSpoolRoundTrip(t *testing.T) {
	ctx := context.Background()
	w := newTestSpool(t)
	rec := validGuestNetRecord()
	name, err := w.WriteGuestNet(ctx, rec)
	if err != nil {
		t.Fatalf("WriteGuestNet: %v", err)
	}
	if name != "pve-lab.obs-00000000001700000000.json" {
		t.Fatalf("name = %q", name)
	}
	fi, err := os.Stat(guestNetPath(w, name))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != spoolFileMode {
		t.Fatalf("file mode = %v, want %v", fi.Mode().Perm(), os.FileMode(spoolFileMode))
	}
	di, err := os.Stat(filepath.Join(w.root, guestNetDirName))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode()&(os.ModePerm|os.ModeSetgid) != spoolDirMode {
		t.Fatalf("dir mode = %v, want %v", di.Mode(), spoolDirMode)
	}

	r, err := OpenSpool(w.root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	names, err := r.ListGuestNet(ctx)
	if err != nil || len(names) != 1 || names[0] != name {
		t.Fatalf("ListGuestNet = %v, %v", names, err)
	}
	got, err := r.ReadGuestNet(ctx, name)
	if err != nil {
		t.Fatalf("ReadGuestNet: %v", err)
	}
	if len(got.NICs) != 3 || got.NICs[0].Tap() != "tap101i0" || got.NICs[2].Tap() != "veth200i0" {
		t.Fatalf("ReadGuestNet = %+v", got)
	}
	if err := r.RemoveGuestNet(ctx, name); err != nil {
		t.Fatalf("RemoveGuestNet: %v", err)
	}
	if names, err := r.ListGuestNet(ctx); err != nil || len(names) != 0 {
		t.Fatalf("after remove: %v, %v", names, err)
	}
}

func TestGuestNetReadSideNeverWritesOrCreates(t *testing.T) {
	ctx := context.Background()
	w := newTestSpool(t)
	r, err := OpenSpool(w.root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Without any collector record the directory does not exist yet.
	if names, err := r.ListGuestNet(ctx); err != nil || len(names) != 0 {
		t.Fatalf("ListGuestNet on fresh spool = %v, %v", names, err)
	}
	if _, err := r.WriteGuestNet(ctx, validGuestNetRecord()); err == nil {
		t.Fatal("read-side spool wrote a guest nic record")
	}
	if _, err := os.Lstat(filepath.Join(w.root, guestNetDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read side created the directory: %v", err)
	}
}

func TestGuestNetWriteSupersedesOlderPendingRecords(t *testing.T) {
	ctx := context.Background()
	s := newTestSpool(t)
	old := validGuestNetRecord()
	other := validGuestNetRecord()
	other.Remote = "pve-other"
	for _, rec := range []GuestNetRecord{old, other} {
		if _, err := s.WriteGuestNet(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	newer := validGuestNetRecord()
	newer.ObservedUnix += 60
	newer.NICs = newer.NICs[:1]
	newName, err := s.WriteGuestNet(ctx, newer)
	if err != nil {
		t.Fatal(err)
	}
	names, err := s.ListGuestNet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != newName || !strings.HasPrefix(names[1], "pve-other.") {
		t.Fatalf("pending = %v, want the newest pve-lab record and pve-other", names)
	}
	// A retry of the same snapshot is idempotent, a different one is refused.
	if _, err := s.WriteGuestNet(ctx, newer); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	changed := newer
	changed.NICs = validGuestNetRecord().NICs
	if _, err := s.WriteGuestNet(ctx, changed); err == nil {
		t.Fatal("a different record with the same name replaced the pending one")
	}
}

func TestGuestNetWriteRefusesInvalidRecord(t *testing.T) {
	s := newTestSpool(t)
	rec := validGuestNetRecord()
	rec.NICs[0].VLAN = 5000
	if _, err := s.WriteGuestNet(context.Background(), rec); !errors.Is(err, ErrGuestNetInvalid) {
		t.Fatalf("err = %v, want ErrGuestNetInvalid", err)
	}
}

func TestGuestNetSpoolRefusesSymlinks(t *testing.T) {
	ctx := context.Background()
	t.Run("directory", func(t *testing.T) {
		s := newTestSpool(t)
		target := t.TempDir()
		if err := os.Symlink(target, filepath.Join(s.root, guestNetDirName)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.WriteGuestNet(ctx, validGuestNetRecord()); !errors.Is(err, ErrSymlink) {
			t.Fatalf("write err = %v, want ErrSymlink", err)
		}
		if _, err := s.ListGuestNet(ctx); !errors.Is(err, ErrSymlink) {
			t.Fatalf("list err = %v, want ErrSymlink", err)
		}
		if entries, _ := os.ReadDir(target); len(entries) != 0 {
			t.Fatalf("wrote through the symlink: %v", entries)
		}
	})
	t.Run("file", func(t *testing.T) {
		s := newTestSpool(t)
		name, err := s.WriteGuestNet(ctx, validGuestNetRecord())
		if err != nil {
			t.Fatal(err)
		}
		secret := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(secret, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := "pve-lab.obs-00000000001700000001.json"
		if err := os.Symlink(secret, guestNetPath(s, link)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ListGuestNet(ctx); !errors.Is(err, ErrSymlink) {
			t.Fatalf("list err = %v, want ErrSymlink", err)
		}
		if _, err := s.ReadGuestNet(ctx, link); !errors.Is(err, ErrSymlink) {
			t.Fatalf("read err = %v, want ErrSymlink", err)
		}
		if err := s.RemoveGuestNet(ctx, link); !errors.Is(err, ErrSymlink) {
			t.Fatalf("remove err = %v, want ErrSymlink", err)
		}
		if _, err := s.ReadGuestNet(ctx, name); err != nil {
			t.Fatalf("regular record unreadable: %v", err)
		}
	})
}

func TestGuestNetReadRejectsHostileFiles(t *testing.T) {
	ctx := context.Background()
	s := newTestSpool(t)
	name, err := s.WriteGuestNet(ctx, validGuestNetRecord())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(guestNetPath(s, name))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, file, body string
		want             error
	}{
		{"oversize", "pve-lab.obs-00000000001700000002.json", strings.Repeat(" ", MaxGuestNetBytes+1), ErrOversize},
		{"garbage", "pve-lab.obs-00000000001700000003.json", "not json", ErrGuestNetInvalid},
		{"remote mismatch", "pve-evil.obs-00000000001700000000.json", string(raw), ErrGuestNetInvalid},
		{"time mismatch", "pve-lab.obs-00000000001700000004.json", string(raw), ErrGuestNetInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(guestNetPath(s, tc.file), []byte(tc.body), 0o640); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ReadGuestNet(ctx, tc.file); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	for _, bad := range []string{"../results/x.json", "pve-lab.json", ".tmp-x", "PVE.obs-00000000001700000000.json", "pve-lab.obs-1.json"} {
		if _, err := s.ReadGuestNet(ctx, bad); !errors.Is(err, ErrBadName) {
			t.Errorf("ReadGuestNet(%q) err = %v, want ErrBadName", bad, err)
		}
		if err := s.RemoveGuestNet(ctx, bad); !errors.Is(err, ErrBadName) {
			t.Errorf("RemoveGuestNet(%q) err = %v, want ErrBadName", bad, err)
		}
	}
	// Malformed names and non-regular entries are not listed.
	if err := os.WriteFile(guestNetPath(s, "README"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(guestNetPath(s, "pve-dir.obs-00000000001700000000.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	names, err := s.ListGuestNet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "README" || strings.HasPrefix(n, "pve-dir.") {
			t.Fatalf("listed %q", n)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package iconstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleIcon(t *testing.T) Icon {
	t.Helper()
	ic, err := Sanitize(encodePNG(t, testImage(50, 30)))
	if err != nil {
		t.Fatal(err)
	}
	return ic
}

func TestStorePutWritesBothSizes(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ic := sampleIcon(t)
	if err := s.Put(context.Background(), ic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for size, want := range map[int][]byte{SmallSize: ic.PNG64, LargeSize: ic.PNG128} {
		p, err := s.Path(ic.SHA256, size)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(p) != dir {
			t.Fatalf("path %q outside store dir", p)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("size %d: stored bytes differ", size)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o640 {
			t.Errorf("size %d: mode %v, want 0640", size, fi.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("store dir has %d entries, want 2 (no temp files left)", len(entries))
	}
}

func TestStorePutIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ic := sampleIcon(t)
	for i := 0; i < 3; i++ {
		if err := s.Put(context.Background(), ic); err != nil {
			t.Fatalf("Put #%d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("store dir has %d entries, want 2", len(entries))
	}
}

func TestStorePutRejectsInconsistentIcon(t *testing.T) {
	good := sampleIcon(t)
	other, err := Sanitize(encodePNG(t, testImage(10, 90)))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ic   Icon
	}{
		{"zero", Icon{}},
		{"path traversal hash", Icon{SHA256: "../../etc/passwd", PNG64: good.PNG64, PNG128: good.PNG128}},
		{"uppercase hash", Icon{SHA256: strings.ToUpper(good.SHA256), PNG64: good.PNG64, PNG128: good.PNG128}},
		{"hash mismatch", Icon{SHA256: other.SHA256, PNG64: good.PNG64, PNG128: good.PNG128}},
		{"sizes swapped", Icon{SHA256: good.SHA256, PNG64: good.PNG128, PNG128: good.PNG128}},
		{"64 not png", Icon{SHA256: good.SHA256, PNG64: []byte("<svg/>"), PNG128: good.PNG128}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Put(context.Background(), c.ic); !errors.Is(err, ErrInvalidIcon) {
				t.Fatalf("err = %v, want ErrInvalidIcon", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("rejected icon left %d files", len(entries))
			}
		})
	}
}

func TestStorePathRejectsBadInput(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	good := sampleIcon(t).SHA256
	for _, c := range []struct {
		hash string
		size int
	}{
		{"", LargeSize},
		{"../x", LargeSize},
		{good[:63], LargeSize},
		{good + "0", LargeSize},
		{strings.Repeat("g", 64), LargeSize},
		{good, 32},
	} {
		if _, err := s.Path(c.hash, c.size); !errors.Is(err, ErrInvalidIcon) {
			t.Errorf("Path(%q, %d): err = %v, want ErrInvalidIcon", c.hash, c.size, err)
		}
	}
}

func TestStorePutRefusesNonRegularTarget(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ic := sampleIcon(t)
	p, err := s.Path(ic.SHA256, SmallSize)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, p); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), ic); err == nil {
		t.Fatal("Put succeeded over a symlink")
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "keep" {
		t.Fatalf("symlink target modified: %q, %v", got, err)
	}
}

func TestNewStoreRequiresDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"", f, filepath.Join(t.TempDir(), "missing")} {
		if _, err := NewStore(d); err == nil {
			t.Errorf("NewStore(%q) succeeded", d)
		}
	}
}

func TestStorePutHonoursCancelledContext(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Put(ctx, sampleIcon(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

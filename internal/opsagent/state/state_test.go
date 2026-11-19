// SPDX-License-Identifier: AGPL-3.0-or-later

package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyCountStartsAtZeroAndAccumulates(t *testing.T) {
	day := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	s := Store{Path: filepath.Join(t.TempDir(), "state.json"), Now: func() time.Time { return day }}
	if n, err := s.Used(); err != nil || n != 0 {
		t.Fatalf("fresh store: used %d, err %v", n, err)
	}
	for _, add := range []int{2, 3} {
		if err := s.Add(add); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.Used(); err != nil || n != 5 {
		t.Fatalf("after adds: used %d, err %v; want 5", n, err)
	}
}

func TestCountResetsOnNextUTCDay(t *testing.T) {
	now := time.Date(2026, 11, 18, 23, 59, 0, 0, time.UTC)
	s := Store{Path: filepath.Join(t.TempDir(), "state.json"), Now: func() time.Time { return now }}
	if err := s.Add(200); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if n, err := s.Used(); err != nil || n != 0 {
		t.Fatalf("next day: used %d, err %v; want 0", n, err)
	}
}

func TestStateFileIsPrivateAndCorruptFileStops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := Store{Path: path, Now: time.Now}
	if err := s.Add(1); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	bad := map[string]string{
		"not json":      "{",
		"unknown field": `{"day":"2026-11-18","llm_calls":1,"x":1}`,
		"negative":      `{"day":"2026-11-18","llm_calls":-4}`,
		"trailing":      `{"day":"2026-11-18","llm_calls":1} {}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Used(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Used: %v, want ErrCorrupt", err)
			}
			if err := s.Add(1); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Add over corrupt file: %v, want ErrCorrupt (no reset)", err)
			}
		})
	}
}

func TestNegativeAddRefused(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "state.json")}
	if err := s.Add(-1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Add(-1): %v, want refusal", err)
	}
}

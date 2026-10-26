// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for per-host pinned quick actions (spec 12, job ui5): ordered
// replace, duplicate rejection, missing-host errors, idempotent add,
// host delete removing the pins, and persistence across a reopen.

package inventory

import (
	"context"
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func TestPinsRoundTrip(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions on empty host: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ListPinnedActions = %+v, want empty", got)
	}

	if err := s.SetPinnedActions(ctx, "web-01", []string{"system.reboot", "core.facts", "package.install_security"}, "admin"); err != nil {
		t.Fatalf("SetPinnedActions: %v", err)
	}
	got, err = s.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions: %v", err)
	}
	want := []PinnedAction{{"system.reboot", 0}, {"core.facts", 1}, {"package.install_security", 2}}
	if len(got) != len(want) {
		t.Fatalf("ListPinnedActions = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pin %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Replace renumbers from zero in the new order.
	if err := s.SetPinnedActions(ctx, "web-01", []string{"core.facts"}, "admin"); err != nil {
		t.Fatalf("SetPinnedActions replace: %v", err)
	}
	got, err = s.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions after replace: %v", err)
	}
	if len(got) != 1 || got[0] != (PinnedAction{"core.facts", 0}) {
		t.Errorf("after replace = %+v, want [core.facts @0]", got)
	}

	// An empty list removes all pins.
	if err := s.SetPinnedActions(ctx, "web-01", nil, "admin"); err != nil {
		t.Fatalf("SetPinnedActions empty: %v", err)
	}
	got, err = s.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions after clear: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("after clear = %+v, want empty", got)
	}
}

func TestPinsRejectDuplicates(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	err := s.SetPinnedActions(ctx, "web-01", []string{"core.facts", "core.facts"}, "admin")
	if err == nil {
		t.Fatal("SetPinnedActions with a duplicate action: want error, got nil")
	}
	got, err := s.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("after rejected set = %+v, want empty (no partial write)", got)
	}
}

func TestPinsMissingHost(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	if _, err := s.ListPinnedActions(ctx, "ghost"); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("ListPinnedActions(ghost) = %v, want ErrHostNotFound", err)
	}
	if err := s.SetPinnedActions(ctx, "ghost", []string{"core.facts"}, "admin"); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("SetPinnedActions(ghost) = %v, want ErrHostNotFound", err)
	}
	if err := s.AddPinnedAction(ctx, "ghost", "core.facts", "admin"); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("AddPinnedAction(ghost) = %v, want ErrHostNotFound", err)
	}
}

func TestPinAddIsIdempotent(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, a := range []string{"core.facts", "system.reboot", "system.reboot", "package.install_security"} {
		if err := s.AddPinnedAction(ctx, "web-01", a, "admin"); err != nil {
			t.Fatalf("AddPinnedAction(%s): %v", a, err)
		}
	}
	got, err := s.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions: %v", err)
	}
	want := []PinnedAction{{"core.facts", 0}, {"system.reboot", 1}, {"package.install_security", 2}}
	if len(got) != len(want) {
		t.Fatalf("ListPinnedActions = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pin %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestHostDeleteRemovesPins(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.SetPinnedActions(ctx, "web-01", []string{"core.facts", "system.reboot"}, "admin"); err != nil {
		t.Fatalf("SetPinnedActions: %v", err)
	}
	if err := s.Delete(ctx, "web-01"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// The pins must be gone from the database, not just hidden behind a
	// missing host: a new host with the same ID starts without pins.
	if _, err := s.Create(ctx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("re-Create: %v", err)
	}
	got, err := s.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("pins after host delete and re-create = %+v, want empty", got)
	}
}

func TestPinPersistence(t *testing.T) {
	s, path := openStore(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.SetPinnedActions(ctx, "web-01", []string{"system.reboot", "core.facts"}, "admin"); err != nil {
		t.Fatalf("SetPinnedActions: %v", err)
	}
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db2, err := serverdb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	s2 := NewWithNow(db2, fixedNow)
	got, err := s2.ListPinnedActions(ctx, "web-01")
	if err != nil {
		t.Fatalf("ListPinnedActions after reopen: %v", err)
	}
	want := []PinnedAction{{"system.reboot", 0}, {"core.facts", 1}}
	if len(got) != len(want) {
		t.Fatalf("after reopen = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pin %d after reopen = %+v, want %+v", i, got[i], want[i])
		}
	}
	var n int
	if err := db2.QueryRow(`SELECT COUNT(*) FROM host_pinned_actions`).Scan(&n); err != nil {
		t.Fatalf("count pins: %v", err)
	}
	if n != 2 {
		t.Errorf("host_pinned_actions rows = %d, want 2", n)
	}
}

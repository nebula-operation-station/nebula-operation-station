// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newVMIDStore(t *testing.T) *FilePveVMIDStore {
	t.Helper()
	return &FilePveVMIDStore{Path: filepath.Join(t.TempDir(), "pve-vmids.json")}
}

var vmidNow = time.Unix(1_800_000_000, 0)

func TestVMIDNextFreeSkipsLiveAndReservedGuests(t *testing.T) {
	s := newVMIDStore(t)
	live := map[uint64]bool{100: true, 101: true, 103: true}
	exp := vmidNow.Add(time.Hour)
	a, err := s.ReserveVMID("lab", "exec-a", 0, live, exp, vmidNow)
	if err != nil || a != 102 {
		t.Fatalf("first = %d %v", a, err)
	}
	b, err := s.ReserveVMID("lab", "exec-b", 0, live, exp, vmidNow)
	if err != nil || b != 104 {
		t.Fatalf("second = %d %v, want 104 (102 reserved, 103 live)", b, err)
	}
	// Another remote has its own VMID space.
	c, err := s.ReserveVMID("other", "exec-c", 0, live, exp, vmidNow)
	if err != nil || c != 102 {
		t.Fatalf("other remote = %d %v", c, err)
	}
	// Reserving again for the same execution replaces its reservation.
	a2, err := s.ReserveVMID("lab", "exec-a", 0, live, exp, vmidNow)
	if err != nil || a2 != 102 {
		t.Fatalf("re-reserve = %d %v", a2, err)
	}
}

func TestVMIDExplicitRequestRefusesLiveOrReserved(t *testing.T) {
	s := newVMIDStore(t)
	live := map[uint64]bool{200: true}
	exp := vmidNow.Add(time.Hour)
	if _, err := s.ReserveVMID("lab", "exec-a", 200, live, exp, vmidNow); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("live vmid: %v", err)
	}
	if v, err := s.ReserveVMID("lab", "exec-a", 201, live, exp, vmidNow); err != nil || v != 201 {
		t.Fatalf("free vmid: %d %v", v, err)
	}
	if _, err := s.ReserveVMID("lab", "exec-b", 201, live, exp, vmidNow); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("vmid reserved by another execution: %v", err)
	}
	for _, bad := range []uint64{99, 1 << 40} {
		if _, err := s.ReserveVMID("lab", "exec-x", bad, live, exp, vmidNow); !errors.Is(err, ErrPveMutationPlan) {
			t.Fatalf("vmid %d: %v", bad, err)
		}
	}
}

func TestVMIDReservationExpiresUnlessStarted(t *testing.T) {
	s := newVMIDStore(t)
	exp := vmidNow.Add(time.Minute)
	if _, err := s.ReserveVMID("lab", "exec-a", 300, nil, exp, vmidNow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveVMID("lab", "exec-b", 301, nil, exp, vmidNow); err != nil {
		t.Fatal(err)
	}
	if err := s.StartVMID("lab", 301, "exec-b"); err != nil {
		t.Fatal(err)
	}
	if err := s.StartVMID("lab", 301, "exec-a"); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("start by a non-holder: %v", err)
	}
	later := vmidNow.Add(2 * time.Minute)
	// 300 expired, 301 started and kept.
	if v, err := s.ReserveVMID("lab", "exec-c", 300, nil, later.Add(time.Hour), later); err != nil || v != 300 {
		t.Fatalf("expired reservation not reusable: %d %v", v, err)
	}
	if _, err := s.ReserveVMID("lab", "exec-c", 301, nil, later.Add(time.Hour), later); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("started reservation expired: %v", err)
	}
	h, ok, err := s.VMIDHolder("lab", 301, later)
	if err != nil || !ok || h.ExecutionID != "exec-b" || !h.Started {
		t.Fatalf("holder = %+v %v %v", h, ok, err)
	}
	if err := s.ReleaseVMID("lab", 301, "exec-b"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.VMIDHolder("lab", 301, later); ok {
		t.Fatal("released reservation still held")
	}
}

func TestVMIDReservationsSurviveRestartAndRejectCorruptFile(t *testing.T) {
	s := newVMIDStore(t)
	if _, err := s.ReserveVMID("lab", "exec-a", 0, nil, vmidNow.Add(time.Hour), vmidNow); err != nil {
		t.Fatal(err)
	}
	again := &FilePveVMIDStore{Path: s.Path}
	if v, err := again.ReserveVMID("lab", "exec-b", 0, nil, vmidNow.Add(time.Hour), vmidNow); err != nil || v != 101 {
		t.Fatalf("after restart = %d %v", v, err)
	}
	if fi, err := os.Stat(s.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", fi, err)
	}
	if err := os.WriteFile(s.Path, []byte(`[{"remote_id":"lab","vmid":1,"bogus":true}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := again.ReserveVMID("lab", "exec-c", 0, nil, vmidNow.Add(time.Hour), vmidNow); err == nil {
		t.Fatal("corrupt reservation file accepted")
	}
}

func TestVMIDConcurrentReservationsAreDistinct(t *testing.T) {
	s := newVMIDStore(t)
	const n = 8
	var wg sync.WaitGroup
	got := make(chan uint64, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.ReserveVMID("lab", "exec-"+string(rune('a'+i)), 0, nil, vmidNow.Add(time.Hour), vmidNow)
			if err != nil {
				t.Error(err)
			}
			got <- v
		}()
	}
	wg.Wait()
	close(got)
	seen := map[uint64]bool{}
	for v := range got {
		if seen[v] {
			t.Fatalf("vmid %d reserved twice", v)
		}
		seen[v] = true
	}
}

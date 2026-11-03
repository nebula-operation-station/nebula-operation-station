// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// bulkCommit commits a candidate through BulkAdmit with the given
// decisions.
func (e *env) bulkCommit(version string, pins map[string]bool, retired []string, mods ...mod) BulkAdmitResult {
	e.t.Helper()
	c := e.candidate(version, mods...)
	out, err := e.s.BulkAdmit(c, BulkAdmitOpts{ConfirmedDigest: c.Manifest.Digest, Pins: pins, Retired: retired, AdminUID: 1000})
	if err != nil {
		e.t.Fatalf("bulk admit %s: %v", version, err)
	}
	return out
}

// pinnedHistory builds docker 1.0.0 → 1.1.0 (docker@1.0.0 pinned) → 1.2.0
// → 1.3.0 (each later old version retired), then moves the clock past
// every 90-day floor, so docker@1.0.0 is only kept by its pin.
func pinnedHistory(t *testing.T) *env {
	e := newEnv(t)
	e.bulkCommit("1.0.0", nil, nil, docker("1.0.0", "echo 1"))
	e.now = e.now.Add(24 * time.Hour)
	e.bulkCommit("1.1.0", map[string]bool{"docker@1.0.0": true}, nil, docker("1.1.0", "echo 1"))
	e.now = e.now.Add(24 * time.Hour)
	e.bulkCommit("1.2.0", nil, []string{"docker@1.1.0"}, docker("1.2.0", "echo 1"))
	e.now = e.now.Add(24 * time.Hour)
	e.bulkCommit("1.3.0", nil, []string{"docker@1.2.0"}, docker("1.3.0", "echo 1"))
	e.now = e.now.Add(200 * 24 * time.Hour)
	return e
}

// TestPinSurvivesLaterAdmissions: a version retained with --pin is stored
// as pinned and is never collected by later admissions (which do not
// repeat the pin), across a store reopen, until it is unpinned.
func TestPinSurvivesLaterAdmissions(t *testing.T) {
	e := pinnedHistory(t)
	e.reopen() // the pin is durable, not held in memory
	if got := e.s.Pins(); !slices.Equal(got, []string{"docker@1.0.0"}) {
		t.Fatalf("Pins() = %v, want [docker@1.0.0]", got)
	}
	// Two more admissions without any pin: docker@1.0.0 is beyond the two
	// most recent predecessors and past its floor, yet kept.
	for _, v := range []string{"1.4.0", "1.5.0"} {
		e.now = e.now.Add(24 * time.Hour)
		old := "docker@" + map[string]string{"1.4.0": "1.3.0", "1.5.0": "1.4.0"}[v]
		out := e.bulkCommit(v, nil, []string{old}, docker(v, "echo 1"))
		if inCollected(out.Collected, "docker@1.0.0") {
			t.Fatalf("admission %s collected the pinned docker@1.0.0", v)
		}
	}
	m, _ := e.s.Module("docker")
	if !slices.ContainsFunc(m.History, func(h VersionRecord) bool { return h.Version == "1.0.0" && h.Pinned }) {
		t.Fatalf("docker@1.0.0 not retained as pinned: %+v", m.History)
	}
	// Plain Admit (no pins argument) honours the stored pin too.
	e.now = e.now.Add(24 * time.Hour)
	if _, res := e.admit(e.candidate("1.6.0", docker("1.6.0", "echo 1"))); hasCollected(res, "docker@1.0.0") {
		t.Fatal("Admit collected the pinned docker@1.0.0")
	}
}

// TestUnpinMakesVersionCollectable: after Unpin the version is subject to
// normal retention again and the next admission collects it.
func TestUnpinMakesVersionCollectable(t *testing.T) {
	e := pinnedHistory(t)
	gen := e.s.Generation()
	if err := e.s.Unpin("docker@1.0.0"); err != nil {
		t.Fatal(err)
	}
	if e.s.Generation() != gen+1 {
		t.Fatalf("unpin must commit a new generation, got %d after %d", e.s.Generation(), gen)
	}
	e.reopen()
	if got := e.s.Pins(); len(got) != 0 {
		t.Fatalf("Pins() after unpin = %v, want none", got)
	}
	m, _ := e.s.Module("docker")
	if !slices.ContainsFunc(m.History, func(h VersionRecord) bool { return h.Version == "1.0.0" }) {
		t.Fatal("unpin itself must not delete bytes; collection happens at the next admission")
	}
	e.now = e.now.Add(24 * time.Hour)
	out := e.bulkCommit("1.4.0", nil, []string{"docker@1.3.0"}, docker("1.4.0", "echo 1"))
	if !inCollected(out.Collected, "docker@1.0.0") {
		t.Fatalf("after unpin docker@1.0.0 should be collected, got %v", out.Collected)
	}
}

// TestUnpinRejectsUnknownOrUnpinned: Unpin of a malformed, unknown or not
// pinned version is rejected and changes nothing.
func TestUnpinRejectsUnknownOrUnpinned(t *testing.T) {
	e := pinnedHistory(t)
	gen := e.s.Generation()
	for _, v := range []string{"", "docker", "@1.0.0", "docker@", "docker@9.9.9", "nosuch@1.0.0", "docker@1.3.0"} {
		if err := e.s.Unpin(v); !errors.Is(err, ErrNotPinned) {
			t.Fatalf("Unpin(%q) = %v, want ErrNotPinned", v, err)
		}
	}
	if e.s.Generation() != gen {
		t.Fatal("a rejected unpin changed the store")
	}
	if got := e.s.Pins(); !slices.Equal(got, []string{"docker@1.0.0"}) {
		t.Fatalf("Pins() = %v after rejected unpins", got)
	}
}

// TestUnpinStaleStoreRejected: an unpin against a store another process
// changed on disk is ErrStale and does not overwrite that change.
func TestUnpinStaleStoreRejected(t *testing.T) {
	e := pinnedHistory(t)
	stale := e.s
	e.reopen()
	e.now = e.now.Add(24 * time.Hour)
	e.bulkCommit("1.4.0", nil, []string{"docker@1.3.0"}, docker("1.4.0", "echo 1"))
	if err := stale.Unpin("docker@1.0.0"); !errors.Is(err, ErrStale) {
		t.Fatalf("stale Unpin = %v, want ErrStale", err)
	}
}

// TestTransientPinNotPersisted: AdmitPinned pins (a retained execution or
// an open review) hold only for that admission and are not stored.
func TestTransientPinNotPersisted(t *testing.T) {
	e := newEnv(t)
	e.admit(e.candidate("1.0.0", docker("1.0.0", "echo 1")))
	e.now = e.now.Add(24 * time.Hour)
	c := e.candidate("1.1.0", docker("1.1.0", "echo 1"))
	r, err := e.s.Review(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.AdmitPinned(c, r, map[string]bool{"docker@1.0.0": true}); err != nil {
		t.Fatal(err)
	}
	if got := e.s.Pins(); len(got) != 0 {
		t.Fatalf("transient pin was persisted: %v", got)
	}
}

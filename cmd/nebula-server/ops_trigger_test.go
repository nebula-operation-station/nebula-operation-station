// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// fakeTriggerSettings returns a fixed row or an error.
type fakeTriggerSettings struct {
	row opsconfig.Row
	err error
}

func (f *fakeTriggerSettings) Get(context.Context) (opsconfig.Row, error) { return f.row, f.err }

// triggerClock is an injected clock the tests move by hand.
type triggerClock struct{ t time.Time }

func (c *triggerClock) Now() time.Time { return c.t }

var triggerT0 = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

func triggerFixture(t *testing.T, enabled bool) (*opsTrigger, string, *triggerClock, *bytes.Buffer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trigger")
	clk := &triggerClock{t: triggerT0}
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	st := &fakeTriggerSettings{row: opsconfig.Row{Settings: opsconfig.Settings{Enabled: enabled}}}
	return newOpsTrigger(st, path, clk.Now, log), path, clk, &logBuf
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	t.Fatal(err)
	return false
}

// TestOpsTriggerTouchesWhenAgentIsOn: with the agent on, the trigger file is
// created.
func TestOpsTriggerTouchesWhenAgentIsOn(t *testing.T) {
	tr, path, _, _ := triggerFixture(t, true)
	tr.Touch()
	if !exists(t, path) {
		t.Fatal("trigger not touched while the agent is on")
	}
}

// TestOpsTriggerNeverTouchesWhenAgentIsOff: with the agent off nothing is
// touched, whatever the findings say.
func TestOpsTriggerNeverTouchesWhenAgentIsOff(t *testing.T) {
	tr, path, _, _ := triggerFixture(t, false)
	for i := 0; i < 3; i++ {
		tr.Touch()
	}
	if exists(t, path) {
		t.Fatal("trigger touched while the agent is off")
	}
}

// TestOpsTriggerNoTouchOnSettingsError: when the settings cannot be read the
// trigger fails closed and touches nothing.
func TestOpsTriggerNoTouchOnSettingsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trigger")
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	tr := newOpsTrigger(&fakeTriggerSettings{err: errors.New("db down")}, path, time.Now, log)
	tr.Touch()
	if exists(t, path) {
		t.Fatal("trigger touched without a readable settings row")
	}
}

// TestOpsTriggerAtMostOncePerMinute: a second touch within a minute is
// skipped; one after a minute touches again. The clock is injected.
func TestOpsTriggerAtMostOncePerMinute(t *testing.T) {
	tr, path, clk, _ := triggerFixture(t, true)
	tr.Touch()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clk.t = triggerT0.Add(30 * time.Second)
	tr.Touch()
	if exists(t, path) {
		t.Fatal("trigger touched 30 s after the last touch")
	}
	clk.t = triggerT0.Add(59*time.Second + 999*time.Millisecond)
	tr.Touch()
	if exists(t, path) {
		t.Fatal("trigger touched just before a minute had passed")
	}
	clk.t = triggerT0.Add(time.Minute)
	tr.Touch()
	if !exists(t, path) {
		t.Fatal("trigger not touched after a minute")
	}
}

// TestOpsTriggerCarriesNoData: the trigger is replaced by an empty file; it
// carries no data, and nothing a previous writer left in it survives (ADR
// 0016 D3, amendment 2026-11-19). Before the amendment the touch kept the
// content unchanged; the atomic replace makes it empty instead.
func TestOpsTriggerCarriesNoData(t *testing.T) {
	tr, path, _, _ := triggerFixture(t, true)
	if err := os.WriteFile(path, []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !tr.Touch() {
		t.Fatal("touch failed")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("trigger content is %q, want empty", got)
	}
}

// TestOpsTriggerPathIsInServerStateDirectory: the trigger lies directly in the
// server's own StateDirectory from nebula-server.service, and the ops agent's
// path unit watches exactly that file (ADR 0016 amendment 2026-11-19).
func TestOpsTriggerPathIsInServerStateDirectory(t *testing.T) {
	if opsTriggerPath != "/var/lib/nebula/server/ops-trigger" {
		t.Fatalf("opsTriggerPath = %q", opsTriggerPath)
	}
	var stateDirs, watched []string
	for _, l := range systemdUnitLines(t, "../../deploy/systemd/nebula-server.service") {
		if v, ok := strings.CutPrefix(l, "StateDirectory="); ok {
			stateDirs = append(stateDirs, strings.Fields(v)...)
		}
	}
	if len(stateDirs) != 1 || "/var/lib/"+stateDirs[0] != filepath.Dir(opsTriggerPath) {
		t.Fatalf("server StateDirectory %q does not hold the trigger %s", stateDirs, opsTriggerPath)
	}
	for _, l := range systemdUnitLines(t, "../../deploy/systemd/nebula-ops-agent.path") {
		for _, k := range []string{"PathChanged=", "PathModified=", "PathExists=", "PathExistsGlob=", "DirectoryNotEmpty="} {
			if v, ok := strings.CutPrefix(l, k); ok {
				watched = append(watched, v)
			}
		}
	}
	if len(watched) != 1 || watched[0] != opsTriggerPath {
		t.Fatalf("path unit watches %q, want only %s", watched, opsTriggerPath)
	}
}

// systemdUnitLines returns the trimmed non-comment lines of a unit file.
func systemdUnitLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// TestOpsTriggerFileIsMode0600: the trigger is created with mode 0600 and
// replaced with mode 0600 even when a looser file was there before.
func TestOpsTriggerFileIsMode0600(t *testing.T) {
	for _, pre := range []bool{false, true} {
		tr, path, _, _ := triggerFixture(t, true)
		if pre {
			if err := os.WriteFile(path, nil, 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		}
		if !tr.Touch() {
			t.Fatal("touch failed")
		}
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("pre-existing=%v: trigger mode %v, want regular 0600", pre, fi.Mode())
		}
	}
}

// TestOpsTriggerReplacesAtomically: every touch puts a new file in place by
// rename (a new inode, so the path unit sees it) and leaves no temporary file
// behind in the state directory.
func TestOpsTriggerReplacesAtomically(t *testing.T) {
	tr, path, clk, _ := triggerFixture(t, true)
	if !tr.Touch() {
		t.Fatal("first touch failed")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	clk.t = triggerT0.Add(time.Minute)
	if !tr.Touch() {
		t.Fatal("second touch failed")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("trigger rewritten in place, want a replace by rename")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("state directory holds %q, want only the trigger", names)
	}
}

// TestOpsTriggerNeverFollowsASymlink: a symlink at the trigger path is
// replaced, never written through; the file it points to stays unchanged.
func TestOpsTriggerNeverFollowsASymlink(t *testing.T) {
	tr, path, _, _ := triggerFixture(t, true)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if !tr.Touch() {
		t.Fatal("touch failed")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("trigger is %v after touch, want a regular file", fi.Mode())
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	vi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" || vi.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target changed: %q %v", got, vi.Mode())
	}
}

// TestOpsTriggerFailureIsLoggedOnly: a touch that fails is logged, does not
// panic and is retried only after the interval.
func TestOpsTriggerFailureIsLoggedOnly(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir", "trigger")
	clk := &triggerClock{t: triggerT0}
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	st := &fakeTriggerSettings{row: opsconfig.Row{Settings: opsconfig.Settings{Enabled: true}}}
	tr := newOpsTrigger(st, missing, clk.Now, log)
	tr.Touch()
	if !strings.Contains(logBuf.String(), "ops agent trigger not touched") {
		t.Fatalf("failed touch not logged: %q", logBuf.String())
	}
	// A second touch inside the interval is skipped without a new attempt.
	logBuf.Reset()
	tr.Touch()
	if logBuf.Len() != 0 {
		t.Fatalf("touch inside the interval logged again: %q", logBuf.String())
	}
}

// deferSink is a notifier sink that accepts every message.
type deferSink struct{}

func (deferSink) Notify(context.Context, notify.Event) int { return 1 }

// deferFinding is an open finding at tier high in episode ep.
func deferFinding(id byte, ep int64) vulnstore.Finding {
	f := vulnstore.Finding{State: vulnstore.StateOpen, Episode: ep, EpisodePeakTier: vulnstore.TierHigh}
	f.Key[0] = id
	return f
}

// TestOpsTriggerReportsWhetherItRan: Touch returns true only when the file was
// touched; a throttled, agent-off or settings-failed call returns false.
func TestOpsTriggerReportsWhetherItRan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trigger")
	clk := &triggerClock{t: triggerT0}
	st := &fakeTriggerSettings{row: opsconfig.Row{Settings: opsconfig.Settings{Enabled: true}}}
	tr := newOpsTrigger(st, path, clk.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !tr.Touch() {
		t.Fatal("first touch with the agent on returned false")
	}
	clk.t = triggerT0.Add(10 * time.Second)
	if tr.Touch() {
		t.Fatal("throttled touch returned true")
	}
	clk.t = triggerT0.Add(time.Minute)
	st.row.Enabled = false
	if tr.Touch() {
		t.Fatal("touch with the agent off returned true")
	}
	st.row.Enabled = true
	st.err = errors.New("settings unreadable")
	if tr.Touch() {
		t.Fatal("touch with an unreadable settings row returned true")
	}
}

// TestOpsTriggerDeferredEpisodesRunOnNextTick: a finding that enters high while
// the trigger is throttled, while the agent is off or while the settings read
// fails is not lost: the notifier keeps it pending and its next Flush touches
// the trigger once the condition has passed (ADR 0016 D3).
func TestOpsTriggerDeferredEpisodesRunOnNextTick(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "trigger")
	clk := &triggerClock{t: triggerT0}
	st := &fakeTriggerSettings{row: opsconfig.Row{Settings: opsconfig.Settings{Enabled: true}}}
	tr := newOpsTrigger(st, path, clk.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	vn, err := vulnnotify.New(vulnnotify.Config{Sink: deferSink{}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	vn.SetTrigger(tr.Touch)

	// Episode 1 touches the trigger; the file is removed to see the next touch.
	vn.TriggerFindings([]vulnstore.Finding{deferFinding(1, 1)})
	if !exists(t, path) {
		t.Fatal("first high finding did not touch the trigger")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// Throttle: episode 2 enters 10 s later and is deferred.
	clk.t = triggerT0.Add(10 * time.Second)
	vn.TriggerFindings([]vulnstore.Finding{deferFinding(2, 1)})
	if exists(t, path) {
		t.Fatal("throttled finding touched the trigger")
	}
	clk.t = triggerT0.Add(time.Minute)
	vn.Flush(ctx)
	if !exists(t, path) {
		t.Fatal("throttled episode not run on the next tick")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// Agent off: episode 3 is deferred until the agent is on again.
	st.row.Enabled = false
	clk.t = triggerT0.Add(2 * time.Minute)
	vn.TriggerFindings([]vulnstore.Finding{deferFinding(3, 1)})
	vn.Flush(ctx)
	if exists(t, path) {
		t.Fatal("trigger touched while the agent is off")
	}
	st.row.Enabled = true
	clk.t = triggerT0.Add(3 * time.Minute)
	vn.Flush(ctx)
	if !exists(t, path) {
		t.Fatal("agent-off episode not run once the agent is on")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// Settings read fails: episode 4 is deferred until the read works.
	st.err = errors.New("settings unreadable")
	clk.t = triggerT0.Add(4 * time.Minute)
	vn.TriggerFindings([]vulnstore.Finding{deferFinding(4, 1)})
	if exists(t, path) {
		t.Fatal("trigger touched with an unreadable settings row")
	}
	st.err = nil
	clk.t = triggerT0.Add(5 * time.Minute)
	vn.Flush(ctx)
	if !exists(t, path) {
		t.Fatal("settings-failed episode not run once the read works")
	}

	// Once run, the episodes are not touched again by later ticks.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clk.t = triggerT0.Add(6 * time.Minute)
	vn.Flush(ctx)
	if exists(t, path) {
		t.Fatal("trigger touched again after the deferred episodes ran")
	}
}

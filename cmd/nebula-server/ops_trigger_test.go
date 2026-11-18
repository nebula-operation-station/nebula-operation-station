// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
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

// TestOpsTriggerKeepsContent: touching never changes the file's content; the
// trigger carries no data.
func TestOpsTriggerKeepsContent(t *testing.T) {
	tr, path, _, _ := triggerFixture(t, true)
	if err := os.WriteFile(path, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr.Touch()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "unchanged" {
		t.Fatalf("content changed to %q", got)
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

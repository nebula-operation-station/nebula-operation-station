// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// blockUntilDone is a loop that runs until its context is cancelled.
func blockUntilDone(started *atomic.Int32) loop {
	return func(ctx context.Context) error {
		started.Add(1)
		<-ctx.Done()
		return nil
	}
}

func runAsync(ctx context.Context, loops []namedLoop) <-chan error {
	done := make(chan error, 1)
	go func() { done <- runLoops(ctx, loops) }()
	return done
}

func waitResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("runLoops did not return")
		return nil
	}
}

func TestRunLoopsShutdownStopsAllLoops(t *testing.T) {
	var started, stopped atomic.Int32
	l := func(ctx context.Context) error {
		started.Add(1)
		<-ctx.Done()
		stopped.Add(1)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, []namedLoop{{"collector", l}, {"live", l}})
	deadline := time.Now().Add(5 * time.Second)
	for started.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("runLoops after shutdown = %v, want nil", err)
	}
	if stopped.Load() != 2 {
		t.Fatalf("stopped loops = %d, want 2", stopped.Load())
	}
}

func TestRunLoopsFailureStopsOtherLoop(t *testing.T) {
	boom := errors.New("boom")
	var started atomic.Int32
	done := runAsync(context.Background(), []namedLoop{
		{"collector", blockUntilDone(&started)},
		{"live", func(context.Context) error { return boom }},
	})
	if err := waitResult(t, done); !errors.Is(err, boom) {
		t.Fatalf("runLoops = %v, want %v", err, boom)
	}
}

func TestRunLoopsEarlyCleanExitIsAnError(t *testing.T) {
	// A loop that stops by itself while the service is running would leave
	// the service half-working; it must end the process with an error so
	// systemd restarts it.
	var started atomic.Int32
	done := runAsync(context.Background(), []namedLoop{
		{"collector", blockUntilDone(&started)},
		{"live", func(context.Context) error { return nil }},
	})
	if err := waitResult(t, done); !errors.Is(err, errLoopStopped) {
		t.Fatalf("runLoops = %v, want %v", err, errLoopStopped)
	}
}

func TestOpenLiveDisabledCreatesNothing(t *testing.T) {
	root := t.TempDir()
	h, err := openLive(root, false)
	if err != nil || h != nil {
		t.Fatalf("openLive(disabled) = %v, %v; want nil, nil", h, err)
	}
	for _, d := range []string{"requests", "live"} {
		if _, err := os.Lstat(filepath.Join(root, d)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists with -live=false: %v", d, err)
		}
	}
}

func TestOpenLiveEnabledProvisionsHandoffDirs(t *testing.T) {
	root := t.TempDir()
	h, err := openLive(root, true)
	if err != nil {
		t.Fatalf("openLive: %v", err)
	}
	defer h.Close()
	want := map[string]os.FileMode{
		"requests": 0o770 | os.ModeSetgid,
		"live":     0o750 | os.ModeSetgid,
	}
	for d, mode := range want {
		fi, err := os.Lstat(filepath.Join(root, d))
		if err != nil {
			t.Fatalf("stat %s: %v", d, err)
		}
		if !fi.IsDir() || fi.Mode()&(os.ModePerm|os.ModeSetgid) != mode {
			t.Fatalf("%s mode = %v, want dir %v", d, fi.Mode(), mode)
		}
	}
}

func TestOpenLiveRefusesRelativeRoot(t *testing.T) {
	if h, err := openLive("relative/pve", true); err == nil {
		h.Close()
		t.Fatal("openLive accepted a relative root")
	}
}

func TestLiveFlagDefaultsOn(t *testing.T) {
	if !defaultLive {
		t.Fatal("-live must default to on")
	}
}

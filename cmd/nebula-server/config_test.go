// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

func intPtr(v int) *int { return &v }

func TestTrafficRetentionDefault(t *testing.T) {
	// No traffic section: the 21-day default.
	d, err := trafficRetention(serverconfig.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if want := 21 * 24 * time.Hour; d != want {
		t.Errorf("retention %v, want %v", d, want)
	}
}

func TestTrafficRetentionValid(t *testing.T) {
	for _, n := range []int{1, 7, 21} {
		d, err := trafficRetention(serverconfig.Config{Traffic: serverconfig.TrafficConfig{RetentionDays: intPtr(n)}})
		if err != nil {
			t.Fatalf("retention_days %d: %v", n, err)
		}
		if want := time.Duration(n) * 24 * time.Hour; d != want {
			t.Errorf("retention_days %d: %v, want %v", n, d, want)
		}
	}
}

func TestTrafficRetentionOutOfRange(t *testing.T) {
	// A config that never went through serverconfig validation must
	// fail closed here, not open the store with an out-of-range
	// retention.
	for _, n := range []int{0, -3, 22, 365} {
		_, err := trafficRetention(serverconfig.Config{Traffic: serverconfig.TrafficConfig{RetentionDays: intPtr(n)}})
		if err == nil {
			t.Errorf("retention_days %d: accepted, want error", n)
		}
	}
}

// TestRunRefusesInvalidTrafficRetention checks that an invalid
// traffic.retention_days stops the start with a clear error naming the
// key, before the server serves anything.
func TestRunRefusesInvalidTrafficRetention(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	path := writeConfig(t, dir, map[string]any{
		"listen":          freeListenAddr(t),
		"public_origin":   swOrigin,
		"data_dir":        dir,
		"executor_socket": "/nonexistent/executor.sock",
		"executor_user":   u.Username,
		"traffic":         map[string]any{"retention_days": 0},
	})
	var stderr bytes.Buffer
	err = run(context.Background(), []string{"-config", path}, &stderr)
	if err == nil {
		t.Fatal("run accepted retention_days 0")
	}
	if !strings.Contains(err.Error(), "traffic.retention_days") {
		t.Errorf("error does not name the key: %v", err)
	}
}

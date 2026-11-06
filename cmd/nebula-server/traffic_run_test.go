// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func TestRunPrunesTrafficToConfiguredRetention(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The oldest row disappears with either retention and signals that
	// run's asynchronous startup prune finished. The ten-day row must
	// disappear only with the configured seven days; the recent row stays.
	now := time.Now().UTC().Truncate(time.Hour)
	hours := make([]int64, 3)
	for i, days := range []int{2, 10, 22} {
		hours[i] = now.Add(-time.Duration(days)*24*time.Hour).Unix() / 3600
		if _, err := db.Exec(`INSERT INTO flow_buckets
			(hour, a, b, proto, server_port, server_side, tier, server_reported, reporter)
			VALUES (?, '10.99.0.1', '10.99.0.2', 6, 22, 0, 'socket', 1, 'host-x')`, hours[i]); err != nil {
			t.Fatal(err)
		}
	}
	count := func(hour int64) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM flow_buckets WHERE hour = ?`, hour).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	listen := freeListenAddr(t)
	path := writeConfig(t, dir, map[string]any{
		"listen": listen, "public_origin": swOrigin, "data_dir": dir,
		"executor_socket": filepath.Join(dir, "no-executor.sock"), "executor_user": u.Username,
		"traffic": map[string]any{"retention_days": 7},
	})
	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &stderr) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			// Read stderr only after run has joined its background writers.
			if err != nil {
				t.Errorf("run: %v (stderr: %s)", err, stderr.String())
			}
		case <-time.After(5 * time.Second):
			t.Error("run did not return within 5s of cancel")
		}
	})
	client := &http.Client{Timeout: time.Second}
	t.Cleanup(client.CloseIdleConnections)
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get("http://" + listen + "/login")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && count(hours[2]) == 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not serve login and finish its startup prune")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := count(hours[1]); n != 0 {
		t.Errorf("ten-day-old bucket survived run with retention_days=7: %d rows", n)
	}
	if n := count(hours[0]); n != 1 {
		t.Errorf("two-day-old bucket removed with retention_days=7: %d rows", n)
	}
}

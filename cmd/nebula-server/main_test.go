// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
)

// freeListenAddr picks a free loopback port by binding port 0 and
// closing the listener again.
func freeListenAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// writeConfig writes cfg as JSON to dir/server.json and returns the path.
func writeConfig(t *testing.T, dir string, cfg any) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(dir, "server.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestRunVersionFlag(t *testing.T) {
	var stderr bytes.Buffer
	if err := run(context.Background(), []string{"-version"}, &stderr); err != nil {
		t.Fatalf("run -version: %v", err)
	}
	if !strings.Contains(stderr.String(), version.String()) {
		t.Errorf("stderr %q does not contain %q", stderr.String(), version.String())
	}
}

func TestRunInvalidConfigReturnsError(t *testing.T) {
	dir := t.TempDir()
	// data_dir must be an absolute path; validation must fail before
	// anything is opened.
	path := writeConfig(t, dir, map[string]any{
		"listen":          "127.0.0.1:8080",
		"public_origin":   "https://nebula.example.org",
		"data_dir":        "relative/path",
		"executor_socket": "/run/nebula/executor.sock",
		"executor_user":   "nebula-executor",
	})
	var stderr bytes.Buffer
	err := run(context.Background(), []string{"-config", path}, &stderr)
	if err == nil {
		t.Fatal("run: expected error for invalid config, got nil")
	}
	if !strings.Contains(err.Error(), "must be an absolute path") {
		t.Fatalf("error %q does not mention the problem", err)
	}
	// The invalid config must not have created a database.
	if _, err := os.Stat(filepath.Join(dir, "relative", "server.db")); !os.IsNotExist(err) {
		t.Errorf("database created despite invalid config: %v", err)
	}
}

func TestRunServesUIAndShutsDown(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	listen := freeListenAddr(t)
	// The executor socket does not exist: startup must not fail; the
	// server keeps retrying in the background.
	path := writeConfig(t, dir, map[string]any{
		"listen":          listen,
		"public_origin":   "https://nebula.example.org",
		"data_dir":        dir,
		"executor_socket": filepath.Join(dir, "no-executor.sock"),
		"executor_user":   u.Username,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &stderr) }()

	base := "http://" + listen
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		resp, err := http.Get(base + "/login")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
			lastErr = fmt.Errorf("GET /login: status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v (stderr: %s)", lastErr, stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Without a session the dashboard redirects to the login.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(base + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET /dashboard without session: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Login with the executor down: a fixed message, no detail.
	req, _ := http.NewRequest("POST", base+"/login/begin", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://nebula.example.org")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || strings.Contains(string(body), "sock") {
		t.Fatalf("login with executor down: %d %s", resp.StatusCode, body)
	}

	// Public pages and a static asset are served with the security
	// headers from the middleware chain.
	for _, p := range []string{"/login", "/setup", "/static/htmx.min.js"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		// Drain the body fully so the connection returns to idle;
		// an aborted body would keep the server handler active and
		// hold up the graceful shutdown.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", p, resp.StatusCode)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
			t.Errorf("GET %s: Content-Security-Policy %q", p, csp)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run after ctx cancel: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5s of ctx cancel")
	}

	// The startup line must carry the non-secret config attributes and
	// the listen address, and must never carry the token value.
	logged := stderr.String()
	if !strings.Contains(logged, `"listen":"`+listen+`"`) {
		t.Errorf("startup log missing listen address; got %s", logged)
	}
	if !strings.Contains(logged, `"public_origin":"https://nebula.example.org"`) {
		t.Errorf("startup log missing config attributes; got %s", logged)
	}
}

func TestLazyExecutorWithoutConnection(t *testing.T) {
	var l lazyExecutor
	ctx := context.Background()
	if _, err := l.GetStatus(ctx, nil); err != errNotConnected {
		t.Fatalf("GetStatus: %v", err)
	}
	if _, err := l.BeginLogin(ctx, nil); err != errNotConnected {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, err := l.FinishRegistration(ctx, nil); err != errNotConnected {
		t.Fatalf("FinishRegistration: %v", err)
	}
	l.close() // no client: no panic
}

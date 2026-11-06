// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// TestRunWiresIconService starts the real server (run): an upload sets the
// icon, the icon page links it, and /icons/ serves it as an inert PNG.
func TestRunWiresIconService(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token, _, err := auth.NewStore(db, nil).Create(ctx, "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		t.Fatal(err)
	}
	units := base64.StdEncoding.EncodeToString([]byte("widgetd.service loaded active running Some unit"))
	doc := []byte(fmt.Sprintf(`{"format":"systemd-units-v1","units":%q}`, units))
	if _, err := cat.IngestServiceList(ctx, softwarecat.Target{Kind: softwarecat.TargetHost, HostID: "h1"}, doc, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	listen := freeListenAddr(t)
	path := writeConfig(t, dir, map[string]any{
		"listen": listen, "public_origin": swOrigin, "data_dir": dir,
		"executor_socket": filepath.Join(dir, "no-executor.sock"), "executor_user": u.Username,
	})
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(runCtx, []string{"-config", path}, &stderr) }()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(method, p, ctype string, body []byte) (*http.Response, string) {
		req, err := http.NewRequest(method, "http://"+listen+p, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
			req.Header.Set("Origin", swOrigin)
		}
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		resp, err := client.Do(req)
		if err != nil {
			return nil, ""
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if resp, _ := send(http.MethodGet, "/software", "", nil); resp != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up (stderr: %s)", stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	resp, body := send(http.MethodPost, uploadPath, "image/png", iconPNG(t, iconRed))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("upload: %d %q", resp.StatusCode, body)
	}
	_, page := send(http.MethodGet, "/software/icon/widgetd", "", nil)
	src := regexp.MustCompile(`/icons/[0-9a-f]{64}\.png`).FindString(page)
	if src == "" {
		t.Fatal("icon page does not link the uploaded icon")
	}
	resp, _ = send(http.MethodGet, src, "", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/png" ||
		resp.Header.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Errorf("GET icon: %d %v", resp.StatusCode, resp.Header)
	}
	if strings.Contains(stderr.String(), `"level":"ERROR"`) && strings.Contains(stderr.String(), "icon") {
		t.Errorf("icon errors in the log: %s", stderr.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5s of cancel")
	}
}

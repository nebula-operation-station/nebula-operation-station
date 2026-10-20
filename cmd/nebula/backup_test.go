// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/nebula-operation-station/nebula-operation-station/internal/backup"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

type recordSystem struct{ calls []string }

func (r *recordSystem) Stop(u ...string) error        { r.calls = append(r.calls, "stop"); return nil }
func (r *recordSystem) Start(u ...string) error       { r.calls = append(r.calls, "start"); return nil }
func (r *recordSystem) Chown(path, name string) error { return nil }

// The server's part, an archive written and checked on disk, and a restore
// that needs "restore" typed.
func TestBackupAndRestoreFiles(t *testing.T) {
	root := t.TempDir()
	old := nebulaRoot
	nebulaRoot = root
	defer func() { nebulaRoot = old }()
	_ = os.MkdirAll(rootPath("var", "lib", "nebula", "server"), 0o750)
	sdb, err := serverdb.Open(rootPath("var", "lib", "nebula", "server", "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close() // the server keeps running during a backup
	_ = os.MkdirAll(rootPath("etc", "nebula"), 0o755)
	_ = os.WriteFile(rootPath("etc", "nebula", "server.json"), []byte(`{"listen":"127.0.0.1:8080"}`), 0o640)
	_ = os.MkdirAll(rootPath("etc", "systemd", "system", "nebula-server.service.d"), 0o755)
	_ = os.WriteFile(rootPath("etc", "systemd", "system", "nebula-server.service.d", "20-discovery.conf"), []byte("[Service]\n"), 0o644)
	_ = os.WriteFile(rootPath("etc", "systemd", "system", "nebula-server.service.d", "evil name.conf"), []byte("x"), 0o644)
	files, sv, err := readServerPart(t.TempDir())
	if err != nil || len(files) != 3 || sv == 0 {
		t.Fatalf("%d files, schema %d, %v", len(files), sv, err)
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	edb, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(t.TempDir(), "executor.db")
	ev, err := edb.Snapshot(snap)
	edb.Close()
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := os.ReadFile(snap)
	files = append(files, backup.File{Path: backup.ExecutorDB, Mode: 0o600, Data: eb})
	id, _ := age.GenerateX25519Identity()
	m := backup.Manifest{Version: "test", CreatedAt: "now", Host: "h", Kind: "config", Schemas: map[string]int{"server": sv, "executor": ev}}
	archive := filepath.Join(t.TempDir(), "b.tar.gz.age")
	if _, _, err := writeArchiveFile(archive, m, files, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeArchiveFile(archive, m, files, nil); err == nil {
		t.Fatal("an existing archive was overwritten")
	}
	idFile := filepath.Join(t.TempDir(), "id")
	_ = os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600)
	if os.Geteuid() != 0 {
		t.Skip("restore needs root")
	}
	sys := &recordSystem{}
	var out bytes.Buffer
	if err := restoreWith([]string{"--identity", idFile, archive}, strings.NewReader("yes\n"), &out, sys, time.Now()); err == nil || len(sys.calls) != 0 {
		t.Fatal("restored without the typed word")
	}
	if err := restoreWith([]string{archive}, strings.NewReader("restore\n"), &out, sys, time.Now()); err == nil {
		t.Fatal("encrypted archive read without identity")
	}
	// A backup of another machine needs its host name typed too.
	realHostname := hostname
	t.Cleanup(func() { hostname = realHostname })
	hostname = func() (string, error) { return "other", nil }
	if err := restoreWith([]string{"--identity", idFile, archive}, strings.NewReader("restore\nother\n"), &out, sys, time.Now()); err == nil || len(sys.calls) != 0 {
		t.Fatal("restored another machine's backup without its name")
	}
	out.Reset()
	if err := restoreWith([]string{"--identity", idFile, archive}, strings.NewReader("restore\nh\n"), &out, sys, time.Now()); err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(out.String(), "nebula unlock") || !strings.Contains(out.String(), "kept the previous data") || len(sys.calls) != 2 {
		t.Fatal(out.String(), sys.calls)
	}

	// A backup that names no host is foreign too, even when this machine's
	// name is unknown as well: only the word "unknown" confirms it (review
	// fx3, note 1).
	m.Host = ""
	unnamed := filepath.Join(t.TempDir(), "u.tar.gz.age")
	if _, _, err := writeArchiveFile(unnamed, m, files, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatal(err)
	}
	hostname = func() (string, error) { return "", errors.New("no hostname") }
	for _, second := range []string{"", "h", "restore"} {
		if err := restoreWith([]string{"--identity", idFile, unnamed}, strings.NewReader("restore\n"+second+"\n"), &out, sys, time.Now()); err == nil || len(sys.calls) != 2 {
			t.Fatalf("an unnamed backup was restored with %q", second)
		}
	}
	out.Reset()
	// A later restore, so its data moves aside under its own name.
	if err := restoreWith([]string{"--identity", idFile, unnamed}, strings.NewReader("restore\nunknown\n"), &out, sys, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err, out.String())
	}
	if !strings.Contains(out.String(), "an unknown machine") || len(sys.calls) != 4 {
		t.Fatal(out.String(), sys.calls)
	}
}

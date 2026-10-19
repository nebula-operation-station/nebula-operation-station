// SPDX-License-Identifier: AGPL-3.0-or-later

package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func dbFiles(t *testing.T) (server, executor []byte, sv, ev int) {
	t.Helper()
	sp := filepath.Join(t.TempDir(), "server.db")
	sdb, err := serverdb.Open(sp)
	if err != nil {
		t.Fatal(err)
	}
	sdb.Close()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	edb, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(t.TempDir(), "executor.db")
	if ev, err = edb.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	edb.Close()
	if sv, err = CheckSQLite(sp); err != nil {
		t.Fatal(err)
	}
	server, _ = os.ReadFile(sp)
	executor, _ = os.ReadFile(snap)
	return server, executor, sv, ev
}

func sample(t *testing.T) (Manifest, []File) {
	t.Helper()
	s, e, sv, ev := dbFiles(t)
	m := Manifest{Version: "test", CreatedAt: "2026-10-19T00:00:00Z", Host: "nebula", Kind: "config", Schemas: map[string]int{"server": sv, "executor": ev}}
	return m, []File{
		{Path: ServerDB, Mode: 0o600, Data: s},
		{Path: ExecutorDB, Mode: 0o600, Data: e},
		{Path: "executor/keys/nebula-default.key", Mode: 0o600, Data: []byte("-----BEGIN OPENSSH PRIVATE KEY----- (encrypted)")},
		{Path: "executor/keys/nebula-default.pub", Mode: 0o644, Data: []byte("ssh-ed25519 AAAA")},
		{Path: "server/config/server.json", Mode: 0o640, Data: []byte(`{"listen":"127.0.0.1:8080"}`)},
	}
}

func TestRoundTrip(t *testing.T) {
	m, files := sample(t)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if err := Write(&enc, m, files, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc.Bytes(), []byte("OPENSSH")) || !bytes.HasPrefix(enc.Bytes(), []byte("age-encryption.org/v1\n")) {
		t.Fatal("not encrypted")
	}
	if _, _, err := Read(bytes.NewReader(enc.Bytes()), nil); !errors.Is(err, ErrEncrypted) {
		t.Fatal(err)
	}
	other, _ := age.GenerateX25519Identity()
	if _, _, err := Read(bytes.NewReader(enc.Bytes()), []age.Identity{other}); err == nil {
		t.Fatal("decrypted with another identity")
	}
	got, gf, err := Read(bytes.NewReader(enc.Bytes()), []age.Identity{id})
	if err != nil || !got.Encrypted || len(gf) != len(files) || got.Schemas["server"] != m.Schemas["server"] {
		t.Fatalf("%+v %v", got, err)
	}
	var plain bytes.Buffer
	if err := Write(&plain, m, files, nil); err != nil {
		t.Fatal(err)
	}
	if got, _, err := Read(bytes.NewReader(plain.Bytes()), nil); err != nil || got.Encrypted {
		t.Fatal(err)
	}
	// Paths outside the fixed set are refused when writing.
	if err := Write(&plain, m, append(files, File{Path: "../etc/shadow", Data: []byte("x")}), nil); err == nil {
		t.Fatal("bad path written")
	}
	if err := Write(&plain, m, append(files, File{Path: "executor/events.key", Data: []byte("x")}), nil); err == nil {
		t.Fatal("event key written")
	}
}

// A changed byte, an extra or a missing file fails the read.
func TestReadRefusesTampering(t *testing.T) {
	m, files := sample(t)
	write := func(m Manifest, fs []File) []byte {
		var b bytes.Buffer
		if err := Write(&b, m, fs, nil); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	good := write(m, files)
	if _, _, err := Read(bytes.NewReader(good), nil); err != nil {
		t.Fatal(err)
	}
	// Rewrite the archive with a changed file but the original manifest.
	m2, _, _ := Read(bytes.NewReader(good), nil)
	changed := append([]File(nil), files...)
	changed[4] = File{Path: changed[4].Path, Mode: 0o640, Data: []byte(`{"listen":"0.0.0.0:80"}`)}
	_ = m2
	if _, _, err := Read(bytes.NewReader(writeRaw(t, m2, changed)), nil); !errors.Is(err, ErrChecksum) && (err == nil || !strings.Contains(err.Error(), "unexpected")) {
		t.Fatalf("changed file accepted: %v", err)
	}
	if _, _, err := Read(bytes.NewReader(writeRaw(t, m2, files[:4])), nil); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatal(err)
	}
	if _, _, err := Read(strings.NewReader("hello"), nil); !errors.Is(err, ErrNotBackup) {
		t.Fatal(err)
	}
}

// writeRaw writes an archive with a given manifest (not recomputed).
func writeRaw(t *testing.T, m Manifest, files []File) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := writeWithManifest(&b, m, files); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type fakeSystem struct {
	calls  []string
	failOn string
}

func (f *fakeSystem) Stop(u ...string) error {
	f.calls = append(f.calls, "stop "+strings.Join(u, ","))
	return nil
}
func (f *fakeSystem) Start(u ...string) error {
	f.calls = append(f.calls, "start "+strings.Join(u, ","))
	return nil
}
func (f *fakeSystem) Chown(p, user string) error {
	if f.failOn != "" && strings.HasSuffix(p, f.failOn) {
		return errors.New("chown failed")
	}
	f.calls = append(f.calls, "chown "+filepath.Base(p)+" "+user)
	return nil
}

func TestRestore(t *testing.T) {
	m, files := sample(t)
	l := Layout{Root: t.TempDir()}
	_ = os.MkdirAll(l.ServerDir(), 0o750)
	_ = os.WriteFile(filepath.Join(l.ServerDir(), "server.db"), []byte("old"), 0o600)
	latest := map[string]int{"server": m.Schemas["server"], "executor": m.Schemas["executor"]}
	now := time.Unix(1_800_000_000, 0)
	sys := &fakeSystem{}
	rep, err := Restore(m, files, l, sys, latest, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.MovedAside) != 1 || len(rep.Config) != 1 || !strings.HasSuffix(rep.Config[0], "server.json") {
		t.Fatalf("%+v", rep)
	}
	if old, _ := os.ReadFile(filepath.Join(rep.MovedAside[0], "server.db")); string(old) != "old" {
		t.Fatal("old data not kept")
	}
	if v, err := CheckSQLite(filepath.Join(l.ExecutorDir(), "executor.db")); err != nil || v != m.Schemas["executor"] {
		t.Fatal(v, err)
	}
	st, _ := os.Stat(filepath.Join(l.ExecutorDir(), "keys", "nebula-default.key"))
	if st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	if sys.calls[0] != "stop "+strings.Join(StopUnits, ",") || sys.calls[len(sys.calls)-1] != "start "+strings.Join(StartUnits, ",") {
		t.Fatal(sys.calls)
	}
	// Nothing is applied from the configuration.
	if _, err := os.Stat(filepath.Join(l.ConfigDir(), "server.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("configuration applied")
	}

	// A newer schema, or a damaged database, stops before anything changes.
	newer := m
	newer.Schemas = map[string]int{"server": m.Schemas["server"] + 1, "executor": m.Schemas["executor"]}
	sys2 := &fakeSystem{}
	if _, err := Restore(newer, files, Layout{Root: t.TempDir()}, sys2, latest, now); err == nil || len(sys2.calls) != 0 {
		t.Fatal("newer schema restored", err)
	}
	bad := append([]File(nil), files...)
	bad[0] = File{Path: ServerDB, Mode: 0o600, Data: []byte("SQLite format 3\x00 broken")}
	if _, err := Restore(m, bad, Layout{Root: t.TempDir()}, sys2, latest, now); err == nil || len(sys2.calls) != 0 {
		t.Fatal("damaged database restored", err)
	}

	// A failure after the move puts the old data back.
	l3 := Layout{Root: t.TempDir()}
	_ = os.MkdirAll(l3.ExecutorDir(), 0o700)
	_ = os.WriteFile(filepath.Join(l3.ExecutorDir(), "marker"), []byte("x"), 0o600)
	sys3 := &fakeSystem{failOn: "executor.db"}
	if _, err := Restore(m, files, l3, sys3, latest, now); err == nil {
		t.Fatal("no error")
	}
	if b, err := os.ReadFile(filepath.Join(l3.ExecutorDir(), "marker")); err != nil || string(b) != "x" {
		t.Fatal("old data not put back")
	}
	if sys3.calls[len(sys3.calls)-1] != "start "+strings.Join(StartUnits, ",") {
		t.Fatal(sys3.calls)
	}
}

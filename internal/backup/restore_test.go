// SPDX-License-Identifier: AGPL-3.0-or-later

package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tree records every entry under root: directories with their mode, files
// with mode and content, symbolic links with their target. A refused restore
// must leave the tree exactly as it was.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := d.Info() // Lstat semantics: symbolic links are not followed
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[rel] = "link " + target
		case info.IsDir():
			out[rel] = fmt.Sprintf("dir %v", info.Mode().Perm())
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = fmt.Sprintf("file %v %q", info.Mode().Perm(), b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// withoutStage drops the staging directory (var/lib/nebula/.restore-*) from a
// tree: Restore removes it on return, after any Start, so it is still there
// when Start runs and is not part of the state the services see.
func withoutStage(m map[string]string) map[string]string {
	prefix := filepath.Join("var", "lib", "nebula", ".restore-")
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			delete(m, k)
		}
	}
	return m
}

// brokenSystem is a fakeSystem whose Stop or Start can fail.
type brokenSystem struct {
	*fakeSystem
	stopErr, startErr error
}

func (b *brokenSystem) Stop(u ...string) error {
	_ = b.fakeSystem.Stop(u...)
	return b.stopErr
}

func (b *brokenSystem) Start(u ...string) error {
	_ = b.fakeSystem.Start(u...)
	return b.startErr
}

// oldLayout returns a layout whose data directories hold the current data.
func oldLayout(t *testing.T) Layout {
	t.Helper()
	l := Layout{Root: t.TempDir()}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(l.ServerDir(), 0o750))
	must(os.WriteFile(filepath.Join(l.ServerDir(), "server.db"), []byte("old server"), 0o600))
	must(os.MkdirAll(filepath.Join(l.ExecutorDir(), "keys"), 0o700))
	must(os.WriteFile(filepath.Join(l.ExecutorDir(), "keys", "old.key"), []byte("old key"), 0o600))
	must(os.WriteFile(filepath.Join(l.ExecutorDir(), "executor.db"), []byte("old executor"), 0o600))
	return l
}

// liveConfig puts live configuration into /etc/nebula (ConfigDir). A refused
// restore must leave it byte for byte, so the cleanup may only remove what the
// restore itself created.
func liveConfig(t *testing.T, l Layout) {
	t.Helper()
	if err := os.MkdirAll(l.ConfigDir(), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.ConfigDir(), "server.json"), []byte(`{"live": true}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.ConfigDir(), "executor.yaml"), []byte("live: executor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// withoutDir removes the given data directories, as on a machine where Nebula
// has never run: the restore must create them itself.
func withoutDir(dirs ...func(Layout) string) func(*testing.T, Layout) {
	return func(t *testing.T, l Layout) {
		t.Helper()
		for _, d := range dirs {
			if err := os.RemoveAll(d(l)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// without drops one file from the backup.
func without(path string) func(*Manifest, *[]File) {
	return func(_ *Manifest, files *[]File) {
		var kept []File
		for _, f := range *files {
			if f.Path != path {
				kept = append(kept, f)
			}
		}
		*files = kept
	}
}

func TestRestoreRefusalsLeaveOldDataUntouched(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ts := now.UTC().Format("20060102-150405")
	startCall := "start " + strings.Join(StartUnits, ",")

	cases := []struct {
		name    string
		mutate  func(*Manifest, *[]File) // changes the backup; nil = none
		arrange func(*testing.T, Layout) // changes the target; nil = none
		failOn  string                   // chown of a path with this suffix fails
		stopErr error                    // Stop fails
		wantErr string                   // substring of the error
		stopped bool                     // Stop is called before the refusal
		started bool                     // Start is called last (undo)
	}{
		{
			name: "newer server schema",
			mutate: func(m *Manifest, _ *[]File) {
				m.Schemas = map[string]int{"server": m.Schemas["server"] + 1, "executor": m.Schemas["executor"]}
			},
			wantErr: "newer than this Nebula knows",
		},
		{
			name: "manifest without executor schema",
			mutate: func(m *Manifest, _ *[]File) {
				m.Schemas = map[string]int{"server": m.Schemas["server"]}
			},
			wantErr: "the manifest has no executor schema version",
		},
		{
			name: "database schema differs from the manifest",
			mutate: func(m *Manifest, _ *[]File) {
				if m.Schemas["server"] < 1 {
					panic("test setup: the server schema must be at least 1")
				}
				m.Schemas = map[string]int{"server": m.Schemas["server"] - 1, "executor": m.Schemas["executor"]}
			},
			wantErr: "the manifest says",
		},
		{
			name: "file path outside the backup layout",
			mutate: func(_ *Manifest, files *[]File) {
				*files = append(*files, File{Path: "../etc/shadow", Data: []byte("x")})
			},
			wantErr: "is not a backup path",
		},
		{
			name:    "server database missing from the backup",
			mutate:  without(ServerDB),
			wantErr: "the backup has no " + ServerDB,
		},
		{
			name:    "executor database missing from the backup",
			mutate:  without(ExecutorDB),
			wantErr: "the backup has no " + ExecutorDB,
		},
		{
			name: "damaged server database",
			mutate: func(_ *Manifest, files *[]File) {
				(*files)[0] = File{Path: ServerDB, Mode: 0o600, Data: []byte("SQLite format 3\x00 broken")}
			},
			// The SQLite check refuses it, not the schema comparison or a later step.
			wantErr: "integrity check of",
		},
		{
			name: "var/lib/nebula is a file, so the staging directory cannot be made",
			arrange: func(t *testing.T, l Layout) {
				base := filepath.Dir(l.ServerDir())
				if err := os.RemoveAll(base); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(base, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "not a directory",
		},
		{
			name: "server data directory is a symbolic link",
			arrange: func(t *testing.T, l Layout) {
				if err := os.RemoveAll(l.ServerDir()); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), l.ServerDir()); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "is not a directory (a symbolic link?); refusing to restore over it",
			stopped: true,
			started: true,
		},
		{
			name: "executor data directory is a symbolic link, after the server directory was moved",
			arrange: func(t *testing.T, l Layout) {
				if err := os.RemoveAll(l.ExecutorDir()); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), l.ExecutorDir()); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "is not a directory (a symbolic link?); refusing to restore over it",
			stopped: true,
			started: true,
		},
		{
			name: "server move-aside target already exists",
			arrange: func(t *testing.T, l Layout) {
				aside := l.ServerDir() + ".pre-restore-" + ts
				if err := os.MkdirAll(aside, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(aside, "keep"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "move ",
			stopped: true,
			started: true,
		},
		{
			name: "executor move-aside target already exists, after the server directory was moved",
			arrange: func(t *testing.T, l Layout) {
				aside := l.ExecutorDir() + ".pre-restore-" + ts
				if err := os.MkdirAll(aside, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(aside, "keep"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "move ",
			stopped: true,
			started: true,
		},
		{
			// Stop may have stopped some units before it failed; they are started again.
			name:    "Stop fails: nothing is moved, the services are started again",
			stopErr: errors.New("unit busy"),
			wantErr: "stop the services",
			stopped: true,
			started: true,
		},
		{
			name:    "owner of the new server directory cannot be set",
			failOn:  "server",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "owner of the new executor directory cannot be set",
			failOn:  "executor",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "owner of the new keys directory cannot be set",
			failOn:  "keys",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "owner of the restored server database cannot be set",
			failOn:  "server.db",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "owner of the restored executor database cannot be set",
			failOn:  "executor.db",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			// The server directory did not exist before: the restore creates it,
			// and a failure after that must remove it again.
			name:    "server data directory did not exist, and the owner of server.db cannot be set",
			arrange: withoutDir(func(l Layout) string { return l.ServerDir() }),
			failOn:  "server.db",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "executor data directory did not exist, and a key file cannot be written",
			arrange: withoutDir(func(l Layout) string { return l.ExecutorDir() }),
			failOn:  "nebula-default.key",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "both data directories did not exist, and the executor database cannot be written",
			arrange: withoutDir(func(l Layout) string { return l.ServerDir() }, func(l Layout) string { return l.ExecutorDir() }),
			failOn:  "executor.db",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "owner of a restored key file cannot be set",
			failOn:  "nebula-default.key",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "configuration file cannot be written",
			failOn:  "server.json",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name:    "configuration file cannot be written, with live configuration in /etc/nebula",
			arrange: liveConfig,
			failOn:  "server.json",
			wantErr: "chown failed",
			stopped: true,
			started: true,
		},
		{
			name: "configuration file name already taken in the new directory, with live configuration",
			arrange: func(t *testing.T, l Layout) {
				liveConfig(t, l)
				dir := filepath.Join(l.ConfigDir(), "from-backup-"+ts)
				if err := os.Mkdir(dir, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "server.json"), []byte("made earlier"), 0o640); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "file exists",
			stopped: true,
			started: true,
		},
		{
			name: "configuration directory cannot be made, after the data was written",
			arrange: func(t *testing.T, l Layout) {
				if err := os.MkdirAll(filepath.Dir(l.ConfigDir()), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(l.ConfigDir(), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "not a directory",
			stopped: true,
			started: true,
		},
	}

	m0, files0 := sample(t) // built once; each case works on copies
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, files := m0, append([]File(nil), files0...)
			latest := map[string]int{"server": m.Schemas["server"], "executor": m.Schemas["executor"]}
			if c.mutate != nil {
				c.mutate(&m, &files)
			}
			l := oldLayout(t)
			if c.arrange != nil {
				c.arrange(t, l)
			}
			before := tree(t, l.Root)
			sys := &brokenSystem{fakeSystem: &fakeSystem{failOn: c.failOn}, stopErr: c.stopErr}
			sys.snap = func() map[string]string { return withoutStage(tree(t, l.Root)) }

			rep, err := Restore(m, files, l, sys, latest, now)

			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %v, want one containing %q", err, c.wantErr)
			}
			if len(rep.MovedAside) != 0 || len(rep.Config) != 0 {
				t.Fatalf("report %+v after a refusal, want an empty one", rep)
			}
			if after := tree(t, l.Root); !maps.Equal(before, after) {
				t.Fatalf("the refused restore changed the target:\nbefore %v\nafter  %v", before, after)
			}

			calls := sys.calls
			if !c.stopped {
				if len(calls) != 0 {
					t.Fatalf("calls %v, want none: the refusal comes before Stop", calls)
				}
				return
			}
			// Exactly one Stop, first. Exactly one Start, last, if the services
			// are started again; none otherwise.
			stops, starts := 0, 0
			for _, call := range calls {
				switch {
				case strings.HasPrefix(call, "stop "):
					stops++
				case strings.HasPrefix(call, "start "):
					starts++
				}
			}
			if len(calls) == 0 || !strings.HasPrefix(calls[0], "stop ") || stops != 1 {
				t.Fatalf("calls %v, want exactly one Stop, first", calls)
			}
			if c.started {
				if starts != 1 || calls[len(calls)-1] != startCall {
					t.Fatalf("calls %v, want exactly one Start, and it last", calls)
				}
				// The services must start on the old data: when Start runs, the
				// new directories and files are gone and the old ones are back.
				if len(sys.atStart) != 1 {
					t.Fatalf("%d snapshots at Start, want 1", len(sys.atStart))
				}
				if at := sys.atStart[0]; !maps.Equal(before, at) {
					t.Fatalf("the services were started before the target was back in its old state:\nbefore   %v\nat Start %v", before, at)
				}
				return
			}
			if starts != 0 {
				t.Fatalf("calls %v, want no Start: the services stay stopped", calls)
			}
		})
	}
}

// A Start failure after a complete restore is reported, and the restore stays:
// the new data is in place, the old directories are kept aside, the report is right.
func TestRestoreReportsWhenStartFails(t *testing.T) {
	m, files := sample(t)
	latest := map[string]int{"server": m.Schemas["server"], "executor": m.Schemas["executor"]}
	now := time.Unix(1_800_000_000, 0)
	l := oldLayout(t)
	startErr := errors.New("unit failed")
	sys := &brokenSystem{fakeSystem: &fakeSystem{}, startErr: startErr}

	rep, err := Restore(m, files, l, sys, latest, now)

	if err == nil || !strings.Contains(err.Error(), "did not start") || !errors.Is(err, startErr) {
		t.Fatalf("error %v, want a wrapped start failure", err)
	}
	if len(rep.MovedAside) != 2 || len(rep.Config) != 1 {
		t.Fatalf("report %+v, want two directories moved aside and one configuration file", rep)
	}
	if b, _ := os.ReadFile(filepath.Join(rep.MovedAside[0], "server.db")); string(b) != "old server" {
		t.Fatal("old server data not kept aside")
	}
	if b, _ := os.ReadFile(filepath.Join(rep.MovedAside[1], "executor.db")); string(b) != "old executor" {
		t.Fatal("old executor data not kept aside")
	}
	if v, err := CheckSQLite(filepath.Join(l.ServerDir(), "server.db")); err != nil || v != m.Schemas["server"] {
		t.Fatal("restored server database missing or wrong schema:", v, err)
	}
	if v, err := CheckSQLite(filepath.Join(l.ExecutorDir(), "executor.db")); err != nil || v != m.Schemas["executor"] {
		t.Fatal("restored executor database missing or wrong schema:", v, err)
	}
	if b, _ := os.ReadFile(rep.Config[0]); !strings.Contains(string(b), "127.0.0.1:8080") {
		t.Fatalf("configuration file %s has %q", rep.Config[0], b)
	}
	if len(sys.calls) == 0 || !strings.HasPrefix(sys.calls[0], "stop ") ||
		sys.calls[len(sys.calls)-1] != "start "+strings.Join(StartUnits, ",") {
		t.Fatalf("calls %v, want Stop first and the Start attempt last", sys.calls)
	}
}

// stubFilesystem replaces the undo's filesystem calls for one test; a nil
// function keeps the real one.
func stubFilesystem(t *testing.T, remove func(string) error, move func(string, string) error) {
	t.Helper()
	realRemove, realRename := removeAll, rename
	t.Cleanup(func() { removeAll, rename = realRemove, realRename })
	if remove != nil {
		removeAll = remove
	}
	if move != nil {
		rename = move
	}
}

// When the old data cannot be put back, the error names where it is, the old
// data stays there, and the services stay stopped (they would run on missing
// data, and StateDirectory= would recreate an empty data directory).
func TestRestoreNamesOldDataThatCannotBePutBack(t *testing.T) {
	m, files := sample(t)
	latest := map[string]int{"server": m.Schemas["server"], "executor": m.Schemas["executor"]}
	now := time.Unix(1_800_000_000, 0)
	ts := now.UTC().Format("20060102-150405")
	errRefused := errors.New("filesystem refused the rename")
	l := oldLayout(t)
	asideServer := l.ServerDir() + ".pre-restore-" + ts
	asideExecutor := l.ExecutorDir() + ".pre-restore-" + ts
	stubFilesystem(t, nil, func(from, to string) error {
		if strings.Contains(from, ".pre-restore-") {
			return errRefused
		}
		return os.Rename(from, to)
	})
	sys := &fakeSystem{failOn: "server.db"} // fails after both directories were moved aside

	rep, err := Restore(m, files, l, sys, latest, now)

	if err == nil || !errors.Is(err, errRefused) {
		t.Fatalf("error %v, want the filesystem error wrapped", err)
	}
	for _, aside := range []string{asideServer, asideExecutor} {
		if !strings.Contains(err.Error(), aside) {
			t.Fatalf("error %q does not name %s, where the old data is", err, aside)
		}
	}
	if len(rep.MovedAside) != 0 || len(rep.Config) != 0 {
		t.Fatalf("report %+v after a refusal, want an empty one", rep)
	}
	if b, _ := os.ReadFile(filepath.Join(asideServer, "server.db")); string(b) != "old server" {
		t.Fatal("old server data is not at the reported path")
	}
	if b, _ := os.ReadFile(filepath.Join(asideExecutor, "executor.db")); string(b) != "old executor" {
		t.Fatal("old executor data is not at the reported path")
	}
	for _, c := range sys.calls {
		if strings.HasPrefix(c, "start ") {
			t.Fatalf("calls %v, want the services left stopped", sys.calls)
		}
	}
	if !strings.Contains(err.Error(), "left stopped") {
		t.Fatalf("error %q does not say the services were left stopped", err)
	}
}

// A new directory that cannot be removed is reported, and the old data that
// cannot be put back is named; old data that was put back is not.
func TestRestoreReportsNewDirectoryThatCannotBeRemoved(t *testing.T) {
	m, files := sample(t)
	latest := map[string]int{"server": m.Schemas["server"], "executor": m.Schemas["executor"]}
	now := time.Unix(1_800_000_000, 0)
	ts := now.UTC().Format("20060102-150405")
	errBusy := errors.New("directory busy")
	l := oldLayout(t)
	asideServer := l.ServerDir() + ".pre-restore-" + ts
	asideExecutor := l.ExecutorDir() + ".pre-restore-" + ts
	stubFilesystem(t, func(p string) error {
		if p == l.ServerDir() {
			return errBusy
		}
		return os.RemoveAll(p)
	}, nil)
	sys := &fakeSystem{failOn: "server.db"}

	_, err := Restore(m, files, l, sys, latest, now)

	if err == nil || !errors.Is(err, errBusy) {
		t.Fatalf("error %v, want the removal error wrapped", err)
	}
	if !strings.Contains(err.Error(), asideServer) {
		t.Fatalf("error %q does not name %s, where the old server data is", err, asideServer)
	}
	if strings.Contains(err.Error(), asideExecutor) {
		t.Fatalf("error %q names %s, but the executor data was put back", err, asideExecutor)
	}
	if b, _ := os.ReadFile(filepath.Join(asideServer, "server.db")); string(b) != "old server" {
		t.Fatal("old server data is not at the reported path")
	}
	if b, _ := os.ReadFile(filepath.Join(l.ExecutorDir(), "executor.db")); string(b) != "old executor" {
		t.Fatal("executor data was not put back")
	}
	for _, c := range sys.calls {
		if strings.HasPrefix(c, "start ") {
			t.Fatalf("calls %v, want the services left stopped after a failed removal", sys.calls)
		}
	}
}

// A Start failure during a refusal is reported with %w, not dropped.
func TestRefusalReportsFailedStart(t *testing.T) {
	m, files := sample(t)
	latest := map[string]int{"server": m.Schemas["server"], "executor": m.Schemas["executor"]}
	now := time.Unix(1_800_000_000, 0)
	l := oldLayout(t)
	if err := os.RemoveAll(l.ServerDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), l.ServerDir()); err != nil {
		t.Fatal(err)
	}
	startErr := errors.New("unit failed")
	sys := &brokenSystem{fakeSystem: &fakeSystem{}, startErr: startErr}

	_, err := Restore(m, files, l, sys, latest, now)

	if err == nil || !strings.Contains(err.Error(), "not a directory") || !errors.Is(err, startErr) {
		t.Fatalf("error %v, want the refusal and the wrapped start failure", err)
	}
}

// When Stop and the Start after it both fail, both causes are returned and
// both can be matched with errors.Is.
func TestRestoreReportsStopAndStartFailures(t *testing.T) {
	m, files := sample(t)
	latest := map[string]int{"server": m.Schemas["server"], "executor": m.Schemas["executor"]}
	now := time.Unix(1_800_000_000, 0)
	l := oldLayout(t)
	before := tree(t, l.Root)
	stopErr := errors.New("unit busy")
	startErr := errors.New("unit failed")
	sys := &brokenSystem{fakeSystem: &fakeSystem{}, stopErr: stopErr, startErr: startErr}

	_, err := Restore(m, files, l, sys, latest, now)

	if err == nil || !errors.Is(err, stopErr) || !errors.Is(err, startErr) || !strings.Contains(err.Error(), "stop the services") {
		t.Fatalf("error %v, want the stop and the start failure, both matchable", err)
	}
	if after := tree(t, l.Root); !maps.Equal(before, after) {
		t.Fatal("a refused restore changed the target")
	}
}

// mkdirTracked reports only the topmost directory it created, and nothing when
// the directory already exists: a cleanup of the reported path can then never
// remove a directory that was there before the restore.
func TestMkdirTrackedReportsOnlyWhatItCreated(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	top, err := mkdirTracked(filepath.Join(root, "a", "b", "c"), 0o750)
	if err != nil {
		t.Fatal(err)
	}
	if top != filepath.Join(root, "a", "b") {
		t.Fatalf("reported %q, want the topmost created directory %q", top, filepath.Join(root, "a", "b"))
	}
	if _, err := os.Stat(filepath.Join(root, "a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	top, err = mkdirTracked(filepath.Join(root, "a", "b", "c"), 0o750)
	if err != nil || top != "" {
		t.Fatalf("second call reported %q, %v; want nothing created", top, err)
	}
	// A regular file in the way is an error, and nothing is claimed.
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if top, err := mkdirTracked(filepath.Join(root, "f", "g"), 0o750); err == nil || top != "" {
		t.Fatalf("under a file: reported %q, %v; want an error and nothing created", top, err)
	}
}

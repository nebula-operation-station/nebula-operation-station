// SPDX-License-Identifier: AGPL-3.0-or-later

package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// System is what a restore needs from the machine: services and owners.
type System interface {
	Stop(units ...string) error
	Start(units ...string) error
	// Chown gives path to the system user (and its group).
	Chown(path, user string) error
}

// Units stopped before and started after a restore, in that order.
var (
	StopUnits  = []string{"nebula-discovery.path", "nebula-discovery.timer", "nebula-server.service", "nebula-executor.service"}
	StartUnits = []string{"nebula-executor.service", "nebula-server.service", "nebula-discovery.path", "nebula-discovery.timer"}
)

// Layout says where Nebula lives; Root is "/" on a real machine.
type Layout struct{ Root string }

func (l Layout) path(p ...string) string { return filepath.Join(append([]string{l.Root}, p...)...) }

// ServerDir, ExecutorDir and ConfigDir are the restored directories.
func (l Layout) ServerDir() string   { return l.path("var", "lib", "nebula", "server") }
func (l Layout) ExecutorDir() string { return l.path("var", "lib", "nebula", "executor") }
func (l Layout) ConfigDir() string   { return l.path("etc", "nebula") }

// Report says what a restore did.
type Report struct {
	MovedAside []string // the data directories before the restore
	Config     []string // configuration files written for review, not applied
}

// CheckSchemas refuses a backup whose schema is newer than this binary
// (latest: per database, the newest version it knows).
func CheckSchemas(m Manifest, latest map[string]int) error {
	for _, k := range []string{"server", "executor"} {
		v, ok := m.Schemas[k]
		if !ok {
			return fmt.Errorf("backup: the manifest has no %s schema version", k)
		}
		if v > latest[k] {
			return fmt.Errorf("backup: the %s database has schema version %d, newer than this Nebula knows (%d); restore it with a newer version", k, v, latest[k])
		}
	}
	return nil
}

// Restore puts a checked backup in place: it checks the schemas, stages
// and checks both databases, stops the services, moves the current data
// directories aside (they are kept), writes the backup's data with the
// right owners and modes, writes its configuration next to the current
// one for review (*.from-backup; never applied), and starts the services.
// The executor then starts locked. On a failure after the move the old
// directories are put back.
func Restore(m Manifest, files []File, l Layout, sys System, latest map[string]int, now time.Time) (Report, error) {
	var rep Report
	if err := CheckSchemas(m, latest); err != nil {
		return rep, err
	}
	byPath := map[string]File{}
	for _, f := range files {
		if !ValidPath(f.Path) {
			return rep, fmt.Errorf("backup: %q is not a backup path", f.Path)
		}
		byPath[f.Path] = f
	}
	for _, p := range []string{ServerDB, ExecutorDB} {
		if _, ok := byPath[p]; !ok {
			return rep, fmt.Errorf("backup: the backup has no %s", p)
		}
	}
	base := l.path("var", "lib", "nebula")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return rep, err
	}
	stage, err := os.MkdirTemp(base, ".restore-")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(stage)
	for p, want := range map[string]string{ServerDB: "server", ExecutorDB: "executor"} {
		dst := filepath.Join(stage, strings.ReplaceAll(p, "/", "_"))
		if err := os.WriteFile(dst, byPath[p].Data, 0o600); err != nil {
			return rep, err
		}
		v, err := CheckSQLite(dst)
		if err != nil {
			return rep, err
		}
		if v != m.Schemas[want] {
			return rep, fmt.Errorf("backup: %s has schema %d, the manifest says %d", p, v, m.Schemas[want])
		}
	}
	if err := sys.Stop(StopUnits...); err != nil {
		return rep, fmt.Errorf("backup: stop the services: %w", err)
	}
	ts := now.UTC().Format("20060102-150405")
	type move struct{ from, to string }
	var moved []move
	undo := func() {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = os.RemoveAll(moved[i].from)
			_ = os.Rename(moved[i].to, moved[i].from)
		}
		_ = sys.Start(StartUnits...)
	}
	for _, d := range []string{l.ServerDir(), l.ExecutorDir()} {
		if _, err := os.Lstat(d); errors.Is(err, os.ErrNotExist) {
			continue
		}
		aside := d + ".pre-restore-" + ts
		if err := os.Rename(d, aside); err != nil {
			undo()
			return rep, fmt.Errorf("backup: move %s aside: %w", d, err)
		}
		moved = append(moved, move{d, aside})
		rep.MovedAside = append(rep.MovedAside, aside)
	}
	fail := func(err error) (Report, error) {
		undo()
		return Report{}, err
	}
	mk := func(dir string, mode os.FileMode, user string) error {
		if err := os.Mkdir(dir, mode); err != nil {
			return err
		}
		if err := os.Chmod(dir, mode); err != nil {
			return err
		}
		return sys.Chown(dir, user)
	}
	put := func(path string, b []byte, mode os.FileMode, user string) error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		if _, err := f.Write(b); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		return sys.Chown(path, user)
	}
	if err := mk(l.ServerDir(), 0o750, "nebula-server"); err != nil {
		return fail(err)
	}
	if err := mk(l.ExecutorDir(), 0o700, "nebula-executor"); err != nil {
		return fail(err)
	}
	if err := mk(filepath.Join(l.ExecutorDir(), "keys"), 0o700, "nebula-executor"); err != nil {
		return fail(err)
	}
	if err := put(filepath.Join(l.ServerDir(), "server.db"), byPath[ServerDB].Data, 0o600, "nebula-server"); err != nil {
		return fail(err)
	}
	if err := put(filepath.Join(l.ExecutorDir(), "executor.db"), byPath[ExecutorDB].Data, 0o600, "nebula-executor"); err != nil {
		return fail(err)
	}
	for _, f := range files {
		switch {
		case strings.HasPrefix(f.Path, "executor/keys/"):
			mode := os.FileMode(0o600)
			if strings.HasSuffix(f.Path, ".pub") {
				mode = 0o644
			}
			if err := put(filepath.Join(l.ExecutorDir(), "keys", filepath.Base(f.Path)), f.Data, mode, "nebula-executor"); err != nil {
				return fail(err)
			}
		case strings.HasPrefix(f.Path, "server/config/") || strings.HasPrefix(f.Path, "server/systemd/"):
			dir := filepath.Join(l.ConfigDir(), "from-backup-"+ts)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fail(err)
			}
			name := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(f.Path, "server/config/"), "server/systemd/"), "/", "_")
			p := filepath.Join(dir, name)
			if err := put(p, f.Data, 0o640, "root"); err != nil {
				return fail(err)
			}
			rep.Config = append(rep.Config, p)
		}
	}
	if err := sys.Start(StartUnits...); err != nil {
		return rep, fmt.Errorf("backup: restored, but the services did not start: %w", err)
	}
	return rep, nil
}

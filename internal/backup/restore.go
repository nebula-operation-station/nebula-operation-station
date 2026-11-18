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

// The filesystem calls that undo depends on. Tests replace them to force the
// failures a real filesystem does not produce on demand.
var (
	removeAll = os.RemoveAll
	rename    = os.Rename
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

// mkdirTracked creates dir and its missing ancestors with mode, top-down, and
// returns the topmost directory this call created ("" if dir already existed).
// A directory that another process creates between the check and the Mkdir
// makes Mkdir fail with ErrExist; it is not claimed, so a cleanup that removes
// the returned path never deletes something this restore did not create.
func mkdirTracked(dir string, mode os.FileMode) (string, error) {
	var missing []string // bottom-up
	for q := dir; ; q = filepath.Dir(q) {
		_, err := os.Lstat(q)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		missing = append(missing, q)
		if filepath.Dir(q) == q {
			break
		}
	}
	top := ""
	for i := len(missing) - 1; i >= 0; i-- {
		err := os.Mkdir(missing[i], mode)
		if errors.Is(err, os.ErrExist) {
			continue // made by someone else meanwhile: not ours to remove
		}
		if err != nil {
			return top, err
		}
		if top == "" {
			top = missing[i]
		}
	}
	return top, nil
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
		// Stop may have stopped some units before it failed, and nothing has
		// moved yet. All StartUnits are started again, including units that
		// were inactive or disabled before: System does not report unit state.
		stopErr := fmt.Errorf("backup: stop the services: %w", err)
		if startErr := sys.Start(StartUnits...); startErr != nil {
			return rep, fmt.Errorf("%w; start the services again: %w", stopErr, startErr)
		}
		return rep, stopErr
	}
	ts := now.UTC().Format("20060102-150405")
	type move struct{ from, to string }
	var moved []move
	var created []string // data directories this restore made; removed on a failure
	// undo returns the data directories to their state before the restore: it
	// removes what this restore created, puts each old directory back, and
	// starts the services. Every error is returned, and an old directory that
	// could not be put back is named, so the operator knows where the data is.
	// If anything could not be removed or put back (prior holds earlier
	// cleanup errors of the caller), the services stay stopped: they would
	// run on missing or half-restored data, and systemd's StateDirectory=
	// would create an empty data directory that blocks a manual rename back.
	undo := func(prior []error) error {
		errs := append([]error(nil), prior...)
		for i := len(created) - 1; i >= 0; i-- {
			if err := removeAll(created[i]); err != nil {
				errs = append(errs, fmt.Errorf("remove the new %s: %w", created[i], err))
			}
		}
		var stranded []string
		for i := len(moved) - 1; i >= 0; i-- {
			if err := rename(moved[i].to, moved[i].from); err != nil {
				stranded = append(stranded, moved[i].to)
				errs = append(errs, fmt.Errorf("put %s back: %w", moved[i].from, err))
			}
		}
		if len(stranded) > 0 {
			errs = append(errs, fmt.Errorf("the old data is still at %s", strings.Join(stranded, ", ")))
		}
		if len(errs) > 0 {
			errs = append(errs, errors.New("the services were left stopped; put the data back by hand, then start them"))
			return errors.Join(errs...)
		}
		if err := sys.Start(StartUnits...); err != nil {
			errs = append(errs, fmt.Errorf("start the services: %w", err))
		}
		return errors.Join(errs...)
	}
	// cfgRoot is the topmost directory this restore created for configuration
	// files; a failure removes it, with any partly written file in it. Live
	// configuration in ConfigDir is never under cfgRoot unless this restore
	// created it, because mkdirTracked reports only what it created.
	var cfgRoot string
	// refuse removes what the restore has written, puts the old data back,
	// starts the services, and returns err. If that cannot be completed, the
	// error says so and names where the old data is.
	refuse := func(err error) (Report, error) {
		var errs []error
		if cfgRoot != "" {
			if rerr := removeAll(cfgRoot); rerr != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", cfgRoot, rerr))
			}
		}
		if uerr := undo(errs); uerr != nil {
			errs = []error{uerr}
		}
		if len(errs) > 0 {
			return Report{}, fmt.Errorf("%w; restoring the previous state failed: %w", err, errors.Join(errs...))
		}
		return Report{}, err
	}
	for _, d := range []string{l.ServerDir(), l.ExecutorDir()} {
		fi, err := os.Lstat(d)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		// Renaming a symbolic link would leave its target in place while
		// the report says the data was moved aside (review m102, F7).
		if err == nil && !fi.IsDir() {
			return refuse(fmt.Errorf("backup: %s is not a directory (a symbolic link?); refusing to restore over it", d))
		}
		aside := d + ".pre-restore-" + ts
		if err := rename(d, aside); err != nil {
			return refuse(fmt.Errorf("backup: move %s aside: %w", d, err))
		}
		moved = append(moved, move{d, aside})
		rep.MovedAside = append(rep.MovedAside, aside)
	}
	mk := func(dir string, mode os.FileMode, user string) error {
		if err := os.Mkdir(dir, mode); err != nil {
			return err
		}
		created = append(created, dir) // ours from here on, even if the owner cannot be set
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
		return refuse(err)
	}
	if err := mk(l.ExecutorDir(), 0o700, "nebula-executor"); err != nil {
		return refuse(err)
	}
	if err := mk(filepath.Join(l.ExecutorDir(), "keys"), 0o700, "nebula-executor"); err != nil {
		return refuse(err)
	}
	if err := put(filepath.Join(l.ServerDir(), "server.db"), byPath[ServerDB].Data, 0o600, "nebula-server"); err != nil {
		return refuse(err)
	}
	if err := put(filepath.Join(l.ExecutorDir(), "executor.db"), byPath[ExecutorDB].Data, 0o600, "nebula-executor"); err != nil {
		return refuse(err)
	}
	for _, f := range files {
		switch {
		case strings.HasPrefix(f.Path, "executor/keys/"):
			mode := os.FileMode(0o600)
			if strings.HasSuffix(f.Path, ".pub") {
				mode = 0o644
			}
			if err := put(filepath.Join(l.ExecutorDir(), "keys", filepath.Base(f.Path)), f.Data, mode, "nebula-executor"); err != nil {
				return refuse(err)
			}
		case strings.HasPrefix(f.Path, "server/config/") || strings.HasPrefix(f.Path, "server/systemd/"):
			dir := filepath.Join(l.ConfigDir(), "from-backup-"+ts)
			created, err := mkdirTracked(dir, 0o750)
			if cfgRoot == "" {
				cfgRoot = created
			}
			if err != nil {
				return refuse(err)
			}
			name := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(f.Path, "server/config/"), "server/systemd/"), "/", "_")
			p := filepath.Join(dir, name)
			if err := put(p, f.Data, 0o640, "root"); err != nil {
				return refuse(err)
			}
			rep.Config = append(rep.Config, p)
		}
	}
	if err := sys.Start(StartUnits...); err != nil {
		return rep, fmt.Errorf("backup: restored, but the services did not start: %w", err)
	}
	return rep, nil
}

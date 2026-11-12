// SPDX-License-Identifier: AGPL-3.0-or-later

package stage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// ErrModules is a module source tree that cannot become a valid
// builtins.tar: a malformed lock, a missing or non-regular script, a
// script that does not match its lock hash, a duplicate module or a
// bundle limit exceeded.
var ErrModules = errors.New("stage: invalid built-in modules")

// maxModuleTreeEntries bounds the entries walked in the module source tree.
const maxModuleTreeEntries = 16384

// epoch is the fixed mtime of every builtins.tar header.
var epoch = time.Unix(0, 0)

// ModuleTar is one built-in module version and its exact nested tar.
type ModuleTar struct {
	// Name and Version come from the module's lock.
	Name    string
	Version string
	// Tar is the module tar as nested in builtins.tar.
	Tar []byte
}

// Builtins is a built builtins.tar with its nested module tars.
type Builtins struct {
	// Tar is the exact builtins.tar.
	Tar []byte
	// Modules are sorted by name, in builtins.tar order.
	Modules []ModuleTar
}

// tarFile is one regular file written to a deterministic tar.
type tarFile struct {
	name string
	data []byte
}

// BuildBuiltins builds builtins.tar from the module source tree dir: every
// directory holding a module.lock.json is one module. Each module tar
// holds exactly the lock and the scripts it references, in ASCII path
// order; builtins.tar holds modules/<name>/<version>.tar per module,
// sorted by name. Every header is POSIX ustar with mode 0644, mtime 0,
// uid/gid 0 and no user or group names, so the output depends only on the
// file contents. The result is checked with release.VerifyBundle and
// release.ParseModuleTar against an unsigned in-memory manifest before it
// is returned.
func BuildBuiltins(ctx context.Context, dir string) (Builtins, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Builtins{}, fmt.Errorf("%w: open module tree: %v", ErrModules, err)
	}
	defer root.Close()
	var lockDirs []string
	walked := 0
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if walked++; walked > maxModuleTreeEntries {
			return fmt.Errorf("more than %d entries", maxModuleTreeEntries)
		}
		if d.Name() == release.LockFile && !d.IsDir() {
			lockDirs = append(lockDirs, path.Dir(p))
		}
		return nil
	})
	if err != nil {
		return Builtins{}, fmt.Errorf("%w: walk module tree: %v", ErrModules, err)
	}
	if len(lockDirs) == 0 || len(lockDirs) > release.MaxModules {
		return Builtins{}, fmt.Errorf("%w: found %d modules, want 1 to %d", ErrModules, len(lockDirs), release.MaxModules)
	}
	var b Builtins
	seen := map[string]string{}
	var nested int64
	for _, d := range lockDirs {
		if err := ctx.Err(); err != nil {
			return Builtins{}, err
		}
		mt, err := buildModule(root, d)
		if err != nil {
			return Builtins{}, fmt.Errorf("%w: %s: %v", ErrModules, d, err)
		}
		if other, dup := seen[mt.Name]; dup {
			return Builtins{}, fmt.Errorf("%w: module %s is defined in %s and %s", ErrModules, mt.Name, other, d)
		}
		seen[mt.Name] = d
		if nested += int64(len(mt.Tar)); nested > release.MaxNestedTotal {
			return Builtins{}, fmt.Errorf("%w: module tars exceed %d bytes in total", ErrModules, release.MaxNestedTotal)
		}
		b.Modules = append(b.Modules, mt)
	}
	sort.Slice(b.Modules, func(i, j int) bool { return b.Modules[i].Name < b.Modules[j].Name })
	outer := make([]tarFile, 0, len(b.Modules))
	for _, m := range b.Modules {
		outer = append(outer, tarFile{name: "modules/" + m.Name + "/" + m.Version + ".tar", data: m.Tar})
	}
	if b.Tar, err = writeTar(outer); err != nil {
		return Builtins{}, fmt.Errorf("%w: write %s: %v", ErrModules, release.BundleArtifact, err)
	}
	if len(b.Tar) > release.MaxBundle {
		return Builtins{}, fmt.Errorf("%w: %s exceeds %d bytes", ErrModules, release.BundleArtifact, release.MaxBundle)
	}
	if err := b.verify(); err != nil {
		return Builtins{}, err
	}
	return b, nil
}

// buildModule builds the module tar of the module in directory d.
func buildModule(root *os.Root, d string) (ModuleTar, error) {
	lock, err := readSource(root, path.Join(d, release.LockFile), release.MaxLockFile)
	if err != nil {
		return ModuleTar{}, err
	}
	l, _, err := modulelock.ParseFirstParty(lock)
	if err != nil {
		return ModuleTar{}, fmt.Errorf("lock: %w", err)
	}
	files := []tarFile{{name: release.LockFile, data: lock}}
	added := map[string]bool{release.LockFile: true}
	for _, name := range l.Names() {
		script := l.Actions[name].Script
		if added[script] {
			continue
		}
		if !fs.ValidPath(script) {
			return ModuleTar{}, fmt.Errorf("action %s: script path %q is not a relative path", name, script)
		}
		data, err := readSource(root, path.Join(d, script), release.MaxScriptFile)
		if err != nil {
			return ModuleTar{}, fmt.Errorf("action %s: %w", name, err)
		}
		files = append(files, tarFile{name: script, data: data})
		added[script] = true
	}
	if len(files) > release.MaxModuleFiles {
		return ModuleTar{}, fmt.Errorf("more than %d files", release.MaxModuleFiles)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	tb, err := writeTar(files)
	if err != nil {
		return ModuleTar{}, err
	}
	if len(tb) > release.MaxModuleTar {
		return ModuleTar{}, fmt.Errorf("module tar exceeds %d bytes", release.MaxModuleTar)
	}
	return ModuleTar{Name: l.Name, Version: l.Version, Tar: tb}, nil
}

// readSource reads a regular file of at most max bytes inside root
// without following a symlink in its last component.
func readSource(root *os.Root, p string, max int64) ([]byte, error) {
	fi, err := root.Lstat(p)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", p, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	f, err := root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", p, max)
	}
	return b, nil
}

// writeTar writes files, in the given order, as a POSIX ustar archive
// with fixed metadata.
func writeTar(files []tarFile) ([]byte, error) {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, f := range files {
		h := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.name,
			Size:     int64(len(f.data)),
			Mode:     0o644,
			ModTime:  epoch,
			Format:   tar.FormatUSTAR,
		}
		if err := w.WriteHeader(h); err != nil {
			return nil, fmt.Errorf("header %s: %w", f.name, err)
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close: %w", err)
	}
	return buf.Bytes(), nil
}

// manifest is the unsigned in-memory manifest for b: the bundle checks of
// VerifyBundle and ParseModuleTar need one, the signature is not checked.
func (b Builtins) manifest(version string) release.Manifest {
	m := release.Manifest{
		ReleaseVersion: version,
		Artifacts:      []release.Artifact{artifactOf(release.BundleArtifact, b.Tar)},
	}
	for _, mt := range b.Modules {
		a := artifactOf(mt.Name, mt.Tar)
		m.Modules = append(m.Modules, release.Module{Name: mt.Name, Version: mt.Version, Size: a.Size, SHA256: a.SHA256})
	}
	return m
}

// verify runs the executor's strict bundle validation over b.
func (b Builtins) verify() error {
	m := b.manifest("0.0.0")
	if _, err := release.VerifyBundle(m, b.Tar); err != nil {
		return fmt.Errorf("%w: built %s fails bundle validation: %v", ErrModules, release.BundleArtifact, err)
	}
	for i, md := range m.Modules {
		if _, err := release.ParseModuleTar(md, b.Modules[i].Tar); err != nil {
			return fmt.Errorf("%w: built module tar fails validation: %v", ErrModules, err)
		}
	}
	return nil
}

func artifactOf(name string, b []byte) release.Artifact {
	s := sha256.Sum256(b)
	return release.Artifact{Name: name, Size: int64(len(b)), SHA256: hex.EncodeToString(s[:])}
}

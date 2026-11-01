// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bootstrap loads the first-party bootstrap modules shipped in
// modules/bootstrap (ADR 0008, section 5, PV-07): the functions of the
// Ubuntu Server Bootstrap Toolkit as ordinary modules (spec 10) for
// Debian 12/13 and Ubuntu 22.04/24.04.
//
// Every bootstrap module provides the four actions install, verify,
// update and uninstall. install, update and uninstall are durable and
// idempotent by contract: re-running one reconciles the component to the
// module's state instead of failing on it. verify is a read-only health
// check: LOW risk, not durable, no secret slots, and it exits non-zero
// when the component is not in place.
//
// Secrets are never values in a module or in a deploy profile. An action
// declares secret slots (e.g. NetBird's setup_key, Telegraf's InfluxDB
// token); the profile references executor vault entries that fill the
// slots at run time, and the prelude hands the script only file paths.
package bootstrap

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
)

// LockFile is the name of the module's lock document in the tree and in
// the module tar.
const LockFile = "module.lock.json"

// AuthorFile is the author's input file; only Pack reads it. Locks and
// tars never contain it.
const AuthorFile = "module.yaml"

// SigFile is the optional signature of the lock, made with
// `ssh-keygen -Y sign -n nebula-module`.
const SigFile = "module.lock.json.sig"

// The four actions every bootstrap module must provide (ADR 0008
// section 5).
const (
	ActionInstall   = "install"
	ActionVerify    = "verify"
	ActionUpdate    = "update"
	ActionUninstall = "uninstall"
)

// RequiredActions lists the actions Load checks for in every module.
var RequiredActions = []string{ActionInstall, ActionVerify, ActionUpdate, ActionUninstall}

// Module is one loaded bootstrap module: its verified first-party lock
// and the exact bytes of the scripts the lock references.
type Module struct {
	Name       string
	Version    string
	Lock       modulelock.Lock
	LockBytes  []byte
	LockSHA256 string
	Scripts    map[string][]byte
}

// Load reads every module under root (root/<name>/module.lock.json and
// its scripts) and checks the bootstrap contract: the directory name
// equals the lock's name, the lock parses as a first-party lock, the
// four bootstrap actions are present with the right run modes, every
// script exists and hashes to the lock, and the directory holds nothing
// but module.yaml, module.lock.json, an optional signature and the
// referenced scripts.
func Load(root string) ([]Module, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read module root: %w", err)
	}
	var out []Module
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := loadOne(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("bootstrap: no modules under %s", root)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func loadOne(dir string) (Module, error) {
	name := filepath.Base(dir)
	lockRaw, err := os.ReadFile(filepath.Join(dir, LockFile))
	if err != nil {
		return Module{}, fmt.Errorf("bootstrap %s: %w", name, err)
	}
	l, lockHash, err := modulelock.ParseFirstParty(lockRaw)
	if err != nil {
		return Module{}, fmt.Errorf("bootstrap %s: %w", name, err)
	}
	if l.Name != name {
		return Module{}, fmt.Errorf("bootstrap %s: the lock names module %s", name, l.Name)
	}
	m := Module{Name: l.Name, Version: l.Version, Lock: l, LockBytes: lockRaw, LockSHA256: lockHash, Scripts: map[string][]byte{}}
	for _, a := range l.Names() {
		script, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(l.Actions[a].Script)))
		if err != nil {
			return Module{}, fmt.Errorf("bootstrap %s: action %s: %w", name, a, err)
		}
		if _, _, err := l.Artifact(a, script); err != nil {
			return Module{}, fmt.Errorf("bootstrap %s: %w", name, err)
		}
		m.Scripts[l.Actions[a].Script] = script
	}
	if err := m.checkContract(); err != nil {
		return Module{}, fmt.Errorf("bootstrap %s: %w", name, err)
	}
	if err := checkDir(dir, l); err != nil {
		return Module{}, fmt.Errorf("bootstrap %s: %w", name, err)
	}
	return m, nil
}

// checkContract enforces the bootstrap action contract (ADR 0008
// section 5): the four required actions, verify read-only and LOW risk,
// the mutating actions durable.
func (m Module) checkContract() error {
	for _, a := range RequiredActions {
		act, ok := m.Lock.Actions[a]
		if !ok {
			return fmt.Errorf("missing required action %s", a)
		}
		switch a {
		case ActionVerify:
			if act.Risk != "LOW" {
				return fmt.Errorf("action verify must be LOW risk")
			}
			if act.Durable {
				return fmt.Errorf("action verify must not be durable")
			}
			if len(act.Secrets) != 0 {
				return fmt.Errorf("action verify must not take secret slots")
			}
		default:
			if !act.Durable {
				return fmt.Errorf("action %s must be durable (idempotent, reconcile-first)", a)
			}
		}
	}
	return nil
}

// checkDir rejects anything in the module directory that is not the
// author file, the lock, an optional signature or a referenced script.
func checkDir(dir string, l modulelock.Lock) error {
	referenced := map[string]bool{AuthorFile: true, LockFile: true, SigFile: true}
	for _, a := range l.Names() {
		referenced[l.Actions[a].Script] = true
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if !isDirPrefix(rel, referenced) {
				return fmt.Errorf("unexpected directory %s", rel)
			}
			return nil
		}
		if !referenced[rel] {
			return fmt.Errorf("file %s is not part of the module", rel)
		}
		return nil
	})
}

func isDirPrefix(dir string, referenced map[string]bool) bool {
	for p := range referenced {
		if len(p) > len(dir) && p[:len(dir)] == dir && p[len(dir)] == '/' {
			return true
		}
	}
	return false
}

// Tar builds the module's tar for the release bundle (spec 10,
// release-bundle profile): an uncompressed POSIX ustar archive holding
// exactly module.lock.json and the lock's scripts, in ASCII path order,
// regular files only. The output is what the release signs and what
// internal/release verifies on the host.
func (m Module) Tar() ([]byte, error) {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	names := make([]string, 0, len(m.Scripts)+1)
	names = append(names, LockFile)
	for n := range m.Scripts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		var data []byte
		if n == LockFile {
			data = m.LockBytes
		} else {
			data = m.Scripts[n]
		}
		hdr := &tar.Header{
			Name:       n,
			Mode:       0o644,
			Size:       int64(len(data)),
			Format:     tar.FormatUSTAR,
			ModTime:    time.Time{},
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
		}
		if err := w.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("bootstrap %s: tar %s: %w", m.Name, n, err)
		}
		if _, err := w.Write(data); err != nil {
			return nil, fmt.Errorf("bootstrap %s: tar %s: %w", m.Name, n, err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("bootstrap %s: close tar: %w", m.Name, err)
	}
	return buf.Bytes(), nil
}

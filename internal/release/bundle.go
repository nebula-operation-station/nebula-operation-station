// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
)

// Bundle limits (spec 10, hard limits).
const (
	// MaxBundle bounds builtins.tar on disk.
	MaxBundle = 80 << 20
	// MaxBundleEntries bounds the outer archive's entries.
	MaxBundleEntries = 128
	// MaxNestedTotal bounds the sum of the nested module tars.
	MaxNestedTotal = 64 << 20
	// MaxModuleFiles bounds the regular files of one module tar.
	MaxModuleFiles = 128
	// MaxInnerEntries bounds inner entries over the whole bundle.
	MaxInnerEntries = 4096
	// MaxInnerContent bounds inner file content over the whole bundle.
	MaxInnerContent = 64 << 20
	// MaxLockFile bounds module.lock.json; MaxScriptFile each script;
	// MaxOtherFile any other file.
	MaxLockFile   = 256 << 10
	MaxScriptFile = 256 << 10
	MaxOtherFile  = 1 << 20
	// MaxInnerPath bounds an inner path.
	MaxInnerPath = 240
)

// Bundle directory entries.
const (
	ManifestFile  = "release-manifest.json"
	SignatureFile = "release-manifest.json.sig"
	// LockFile is the lock inside every module tar.
	LockFile = "module.lock.json"
)

var innerComponentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// validInnerPath checks the inner path grammar: 1 to 240 bytes, at most
// four components of [a-z0-9][a-z0-9_.-]{0,63}.
func validInnerPath(p string) bool {
	if len(p) == 0 || len(p) > MaxInnerPath {
		return false
	}
	parts := strings.Split(p, "/")
	if len(parts) > 4 {
		return false
	}
	for _, c := range parts {
		if !innerComponentRe.MatchString(c) || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// ActionArtifact is the executor-built artifact of one action.
type ActionArtifact struct {
	// ActionID is <family>.<action>.
	ActionID string
	// Risk is the risk the action is trusted at (modulelock TrustRisk).
	Risk string
	// Script is the lock-referenced script path; ScriptSHA256 its hash.
	Script       string
	ScriptSHA256 string
	// Bytes is the artifact that runs on the host; SHA256 its hash.
	Bytes  []byte
	SHA256 string
}

// ModuleBundle is one verified built-in module version from a bundle.
type ModuleBundle struct {
	// Module is the manifest entry.
	Module Module
	// Tar is the exact module tar the manifest hashes.
	Tar []byte
	// Lock is the parsed lock; LockHash the SHA-256 of its bytes.
	Lock     modulelock.Lock
	LockHash string
	// Files are the module's files by path, in ASCII order of Paths.
	Files map[string][]byte
	Paths []string
	// Actions are the built artifacts, sorted by action ID.
	Actions []ActionArtifact
}

// Candidate is a verified local release bundle: provenance first, then
// the bundle's size, hash and complete module list.
type Candidate struct {
	// Manifest is the verified, signed manifest.
	Manifest Manifest
	// Modules are the verified modules, in manifest order.
	Modules []ModuleBundle
}

// ReadBundleDir reads and verifies a local review directory holding
// exactly release-manifest.json, its signature and builtins.tar, all
// regular files opened without following symlinks. roots are the active
// roots of the executor's durable root state.
func ReadBundleDir(dir string, roots []Root) (Candidate, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return Candidate{}, fmt.Errorf("%w: open bundle directory: %v", ErrBundle, err)
	}
	defer r.Close()
	d, err := r.Open(".")
	if err != nil {
		return Candidate{}, fmt.Errorf("%w: list bundle directory: %v", ErrBundle, err)
	}
	names, err := d.Readdirnames(8)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return Candidate{}, fmt.Errorf("%w: list bundle directory: %v", ErrBundle, err)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != strings.Join([]string{BundleArtifact, ManifestFile, SignatureFile}, ",") {
		return Candidate{}, fmt.Errorf("%w: the directory must hold exactly %s, %s and %s", ErrBundle, ManifestFile, SignatureFile, BundleArtifact)
	}
	man, err := readRegular(r, ManifestFile, MaxManifest)
	if err != nil {
		return Candidate{}, err
	}
	sig, err := readRegular(r, SignatureFile, MaxSignature)
	if err != nil {
		return Candidate{}, err
	}
	m, err := VerifyManifest(roots, man, sig)
	if err != nil {
		return Candidate{}, err
	}
	tarBytes, err := readRegular(r, BundleArtifact, MaxBundle)
	if err != nil {
		return Candidate{}, err
	}
	mods, err := VerifyBundle(m, tarBytes)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{Manifest: m, Modules: mods}, nil
}

// readRegular reads a regular file of at most max bytes without
// following symlinks.
func readRegular(r *os.Root, name string, max int64) ([]byte, error) {
	if fi, err := r.Lstat(name); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrBundle, name)
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrBundle, name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%w: %s is not a regular file of at most %d bytes", ErrBundle, name, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fmt.Errorf("%w: read %s: at most %d bytes", ErrBundle, name, max)
	}
	return b, nil
}

// VerifyBundle checks builtins.tar against a verified manifest: exact
// size and hash, one modules/<name>/<version>.tar per manifest module in
// manifest order with the manifest's size and hash, and inside each
// module tar exactly its lock and the scripts the lock references, in
// ASCII path order, with every script hash checked and every action
// artifact built here. Any violation rejects the whole bundle.
func VerifyBundle(m Manifest, b []byte) ([]ModuleBundle, error) {
	bad := func(format string, a ...any) ([]ModuleBundle, error) {
		return nil, fmt.Errorf("%w: %s", ErrBundle, fmt.Sprintf(format, a...))
	}
	want := m.Bundle()
	if want.Name == "" {
		return bad("the manifest lists no %s", BundleArtifact)
	}
	if int64(len(b)) != want.Size || len(b) > MaxBundle {
		return bad("%s is %d bytes, the manifest says %d", BundleArtifact, len(b), want.Size)
	}
	if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != want.SHA256 {
		return bad("%s does not match the manifest's sha256", BundleArtifact)
	}
	outer, err := readUstar(b, tarLimits{maxEntries: MaxBundleEntries, maxFile: MaxModuleTar, maxTotal: MaxNestedTotal},
		func(p string) bool { return strings.HasPrefix(p, "modules/") && len(p) <= MaxInnerPath })
	if err != nil {
		return bad("%s: %v", BundleArtifact, err)
	}
	if len(outer) != len(m.Modules) {
		return bad("%s holds %d modules, the manifest lists %d", BundleArtifact, len(outer), len(m.Modules))
	}
	innerEntries := 0
	var innerBytes int64
	out := make([]ModuleBundle, 0, len(outer))
	for i, e := range outer {
		md := m.Modules[i]
		if e.name != "modules/"+md.Name+"/"+md.Version+".tar" {
			return bad("entry %d is %q, want modules/%s/%s.tar", i, e.name, md.Name, md.Version)
		}
		if int64(len(e.data)) != md.Size {
			return bad("%s is %d bytes, the manifest says %d", e.name, len(e.data), md.Size)
		}
		if s := sha256.Sum256(e.data); hex.EncodeToString(s[:]) != md.SHA256 {
			return bad("%s does not match the manifest's sha256", e.name)
		}
		files, err := readUstar(e.data, tarLimits{maxEntries: MaxModuleFiles, maxFile: MaxOtherFile, maxTotal: MaxInnerContent}, validInnerPath)
		if err != nil {
			return bad("%s: %v", e.name, err)
		}
		innerEntries += len(files)
		for _, f := range files {
			innerBytes += int64(len(f.data))
		}
		if innerEntries > MaxInnerEntries || innerBytes > MaxInnerContent {
			return bad("the bundle exceeds %d inner entries or %d bytes of inner content", MaxInnerEntries, MaxInnerContent)
		}
		mb, err := verifyModule(md, e.data, files)
		if err != nil {
			return bad("%s: %v", e.name, err)
		}
		out = append(out, mb)
	}
	return out, nil
}

func verifyModule(md Module, tar []byte, files []tarEntry) (ModuleBundle, error) {
	mb := ModuleBundle{Module: md, Tar: tar, Files: map[string][]byte{}}
	for i, f := range files {
		if i > 0 && files[i-1].name >= f.name {
			return ModuleBundle{}, errors.New("files are not in ASCII path order")
		}
		mb.Files[f.name] = f.data
		mb.Paths = append(mb.Paths, f.name)
	}
	lock, ok := mb.Files[LockFile]
	if !ok {
		return ModuleBundle{}, fmt.Errorf("missing %s", LockFile)
	}
	if len(lock) > MaxLockFile {
		return ModuleBundle{}, fmt.Errorf("%s exceeds %d bytes", LockFile, MaxLockFile)
	}
	l, lockHash, err := modulelock.ParseFirstParty(lock)
	if err != nil {
		return ModuleBundle{}, err
	}
	if l.Name != md.Name || l.Version != md.Version {
		return ModuleBundle{}, fmt.Errorf("the lock names %s %s, the manifest %s %s", l.Name, l.Version, md.Name, md.Version)
	}
	mb.Lock, mb.LockHash = l, lockHash
	referenced := map[string]bool{LockFile: true}
	for _, name := range l.Names() {
		a := l.Actions[name]
		script, ok := mb.Files[a.Script]
		if !ok {
			return ModuleBundle{}, fmt.Errorf("action %s: script %s is missing", name, a.Script)
		}
		if len(script) > MaxScriptFile {
			return ModuleBundle{}, fmt.Errorf("action %s: script exceeds %d bytes", name, MaxScriptFile)
		}
		art, artHash, err := l.Artifact(name, script)
		if err != nil {
			return ModuleBundle{}, err
		}
		referenced[a.Script] = true
		mb.Actions = append(mb.Actions, ActionArtifact{ActionID: l.ActionID(name), Risk: a.TrustRisk(),
			Script: a.Script, ScriptSHA256: a.SHA256, Bytes: art, SHA256: artHash})
	}
	for _, p := range mb.Paths {
		if !referenced[p] {
			return ModuleBundle{}, fmt.Errorf("file %s is not referenced by the lock", p)
		}
	}
	return mb, nil
}
